import { spawn, ChildProcess } from 'child_process';
import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';

interface StreamJsonMessage {
  type: string;
  id?: string;
  message?: {
    id: string;
    content: Array<{ type: string; text?: string }>;
    stop_reason?: string;
  };
  index?: number;
  content_block?: { type: string; text?: string };
  delta?: { type: string; text?: string };
}

interface PendingRequest {
  id: string;
  resolve: (response: string) => void;
  reject: (error: Error) => void;
  onDelta?: (text: string) => void;
  onComplete?: () => void;
  buffer: string;
}

export class ClaudeProcess extends EventEmitter {
  private process: ChildProcess | null = null;
  private pendingRequests: Map<string, PendingRequest> = new Map();
  private buffer: string = '';
  private ready: boolean = false;
  private readyPromise: Promise<void>;
  private readyResolve!: () => void;

  constructor() {
    super();
    this.readyPromise = new Promise((resolve) => {
      this.readyResolve = resolve;
    });
    this.start();
  }

  private start(): void {
    console.log('[ProcessPool] Starting claude process...');

    this.process = spawn('claude', [
      '--print',
      '--input-format', 'stream-json',
      '--output-format', 'stream-json',
      '--dangerously-skip-permissions'
    ], {
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
      env: { ...process.env, LANG: 'en_US.UTF-8' }
    });

    this.process.stdout?.on('data', (data: Buffer) => {
      this.handleOutput(data.toString());
    });

    this.process.stderr?.on('data', (data: Buffer) => {
      console.error('[ProcessPool] stderr:', data.toString());
    });

    this.process.on('close', (code) => {
      console.log(`[ProcessPool] Process exited with code ${code}`);
      this.ready = false;
      // 重启进程
      setTimeout(() => this.start(), 1000);
    });

    this.process.on('error', (err) => {
      console.error('[ProcessPool] Process error:', err);
      this.ready = false;
    });

    // 标记为就绪
    this.ready = true;
    this.readyResolve();
    console.log('[ProcessPool] Claude process started');
  }

  private handleOutput(data: string): void {
    this.buffer += data;

    // 按行处理
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() || ''; // 保留最后一个不完整的行

    for (const line of lines) {
      if (!line.trim()) continue;

      try {
        const msg: StreamJsonMessage = JSON.parse(line);
        this.handleMessage(msg);
      } catch {
        // 非 JSON 行，可能是普通文本输出
        console.log('[ProcessPool] Non-JSON output:', line.substring(0, 100));
      }
    }
  }

  private handleMessage(msg: StreamJsonMessage): void {
    // Claude stream-json 格式的消息处理
    // 找到对应的请求（当前只支持单个请求）
    const request = this.pendingRequests.values().next().value as PendingRequest | undefined;
    if (!request) return;

    switch (msg.type) {
      case 'content_block_delta':
        if (msg.delta?.text) {
          request.buffer += msg.delta.text;
          request.onDelta?.(msg.delta.text);
        }
        break;

      case 'message_stop':
        request.onComplete?.();
        request.resolve(request.buffer);
        this.pendingRequests.delete(request.id);
        break;

      case 'error':
        request.reject(new Error(JSON.stringify(msg)));
        this.pendingRequests.delete(request.id);
        break;
    }
  }

  async waitReady(): Promise<void> {
    return this.readyPromise;
  }

  isReady(): boolean {
    return this.ready && this.process !== null;
  }

  isBusy(): boolean {
    return this.pendingRequests.size > 0;
  }

  async sendMessage(
    userMessage: string,
    onDelta?: (text: string) => void,
    onComplete?: () => void
  ): Promise<string> {
    if (!this.process || !this.ready) {
      throw new Error('Claude process not ready');
    }

    const requestId = uuidv4();

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(requestId, {
        id: requestId,
        resolve,
        reject,
        onDelta,
        onComplete,
        buffer: ''
      });

      // 发送 stream-json 格式的消息
      const inputMsg = {
        type: 'user_message',
        message: userMessage
      };

      this.process!.stdin?.write(JSON.stringify(inputMsg) + '\n');
    });
  }

  destroy(): void {
    if (this.process) {
      this.process.kill();
      this.process = null;
    }
    this.ready = false;
  }
}

// 进程池管理器
export class ClaudeProcessPool {
  private processes: ClaudeProcess[] = [];
  private poolSize: number;

  constructor(poolSize: number = 2) {
    this.poolSize = poolSize;
  }

  async initialize(): Promise<void> {
    console.log(`[ProcessPool] Initializing pool with ${this.poolSize} processes...`);

    for (let i = 0; i < this.poolSize; i++) {
      const process = new ClaudeProcess();
      await process.waitReady();
      this.processes.push(process);
    }

    console.log('[ProcessPool] Pool initialized');
  }

  getAvailableProcess(): ClaudeProcess | null {
    // 优先找空闲的进程
    for (const p of this.processes) {
      if (p.isReady() && !p.isBusy()) {
        return p;
      }
    }

    // 如果都忙，返回第一个就绪的
    for (const p of this.processes) {
      if (p.isReady()) {
        return p;
      }
    }

    return null;
  }

  destroy(): void {
    for (const p of this.processes) {
      p.destroy();
    }
    this.processes = [];
  }
}

// 单例模式
let poolInstance: ClaudeProcessPool | null = null;

export async function getProcessPool(poolSize: number = 2): Promise<ClaudeProcessPool> {
  if (!poolInstance) {
    poolInstance = new ClaudeProcessPool(poolSize);
    await poolInstance.initialize();
  }
  return poolInstance;
}
