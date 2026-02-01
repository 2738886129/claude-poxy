import { spawn, ChildProcess } from 'child_process';
import type { Request, Response, RequestHandler } from 'express';

interface Message {
  role: 'user' | 'assistant';
  content: string | Array<{ type: string; text?: string }>;
}

interface ApiRequest {
  model?: string;
  messages: Message[];
  max_tokens?: number;
  stream?: boolean;
}

// 从 message 中提取文本内容
function extractMessageContent(msg: Message): string {
  if (typeof msg.content === 'string') {
    return msg.content;
  } else if (Array.isArray(msg.content)) {
    return msg.content
      .filter(part => part.type === 'text' && part.text)
      .map(part => part.text)
      .join('\n');
  }
  return '';
}

// 将所有 messages 转换为对话格式
function formatConversation(messages: Message[]): string {
  const parts: string[] = [];

  for (const msg of messages) {
    const content = extractMessageContent(msg);
    if (!content) continue;

    if (msg.role === 'user') {
      parts.push(`Human: ${content}`);
    } else if (msg.role === 'assistant') {
      parts.push(`Assistant: ${content}`);
    }
  }

  // 添加最后的 Human/Assistant 标记让 Claude 知道继续回复
  if (parts.length > 0 && !parts[parts.length - 1].startsWith('Human:')) {
    // 如果最后不是用户消息，可能有问题
  }

  return parts.join('\n\n');
}

// 从 messages 中提取最后一条用户消息（用于日志）
function extractUserMessage(messages: Message[]): string {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg.role === 'user') {
      return extractMessageContent(msg);
    }
  }
  return '';
}

// 生成唯一 ID
function generateId(): string {
  return 'msg_' + Math.random().toString(36).substring(2, 15);
}

// 创建 SSE 事件
function createSSEEvent(event: string, data: object): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

function createMessageStart(id: string, model: string): string {
  return createSSEEvent('message_start', {
    type: 'message_start',
    message: {
      id,
      type: 'message',
      role: 'assistant',
      content: [],
      model,
      stop_reason: null,
      stop_sequence: null,
      usage: { input_tokens: 0, output_tokens: 0 }
    }
  });
}

function createContentBlockStart(index: number): string {
  return createSSEEvent('content_block_start', {
    type: 'content_block_start',
    index,
    content_block: { type: 'text', text: '' }
  });
}

function createContentBlockDelta(index: number, text: string): string {
  return createSSEEvent('content_block_delta', {
    type: 'content_block_delta',
    index,
    delta: { type: 'text_delta', text }
  });
}

function createContentBlockStop(index: number): string {
  return createSSEEvent('content_block_stop', {
    type: 'content_block_stop',
    index
  });
}

function createMessageDelta(stopReason: string): string {
  return createSSEEvent('message_delta', {
    type: 'message_delta',
    delta: { stop_reason: stopReason, stop_sequence: null },
    usage: { output_tokens: 0 }
  });
}

function createMessageStop(): string {
  return createSSEEvent('message_stop', { type: 'message_stop' });
}

// ========== 进程池管理 ==========
interface PooledProcess {
  process: ChildProcess;
  busy: boolean;
  lastUsed: number;
}

class ClaudeProcessPool {
  private pool: PooledProcess[] = [];
  private maxSize: number;
  private warmupCount: number;

  constructor(maxSize: number = 3, warmupCount: number = 1) {
    this.maxSize = maxSize;
    this.warmupCount = warmupCount;
  }

  async initialize(): Promise<void> {
    console.log(`[ProcessPool] Warming up ${this.warmupCount} processes...`);
    for (let i = 0; i < this.warmupCount; i++) {
      await this.warmupProcess();
    }
    console.log('[ProcessPool] Warmup complete');
  }

  private async warmupProcess(): Promise<void> {
    // 预启动一个进程，发送一个简单请求让它初始化
    return new Promise((resolve) => {
      const proc = spawn('claude', [
        '--print',
        '--output-format', 'text',
        '--dangerously-skip-permissions'
      ], {
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: false,
        env: { ...process.env, LANG: 'en_US.UTF-8' }
      });

      // 发送一个简单的 warmup 请求
      proc.stdin.write('hi');
      proc.stdin.end();

      proc.on('close', () => {
        resolve();
      });

      proc.on('error', () => {
        resolve();
      });

      // 超时处理
      setTimeout(() => resolve(), 10000);
    });
  }

  // 创建新进程处理请求（流式模式）
  createStreamProcess(
    userMessage: string,
    onText: (text: string) => void,
    onClose: (code: number | null) => void,
    onError: (err: Error) => void
  ): ChildProcess {
    const proc = spawn('claude', [
      '--print',
      '--output-format', 'stream-json',
      '--verbose',
      '--dangerously-skip-permissions'
    ], {
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
      env: { ...process.env, LANG: 'en_US.UTF-8' }
    });

    let buffer = '';

    proc.stdout.on('data', (data: Buffer) => {
      buffer += data.toString();

      // 按行解析 JSON
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line);
          // 提取 assistant 消息中的文本
          if (msg.type === 'assistant' && msg.message?.content) {
            for (const block of msg.message.content) {
              if (block.type === 'text' && block.text) {
                onText(block.text);
              }
            }
          }
          // 处理 content_block_delta
          if (msg.type === 'content_block_delta' && msg.delta?.text) {
            onText(msg.delta.text);
          }
        } catch {
          // 非 JSON 行，可能是普通文本
          if (line.trim()) {
            onText(line);
          }
        }
      }
    });

    proc.stderr.on('data', (data: Buffer) => {
      const text = data.toString();
      if (!text.includes('Debugger') && !text.includes('inspector')) {
        console.error('[CLI Proxy] stderr:', text);
      }
    });

    proc.on('close', onClose);
    proc.on('error', onError);

    proc.stdin.write(userMessage);
    proc.stdin.end();

    return proc;
  }

  // 创建新进程处理请求（非流式模式）
  createProcess(
    userMessage: string,
    onData: (text: string) => void,
    onClose: (code: number | null) => void,
    onError: (err: Error) => void
  ): ChildProcess {
    const proc = spawn('claude', [
      '--print',
      '--output-format', 'text',
      '--dangerously-skip-permissions'
    ], {
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
      env: { ...process.env, LANG: 'en_US.UTF-8' }
    });

    proc.stdout.on('data', (data: Buffer) => {
      onData(data.toString());
    });

    proc.stderr.on('data', (data: Buffer) => {
      const text = data.toString();
      if (!text.includes('Debugger') && !text.includes('inspector')) {
        console.error('[CLI Proxy] stderr:', text);
      }
    });

    proc.on('close', onClose);
    proc.on('error', onError);

    proc.stdin.write(userMessage);
    proc.stdin.end();

    return proc;
  }
}

// 全局进程池实例
const processPool = new ClaudeProcessPool(3, 1);

// 初始化进程池
let poolInitialized = false;
async function ensurePoolInitialized(): Promise<void> {
  if (!poolInitialized) {
    await processPool.initialize();
    poolInitialized = true;
  }
}

// 处理流式响应
async function handleStreamingRequest(
  userMessage: string,
  model: string,
  res: Response
): Promise<void> {
  const messageId = generateId();

  // 设置 SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  // 发送开始事件
  res.write(createMessageStart(messageId, model));
  res.write(createContentBlockStart(0));

  return new Promise((resolve) => {
    processPool.createStreamProcess(
      userMessage,
      (text) => {
        res.write(createContentBlockDelta(0, text));
      },
      (code) => {
        console.log(`[CLI Proxy] Process exited with code ${code}`);
        res.write(createContentBlockStop(0));
        res.write(createMessageDelta('end_turn'));
        res.write(createMessageStop());
        res.end();
        resolve();
      },
      (err) => {
        console.error('[CLI Proxy] Process error:', err);
        res.write(createContentBlockDelta(0, `Error: ${err.message}`));
        res.write(createContentBlockStop(0));
        res.write(createMessageDelta('error'));
        res.write(createMessageStop());
        res.end();
        resolve();
      }
    );
  });
}

// 处理非流式响应
async function handleNonStreamingRequest(
  userMessage: string,
  model: string,
  res: Response
): Promise<void> {
  return new Promise((resolve) => {
    let fullResponse = '';

    processPool.createProcess(
      userMessage,
      (text) => {
        fullResponse += text;
      },
      (code) => {
        if (code !== 0 && !fullResponse) {
          res.status(500).json({
            type: 'error',
            error: {
              type: 'api_error',
              message: `Claude CLI exited with code ${code}`
            }
          });
        } else {
          res.json({
            id: generateId(),
            type: 'message',
            role: 'assistant',
            content: [{ type: 'text', text: fullResponse }],
            model,
            stop_reason: 'end_turn',
            stop_sequence: null,
            usage: {
              input_tokens: 0,
              output_tokens: 0
            }
          });
        }
        resolve();
      },
      (err) => {
        res.status(500).json({
          type: 'error',
          error: {
            type: 'api_error',
            message: err.message
          }
        });
        resolve();
      }
    );
  });
}

// 主处理函数
export function createCliProxy(): RequestHandler {
  // 启动时预热进程池
  ensurePoolInitialized().catch(console.error);

  return async (req: Request, res: Response) => {
    console.log(`\n[CLI Proxy] ${req.method} ${req.path}`);

    if (req.method !== 'POST') {
      res.status(405).json({ error: 'Method not allowed' });
      return;
    }

    try {
      const body: ApiRequest = req.body;
      const messages = body.messages || [];
      const model = body.model || 'claude-sonnet-4-20250514';
      const stream = body.stream !== false;

      // 将完整对话历史格式化为输入
      const conversation = formatConversation(messages);
      const lastUserMessage = extractUserMessage(messages);

      console.log(`[CLI Proxy] Messages count: ${messages.length}`);
      console.log(`[CLI Proxy] Last user message: ${lastUserMessage.substring(0, 100)}...`);
      console.log(`[CLI Proxy] Stream: ${stream}`);

      if (!conversation) {
        res.status(400).json({
          type: 'error',
          error: {
            type: 'invalid_request_error',
            message: 'No messages found'
          }
        });
        return;
      }

      if (stream) {
        await handleStreamingRequest(conversation, model, res);
      } else {
        await handleNonStreamingRequest(conversation, model, res);
      }
    } catch (err) {
      console.error('[CLI Proxy] Error:', err);
      res.status(500).json({
        type: 'error',
        error: {
          type: 'api_error',
          message: err instanceof Error ? err.message : 'Unknown error'
        }
      });
    }
  };
}

// 处理 count_tokens 请求
export function createTokenCountHandler(): RequestHandler {
  return (_req: Request, res: Response) => {
    res.json({ input_tokens: 100 });
  };
}
