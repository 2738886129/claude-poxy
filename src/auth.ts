import { Request, Response, NextFunction, RequestHandler } from 'express';
import { createHash, randomBytes } from 'crypto';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

// ===== 类型定义 =====
export interface ApiKeyEntry {
  id: string;
  keyHash: string;           // SHA-256 哈希
  keyPrefix: string;         // 前12位，用于识别
  name: string;
  createdAt: string;
  lastUsedAt?: string;
  expiresInDays: number;     // Cookie 有效期（天）
}

interface AuthConfig {
  enabled: boolean;          // 是否启用认证
  apiKeys: ApiKeyEntry[];
}

// ===== 配置管理 =====
const AUTH_CONFIG_PATH = join(process.cwd(), 'auth.json');

export function loadAuthConfig(): AuthConfig {
  if (existsSync(AUTH_CONFIG_PATH)) {
    try {
      return JSON.parse(readFileSync(AUTH_CONFIG_PATH, 'utf-8'));
    } catch {
      console.error('[Auth] 读取认证配置失败');
    }
  }
  return { enabled: false, apiKeys: [] };
}

function saveAuthConfig(config: AuthConfig): void {
  writeFileSync(AUTH_CONFIG_PATH, JSON.stringify(config, null, 2));
}

// ===== 密钥工具函数 =====
function generateApiKey(): string {
  const prefix = 'cpxy_';
  const randomPart = randomBytes(24).toString('base64url').substring(0, 32);
  return prefix + randomPart;
}

function hashApiKey(key: string): string {
  return 'sha256:' + createHash('sha256').update(key).digest('hex');
}

function getKeyPrefix(key: string): string {
  return key.substring(0, 12) + '...';
}

// ===== API Key 管理 =====
export function createApiKey(name: string, expiresInDays: number = 7): { id: string; key: string } {
  const config = loadAuthConfig();
  const key = generateApiKey();
  const id = 'key_' + randomBytes(6).toString('hex');

  const entry: ApiKeyEntry = {
    id,
    keyHash: hashApiKey(key),
    keyPrefix: getKeyPrefix(key),
    name,
    createdAt: new Date().toISOString(),
    expiresInDays,
  };

  config.apiKeys.push(entry);
  config.enabled = true;
  saveAuthConfig(config);

  console.log(`[Auth] 创建 API Key: ${name} (${id}), 有效期: ${expiresInDays} 天`);
  return { id, key };  // 返回原始 key，只此一次
}

export function revokeApiKey(id: string): boolean {
  const config = loadAuthConfig();
  const index = config.apiKeys.findIndex(k => k.id === id);
  if (index !== -1) {
    config.apiKeys.splice(index, 1);
    saveAuthConfig(config);
    console.log(`[Auth] 撤销 API Key: ${id}`);
    return true;
  }
  return false;
}

export function listApiKeys(): ApiKeyEntry[] {
  return loadAuthConfig().apiKeys;
}

// ===== 认证验证 =====
export function validateApiKey(key: string): ApiKeyEntry | null {
  const config = loadAuthConfig();
  const keyHash = hashApiKey(key);

  for (const entry of config.apiKeys) {
    if (entry.keyHash === keyHash) {
      // 更新最后使用时间
      entry.lastUsedAt = new Date().toISOString();
      saveAuthConfig(config);
      return entry;
    }
  }
  return null;
}

// 获取 Key 的 Cookie 有效期（毫秒）
export function getKeyExpiresMs(entry: ApiKeyEntry): number {
  const days = entry.expiresInDays || 7; // 默认 7 天
  return days * 24 * 60 * 60 * 1000;
}

function extractApiKey(req: Request): string | null {
  // 1. 从 Authorization header 提取
  const authHeader = req.headers.authorization;
  if (authHeader) {
    if (authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    return authHeader;
  }

  // 2. 从 X-Proxy-Key header 提取
  const proxyKey = req.headers['x-proxy-key'];
  if (proxyKey && typeof proxyKey === 'string') {
    return proxyKey;
  }

  // 3. 从 Cookie 提取
  const cookies = req.headers.cookie;
  if (cookies) {
    const match = cookies.match(/proxy_key=([^;]+)/);
    if (match) {
      return match[1];
    }
  }

  return null;
}

// ===== 中间件 =====
export function createAuthMiddleware(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const config = loadAuthConfig();

    // 如果认证未启用或没有 Key，跳过验证
    if (!config.enabled || config.apiKeys.length === 0) {
      return next();
    }

    const apiKey = extractApiKey(req);

    if (!apiKey) {
      // 判断是浏览器请求还是 API 请求
      const acceptHeader = req.headers.accept || '';
      const isApiRequest = req.path.startsWith('/v1/') ||
                          acceptHeader.includes('application/json') ||
                          req.headers['x-proxy-key'] !== undefined;

      if (isApiRequest) {
        console.log(`[Auth] 未提供 API Key: ${req.method} ${req.path}`);
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'API Key required. Use Authorization: Bearer <key> header.'
        });
      } else {
        // 浏览器请求，重定向到登录页
        return res.redirect('/__proxy__/login');
      }
    }

    const keyEntry = validateApiKey(apiKey);

    if (!keyEntry) {
      const acceptHeader = req.headers.accept || '';
      const isApiRequest = req.path.startsWith('/v1/') ||
                          acceptHeader.includes('application/json');

      if (isApiRequest) {
        console.log(`[Auth] 无效的 API Key: ${apiKey.substring(0, 12)}...`);
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Invalid API Key'
        });
      } else {
        // 浏览器请求，重定向到登录页并显示错误
        return res.redirect('/__proxy__/login?error=invalid');
      }
    }

    // 将 key 信息附加到请求对象
    (req as any).apiKeyEntry = keyEntry;
    console.log(`[Auth] 认证成功: ${keyEntry.name}`);

    next();
  };
}

// ===== 认证状态检查 =====
export function isAuthEnabled(): boolean {
  const config = loadAuthConfig();
  return config.enabled && config.apiKeys.length > 0;
}

export function enableAuth(): void {
  const config = loadAuthConfig();
  config.enabled = true;
  saveAuthConfig(config);
}

export function disableAuth(): void {
  const config = loadAuthConfig();
  config.enabled = false;
  saveAuthConfig(config);
}

// ===== 登录页面 HTML =====
export function getLoginPageHtml(error?: string): string {
  const errorMessage = error === 'invalid' ? '无效的 API Key，请重试' : '';

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Claude Proxy - 登录</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .login-container {
      background: white;
      padding: 40px;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      width: 100%;
      max-width: 400px;
    }
    h1 {
      text-align: center;
      color: #333;
      margin-bottom: 8px;
      font-size: 24px;
    }
    .subtitle {
      text-align: center;
      color: #666;
      margin-bottom: 32px;
      font-size: 14px;
    }
    .form-group {
      margin-bottom: 24px;
    }
    label {
      display: block;
      margin-bottom: 8px;
      color: #333;
      font-weight: 500;
    }
    input[type="text"] {
      width: 100%;
      padding: 12px 16px;
      border: 2px solid #e1e1e1;
      border-radius: 8px;
      font-size: 16px;
      transition: border-color 0.2s;
    }
    input[type="text"]:focus {
      outline: none;
      border-color: #667eea;
    }
    button {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
    }
    button:active {
      transform: translateY(0);
    }
    .error-message {
      background: #fee2e2;
      color: #dc2626;
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 24px;
      text-align: center;
      font-size: 14px;
    }
    .help-text {
      text-align: center;
      color: #888;
      font-size: 12px;
      margin-top: 24px;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>Claude Proxy</h1>
    <p class="subtitle">请输入 API Key 以继续</p>
    ${errorMessage ? `<div class="error-message">${errorMessage}</div>` : ''}
    <form method="POST" action="/__proxy__/login">
      <div class="form-group">
        <label for="api_key">API Key</label>
        <input type="text" id="api_key" name="api_key" placeholder="cpxy_xxxxxxxx" required autocomplete="off">
      </div>
      <button type="submit">登录</button>
    </form>
    <p class="help-text">请联系管理员获取 API Key</p>
  </div>
</body>
</html>`;
}
