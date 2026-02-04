import { Request, Response, NextFunction, RequestHandler } from 'express';
import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

// ===== 类型定义 =====
export type KeyPermission = 'web' | 'api';  // web = 浏览器访问, api = Claude Code 访问

export interface ApiKeyEntry {
  id: string;
  encryptedKey: string;      // AES 加密的完整 Key
  keyHash: string;           // SHA-256 哈希（用于验证）
  keyPrefix: string;         // 前12位，用于快速识别
  name: string;
  createdAt: string;
  lastUsedAt?: string;
  expiresInDays: number;     // Cookie 有效期（天）
  permissions: KeyPermission[];  // 授权类型：web（浏览器）、api（Claude Code）
  isAdmin?: boolean;         // 是否为管理员凭证（可访问所有对话和项目，无脚本注入）
}

interface AuthConfig {
  enabled: boolean;          // 是否启用认证
  adminPassword?: string;    // 管理员密码哈希
  encryptionKey?: string;    // 加密密钥（首次运行时生成）
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

// ===== 加密工具函数 =====
function getOrCreateEncryptionKey(): string {
  const config = loadAuthConfig();
  if (config.encryptionKey) {
    return config.encryptionKey;
  }
  // 生成新的加密密钥
  const newKey = randomBytes(32).toString('hex');
  config.encryptionKey = newKey;
  saveAuthConfig(config);
  return newKey;
}

function encryptKey(plainKey: string): string {
  const encKey = getOrCreateEncryptionKey();
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', Buffer.from(encKey, 'hex'), iv);
  let encrypted = cipher.update(plainKey, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decryptKey(encryptedKey: string): string {
  const encKey = getOrCreateEncryptionKey();
  const [ivHex, encrypted] = encryptedKey.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = createDecipheriv('aes-256-cbc', Buffer.from(encKey, 'hex'), iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
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

function hashPassword(password: string): string {
  return 'sha256:' + createHash('sha256').update(password).digest('hex');
}

function getKeyPrefix(key: string): string {
  return key.substring(0, 12) + '...';
}

// ===== 管理员密码管理 =====
export function setAdminPassword(password: string): void {
  const config = loadAuthConfig();
  config.adminPassword = hashPassword(password);
  saveAuthConfig(config);
  console.log('[Auth] 管理员密码已设置');
}

export function verifyAdminPassword(password: string): boolean {
  const config = loadAuthConfig();
  if (!config.adminPassword) {
    return false;
  }
  return config.adminPassword === hashPassword(password);
}

export function hasAdminPassword(): boolean {
  const config = loadAuthConfig();
  return !!config.adminPassword;
}

// ===== API Key 管理 =====
export function createApiKey(
  name: string,
  expiresInDays: number = 7,
  permissions: KeyPermission[] = ['web', 'api'],  // 默认两种权限都有
  isAdmin: boolean = false  // 是否为管理员凭证
): { id: string; key: string } {
  const config = loadAuthConfig();
  const key = generateApiKey();
  const id = 'key_' + randomBytes(6).toString('hex');

  const entry: ApiKeyEntry = {
    id,
    encryptedKey: encryptKey(key),
    keyHash: hashApiKey(key),
    keyPrefix: getKeyPrefix(key),
    name,
    createdAt: new Date().toISOString(),
    expiresInDays,
    permissions,
    isAdmin,
  };

  config.apiKeys.push(entry);
  config.enabled = true;
  saveAuthConfig(config);

  const permStr = permissions.map(p => p === 'web' ? 'Web' : 'API').join('+');
  const adminStr = isAdmin ? ' [管理员]' : '';
  console.log(`[Auth] 创建 API Key: ${name} (${id}), 有效期: ${expiresInDays} 天, 权限: ${permStr}${adminStr}`);
  return { id, key };
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

export function updateApiKeyPermissions(id: string, permissions: KeyPermission[]): boolean {
  const config = loadAuthConfig();
  const entry = config.apiKeys.find(k => k.id === id);
  if (entry) {
    entry.permissions = permissions;
    saveAuthConfig(config);
    const permStr = permissions.map(p => p === 'web' ? 'Web' : 'API').join('+');
    console.log(`[Auth] 更新 API Key 权限: ${id} -> ${permStr}`);
    return true;
  }
  return false;
}

export function listApiKeys(): ApiKeyEntry[] {
  return loadAuthConfig().apiKeys;
}

// 获取完整的 API Key（管理员用）
export function getFullApiKey(id: string): string | null {
  const config = loadAuthConfig();
  const entry = config.apiKeys.find(k => k.id === id);
  if (entry) {
    try {
      return decryptKey(entry.encryptedKey);
    } catch {
      console.error(`[Auth] 解密 Key ${id} 失败`);
      return null;
    }
  }
  return null;
}

// 获取所有 Key 的完整信息（管理员用）
export function listApiKeysWithFullKey(): (ApiKeyEntry & { fullKey: string })[] {
  const config = loadAuthConfig();
  return config.apiKeys.map(entry => {
    let fullKey = '';
    try {
      fullKey = decryptKey(entry.encryptedKey);
    } catch {
      fullKey = '[解密失败]';
    }
    return { ...entry, fullKey };
  });
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

  // 2. 从 X-API-Key header 提取 (Claude Code 使用此 header)
  const apiKeyHeader = req.headers['x-api-key'];
  if (apiKeyHeader && typeof apiKeyHeader === 'string') {
    return apiKeyHeader;
  }

  // 3. 从 X-Proxy-Key header 提取
  const proxyKey = req.headers['x-proxy-key'];
  if (proxyKey && typeof proxyKey === 'string') {
    return proxyKey;
  }

  // 4. 从 Cookie 提取
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
// requiredPermission: 'web' = 浏览器访问, 'api' = Claude Code API 访问
export function createAuthMiddleware(requiredPermission?: KeyPermission): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const config = loadAuthConfig();

    // 如果认证未启用或没有 Key，跳过验证
    if (!config.enabled || config.apiKeys.length === 0) {
      return next();
    }

    const apiKey = extractApiKey(req);

    // 判断是浏览器请求还是 API 请求
    const acceptHeader = req.headers.accept || '';
    const isApiRequest = req.path.startsWith('/v1/') ||
                        acceptHeader.includes('application/json') ||
                        req.headers['x-proxy-key'] !== undefined;

    // 自动检测所需权限（如果未指定）
    const permission = requiredPermission || (isApiRequest ? 'api' : 'web');

    if (!apiKey) {
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

    // 检查权限
    const keyPermissions = keyEntry.permissions;
    if (!keyPermissions.includes(permission)) {
      const permName = permission === 'web' ? 'Web 访问' : 'API 访问';
      console.log(`[Auth] 权限不足: ${keyEntry.name} 没有 ${permName} 权限`);

      if (isApiRequest) {
        return res.status(403).json({
          error: 'Forbidden',
          message: `This API Key does not have ${permission} permission`
        });
      } else {
        return res.redirect('/__proxy__/login?error=no_permission');
      }
    }

    // 将 key 信息附加到请求对象
    (req as any).apiKeyEntry = keyEntry;
    console.log(`[Auth] 认证成功: ${keyEntry.name} (${permission})`);

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
  const errorMessage = error === 'invalid' ? '无效的 API Key，请重试' :
                       error === 'no_permission' ? '此 Key 没有 Web 访问权限' : '';

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Claude Proxy - 登录</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
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
    h1 { text-align: center; color: #333; margin-bottom: 8px; font-size: 24px; }
    .subtitle { text-align: center; color: #666; margin-bottom: 32px; font-size: 14px; }
    .form-group { margin-bottom: 24px; }
    label { display: block; margin-bottom: 8px; color: #333; font-weight: 500; }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 12px 16px;
      border: 2px solid #e1e1e1;
      border-radius: 8px;
      font-size: 16px;
      transition: border-color 0.2s;
    }
    input:focus { outline: none; border-color: #667eea; }
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
    button:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4); }
    button:active { transform: translateY(0); }
    .error-message {
      background: #fee2e2;
      color: #dc2626;
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 24px;
      text-align: center;
      font-size: 14px;
    }
    .help-text { text-align: center; color: #888; font-size: 12px; margin-top: 24px; }
    .admin-link { text-align: center; margin-top: 16px; }
    .admin-link a { color: #667eea; text-decoration: none; font-size: 13px; }
    .admin-link a:hover { text-decoration: underline; }
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

// ===== 管理员页面 HTML =====
export function getAdminLoginHtml(error?: string): string {
  const errorMessage = error === 'invalid' ? '密码错误' :
                       error === 'not_set' ? '管理员密码未设置，请先通过 CLI 设置' : '';

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Claude Proxy - 管理员登录</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .login-container {
      background: white;
      padding: 40px;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
      width: 100%;
      max-width: 400px;
    }
    h1 { text-align: center; color: #333; margin-bottom: 8px; font-size: 24px; }
    .subtitle { text-align: center; color: #666; margin-bottom: 32px; font-size: 14px; }
    .form-group { margin-bottom: 24px; }
    label { display: block; margin-bottom: 8px; color: #333; font-weight: 500; }
    input[type="password"] {
      width: 100%;
      padding: 12px 16px;
      border: 2px solid #e1e1e1;
      border-radius: 8px;
      font-size: 16px;
    }
    input:focus { outline: none; border-color: #1a1a2e; }
    button {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover { opacity: 0.9; }
    .error-message {
      background: #fee2e2;
      color: #dc2626;
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 24px;
      text-align: center;
      font-size: 14px;
    }
    .back-link { text-align: center; margin-top: 16px; }
    .back-link a { color: #666; text-decoration: none; font-size: 13px; }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>管理员登录</h1>
    <p class="subtitle">请输入管理员密码</p>
    ${errorMessage ? `<div class="error-message">${errorMessage}</div>` : ''}
    <form method="POST" action="/login">
      <div class="form-group">
        <label for="password">密码</label>
        <input type="password" id="password" name="password" required>
      </div>
      <button type="submit">登录</button>
    </form>
    <div class="back-link">
      <a href="http://localhost:3000/__proxy__/login">返回用户登录</a>
    </div>
  </div>
</body>
</html>`;
}

export function getAdminDashboardHtml(keys: (ApiKeyEntry & { fullKey: string })[], message?: string): string {
  const getPermissionBadges = (permissions: KeyPermission[]) => {
    const badges = [];
    if (permissions.includes('web')) badges.push('<span class="badge badge-web">Web</span>');
    if (permissions.includes('api')) badges.push('<span class="badge badge-api">API</span>');
    return badges.join(' ');
  };

  const keyRows = keys.map(k => `
    <tr>
      <td>${k.name}</td>
      <td>
        <code class="key-display">${k.fullKey}</code>
        <button class="copy-btn" onclick="copyKey('${k.fullKey}')">复制</button>
      </td>
      <td>
        <form method="POST" action="/update-perm" style="display:inline" class="perm-form">
          <input type="hidden" name="id" value="${k.id}">
          <label class="perm-checkbox"><input type="checkbox" name="perm_web" value="1" ${k.permissions.includes('web') ? 'checked' : ''} onchange="this.form.submit()"> Web</label>
          <label class="perm-checkbox"><input type="checkbox" name="perm_api" value="1" ${k.permissions.includes('api') ? 'checked' : ''} onchange="this.form.submit()"> API</label>
        </form>
      </td>
      <td>${k.isAdmin ? '<span class="badge" style="background:#fee2e2;color:#dc2626;">管理员</span>' : '<span class="badge" style="background:#e5e7eb;color:#4b5563;">普通</span>'}</td>
      <td>${k.expiresInDays} 天</td>
      <td>${new Date(k.createdAt).toLocaleString('zh-CN')}</td>
      <td>${k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString('zh-CN') : '从未'}</td>
      <td>
        <form method="POST" action="/revoke" style="display:inline">
          <input type="hidden" name="id" value="${k.id}">
          <button type="submit" class="btn-danger" onclick="return confirm('确定要撤销此 Key 吗？')">撤销</button>
        </form>
      </td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Claude Proxy - 管理面板</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f5f5f5;
      min-height: 100vh;
      padding: 20px;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 30px;
      padding: 20px;
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    h1 { font-size: 24px; color: #333; }
    .logout-btn {
      padding: 8px 16px;
      background: #666;
      color: white;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      text-decoration: none;
      font-size: 14px;
    }
    .card {
      background: white;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 20px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    .card h2 { font-size: 18px; margin-bottom: 20px; color: #333; }
    .form-row { display: flex; gap: 12px; flex-wrap: wrap; }
    .form-group { flex: 1; min-width: 150px; }
    .form-group label { display: block; margin-bottom: 6px; font-size: 14px; color: #666; }
    .form-group input, .form-group select {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid #ddd;
      border-radius: 6px;
      font-size: 14px;
    }
    .btn-primary {
      padding: 10px 20px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
    }
    .btn-danger {
      padding: 6px 12px;
      background: #dc2626;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
    th { background: #f9f9f9; font-weight: 600; color: #666; font-size: 13px; }
    td { font-size: 14px; }
    .key-display {
      font-family: monospace;
      background: #f5f5f5;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      user-select: all;
    }
    .copy-btn {
      margin-left: 8px;
      padding: 4px 8px;
      background: #667eea;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 11px;
    }
    .message {
      padding: 12px 16px;
      border-radius: 8px;
      margin-bottom: 20px;
      font-size: 14px;
    }
    .message.success { background: #d1fae5; color: #065f46; }
    .message.error { background: #fee2e2; color: #dc2626; }
    .empty-state { text-align: center; padding: 40px; color: #888; }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 500;
      margin-right: 4px;
    }
    .badge-web { background: #dbeafe; color: #1d4ed8; }
    .badge-api { background: #fef3c7; color: #b45309; }
    .checkbox-group {
      display: flex;
      gap: 16px;
      align-items: center;
    }
    .checkbox-group label {
      display: flex;
      align-items: center;
      gap: 6px;
      cursor: pointer;
      font-size: 14px;
    }
    .checkbox-group input[type="checkbox"] {
      width: 16px;
      height: 16px;
      cursor: pointer;
    }
    .perm-form { display: flex; gap: 12px; }
    .perm-checkbox {
      display: flex;
      align-items: center;
      gap: 4px;
      font-size: 12px;
      cursor: pointer;
    }
    .perm-checkbox input { cursor: pointer; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>API Key 管理面板</h1>
      <a href="/logout" class="logout-btn">退出登录</a>
    </header>

    ${message ? `<div class="message success">${message}</div>` : ''}

    <div class="card">
      <h2>创建新 Key</h2>
      <form method="POST" action="/create">
        <div class="form-row">
          <div class="form-group">
            <label>名称</label>
            <input type="text" name="name" placeholder="例如：小明的电脑" required>
          </div>
          <div class="form-group">
            <label>有效期（天）</label>
            <input type="number" name="days" value="7" min="1" max="3650" required>
          </div>
          <div class="form-group">
            <label>授权类型</label>
            <div class="checkbox-group">
              <label><input type="checkbox" name="perm_web" value="1" checked> Web 访问</label>
              <label><input type="checkbox" name="perm_api" value="1" checked> Claude Code</label>
            </div>
          </div>
          <div class="form-group">
            <label>管理员权限</label>
            <div class="checkbox-group">
              <label><input type="checkbox" name="isAdmin"> 管理员凭证</label>
            </div>
            <small style="color:#666;font-size:12px;display:block;margin-top:4px;">管理员可访问所有对话和项目,无脚本注入</small>
          </div>
          <div class="form-group" style="display:flex;align-items:flex-end;">
            <button type="submit" class="btn-primary">创建</button>
          </div>
        </div>
      </form>
    </div>

    <div class="card">
      <h2>已有 Key（${keys.length} 个）</h2>
      ${keys.length === 0 ? `
        <div class="empty-state">暂无 API Key，请创建一个</div>
      ` : `
        <table>
          <thead>
            <tr>
              <th>名称</th>
              <th>Key</th>
              <th>权限</th>
              <th>角色</th>
              <th>有效期</th>
              <th>创建时间</th>
              <th>最后使用</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            ${keyRows}
          </tbody>
        </table>
      `}
    </div>
  </div>

  <script>
    function copyKey(key) {
      navigator.clipboard.writeText(key).then(() => {
        alert('已复制到剪贴板');
      }).catch(() => {
        prompt('请手动复制:', key);
      });
    }
  </script>
</body>
</html>`;
}
