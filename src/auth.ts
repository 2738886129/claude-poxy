import { Request, Response, NextFunction, RequestHandler } from 'express';
import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

// ===== 类型定义 =====
export type KeyPermission = 'web';  // web = 浏览器访问

export interface ApiKeyEntry {
  id: string;
  encryptedKey: string;      // AES 加密的完整 Key
  keyHash: string;           // SHA-256 哈希（用于验证）
  keyPrefix: string;         // 前12位，用于快速识别
  name: string;
  createdAt: string;
  lastUsedAt?: string;
  expiresInDays: number;     // Cookie 有效期（天）
  permissions: KeyPermission[];  // 授权类型：web（浏览器访问）
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
  permissions: KeyPermission[] = ['web'],  // 默认 web 权限
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

  const permStr = permissions.join('+');
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
    const permStr = permissions.join('+');
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

    // 所有请求都需要 web 权限
    const permission: KeyPermission = 'web';

    if (!apiKey) {
      // 浏览器请求，重定向到登录页
      return res.redirect('/__proxy__/login');
    }

    const keyEntry = validateApiKey(apiKey);

    if (!keyEntry) {
      // 浏览器请求，重定向到登录页并显示错误
      return res.redirect('/__proxy__/login?error=invalid');
    }

    // 检查权限
    const keyPermissions = keyEntry.permissions;
    if (!keyPermissions.includes(permission)) {
      console.log(`[Auth] 权限不足: ${keyEntry.name} 没有 Web 访问权限`);
      return res.redirect('/__proxy__/login?error=no_permission');
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
export function getAdminLoginHtml(message?: string): string {
  const isSuccess = message === 'password_changed';
  const needsSetup = message === 'not_set';
  const displayMessage = message === 'invalid' ? '密码错误' :
                         message === 'password_changed' ? '密码修改成功，请使用新密码登录' : '';

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
    input[type="password"],
    input[type="text"] {
      width: 100%;
      padding: 12px 16px;
      border: 2px solid #e1e1e1;
      border-radius: 8px;
      font-size: 16px;
      transition: border-color 0.2s;
    }
    .password-wrapper input { padding-right: 44px; }
    input:focus { outline: none; border-color: #1a1a2e; }
    button[type="submit"] {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.2s, transform 0.2s;
    }
    button[type="submit"]:hover { opacity: 0.9; transform: translateY(-1px); }
    button[type="submit"]:active { transform: translateY(0); }
    .message-box {
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 24px;
      text-align: center;
      font-size: 14px;
    }
    .message-box.error { background: #fee2e2; color: #dc2626; }
    .message-box.success { background: #d1fae5; color: #065f46; }

    /* Modal 样式 */
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.6);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      animation: fadeIn 0.2s ease;
    }
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    .modal {
      background: white;
      border-radius: 16px;
      padding: 32px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      animation: slideUp 0.3s ease;
    }
    @keyframes slideUp {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .modal h2 { text-align: center; color: #333; margin-bottom: 8px; font-size: 20px; }
    .modal .subtitle { margin-bottom: 24px; }
    .modal .form-group { margin-bottom: 16px; }
    .modal .hint { font-size: 12px; color: #888; margin-top: 4px; }

    /* Password toggle */
    .password-wrapper { position: relative; display: block; }
    .password-toggle {
      position: absolute;
      right: 12px;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      cursor: pointer;
      color: #9ca3af;
      padding: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      width: auto;
    }
    .password-toggle:hover { color: #6b7280; background: none; opacity: 1; transform: translateY(-50%); }

    /* Toast 样式 */
    .toast {
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 14px 24px;
      border-radius: 8px;
      color: white;
      font-size: 14px;
      font-weight: 500;
      z-index: 2000;
      animation: toastIn 0.3s ease, toastOut 0.3s ease 2.7s forwards;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    .toast.success { background: #10b981; }
    .toast.error { background: #ef4444; }
    @keyframes toastIn {
      from { opacity: 0; transform: translateX(100%); }
      to { opacity: 1; transform: translateX(0); }
    }
    @keyframes toastOut {
      from { opacity: 1; transform: translateX(0); }
      to { opacity: 0; transform: translateX(100%); }
    }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>管理员登录</h1>
    <p class="subtitle">请输入管理员密码</p>
    ${displayMessage ? `<div class="message-box ${isSuccess ? 'success' : 'error'}">${displayMessage}</div>` : ''}
    <form method="POST" action="/login" id="loginForm">
      <div class="form-group">
        <label for="password">密码</label>
        <div class="password-wrapper">
          <input type="password" id="password" name="password" required>
          <button type="button" class="password-toggle" onclick="togglePassword(this)">
            <svg class="eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            <svg class="eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
          </button>
        </div>
      </div>
      <button type="submit">登录</button>
    </form>
    <script>
      function togglePassword(btn) {
        var wrapper = btn.parentElement;
        var input = wrapper.querySelector('input');
        var eyeOpen = btn.querySelector('.eye-open');
        var eyeClosed = btn.querySelector('.eye-closed');
        if (input.type === 'password') {
          input.type = 'text';
          eyeOpen.style.display = 'none';
          eyeClosed.style.display = 'block';
        } else {
          input.type = 'password';
          eyeOpen.style.display = 'block';
          eyeClosed.style.display = 'none';
        }
      }
    </script>
  </div>

  ${needsSetup ? `
  <!-- 首次设置密码弹窗 -->
  <div class="modal-overlay" id="setupModal">
    <div class="modal">
      <h2>🔐 设置管理员密码</h2>
      <p class="subtitle" style="text-align:center;color:#666;">首次使用，请设置管理员密码</p>
      <form id="setupForm">
        <div class="form-group">
          <label for="new_password">密码</label>
          <div class="password-wrapper">
            <input type="password" id="new_password" name="new_password" required minlength="6">
            <button type="button" class="password-toggle" onclick="togglePasswordSetup(this)">
              <svg class="eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
              <svg class="eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
            </button>
          </div>
          <div class="hint">至少 6 个字符</div>
        </div>
        <div class="form-group">
          <label for="confirm_password">确认密码</label>
          <div class="password-wrapper">
            <input type="password" id="confirm_password" name="confirm_password" required minlength="6">
            <button type="button" class="password-toggle" onclick="togglePasswordSetup(this)">
              <svg class="eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
              <svg class="eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
            </button>
          </div>
        </div>
        <button type="submit">设置密码</button>
      </form>
    </div>
  </div>

  <script>
    function togglePasswordSetup(btn) {
      var wrapper = btn.parentElement;
      var input = wrapper.querySelector('input');
      var eyeOpen = btn.querySelector('.eye-open');
      var eyeClosed = btn.querySelector('.eye-closed');
      if (input.type === 'password') {
        input.type = 'text';
        eyeOpen.style.display = 'none';
        eyeClosed.style.display = 'block';
      } else {
        input.type = 'password';
        eyeOpen.style.display = 'block';
        eyeClosed.style.display = 'none';
      }
    }

    // Toast 提示函数
    function showToast(message, type = 'success') {
      const existing = document.querySelector('.toast');
      if (existing) existing.remove();

      const toast = document.createElement('div');
      toast.className = 'toast ' + type;
      toast.textContent = message;
      document.body.appendChild(toast);

      setTimeout(() => toast.remove(), 3000);
    }

    // 设置密码表单处理
    document.getElementById('setupForm').addEventListener('submit', async (e) => {
      e.preventDefault();

      const newPwd = document.getElementById('new_password').value;
      const confirmPwd = document.getElementById('confirm_password').value;

      if (newPwd !== confirmPwd) {
        showToast('两次输入的密码不一致', 'error');
        return;
      }

      if (newPwd.length < 6) {
        showToast('密码至少需要 6 个字符', 'error');
        return;
      }

      try {
        const res = await fetch('/setup-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'password=' + encodeURIComponent(newPwd)
        });

        const data = await res.json();

        if (data.success) {
          showToast('密码设置成功！', 'success');
          document.getElementById('setupModal').style.display = 'none';
          setTimeout(() => {
            document.getElementById('password').focus();
          }, 500);
        } else {
          showToast(data.message || '设置失败', 'error');
        }
      } catch (err) {
        showToast('网络错误，请重试', 'error');
      }
    });
  </script>
  ` : ''}
</body>
</html>`;
}

export function getAdminDashboardHtml(keys: (ApiKeyEntry & { fullKey: string })[], message?: string): string {
  const isError = message?.includes('失败') || message?.includes('错误') || message?.includes('不能') || message?.includes('至少');

  const keyRows = keys.map(k => `
    <tr data-id="${k.id}">
      <td>
        <div class="name-cell">
          <span class="key-name">${k.name}</span>
          ${k.isAdmin ? '<span class="badge badge-admin">管理员</span>' : ''}
        </div>
      </td>
      <td>
        <div class="key-cell">
          <code class="key-display">${k.fullKey}</code>
          <button class="icon-btn copy-btn" onclick="copyKey('${k.fullKey}')" title="复制">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
          </button>
        </div>
      </td>
      <td><span class="date-text">${k.expiresInDays} 天</span></td>
      <td><span class="date-text">${new Date(k.createdAt).toLocaleDateString('zh-CN')}</span></td>
      <td><span class="date-text ${!k.lastUsedAt ? 'muted' : ''}">${k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleDateString('zh-CN') : '从未'}</span></td>
      <td>
        <button class="icon-btn danger" onclick="revokeKey('${k.id}', '${k.name}')" title="撤销">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="3 6 5 6 21 6"></polyline>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
          </svg>
        </button>
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
      background: linear-gradient(135deg, #f5f7fa 0%, #e4e8ec 100%);
      min-height: 100vh;
      padding: 24px;
    }
    .container { max-width: 1000px; margin: 0 auto; }

    /* Header */
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding: 20px 24px;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      border-radius: 16px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.15);
    }
    header h1 {
      font-size: 20px;
      color: white;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    header h1::before { content: '🔐'; font-size: 24px; }
    .header-actions { display: flex; gap: 12px; align-items: center; }
    .btn-secondary {
      padding: 8px 16px;
      background: rgba(255,255,255,0.1);
      color: white;
      border: 1px solid rgba(255,255,255,0.2);
      border-radius: 8px;
      cursor: pointer;
      text-decoration: none;
      font-size: 13px;
      transition: all 0.2s;
    }
    .btn-secondary:hover { background: rgba(255,255,255,0.2); }

    /* Cards */
    .card {
      background: white;
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 20px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.08);
      border: 1px solid rgba(0,0,0,0.05);
    }
    .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    .card h2 { font-size: 16px; color: #333; display: flex; align-items: center; gap: 8px; }
    .card h2 .count { background: #e5e7eb; color: #4b5563; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; }

    /* Form */
    .form-row { display: flex; gap: 16px; flex-wrap: wrap; align-items: flex-end; }
    .form-group { flex: 1; min-width: 140px; }
    .form-group.small { flex: 0 0 100px; }
    .form-group label { display: block; margin-bottom: 6px; font-size: 13px; color: #666; font-weight: 500; }
    .form-group input[type="text"],
    .form-group input[type="number"],
    .form-group input[type="password"] {
      width: 100%;
      padding: 10px 14px;
      border: 1.5px solid #e5e7eb;
      border-radius: 8px;
      font-size: 14px;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .form-group input:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); }
    .checkbox-group { display: flex; gap: 12px; align-items: center; padding: 8px 0; }
    .checkbox-group label { display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 13px; color: #333; margin-bottom: 0; }
    .checkbox-group input[type="checkbox"] { width: 16px; height: 16px; cursor: pointer; accent-color: #667eea; }
    .btn-primary {
      padding: 10px 24px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4); }
    .btn-primary:active { transform: translateY(0); }
    .hint { font-size: 11px; color: #888; margin-top: 4px; }

    /* Table */
    .table-wrapper { overflow-x: auto; margin: 0 -8px; padding: 0 8px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 14px 12px; text-align: left; }
    th { background: #f9fafb; font-weight: 600; color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #e5e7eb; }
    td { font-size: 14px; border-bottom: 1px solid #f3f4f6; vertical-align: middle; }
    tr:hover { background: #f9fafb; }
    tr:last-child td { border-bottom: none; }

    /* Key display */
    .key-cell { display: flex; align-items: center; gap: 8px; }
    .key-display { font-family: 'SF Mono', Monaco, 'Courier New', monospace; background: #f3f4f6; padding: 6px 10px; border-radius: 6px; font-size: 12px; color: #374151; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .name-cell { display: flex; align-items: center; gap: 8px; }
    .key-name { font-weight: 500; color: #1f2937; }
    .date-text { color: #6b7280; font-size: 13px; }
    .date-text.muted { color: #9ca3af; }

    /* Badges */
    .badge { display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; }
    .badge-admin { background: linear-gradient(135deg, #fef3c7, #fde68a); color: #92400e; }

    /* Icon buttons */
    .icon-btn { width: 32px; height: 32px; border: none; border-radius: 8px; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: all 0.2s; background: #f3f4f6; color: #6b7280; }
    .icon-btn:hover { background: #e5e7eb; color: #374151; }
    .icon-btn.copy-btn:hover { background: #eff6ff; color: #2563eb; }
    .icon-btn.danger:hover { background: #fef2f2; color: #dc2626; }

    /* Empty state */
    .empty-state { text-align: center; padding: 48px 20px; color: #9ca3af; }
    .empty-state svg { margin-bottom: 16px; opacity: 0.5; }
    .empty-state p { font-size: 14px; }

    /* Toast */
    .toast-container { position: fixed; top: 20px; right: 20px; z-index: 2000; display: flex; flex-direction: column; gap: 8px; }
    .toast { padding: 14px 20px; border-radius: 10px; color: white; font-size: 14px; font-weight: 500; box-shadow: 0 4px 20px rgba(0,0,0,0.15); animation: toastIn 0.3s ease; display: flex; align-items: center; gap: 10px; }
    .toast.success { background: linear-gradient(135deg, #10b981, #059669); }
    .toast.error { background: linear-gradient(135deg, #ef4444, #dc2626); }
    .toast.hiding { animation: toastOut 0.3s ease forwards; }
    @keyframes toastIn { from { opacity: 0; transform: translateX(100%); } to { opacity: 1; transform: translateX(0); } }
    @keyframes toastOut { from { opacity: 1; transform: translateX(0); } to { opacity: 0; transform: translateX(100%); } }

    /* Modal */
    .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); display: none; align-items: center; justify-content: center; z-index: 1000; }
    .modal-overlay.show { display: flex; }
    .modal { background: white; border-radius: 16px; padding: 28px; width: 100%; max-width: 420px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3); animation: modalIn 0.3s ease; }
    @keyframes modalIn { from { opacity: 0; transform: scale(0.95) translateY(10px); } to { opacity: 1; transform: scale(1) translateY(0); } }
    .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    .modal-header h3 { font-size: 18px; color: #1f2937; display: flex; align-items: center; gap: 8px; }
    .modal-close { width: 32px; height: 32px; border: none; background: #f3f4f6; border-radius: 8px; cursor: pointer; display: flex; align-items: center; justify-content: center; color: #6b7280; transition: all 0.2s; }
    .modal-close:hover { background: #e5e7eb; color: #374151; }
    .modal-body { margin-bottom: 24px; }
    .modal-body .form-group { margin-bottom: 16px; }
    .modal-body .form-group:last-child { margin-bottom: 0; }
    .modal-footer { display: flex; gap: 12px; justify-content: flex-end; }
    .btn-cancel { padding: 10px 20px; background: #f3f4f6; color: #374151; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 500; transition: background 0.2s; }

    /* Password input with toggle */
    .password-wrapper { position: relative; }
    .password-wrapper input { padding-right: 40px; }
    .password-toggle { position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; color: #9ca3af; padding: 4px; display: flex; align-items: center; justify-content: center; }
    .password-toggle:hover { color: #6b7280; }
    .btn-cancel:hover { background: #e5e7eb; }
    .confirm-message { font-size: 14px; color: #4b5563; line-height: 1.6; margin-bottom: 8px; }
    .confirm-warning { font-size: 13px; color: #dc2626; background: #fef2f2; padding: 10px 12px; border-radius: 8px; }
    .btn-danger { padding: 10px 20px; background: linear-gradient(135deg, #ef4444, #dc2626); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 500; transition: transform 0.2s, box-shadow 0.2s; }
    .btn-danger:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(220, 38, 38, 0.4); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>API Key 管理面板</h1>
      <div class="header-actions">
        <button class="btn-secondary" onclick="showPasswordModal()">🔑 修改密码</button>
        <a href="/logout" class="btn-secondary">退出登录</a>
      </div>
    </header>

    <div class="card">
      <div class="card-header"><h2>➕ 创建新 Key</h2></div>
      <form method="POST" action="/create">
        <div class="form-row" style="margin-bottom: 16px;">
          <div class="form-group" style="flex: 2;">
            <label>名称</label>
            <input type="text" name="name" placeholder="例如：小明的电脑" required>
          </div>
          <div class="form-group" style="flex: 1; min-width: 120px;">
            <label>有效期（天）</label>
            <input type="number" name="days" value="7" min="1" max="3650" required>
          </div>
        </div>
        <div class="form-row" style="align-items: center;">
          <div class="form-group" style="flex: 1;">
            <div class="checkbox-group" style="padding: 0;">
              <label><input type="checkbox" name="isAdmin"> 管理员权限</label>
              <span class="hint" style="margin-left: 8px; margin-top: 0;">（可访问全部内容，无脚本注入）</span>
            </div>
          </div>
          <div class="form-group" style="flex: 0;">
            <button type="submit" class="btn-primary">创建 Key</button>
          </div>
        </div>
      </form>
    </div>

    <div class="card">
      <div class="card-header"><h2>📋 已有 Key <span class="count">${keys.length}</span></h2></div>
      ${keys.length === 0 ? `
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
          <p>暂无 API Key，请创建一个</p>
        </div>
      ` : `
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>名称</th>
                <th>Key</th>
                <th>有效期</th>
                <th>创建时间</th>
                <th>最后使用</th>
                <th style="width:50px;"></th>
              </tr>
            </thead>
            <tbody>${keyRows}</tbody>
          </table>
        </div>
      `}
    </div>
  </div>

  <div class="toast-container" id="toastContainer"></div>

  <!-- 修改密码弹窗 -->
  <div class="modal-overlay" id="passwordModal">
    <div class="modal">
      <div class="modal-header">
        <h3>🔑 修改管理员密码</h3>
        <button class="modal-close" onclick="hidePasswordModal()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
        </button>
      </div>
      <form id="passwordForm" method="POST" action="/change-password">
        <div class="modal-body">
          <div class="form-group">
            <label>当前密码</label>
            <div class="password-wrapper">
              <input type="password" name="current_password" required>
              <button type="button" class="password-toggle" onclick="togglePassword(this)">
                <svg class="eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                <svg class="eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
              </button>
            </div>
          </div>
          <div class="form-group">
            <label>新密码</label>
            <div class="password-wrapper">
              <input type="password" name="new_password" required minlength="6">
              <button type="button" class="password-toggle" onclick="togglePassword(this)">
                <svg class="eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                <svg class="eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
              </button>
            </div>
            <span class="hint">至少 6 个字符</span>
          </div>
          <div class="form-group">
            <label>确认新密码</label>
            <div class="password-wrapper">
              <input type="password" name="confirm_password" required minlength="6">
              <button type="button" class="password-toggle" onclick="togglePassword(this)">
                <svg class="eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                <svg class="eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
              </button>
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn-cancel" onclick="hidePasswordModal()">取消</button>
          <button type="submit" class="btn-primary">确认修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- 确认撤销弹窗 -->
  <div class="modal-overlay" id="revokeModal">
    <div class="modal">
      <div class="modal-header">
        <h3>⚠️ 确认撤销</h3>
        <button class="modal-close" onclick="hideRevokeModal()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
        </button>
      </div>
      <div class="modal-body">
        <p class="confirm-message">确定要撤销 Key "<span id="revokeKeyName"></span>" 吗？</p>
        <p class="confirm-warning">此操作无法撤销，使用此 Key 的用户将立即失去访问权限。</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn-cancel" onclick="hideRevokeModal()">取消</button>
        <form id="revokeForm" method="POST" action="/revoke" style="margin:0;">
          <input type="hidden" name="id" id="revokeKeyId">
          <button type="submit" class="btn-danger">确认撤销</button>
        </form>
      </div>
    </div>
  </div>

  <script>
    function showToast(message, type) {
      type = type || 'success';
      var container = document.getElementById('toastContainer');
      var toast = document.createElement('div');
      toast.className = 'toast ' + type;
      var icons = { success: '✓', error: '✕' };
      toast.innerHTML = '<span>' + (icons[type] || '') + '</span><span>' + message + '</span>';
      container.appendChild(toast);
      setTimeout(function() {
        toast.classList.add('hiding');
        setTimeout(function() { toast.remove(); }, 300);
      }, 3000);
    }

    ${message ? `showToast('${message.replace(/'/g, "\\'")}', '${isError ? 'error' : 'success'}');` : ''}

    function copyKey(key) {
      // 使用 fallback 方法支持非 HTTPS 环境
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(key).then(function() {
          showToast('已复制到剪贴板', 'success');
        }).catch(function() {
          fallbackCopy(key);
        });
      } else {
        fallbackCopy(key);
      }
    }

    function fallbackCopy(text) {
      var textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-9999px';
      textArea.style.top = '-9999px';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {
        var successful = document.execCommand('copy');
        if (successful) {
          showToast('已复制到剪贴板', 'success');
        } else {
          showToast('复制失败，请手动复制', 'error');
        }
      } catch (err) {
        showToast('复制失败，请手动复制', 'error');
      }
      document.body.removeChild(textArea);
    }

    function togglePassword(btn) {
      var wrapper = btn.parentElement;
      var input = wrapper.querySelector('input');
      var eyeOpen = btn.querySelector('.eye-open');
      var eyeClosed = btn.querySelector('.eye-closed');
      if (input.type === 'password') {
        input.type = 'text';
        eyeOpen.style.display = 'none';
        eyeClosed.style.display = 'block';
      } else {
        input.type = 'password';
        eyeOpen.style.display = 'block';
        eyeClosed.style.display = 'none';
      }
    }

    function revokeKey(id, name) {
      document.getElementById('revokeKeyId').value = id;
      document.getElementById('revokeKeyName').textContent = name;
      document.getElementById('revokeModal').classList.add('show');
    }

    function hideRevokeModal() {
      document.getElementById('revokeModal').classList.remove('show');
    }

    function showPasswordModal() {
      document.getElementById('passwordModal').classList.add('show');
      document.getElementById('passwordForm').reset();
    }

    function hidePasswordModal() {
      document.getElementById('passwordModal').classList.remove('show');
    }

    document.getElementById('passwordForm').addEventListener('submit', function(e) {
      var newPwd = this.new_password.value;
      var confirmPwd = this.confirm_password.value;
      if (newPwd !== confirmPwd) {
        e.preventDefault();
        showToast('两次输入的密码不一致', 'error');
        return false;
      }
    });

    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') {
        hidePasswordModal();
        hideRevokeModal();
      }
    });

    document.querySelectorAll('.modal-overlay').forEach(function(overlay) {
      overlay.addEventListener('click', function(e) {
        if (e.target === overlay) overlay.classList.remove('show');
      });
    });
  </script>
</body>
</html>`;
}
