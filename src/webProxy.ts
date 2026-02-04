import { createProxyMiddleware } from 'http-proxy-middleware';
import type { RequestHandler, Request } from 'express';
import type { ServerResponse } from 'http';
import { readFileSync, existsSync, writeFileSync } from 'fs';
import { join } from 'path';
import { Transform, TransformCallback } from 'stream';
// import { getCache } from './staticCache.js'; // 缓存已禁用
import type { ApiKeyEntry } from './auth.js';
import https from 'https';
import { HttpsProxyAgent } from 'https-proxy-agent';

const CLAUDE_WEB_URL = 'https://claude.ai';

// 代理配置（仅从 .env 的 PROXY_URL 读取）
const PROXY_URL = process.env.PROXY_URL || '';

// 创建共享的 HTTPS Agent，启用 Keep-Alive
// 如果配置了代理，使用 HttpsProxyAgent；否则直连
const httpsAgent = PROXY_URL
  ? new HttpsProxyAgent(PROXY_URL, {
      keepAlive: true,
      keepAliveMsecs: 1000,
      maxSockets: 256,
      maxFreeSockets: 256,
      timeout: 120000,
    })
  : new https.Agent({
      keepAlive: true,
      keepAliveMsecs: 1000,
      maxSockets: 256,
      maxFreeSockets: 256,
      timeout: 120000,
      scheduling: 'lifo' // 后进先出，提高热连接复用率
    });

// 启动时打印代理状态
if (PROXY_URL) {
  console.log(`[Web Proxy] 使用代理: ${PROXY_URL}`);
} else {
  console.log('[Web Proxy] 直连模式（未配置 PROXY_URL）');
}

// 指纹配置接口
interface FingerprintConfig {
  userAgent: string;
  platform: string;
  language: string;
  languages: string[];
  hardwareConcurrency: number;
  deviceMemory: number;
  maxTouchPoints: number;
  vendor: string;
  appVersion: string;
  screen: {
    width: number;
    height: number;
    colorDepth: number;
    pixelDepth: number;
  };
  timezone: string;
  timezoneOffset: number;
  secChUa: string;
  secChUaPlatform: string;
  secChUaMobile: string;
  acceptLanguage: string;
  webgl: {
    vendor: string;
    renderer: string;
    extensions: string[];
  };
}

// 加载指纹配置
function loadFingerprint(): FingerprintConfig {
  const fingerprintPath = join(process.cwd(), 'fingerprint.json');
  if (existsSync(fingerprintPath)) {
    try {
      const content = readFileSync(fingerprintPath, 'utf-8');
      const config = JSON.parse(content);
      console.log('[Fingerprint] 已加载自定义浏览器指纹');
      return config;
    } catch (err) {
      console.error('[Fingerprint] 读取指纹配置失败,使用默认配置:', err);
    }
  }
  // 默认指纹配置(如果文件不存在)
  return {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    platform: 'Win32',
    language: 'en-US',
    languages: ['en-US', 'en'],
    hardwareConcurrency: 8,
    deviceMemory: 8,
    maxTouchPoints: 0,
    vendor: 'Google Inc.',
    appVersion: '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    screen: { width: 1920, height: 1080, colorDepth: 24, pixelDepth: 24 },
    timezone: 'Asia/Shanghai',
    timezoneOffset: -480,
    secChUa: '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    secChUaPlatform: '"Windows"',
    secChUaMobile: '?0',
    acceptLanguage: 'en-US,en;q=0.9',
    webgl: {
      vendor: 'Google Inc. (NVIDIA)',
      renderer: 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)',
      extensions: ['ANGLE_instanced_arrays', 'EXT_blend_minmax', 'WEBGL_debug_renderer_info']
    }
  };
}

// 全局指纹配置
const FINGERPRINT = loadFingerprint();

// 注入的脚本 - 关键 polyfill 必须内联执行,确保在 Claude 代码之前运行
// 其他伪装代码仍然通过外部脚本加载
// 所有模式都注入 polyfill + 加载伪装脚本
const INJECT_SCRIPT = `<script>
// ========== 关键 polyfill: crypto.randomUUID ==========
// 必须在此内联,因为 Claude 的代码会立即使用
if (!crypto.randomUUID) {
  console.log('[Proxy] 注入 crypto.randomUUID polyfill');
  crypto.randomUUID = function() {
    return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, function(c) {
      return (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16);
    });
  };
}
// ========== 加载其他伪装脚本 ==========
(function(){
  var s=document.createElement('script');
  s.src='/__proxy__/inject.js';
  s.async=false;
  (document.head||document.documentElement).appendChild(s);
})();
</script>`;

// ========== HTML 流式注入器 ==========
// 使用 Transform Stream 实现流式脚本注入，避免缓冲整个 HTML
class HtmlScriptInjector extends Transform {
  private scriptToInject: string;
  private injected: boolean = false;
  private buffer: string = '';

  constructor(scriptToInject: string) {
    super();
    this.scriptToInject = scriptToInject;
  }

  _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    // 如果已经注入，直接传递数据
    if (this.injected) {
      callback(null, chunk);
      return;
    }

    // 将 chunk 添加到缓冲区
    this.buffer += chunk.toString('utf8');

    // 尝试查找 <head> 标签
    const headOpenRegex = /<head(\s[^>]*)?>|<head>/i;
    const headMatch = this.buffer.match(headOpenRegex);

    if (headMatch && headMatch.index !== undefined) {
      // 找到 <head> 标签，注入脚本
      const insertPos = headMatch.index + headMatch[0].length;
      const before = this.buffer.slice(0, insertPos);
      const after = this.buffer.slice(insertPos);

      this.injected = true;

      // 输出：<head> 之前的内容 + <head> 标签 + 注入脚本 + 剩余内容
      callback(null, Buffer.from(before + this.scriptToInject + after, 'utf8'));
      this.buffer = '';
      return;
    }

    // 检查是否有 </head> 作为备选注入点
    if (this.buffer.includes('</head>')) {
      const modifiedHtml = this.buffer.replace('</head>', `${this.scriptToInject}</head>`);
      this.injected = true;
      callback(null, Buffer.from(modifiedHtml, 'utf8'));
      this.buffer = '';
      return;
    }

    // 如果缓冲区太大（超过 64KB），可能不是标准 HTML，直接输出
    if (this.buffer.length > 65536) {
      this.injected = true; // 放弃注入
      callback(null, Buffer.from(this.buffer, 'utf8'));
      this.buffer = '';
      return;
    }

    // 继续等待更多数据
    callback();
  }

  _flush(callback: TransformCallback): void {
    // 流结束时，输出剩余缓冲区内容
    if (this.buffer.length > 0) {
      callback(null, Buffer.from(this.buffer, 'utf8'));
    } else {
      callback();
    }
  }
}

// 从配置导出的浏览器信息常量
const SPOOFED_USER_AGENT = FINGERPRINT.userAgent;
const SPOOFED_ACCEPT_LANGUAGE = FINGERPRINT.acceptLanguage;
const SPOOFED_SEC_CH_UA = FINGERPRINT.secChUa;
const SPOOFED_SEC_CH_UA_PLATFORM = FINGERPRINT.secChUaPlatform;
const SPOOFED_SEC_CH_UA_MOBILE = FINGERPRINT.secChUaMobile;

// 导出指纹配置供其他模块使用
export { FINGERPRINT };

// 凭证级别的权限配置
interface KeyPermissionConfig {
  allowedChats: string[];
  allowedProjects: string[];
  revoked?: boolean;  // 标记凭证是否已被撤销
  revokedAt?: string; // 撤销时间（ISO 8601 格式）
}

// config.json 的新结构：{ keyId: config }
interface ConfigFile {
  [keyId: string]: KeyPermissionConfig;
}

// 配置文件路径
const CONFIG_PATH = join(process.cwd(), 'config.json');

// 读取配置文件
function loadConfig(): ConfigFile {
  if (existsSync(CONFIG_PATH)) {
    try {
      const content = readFileSync(CONFIG_PATH, 'utf-8');
      return JSON.parse(content);
    } catch (err) {
      console.error('[Config] 读取配置文件失败:', err);
    }
  }
  return {};
}

// 保存配置文件
function saveConfig(config: ConfigFile): void {
  try {
    writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf-8');
  } catch (err) {
    console.error('[Config] 保存配置文件失败:', err);
  }
}

// 获取凭证的权限配置（默认严格模式）
function getKeyPermissionConfig(keyId: string): KeyPermissionConfig {
  const config = loadConfig();
  return config[keyId] || { allowedChats: [], allowedProjects: [] };
}

// 扩展 Request 类型，包含凭证信息
interface RequestWithApiKey extends Request {
  apiKeyEntry?: ApiKeyEntry;
}

// 获取有效的允许列表（凭证隔离）
function getEffectiveAllowedList(
  keyEntry: ApiKeyEntry | undefined,
  type: 'chats' | 'projects'
): string[] {
  if (!keyEntry) {
    return [];  // 未认证，默认严格模式
  }

  const permConfig = getKeyPermissionConfig(keyEntry.id);
  return type === 'chats' ? permConfig.allowedChats : permConfig.allowedProjects;
}

// 自动添加对话到凭证白名单
function addAllowedChatToKey(keyId: string, chatUuid: string): void {
  const config = loadConfig();

  if (!config[keyId]) {
    config[keyId] = { allowedChats: [], allowedProjects: [] };
  }

  if (!config[keyId].allowedChats.includes(chatUuid)) {
    config[keyId].allowedChats.push(chatUuid);
    saveConfig(config);
    console.log(`[Config] 对话 ${chatUuid} 已自动添加到凭证 ${keyId}`);
  }
}

// 自动从凭证移除对话
function removeAllowedChatFromKey(keyId: string, chatUuid: string): void {
  const config = loadConfig();

  if (config[keyId] && config[keyId].allowedChats) {
    const index = config[keyId].allowedChats.indexOf(chatUuid);
    if (index !== -1) {
      config[keyId].allowedChats.splice(index, 1);
      saveConfig(config);
      console.log(`[Config] 对话 ${chatUuid} 已从凭证 ${keyId} 移除`);
    }
  }
}

// 自动添加项目到凭证白名单
function addAllowedProjectToKey(keyId: string, projectUuid: string): void {
  const config = loadConfig();

  if (!config[keyId]) {
    config[keyId] = { allowedChats: [], allowedProjects: [] };
  }

  if (!config[keyId].allowedProjects.includes(projectUuid)) {
    config[keyId].allowedProjects.push(projectUuid);
    saveConfig(config);
    console.log(`[Config] 项目 ${projectUuid} 已自动添加到凭证 ${keyId}`);
  }
}

// 自动从凭证移除项目
function removeAllowedProjectFromKey(keyId: string, projectUuid: string): void {
  const config = loadConfig();

  if (config[keyId] && config[keyId].allowedProjects) {
    const index = config[keyId].allowedProjects.indexOf(projectUuid);
    if (index !== -1) {
      config[keyId].allowedProjects.splice(index, 1);
      saveConfig(config);
      console.log(`[Config] 项目 ${projectUuid} 已从凭证 ${keyId} 移除`);
    }
  }
}

// 导出此函数供 auth-cli 调用
export function markKeyAsRevoked(keyId: string): void {
  const config = loadConfig();

  if (config[keyId]) {
    config[keyId].revoked = true;
    config[keyId].revokedAt = new Date().toISOString();
    saveConfig(config);
    console.log(`[Config] 凭证 ${keyId} 已标记为已撤销`);
  } else {
    // 如果配置不存在，创建一个空配置并标记
    config[keyId] = {
      allowedChats: [],
      allowedProjects: [],
      revoked: true,
      revokedAt: new Date().toISOString()
    };
    saveConfig(config);
    console.log(`[Config] 凭证 ${keyId} 配置已创建并标记为已撤销`);
  }
}

// 检查是否是创建对话的 API（POST 请求到 chat_conversations）
function isCreateChatApi(url: string, method: string): boolean {
  // POST /api/organizations/{org_id}/chat_conversations
  return method === 'POST' && /\/api\/organizations\/[^/]+\/chat_conversations$/.test(url);
}

// 检查是否是创建项目的 API（POST 请求到 projects）
function isCreateProjectApi(url: string, method: string): boolean {
  // POST /api/organizations/{org_id}/projects
  return method === 'POST' && /\/api\/organizations\/[^/]+\/projects$/.test(url);
}

// 检查是否是删除对话的 API（DELETE 请求到 chat_conversations/{uuid}）
function isDeleteChatApi(url: string, method: string): { isDelete: boolean; uuid: string | null } {
  // DELETE /api/organizations/{org_id}/chat_conversations/{uuid}
  if (method !== 'DELETE') return { isDelete: false, uuid: null };
  const match = url.match(/\/api\/organizations\/[^/]+\/chat_conversations\/([a-f0-9-]+)$/);
  return { isDelete: !!match, uuid: match ? match[1] : null };
}

// 检查是否是删除项目的 API（DELETE 请求到 projects/{uuid}）
function isDeleteProjectApi(url: string, method: string): { isDelete: boolean; uuid: string | null } {
  // DELETE /api/organizations/{org_id}/projects/{uuid}
  if (method !== 'DELETE') return { isDelete: false, uuid: null };
  const match = url.match(/\/api\/organizations\/[^/]+\/projects\/([a-f0-9-]+)$/);
  return { isDelete: !!match, uuid: match ? match[1] : null };
}

// 检查是否是对话列表 API (仅 GET 请求)
function isChatListApi(url: string, method: string): boolean {
  // Claude 的对话列表 API: /api/organizations/{org_id}/chat_conversations
  // 排除 count_all 接口，排除 POST 请求（创建对话）
  if (method !== 'GET') return false;
  return /\/api\/organizations\/[^/]+\/chat_conversations(?!\/)/.test(url) ||
         /\/api\/organizations\/[^/]+\/chat_conversations\?/.test(url);
}

// 检查是否是对话计数 API
function isChatCountApi(url: string): boolean {
  return /\/api\/organizations\/[^/]+\/chat_conversations\/count_all/.test(url);
}

// 检查是否是项目列表 API
function isProjectListApi(url: string): boolean {
  // Claude 的项目列表 API:
  // - /api/organizations/{org_id}/projects_v2
  // - /api/organizations/{org_id}/projects?... (带查询参数的列表请求)
  // 注意：要排除单个项目详情的请求 /projects/{uuid}
  if (/\/api\/organizations\/[^/]+\/projects_v2/.test(url)) {
    return true;
  }
  // 匹配 /projects? 但排除 /projects/{uuid}
  if (/\/api\/organizations\/[^/]+\/projects\?/.test(url)) {
    return true;
  }
  return false;
}

// 检查是否是搜索 API
function isSearchApi(url: string): boolean {
  // 搜索 API: /api/organizations/{org_id}/conversation/search
  return /\/api\/organizations\/[^/]+\/conversation\/search/.test(url);
}

// 检查是否需要过滤
// 空列表 = 不显示任何内容（严格模式）
// 如果第一项以 '示例' 开头，则不过滤（初始配置示例）
// 如果第一项是 '*'，则显示所有（通配符）
function shouldFilter(allowedList: string[]): boolean {
  // 空列表：严格模式，不显示任何内容
  if (allowedList.length === 0) {
    return true;
  }
  // 通配符 '*'：显示所有
  if (allowedList[0] === '*') {
    return false;
  }
  // 示例配置：不过滤
  if (allowedList[0].startsWith('示例')) {
    return false;
  }
  return true;
}

// 过滤列表（通用）
function filterList(data: unknown, allowedIds: string[]): unknown {
  if (!shouldFilter(allowedIds)) {
    return data;
  }

  if (Array.isArray(data)) {
    return data.filter((item: { uuid?: string }) =>
      item.uuid && allowedIds.includes(item.uuid)
    );
  }

  return data;
}

export function createWebProxy(sessionKey: string): RequestHandler {
  // 缓存功能已禁用，改用压缩透传优化
  // const cache = getCache();

  const proxyMiddleware = createProxyMiddleware({
    target: CLAUDE_WEB_URL,
    changeOrigin: true,
    secure: true,
    selfHandleResponse: true,
    agent: httpsAgent, // 使用 Keep-Alive Agent 提升性能
    proxyTimeout: 120000, // 2分钟超时
    timeout: 120000,

    on: {
      proxyReq: (proxyReq, req) => {
        // 添加保护：检查请求状态，避免在已发送头部后修改
        const isFinished = (proxyReq as any).finished;
        const isHeadersSent = (proxyReq as any).headersSent;

        if (isFinished || isHeadersSent) {
          console.warn(`[Web Proxy] Skipping header modification for ${req.url} (finished: ${isFinished}, headersSent: ${isHeadersSent})`);
          return;
        }

        try {
          // 设置请求超时
          proxyReq.setTimeout(120000);
          // 注入 sessionKey Cookie
          const existingCookie = proxyReq.getHeader('cookie') as string || '';
          const newCookie = existingCookie
            ? `${existingCookie}; sessionKey=${sessionKey}`
            : `sessionKey=${sessionKey}`;
          proxyReq.setHeader('cookie', newCookie);

          // 设置正确的 Host
          proxyReq.setHeader('host', 'claude.ai');

          // 移除可能暴露代理的头
          proxyReq.removeHeader('x-forwarded-host');
          proxyReq.removeHeader('x-forwarded-proto');
          proxyReq.removeHeader('x-forwarded-for');
          proxyReq.removeHeader('x-real-ip');
          proxyReq.removeHeader('x-client-ip');
          proxyReq.removeHeader('cf-connecting-ip');
          proxyReq.removeHeader('true-client-ip');
          proxyReq.removeHeader('via');

          // 覆盖客户端浏览器指纹相关的请求头
          proxyReq.setHeader('user-agent', SPOOFED_USER_AGENT);
          proxyReq.setHeader('accept-language', SPOOFED_ACCEPT_LANGUAGE);
          proxyReq.setHeader('sec-ch-ua', SPOOFED_SEC_CH_UA);
          proxyReq.setHeader('sec-ch-ua-platform', SPOOFED_SEC_CH_UA_PLATFORM);
          proxyReq.setHeader('sec-ch-ua-mobile', SPOOFED_SEC_CH_UA_MOBILE);

          // 修正 referer 和 origin，避免暴露代理地址
          const referer = proxyReq.getHeader('referer') as string;
          if (referer) {
            proxyReq.setHeader('referer', referer.replace(/^https?:\/\/[^/]+/, 'https://claude.ai'));
          }
          const origin = proxyReq.getHeader('origin') as string;
          if (origin && !origin.includes('claude.ai')) {
            proxyReq.setHeader('origin', 'https://claude.ai');
          }

          // 请求未压缩的响应
          // 注意：压缩透传在某些环境下不兼容，暂时禁用
          proxyReq.setHeader('accept-encoding', 'identity');

          console.log(`[Web Proxy] ${req.method} ${req.url}`);
        } catch (err: any) {
          // 忽略 ERR_HTTP_HEADERS_SENT 错误，这在某些竞态条件下可能发生
          if (err.code === 'ERR_HTTP_HEADERS_SENT') {
            console.warn(`[Web Proxy] Headers already sent for ${req.url}, ignoring`);
            return;
          }
          console.error(`[Web Proxy] Error in proxyReq handler:`, err.message);
        }
      },

      proxyRes: (proxyRes, req, res) => {
        // 移除 CSP 头
        delete proxyRes.headers['content-security-policy'];
        delete proxyRes.headers['content-security-policy-report-only'];

        // 修改 Set-Cookie：移除域名，并过滤掉 sessionKey（防止泄露真实 session token）
        const setCookie = proxyRes.headers['set-cookie'];
        if (setCookie) {
          const filteredCookies = setCookie
            .filter(cookie => !cookie.toLowerCase().startsWith('sessionkey='))
            .map(cookie => cookie.replace(/domain=[^;]+;?/gi, ''));

          if (filteredCookies.length > 0) {
            proxyRes.headers['set-cookie'] = filteredCookies;
          } else {
            delete proxyRes.headers['set-cookie'];
          }
        }

        const contentType = proxyRes.headers['content-type'] || '';
        const reqUrl = req.url || '';
        const reqMethod = req.method || 'GET';

        // ========== 性能优化：提前识别不需要处理的请求，直接流式转发 ==========
        // 这是最关键的优化：大部分请求（90%+）都不需要缓冲处理
        const needsInterception =
          // 1. 需要拦截的 API
          isChatListApi(reqUrl, reqMethod) ||
          isProjectListApi(reqUrl) ||
          isSearchApi(reqUrl) ||
          isChatCountApi(reqUrl) ||
          isCreateChatApi(reqUrl, reqMethod) ||
          isCreateProjectApi(reqUrl, reqMethod) ||
          isDeleteChatApi(reqUrl, reqMethod).isDelete ||
          isDeleteProjectApi(reqUrl, reqMethod).isDelete ||
          // 2. HTML 页面（需要注入脚本）
          contentType.includes('text/html');

        // 如果不需要拦截，直接流式转发（压缩内容直接透传）
        if (!needsInterception) {
          console.log('[Web Proxy] 流式转发:', reqMethod, reqUrl);
          (res as ServerResponse).writeHead(proxyRes.statusCode || 200, proxyRes.headers);
          proxyRes.pipe(res as ServerResponse);
          return;
        }
        // ========== 以下是需要拦截处理的请求 ==========

        // 处理删除对话 API - 从允许列表移除(仅非管理员)
        const deleteChat = isDeleteChatApi(reqUrl, reqMethod);
        if (deleteChat.isDelete && deleteChat.uuid) {
          const chatUuid = deleteChat.uuid;
          // 删除成功时从配置中移除(仅非管理员)
          if (proxyRes.statusCode && proxyRes.statusCode >= 200 && proxyRes.statusCode < 300) {
            const keyEntry = (req as RequestWithApiKey).apiKeyEntry;
            if (keyEntry && !keyEntry.isAdmin) {
              removeAllowedChatFromKey(keyEntry.id, chatUuid);
              console.log(`[Web Proxy] 对话已删除并从凭证 ${keyEntry.name} 移除:`, chatUuid);
            }
          }
          // 直接转发响应
          (res as ServerResponse).writeHead(proxyRes.statusCode || 200, proxyRes.headers);
          proxyRes.pipe(res as ServerResponse);
          return;
        }

        // 处理删除项目 API - 从允许列表移除(仅非管理员)
        const deleteProject = isDeleteProjectApi(reqUrl, reqMethod);
        if (deleteProject.isDelete && deleteProject.uuid) {
          const projectUuid = deleteProject.uuid;
          // 删除成功时从配置中移除(仅非管理员)
          if (proxyRes.statusCode && proxyRes.statusCode >= 200 && proxyRes.statusCode < 300) {
            const keyEntry = (req as RequestWithApiKey).apiKeyEntry;
            if (keyEntry && !keyEntry.isAdmin) {
              removeAllowedProjectFromKey(keyEntry.id, projectUuid);
              console.log(`[Web Proxy] 项目已删除并从凭证 ${keyEntry.name} 移除:`, projectUuid);
            }
          }
          // 直接转发响应
          (res as ServerResponse).writeHead(proxyRes.statusCode || 200, proxyRes.headers);
          proxyRes.pipe(res as ServerResponse);
          return;
        }

        // 处理创建对话 API - 将新对话添加到允许列表
        if (isCreateChatApi(reqUrl, reqMethod) && contentType.includes('application/json')) {
          const chunks: Buffer[] = [];

          proxyRes.on('data', (chunk: Buffer) => chunks.push(chunk));
          proxyRes.on('end', () => {
            try {
              const body = Buffer.concat(chunks).toString('utf8');
              const data = JSON.parse(body);

              // 如果创建成功，将新对话 UUID 添加到配置(仅非管理员)
              if (data && data.uuid && proxyRes.statusCode && proxyRes.statusCode >= 200 && proxyRes.statusCode < 300) {
                const chatUuid = data.uuid;
                const keyEntry = (req as RequestWithApiKey).apiKeyEntry;
                if (keyEntry && !keyEntry.isAdmin) {
                  addAllowedChatToKey(keyEntry.id, chatUuid);
                  console.log(`[Web Proxy] 新对话已创建并自动添加到凭证 ${keyEntry.name}:`, chatUuid);
                }
              }

              // 原样返回响应
              const responseBuffer = Buffer.from(body, 'utf8');
              const headers = { ...proxyRes.headers };
              headers['content-length'] = String(responseBuffer.length);
              delete headers['content-encoding'];

              (res as ServerResponse).writeHead(proxyRes.statusCode || 200, headers);
              (res as ServerResponse).end(responseBuffer);
            } catch (err) {
              console.error('[Web Proxy] Error processing create chat response:', err);
              (res as ServerResponse).writeHead(500, { 'Content-Type': 'text/plain' });
              (res as ServerResponse).end('Proxy Error');
            }
          });
          return;
        }

        // 处理创建项目 API - 将新项目添加到允许列表
        if (isCreateProjectApi(reqUrl, reqMethod) && contentType.includes('application/json')) {
          const chunks: Buffer[] = [];

          proxyRes.on('data', (chunk: Buffer) => chunks.push(chunk));
          proxyRes.on('end', () => {
            try {
              const body = Buffer.concat(chunks).toString('utf8');
              const data = JSON.parse(body);

              // 如果创建成功，将新项目 UUID 添加到配置(仅非管理员)
              if (data && data.uuid && proxyRes.statusCode && proxyRes.statusCode >= 200 && proxyRes.statusCode < 300) {
                const projectUuid = data.uuid;
                const keyEntry = (req as RequestWithApiKey).apiKeyEntry;
                if (keyEntry && !keyEntry.isAdmin) {
                  addAllowedProjectToKey(keyEntry.id, projectUuid);
                  console.log(`[Web Proxy] 新项目已创建并自动添加到凭证 ${keyEntry.name}:`, projectUuid);
                }
              }

              // 原样返回响应
              const responseBuffer = Buffer.from(body, 'utf8');
              const headers = { ...proxyRes.headers };
              headers['content-length'] = String(responseBuffer.length);
              delete headers['content-encoding'];

              (res as ServerResponse).writeHead(proxyRes.statusCode || 200, headers);
              (res as ServerResponse).end(responseBuffer);
            } catch (err) {
              console.error('[Web Proxy] Error processing create project response:', err);
              (res as ServerResponse).writeHead(500, { 'Content-Type': 'text/plain' });
              (res as ServerResponse).end('Proxy Error');
            }
          });
          return;
        }

        // 处理搜索 API
        if (isSearchApi(reqUrl) && contentType.includes('application/json')) {
          const chunks: Buffer[] = [];

          proxyRes.on('data', (chunk: Buffer) => chunks.push(chunk));
          proxyRes.on('end', () => {
            try {
              const body = Buffer.concat(chunks).toString('utf8');
              let data = JSON.parse(body);
              const keyEntry = (req as RequestWithApiKey).apiKeyEntry;

              // 管理员模式:不过滤搜索结果
              if (keyEntry && keyEntry.isAdmin) {
                const responseBody = JSON.stringify(data);
                const responseBuffer = Buffer.from(responseBody, 'utf8');
                const headers = { ...proxyRes.headers };
                headers['content-length'] = String(responseBuffer.length);
                delete headers['content-encoding'];
                (res as ServerResponse).writeHead(proxyRes.statusCode || 200, headers);
                (res as ServerResponse).end(responseBuffer);
                return;
              }

              // 普通模式:过滤搜索结果
              const effectiveChatList = getEffectiveAllowedList(keyEntry, 'chats');

              // 如果响应是双重编码的 JSON 字符串，再解析一次
              if (typeof data === 'string') {
                data = JSON.parse(data);
              }

              console.log('[Web Proxy] 搜索 API 响应类型:', typeof data, '结构:', JSON.stringify(data).substring(0, 200));

              let filtered = data;

              // 搜索结果格式: {"chunks": [{..., extras: {conversation_uuid, doc_type}}]}
              if (data && data.chunks && Array.isArray(data.chunks)) {
                interface SearchChunk {
                  extras?: {
                    conversation_uuid?: string;
                    doc_type?: string;
                  };
                }
                const filteredChunks = data.chunks.filter((chunk: SearchChunk) => {
                  const extras = chunk.extras;
                  if (!extras) return true;

                  const docType = extras.doc_type;
                  const conversationUuid = extras.conversation_uuid;

                  // 对话类型
                  if (docType === 'conversation' && conversationUuid) {
                    if (shouldFilter(effectiveChatList)) {
                      return effectiveChatList.includes(conversationUuid);
                    }
                  }

                  // 项目类型 - 如果有 project_uuid
                  // 目前搜索结果主要是对话，项目可能单独处理

                  return true;
                });

                filtered = { ...data, chunks: filteredChunks };
                console.log('[Web Proxy] 搜索过滤: 原始', data.chunks.length, '条 -> 过滤后', filteredChunks.length, '条');
              }

              const responseBody = JSON.stringify(filtered);
              const responseBuffer = Buffer.from(responseBody, 'utf8');

              const headers = { ...proxyRes.headers };
              headers['content-length'] = String(responseBuffer.length);
              delete headers['content-encoding'];

              (res as ServerResponse).writeHead(proxyRes.statusCode || 200, headers);
              (res as ServerResponse).end(responseBuffer);
            } catch (err) {
              console.error('[Web Proxy] Error filtering search results:', err);
              (res as ServerResponse).writeHead(500, { 'Content-Type': 'text/plain' });
              (res as ServerResponse).end('Proxy Error');
            }
          });
          return;
        }

        // 处理对话计数 API
        if (isChatCountApi(reqUrl) && contentType.includes('application/json')) {
          const keyEntry = (req as RequestWithApiKey).apiKeyEntry;

          // 管理员模式:直接透传真实数量
          if (keyEntry && keyEntry.isAdmin) {
            // 直接转发原始响应
            (res as ServerResponse).writeHead(proxyRes.statusCode || 200, proxyRes.headers);
            proxyRes.pipe(res as ServerResponse);
            return;
          }

          // 普通模式:返回过滤后的数量
          const effectiveList = getEffectiveAllowedList(keyEntry, 'chats');
          if (shouldFilter(effectiveList)) {
            // 返回允许的聊天数量
            const responseData = {
              count: effectiveList.length,
              is_first_conversation: effectiveList.length === 0
            };
            const responseBody = JSON.stringify(responseData);
            const responseBuffer = Buffer.from(responseBody, 'utf8');

            const headers = { ...proxyRes.headers };
            headers['content-length'] = String(responseBuffer.length);
            headers['content-type'] = 'application/json';
            delete headers['content-encoding'];

            // 消费原始响应
            proxyRes.on('data', () => {});
            proxyRes.on('end', () => {
              (res as ServerResponse).writeHead(proxyRes.statusCode || 200, headers);
              (res as ServerResponse).end(responseBuffer);
            });
            return;
          }
        }

        // 处理对话列表 API (仅 GET 请求)
        if (isChatListApi(reqUrl, reqMethod) && contentType.includes('application/json')) {
          const chunks: Buffer[] = [];

          proxyRes.on('data', (chunk: Buffer) => chunks.push(chunk));
          proxyRes.on('end', () => {
            try {
              const body = Buffer.concat(chunks).toString('utf8');
              const data = JSON.parse(body);
              const keyEntry = (req as RequestWithApiKey).apiKeyEntry;

              // 管理员模式:不过滤,直接返回所有对话
              if (keyEntry && keyEntry.isAdmin) {
                const responseBody = JSON.stringify(data);
                const responseBuffer = Buffer.from(responseBody, 'utf8');
                const headers = { ...proxyRes.headers };
                headers['content-length'] = String(responseBuffer.length);
                delete headers['content-encoding'];
                (res as ServerResponse).writeHead(proxyRes.statusCode || 200, headers);
                (res as ServerResponse).end(responseBuffer);
                return;
              }

              // 普通模式:应用白名单过滤
              const effectiveList = getEffectiveAllowedList(keyEntry, 'chats');
              const filtered = filterList(data, effectiveList);
              const responseBody = JSON.stringify(filtered);
              const responseBuffer = Buffer.from(responseBody, 'utf8');

              const headers = { ...proxyRes.headers };
              headers['content-length'] = String(responseBuffer.length);
              delete headers['content-encoding'];

              (res as ServerResponse).writeHead(proxyRes.statusCode || 200, headers);
              (res as ServerResponse).end(responseBuffer);
            } catch (err) {
              console.error('[Web Proxy] Error filtering chat list:', err);
              (res as ServerResponse).writeHead(500, { 'Content-Type': 'text/plain' });
              (res as ServerResponse).end('Proxy Error');
            }
          });
          return;
        }

        // 处理项目列表 API
        if (isProjectListApi(reqUrl) && contentType.includes('application/json')) {
          const chunks: Buffer[] = [];

          proxyRes.on('data', (chunk: Buffer) => chunks.push(chunk));
          proxyRes.on('end', () => {
            try {
              const body = Buffer.concat(chunks).toString('utf8');
              const data = JSON.parse(body);
              const keyEntry = (req as RequestWithApiKey).apiKeyEntry;

              // 管理员模式:不过滤,返回所有项目
              if (keyEntry && keyEntry.isAdmin) {
                const responseBody = JSON.stringify(data);
                const responseBuffer = Buffer.from(responseBody, 'utf8');
                const headers = { ...proxyRes.headers };
                headers['content-length'] = String(responseBuffer.length);
                delete headers['content-encoding'];
                (res as ServerResponse).writeHead(proxyRes.statusCode || 200, headers);
                (res as ServerResponse).end(responseBuffer);
                return;
              }

              // 普通模式:应用白名单过滤
              const effectiveList = getEffectiveAllowedList(keyEntry, 'projects');

              console.log('[Web Proxy] 项目列表 API 响应结构:', JSON.stringify(data).substring(0, 500));

              let filtered;
              if (shouldFilter(effectiveList)) {
                // projects_v2 可能返回数组或带有 results/data 字段的对象
                if (Array.isArray(data)) {
                  filtered = data.filter((item: { uuid?: string }) =>
                    item.uuid && effectiveList.includes(item.uuid)
                  );
                } else if (data && typeof data === 'object') {
                  // 可能是 { results: [...] } 或 { data: [...] } 格式
                  const arrayField = data.results || data.data || data.projects;
                  if (Array.isArray(arrayField)) {
                    const filteredArray = arrayField.filter((item: { uuid?: string }) =>
                      item.uuid && effectiveList.includes(item.uuid)
                    );
                    filtered = { ...data };
                    if (data.results) filtered.results = filteredArray;
                    else if (data.data) filtered.data = filteredArray;
                    else if (data.projects) filtered.projects = filteredArray;
                  } else {
                    filtered = data;
                  }
                } else {
                  filtered = data;
                }
              } else {
                filtered = data;
              }

              const responseBody = JSON.stringify(filtered);
              const responseBuffer = Buffer.from(responseBody, 'utf8');

              const headers = { ...proxyRes.headers };
              headers['content-length'] = String(responseBuffer.length);
              delete headers['content-encoding'];

              (res as ServerResponse).writeHead(proxyRes.statusCode || 200, headers);
              (res as ServerResponse).end(responseBuffer);
            } catch (err) {
              console.error('[Web Proxy] Error filtering project list:', err);
              (res as ServerResponse).writeHead(500, { 'Content-Type': 'text/plain' });
              (res as ServerResponse).end('Proxy Error');
            }
          });
          return;
        }

        // 处理 HTML 响应，流式注入脚本
        // 优化：使用 Transform Stream 流式处理，避免缓冲整个 HTML
        if (contentType.includes('text/html') && !reqUrl.startsWith('/api/')) {
          // 准备注入的脚本
          const keyEntry = (req as RequestWithApiKey).apiKeyEntry;
          const isAdmin = keyEntry && keyEntry.isAdmin;
          const adminFlagScript = `<script>window.__PROXY_IS_ADMIN__=${isAdmin ? 'true' : 'false'};</script>`;
          const scriptToInject = adminFlagScript + INJECT_SCRIPT;

          // 设置响应头（流式处理无法预知 content-length，使用 chunked 传输）
          const headers = { ...proxyRes.headers };
          delete headers['content-length']; // 移除，使用 chunked 编码
          delete headers['content-encoding']; // 移除压缩编码

          (res as ServerResponse).writeHead(proxyRes.statusCode || 200, headers);

          // 创建流式注入器并管道连接
          const injector = new HtmlScriptInjector(scriptToInject);

          injector.on('error', (err) => {
            console.error('[Web Proxy] HTML stream error:', err);
          });

          proxyRes.pipe(injector).pipe(res as ServerResponse);
          return;
        }
        // 注意：不需要处理的请求（包括静态资源缓存）已在开头流式转发
      },

      error: (err, _req, res) => {
        console.error('[Web Proxy] Error:', err.message);
        if ('writeHead' in res && typeof res.writeHead === 'function') {
          res.writeHead(502, { 'Content-Type': 'text/plain' });
          res.end('Web Proxy Error: ' + err.message);
        }
      }
    }
  });

  // 直接返回代理中间件（缓存已禁用）
  return proxyMiddleware;
}
