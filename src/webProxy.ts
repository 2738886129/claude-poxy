import { createProxyMiddleware } from 'http-proxy-middleware';
import type { RequestHandler, Request } from 'express';
import type { ServerResponse } from 'http';
import { readFileSync, existsSync, writeFileSync } from 'fs';
import { join } from 'path';
import { getCache } from './staticCache.js';
import type { ApiKeyEntry } from './auth.js';

const CLAUDE_WEB_URL = 'https://claude.ai';

// 注入的脚本 - 关键 polyfill 必须内联执行,确保在 Claude 代码之前运行
// 其他伪装代码仍然通过外部脚本加载
// 管理员模式：仅注入必需的 crypto.randomUUID polyfill
const ADMIN_MINIMAL_SCRIPT = `<script>
// ========== 关键 polyfill: crypto.randomUUID ==========
// 管理员模式：仅注入此 polyfill，不加载其他伪装脚本
if (!crypto.randomUUID) {
  crypto.randomUUID = function() {
    return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, function(c) {
      return (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16);
    });
  };
}
</script>`;

// 普通模式：注入 polyfill + 加载伪装脚本
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

// 伪装的浏览器信息 - 模拟一个通用的 Chrome 浏览器
const SPOOFED_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const SPOOFED_ACCEPT_LANGUAGE = 'en-US,en;q=0.9';
const SPOOFED_SEC_CH_UA = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"';
const SPOOFED_SEC_CH_UA_PLATFORM = '"Windows"';
const SPOOFED_SEC_CH_UA_MOBILE = '?0';

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
  const cache = getCache();

  // 创建一个中间件来处理缓存
  const cacheMiddleware: RequestHandler = (req, res, next) => {
    const url = req.url || '';
    const method = req.method || 'GET';

    // 检查是否可缓存且有缓存
    if (cache.isCacheable(url, method)) {
      const cached = cache.get(url);
      if (cached) {
        console.log(`[Cache] HIT: ${url}`);

        // 设置响应头
        res.status(cached.entry.statusCode);
        for (const [key, value] of Object.entries(cached.entry.headers)) {
          res.setHeader(key, value);
        }
        res.setHeader('x-cache', 'HIT');
        res.send(cached.data);
        return;
      }
    }

    next();
  };

  const proxyMiddleware = createProxyMiddleware({
    target: CLAUDE_WEB_URL,
    changeOrigin: true,
    secure: true,
    selfHandleResponse: true,
    proxyTimeout: 120000, // 2分钟超时
    timeout: 120000,

    on: {
      proxyReq: (proxyReq, req) => {
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

        // 请求未压缩的响应，便于修改
        proxyReq.setHeader('accept-encoding', 'identity');

        console.log(`[Web Proxy] ${req.method} ${req.url}`);
      },

      proxyRes: (proxyRes, req, res) => {
        // 移除 CSP 头
        delete proxyRes.headers['content-security-policy'];
        delete proxyRes.headers['content-security-policy-report-only'];

        // 修改 Set-Cookie 的域名
        const setCookie = proxyRes.headers['set-cookie'];
        if (setCookie) {
          proxyRes.headers['set-cookie'] = setCookie.map(cookie =>
            cookie.replace(/domain=[^;]+;?/gi, '')
          );
        }

        const contentType = proxyRes.headers['content-type'] || '';
        const reqUrl = req.url || '';
        const reqMethod = req.method || 'GET';

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

        // 处理 HTML 响应，注入脚本
        if (contentType.includes('text/html')) {
          const keyEntry = (req as RequestWithApiKey).apiKeyEntry;
          const chunks: Buffer[] = [];

          proxyRes.on('data', (chunk: Buffer) => chunks.push(chunk));
          proxyRes.on('end', () => {
            try {
              let htmlStr = Buffer.concat(chunks).toString('utf8');

              // 选择注入脚本：管理员模式仅注入必需 polyfill，普通模式注入完整脚本
              const scriptToInject = (keyEntry && keyEntry.isAdmin) ? ADMIN_MINIMAL_SCRIPT : INJECT_SCRIPT;

              // 在 <head> 后立即注入脚本
              // 注意: 这会导致 React hydration 警告 #418,但不影响功能
              // React #418 是由于 SSR HTML 和客户端 HTML 不匹配,但这是代理的必要副作用
              const headOpenRegex = /<head(\s[^>]*)?>|<head>/i;
              const headMatch = htmlStr.match(headOpenRegex);
              if (headMatch) {
                htmlStr = htmlStr.replace(headMatch[0], `${headMatch[0]}${scriptToInject}`);
              } else if (htmlStr.includes('</head>')) {
                htmlStr = htmlStr.replace('</head>', `${scriptToInject}</head>`);
              }

              const responseBuffer = Buffer.from(htmlStr, 'utf8');

              const headers = { ...proxyRes.headers };
              headers['content-length'] = String(responseBuffer.length);
              delete headers['content-encoding'];

              (res as ServerResponse).writeHead(proxyRes.statusCode || 200, headers);
              (res as ServerResponse).end(responseBuffer);
            } catch (err) {
              console.error('[Web Proxy] Error processing HTML:', err);
              (res as ServerResponse).writeHead(500, { 'Content-Type': 'text/plain' });
              (res as ServerResponse).end('Proxy Error');
            }
          });
        } else if (cache.isCacheable(reqUrl, req.method || 'GET')) {
          // 可缓存的静态资源 - 收集响应并缓存
          const chunks: Buffer[] = [];

          proxyRes.on('data', (chunk: Buffer) => chunks.push(chunk));
          proxyRes.on('end', () => {
            try {
              const responseBuffer = Buffer.concat(chunks);
              const statusCode = proxyRes.statusCode || 200;

              // 只缓存成功的响应
              if (statusCode >= 200 && statusCode < 300) {
                const headersToCache: Record<string, string> = {};
                for (const [key, value] of Object.entries(proxyRes.headers)) {
                  if (value && typeof value === 'string') {
                    headersToCache[key] = value;
                  } else if (Array.isArray(value)) {
                    headersToCache[key] = value.join(', ');
                  }
                }
                cache.set(reqUrl, responseBuffer, statusCode, contentType, headersToCache);
              }

              const headers = { ...proxyRes.headers };
              headers['x-cache'] = 'MISS';

              (res as ServerResponse).writeHead(statusCode, headers);
              (res as ServerResponse).end(responseBuffer);
            } catch (err) {
              console.error('[Web Proxy] Error caching response:', err);
              (res as ServerResponse).writeHead(500, { 'Content-Type': 'text/plain' });
              (res as ServerResponse).end('Proxy Error');
            }
          });
        } else {
          // 其他内容直接转发
          console.log('[Web Proxy] 直接转发:', reqMethod, reqUrl, 'Content-Type:', contentType);
          (res as ServerResponse).writeHead(proxyRes.statusCode || 200, proxyRes.headers);
          proxyRes.pipe(res as ServerResponse);
        }
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

  // 返回组合的中间件：先检查缓存，再代理
  return (req, res, next) => {
    cacheMiddleware(req, res, () => {
      proxyMiddleware(req, res, next);
    });
  };
}
