import { createProxyMiddleware } from 'http-proxy-middleware';
import type { RequestHandler } from 'express';
import type { ServerResponse } from 'http';
import { readFileSync, existsSync, writeFileSync } from 'fs';
import { join } from 'path';
import { getCache } from './staticCache.js';

const CLAUDE_WEB_URL = 'https://claude.ai';

// 注入的脚本标签
const INJECT_SCRIPT = '<script src="/__proxy__/inject.js"></script>';

// 配置类型
interface Config {
  allowedChats: string[];
  allowedProjects: string[];
}

// 配置文件路径
const CONFIG_PATH = join(process.cwd(), 'config.json');

// 读取配置文件
function loadConfig(): Config {
  if (existsSync(CONFIG_PATH)) {
    try {
      const content = readFileSync(CONFIG_PATH, 'utf-8');
      return JSON.parse(content);
    } catch (err) {
      console.error('[Config] 读取配置文件失败:', err);
    }
  }
  return { allowedChats: [], allowedProjects: [] };
}

// 保存配置文件
function saveConfig(config: Config): void {
  try {
    writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf-8');
    console.log('[Config] 配置已保存');
  } catch (err) {
    console.error('[Config] 保存配置文件失败:', err);
  }
}

// 添加新对话到允许列表
function addAllowedChat(chatUuid: string): void {
  const config = loadConfig();
  if (!config.allowedChats.includes(chatUuid)) {
    config.allowedChats.push(chatUuid);
    saveConfig(config);
    console.log('[Config] 新对话已添加:', chatUuid);
  }
}

// 添加新项目到允许列表
function addAllowedProject(projectUuid: string): void {
  const config = loadConfig();
  if (!config.allowedProjects.includes(projectUuid)) {
    config.allowedProjects.push(projectUuid);
    saveConfig(config);
    console.log('[Config] 新项目已添加:', projectUuid);
  }
}

// 从允许列表中移除对话
function removeAllowedChat(chatUuid: string): void {
  const config = loadConfig();
  const index = config.allowedChats.indexOf(chatUuid);
  if (index !== -1) {
    config.allowedChats.splice(index, 1);
    saveConfig(config);
    console.log('[Config] 对话已移除:', chatUuid);
  }
}

// 从允许列表中移除项目
function removeAllowedProject(projectUuid: string): void {
  const config = loadConfig();
  const index = config.allowedProjects.indexOf(projectUuid);
  if (index !== -1) {
    config.allowedProjects.splice(index, 1);
    saveConfig(config);
    console.log('[Config] 项目已移除:', projectUuid);
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

        // 处理删除对话 API - 从允许列表移除
        const deleteChat = isDeleteChatApi(reqUrl, reqMethod);
        if (deleteChat.isDelete && deleteChat.uuid) {
          const chatUuid = deleteChat.uuid;
          // 删除成功时从配置中移除
          if (proxyRes.statusCode && proxyRes.statusCode >= 200 && proxyRes.statusCode < 300) {
            removeAllowedChat(chatUuid);
            console.log('[Web Proxy] 对话已删除并从允许列表移除:', chatUuid);
          }
          // 直接转发响应
          (res as ServerResponse).writeHead(proxyRes.statusCode || 200, proxyRes.headers);
          proxyRes.pipe(res as ServerResponse);
          return;
        }

        // 处理删除项目 API - 从允许列表移除
        const deleteProject = isDeleteProjectApi(reqUrl, reqMethod);
        if (deleteProject.isDelete && deleteProject.uuid) {
          const projectUuid = deleteProject.uuid;
          // 删除成功时从配置中移除
          if (proxyRes.statusCode && proxyRes.statusCode >= 200 && proxyRes.statusCode < 300) {
            removeAllowedProject(projectUuid);
            console.log('[Web Proxy] 项目已删除并从允许列表移除:', projectUuid);
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

              // 如果创建成功，将新对话 UUID 添加到配置
              if (data && data.uuid && proxyRes.statusCode && proxyRes.statusCode >= 200 && proxyRes.statusCode < 300) {
                addAllowedChat(data.uuid);
                console.log('[Web Proxy] 新对话已创建并添加到允许列表:', data.uuid);
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

              // 如果创建成功，将新项目 UUID 添加到配置
              if (data && data.uuid && proxyRes.statusCode && proxyRes.statusCode >= 200 && proxyRes.statusCode < 300) {
                addAllowedProject(data.uuid);
                console.log('[Web Proxy] 新项目已创建并添加到允许列表:', data.uuid);
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
              const config = loadConfig();

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
                    if (shouldFilter(config.allowedChats)) {
                      return config.allowedChats.includes(conversationUuid);
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
          const config = loadConfig();
          if (shouldFilter(config.allowedChats)) {
            // 返回允许的聊天数量
            const responseData = {
              count: config.allowedChats.length,
              is_first_conversation: config.allowedChats.length === 0
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
              const config = loadConfig();
              const filtered = filterList(data, config.allowedChats);
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
              const config = loadConfig();

              console.log('[Web Proxy] 项目列表 API 响应结构:', JSON.stringify(data).substring(0, 500));

              let filtered;
              if (shouldFilter(config.allowedProjects)) {
                // projects_v2 可能返回数组或带有 results/data 字段的对象
                if (Array.isArray(data)) {
                  filtered = data.filter((item: { uuid?: string }) =>
                    item.uuid && config.allowedProjects.includes(item.uuid)
                  );
                } else if (data && typeof data === 'object') {
                  // 可能是 { results: [...] } 或 { data: [...] } 格式
                  const arrayField = data.results || data.data || data.projects;
                  if (Array.isArray(arrayField)) {
                    const filteredArray = arrayField.filter((item: { uuid?: string }) =>
                      item.uuid && config.allowedProjects.includes(item.uuid)
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
          const chunks: Buffer[] = [];

          proxyRes.on('data', (chunk: Buffer) => chunks.push(chunk));
          proxyRes.on('end', () => {
            try {
              let html = Buffer.concat(chunks).toString('utf8');

              // 在 </head> 前注入脚本
              if (html.includes('</head>')) {
                html = html.replace('</head>', `${INJECT_SCRIPT}</head>`);
              }

              const responseBuffer = Buffer.from(html, 'utf8');

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
