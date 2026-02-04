import { createProxyMiddleware } from 'http-proxy-middleware';
import type { RequestHandler, Request } from 'express';
import type { ServerResponse } from 'http';
import { readFileSync, existsSync, writeFileSync } from 'fs';
import { join } from 'path';
import { getCache } from './staticCache.js';
import type { ApiKeyEntry } from './auth.js';
import https from 'https';

const CLAUDE_WEB_URL = 'https://claude.ai';

// 从原 webProxy.ts 导入必要的函数和配置
// 这里需要导出这些函数以便复用

// ==================== 优化策略 ====================
// 1. 创建两个代理实例：
//    - streamingProxy: 流式转发，不缓冲（默认路径）
//    - interceptingProxy: 拦截特定 API 进行过滤
// 2. 路由逻辑：
//    - 需要拦截的 API -> interceptingProxy
//    - 其他所有请求 -> streamingProxy
// 3. 性能提升：
//    - 大部分请求（静态资源、普通 API）直接流式转发
//    - 只有少数过滤 API 才缓冲处理
//    - 减少条件判断和内存使用
// ==================================================

// 需要拦截的 API 路径模式
const INTERCEPT_PATTERNS = [
  /\/api\/organizations\/[^/]+\/chat_conversations/,  // 聊天列表
  /\/api\/organizations\/[^/]+\/projects_v2/,         // 项目列表 v2
  /\/api\/organizations\/[^/]+\/projects\?/,          // 项目列表（带参数）
  /\/api\/organizations\/[^/]+\/conversation\/search/, // 搜索 API
  /\/api\/organizations\/[^/]+\/chat_conversations\/[^/]+\/name/, // 对话重命名 API (POST)
  /\/api\/organizations\/[^/]+\/projects\/[^/]+$/     // 项目详情/删除 (DELETE)
];

// 检查路径是否需要拦截
function shouldIntercept(url: string, method: string): boolean {
  // HTML 页面需要注入脚本，必须拦截
  if (!url.startsWith('/api/') && !url.startsWith('/_next/')) {
    // 可能是 HTML 页面
    return true;
  }

  // 检查是否匹配需要拦截的 API 模式
  return INTERCEPT_PATTERNS.some(pattern => pattern.test(url));
}

// 创建共享的 HTTPS Agent，启用 Keep-Alive
const httpsAgent = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 1000,
  maxSockets: 256,
  maxFreeSockets: 256,
  timeout: 120000,
  scheduling: 'lifo' // 后进先出，提高热连接复用
});

/**
 * 创建优化的 Web 代理
 * 使用双代理策略：流式转发 + 选择性拦截
 */
export function createOptimizedWebProxy(
  sessionKey: string,
  originalCreateWebProxy: (sessionKey: string) => RequestHandler
): RequestHandler {
  const cache = getCache();

  // 原有的拦截代理（处理需要过滤的 API 和 HTML 注入）
  const interceptingProxy = originalCreateWebProxy(sessionKey);

  // 新的流式代理（不缓冲，直接转发）
  const streamingProxy = createProxyMiddleware({
    target: CLAUDE_WEB_URL,
    changeOrigin: true,
    secure: true,
    selfHandleResponse: false, // 关键：不自己处理响应，让 http-proxy 流式转发
    agent: httpsAgent,         // 使用 Keep-Alive Agent
    proxyTimeout: 120000,
    timeout: 120000,

    on: {
      proxyReq: (proxyReq, req) => {
        // 添加保护：检查请求状态，避免在已发送头部后修改
        const isFinished = (proxyReq as any).finished;
        const isHeadersSent = (proxyReq as any).headersSent;

        if (isFinished || isHeadersSent) {
          console.warn(`[Streaming Proxy] Skipping header modification for ${req.url} (finished: ${isFinished}, headersSent: ${isHeadersSent})`);
          return;
        }

        try {
          // 设置超时
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

          // 修正 referer 和 origin
          const referer = proxyReq.getHeader('referer') as string;
          if (referer) {
            proxyReq.setHeader('referer', referer.replace(/^https?:\/\/[^/]+/, 'https://claude.ai'));
          }
          const origin = proxyReq.getHeader('origin') as string;
          if (origin && !origin.includes('claude.ai')) {
            proxyReq.setHeader('origin', 'https://claude.ai');
          }

          console.log(`[Streaming Proxy] ${req.method} ${req.url}`);
        } catch (err: any) {
          // 忽略 ERR_HTTP_HEADERS_SENT 错误，这在某些竞态条件下可能发生
          if (err.code === 'ERR_HTTP_HEADERS_SENT') {
            console.warn(`[Streaming Proxy] Headers already sent for ${req.url}, ignoring`);
            return;
          }
          console.error(`[Streaming Proxy] Error in proxyReq handler:`, err.message);
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
      },

      error: (err, _req, res) => {
        console.error('[Streaming Proxy] Error:', err.message);
        if ('writeHead' in res && typeof res.writeHead === 'function') {
          res.writeHead(502, { 'Content-Type': 'text/plain' });
          res.end('Streaming Proxy Error: ' + err.message);
        }
      }
    }
  });

  // 缓存中间件
  const cacheMiddleware: RequestHandler = (req, res, next) => {
    const url = req.url || '';
    const method = req.method || 'GET';

    // 只在流式代理路径检查缓存
    if (!shouldIntercept(url, method) && cache.isCacheable(url, method)) {
      const cached = cache.get(url);
      if (cached) {
        console.log(`[Cache] HIT: ${url}`);
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

  // 路由中间件：决定使用哪个代理
  return (req, res, next) => {
    const url = req.url || '';
    const method = req.method || 'GET';

    // 先检查缓存
    cacheMiddleware(req, res, () => {
      // 判断是否需要拦截
      if (shouldIntercept(url, method)) {
        console.log(`[Router] 拦截路由: ${method} ${url}`);
        interceptingProxy(req, res, next);
      } else {
        console.log(`[Router] 流式路由: ${method} ${url}`);
        streamingProxy(req, res, next);
      }
    });
  };
}
