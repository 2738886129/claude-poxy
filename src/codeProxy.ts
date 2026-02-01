import { createProxyMiddleware } from 'http-proxy-middleware';
import type { RequestHandler } from 'express';

const ANTHROPIC_API_URL = 'https://api.anthropic.com';

export function createCodeProxy(accessToken: string, pathPrefix: string = ''): RequestHandler {
  return createProxyMiddleware({
    target: ANTHROPIC_API_URL,
    changeOrigin: true,
    secure: true,

    on: {
      proxyReq: (proxyReq, req) => {
        // 修正路径：补回被 express 去掉的前缀
        if (pathPrefix && !proxyReq.path.startsWith(pathPrefix)) {
          proxyReq.path = pathPrefix + proxyReq.path;
        }

        // ===== 调试：打印所有请求信息 =====
        console.log('\n========== 请求详情 ==========');
        console.log(`[Method] ${req.method}`);
        console.log(`[Path] ${proxyReq.path}`);
        console.log('[Headers]');
        const headers = req.headers;
        for (const [key, value] of Object.entries(headers)) {
          // 隐藏敏感信息的部分内容
          if (key.toLowerCase().includes('auth') || key.toLowerCase().includes('key') || key.toLowerCase().includes('cookie')) {
            const val = String(value);
            console.log(`  ${key}: ${val.substring(0, 30)}...`);
          } else {
            console.log(`  ${key}: ${value}`);
          }
        }
        console.log('================================\n');

        // 移除客户端的 x-api-key，使用 OAuth Bearer Token
        proxyReq.removeHeader('x-api-key');
        proxyReq.setHeader('Authorization', `Bearer ${accessToken}`);

        // 设置正确的 Host
        proxyReq.setHeader('host', 'api.anthropic.com');

        // 移除可能暴露代理的头
        proxyReq.removeHeader('x-forwarded-host');
        proxyReq.removeHeader('x-forwarded-proto');

        console.log(`[Code Proxy] ${req.method} ${proxyReq.path}`);
      },

      proxyRes: (proxyRes) => {
        // 添加 CORS 头支持跨域
        proxyRes.headers['access-control-allow-origin'] = '*';
        proxyRes.headers['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
        proxyRes.headers['access-control-allow-headers'] = 'Content-Type, Authorization, x-api-key, anthropic-version';
      },

      error: (err, req, res) => {
        console.error('[Code Proxy] Error:', err.message);
        if ('writeHead' in res && typeof res.writeHead === 'function') {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Code Proxy Error', message: err.message }));
        }
      }
    }
  });
}
