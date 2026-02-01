import express from 'express';
import dotenv from 'dotenv';
import { existsSync, readFileSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { createWebProxy } from './webProxy.js';
import { createCliProxy, createTokenCountHandler } from './cliProxy.js';
import { getCache } from './staticCache.js';

// 读取配置文件
function loadConfig(): { allowedChats: string[]; allowedProjects: string[] } {
  const configPath = join(process.cwd(), 'config.json');
  if (existsSync(configPath)) {
    try {
      const content = readFileSync(configPath, 'utf-8');
      return JSON.parse(content);
    } catch {
      console.error('[Config] 读取配置文件失败');
    }
  }
  return { allowedChats: [], allowedProjects: [] };
}

// 加载环境变量
dotenv.config();

// 检查本机 claude 是否已登录
function checkClaudeLogin(): void {
  const defaultPath = join(homedir(), '.claude', '.credentials.json');
  const credentialsPath = process.env.CLAUDE_CREDENTIALS_PATH || defaultPath;

  if (!existsSync(credentialsPath)) {
    console.error('错误: 本机 Claude Code 未登录');
    console.error('请先运行 "claude" 命令登录 Claude Max 账号');
    process.exit(1);
  }
  console.log('✓ 检测到本机 Claude Code 已登录');
}

const PORT = parseInt(process.env.PORT || '3000', 10);
const SESSION_KEY = process.env.CLAUDE_SESSION_KEY;

// 检查登录状态
checkClaudeLogin();

const app = express();

// Web 代理必须在 express.json() 之前挂载
// 否则 POST 请求的 body 会被消费，导致代理无法正确转发
if (SESSION_KEY) {
  // 创建一次代理实例并复用，避免内存泄漏警告
  const webProxy = createWebProxy(SESSION_KEY);

  // 排除 CLI API 路径和内部路径
  app.use((req, res, next) => {
    const path = req.path;
    // 这些路径需要 express.json() 处理，跳过 Web 代理
    if (path.startsWith('/v1/') || path.startsWith('/__proxy__/')) {
      return next();
    }
    // 其他路径走 Web 代理
    return webProxy(req, res, next);
  });
}

// 提供自定义注入脚本
app.get('/__proxy__/inject.js', (_req, res) => {
  res.type('application/javascript').send(`
    (function() {
      // 项目和聊天过滤已移到 API 层，此脚本只负责隐藏 UI 元素

      // 使用 CSS 注入
      const style = document.createElement('style');
      style.id = 'proxy-hide-styles';
      style.textContent = \`
        /* 隐藏用户菜单按钮 */
        [data-testid="user-menu-button"],
        [data-testid="user-menu-button"]:parent {
          display: none !important;
        }
        /* 隐藏用户菜单容器 */
        .border-t-0\\.5.border-border-300 {
          display: none !important;
        }
        /* 隐藏 Artifacts 导航项 */
        a[href="/artifacts"],
        a[href="/artifacts"]:parent {
          display: none !important;
        }
        .relative.group:has(a[href="/artifacts"]) {
          display: none !important;
        }
        /* 隐藏 Code 导航项 */
        a[href="/code"],
        a[href="/code"]:parent {
          display: none !important;
        }
        .relative.group:has(a[href="/code"]) {
          display: none !important;
        }
      \`;

      if (!document.getElementById('proxy-hide-styles')) {
        document.head.appendChild(style);
      }

      function hideElements() {
        // 隐藏用户菜单按钮的容器
        const userMenuBtn = document.querySelector('[data-testid="user-menu-button"]');
        if (userMenuBtn) {
          const container = userMenuBtn.closest('.flex.items-center.gap-2');
          if (container && container.style.display !== 'none') {
            container.style.display = 'none';
          }
        }

        // 隐藏 Artifacts 导航项
        const artifactsLink = document.querySelector('a[href="/artifacts"]');
        if (artifactsLink) {
          const container = artifactsLink.closest('.relative.group');
          if (container && container.style.display !== 'none') {
            container.style.display = 'none';
          }
        }

        // 隐藏 Code 导航项
        const codeLink = document.querySelector('a[href="/code"]');
        if (codeLink) {
          const container = codeLink.closest('.relative.group');
          if (container && container.style.display !== 'none') {
            container.style.display = 'none';
          }
        }
        // 项目过滤已移到 API 层 (projects_v2)，不需要前端过滤
      }

      // 立即执行
      hideElements();

      // 监听 DOM 变化
      const observer = new MutationObserver(() => {
        hideElements();
      });

      // 确保 document.documentElement 存在
      if (document.documentElement) {
        observer.observe(document.documentElement, {
          childList: true,
          subtree: true,
          attributes: false,
          characterData: false
        });
      }

      // 监听路由变化（等待 body 存在）
      let lastUrl = location.href;
      function setupUrlObserver() {
        if (document.body) {
          const urlObserver = new MutationObserver(() => {
            if (location.href !== lastUrl) {
              lastUrl = location.href;
              setTimeout(hideElements, 100);
              setTimeout(hideElements, 500);
            }
          });
          urlObserver.observe(document.body, { childList: true, subtree: true });
        } else {
          // body 还不存在，稍后重试
          setTimeout(setupUrlObserver, 50);
        }
      }
      setupUrlObserver();

      // 定时检查
      setInterval(hideElements, 1000);
    })();
  `);
});

// 解析 JSON body
app.use(express.json({ limit: '50mb' }));

// 缓存统计接口
app.get('/__proxy__/cache/stats', (_req, res) => {
  const cache = getCache();
  const stats = cache.getStats();
  res.json({
    enabled: true,
    count: stats.count,
    sizeMB: stats.sizeMB.toFixed(2),
    maxSizeMB: stats.maxSizeMB,
    usagePercent: ((stats.sizeMB / stats.maxSizeMB) * 100).toFixed(1),
  });
});

// 清空缓存接口
app.post('/__proxy__/cache/clear', (_req, res) => {
  const cache = getCache();
  cache.clear();
  res.json({ success: true, message: '缓存已清空' });
});

// Claude Code API 代理 - 通过本机 CLI 处理
// /v1/messages - 主要的聊天接口
app.post('/v1/messages', createCliProxy());

// /v1/messages/count_tokens - token 计数（返回假数据）
app.post('/v1/messages/count_tokens', createTokenCountHandler());

// 启动服务器
app.listen(PORT, '0.0.0.0', () => {
  const cache = getCache();
  const stats = cache.getStats();

  console.log('========================================');
  console.log('  Claude Max 反向代理已启动');
  console.log('========================================');
  console.log(`  本地访问: http://localhost:${PORT}`);
  console.log(`  局域网访问: http://<你的IP>:${PORT}`);
  console.log('');
  console.log('  Claude Code 代理: /v1/messages -> 本机 claude CLI');
  if (SESSION_KEY) {
    console.log('  Web 代理: /* -> claude.ai');
  }
  console.log('');
  console.log(`  静态资源缓存: ${stats.count} 个文件, ${stats.sizeMB.toFixed(2)} MB`);
  console.log(`  缓存管理: GET /__proxy__/cache/stats`);
  console.log(`            POST /__proxy__/cache/clear`);
  console.log('========================================');
});
