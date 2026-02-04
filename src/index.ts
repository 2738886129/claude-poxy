import express from 'express';
import dotenv from 'dotenv';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { createWebProxy, FINGERPRINT } from './webProxy.js';
import { createOptimizedWebProxy } from './webProxy.optimized.js';
import { getCache } from './staticCache.js';
import {
  createAuthMiddleware,
  validateApiKey,
  getLoginPageHtml,
  isAuthEnabled,
  getKeyExpiresMs
} from './auth.js';
import { startAdminServer } from './adminServer.js';

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

const PORT = parseInt(process.env.PORT || '3000', 10);
const SESSION_KEY = process.env.CLAUDE_SESSION_KEY;

const app = express();

// ===== 认证相关路由（必须在代理之前） =====

// 登录页面
app.get('/__proxy__/login', (req, res) => {
  const error = req.query.error as string | undefined;
  res.type('html').send(getLoginPageHtml(error));
});

// 处理登录表单提交
app.use('/__proxy__/login', express.urlencoded({ extended: false }));
app.post('/__proxy__/login', (req, res) => {
  const apiKey = req.body.api_key;

  if (!apiKey) {
    return res.redirect('/__proxy__/login?error=invalid');
  }

  const keyEntry = validateApiKey(apiKey);
  if (!keyEntry) {
    return res.redirect('/__proxy__/login?error=invalid');
  }

  // 设置 Cookie，使用 Key 配置的有效期
  const maxAge = getKeyExpiresMs(keyEntry);
  res.cookie('proxy_key', apiKey, {
    maxAge,
    httpOnly: true,
    sameSite: 'lax'
  });

  const days = keyEntry.expiresInDays || 7;
  console.log(`[Auth] 用户登录成功: ${keyEntry.name}, Cookie 有效期: ${days} 天`);
  res.redirect('/');
});

// 登出
app.get('/__proxy__/logout', (_req, res) => {
  res.clearCookie('proxy_key');
  res.redirect('/__proxy__/login');
});

// Web 代理必须在 express.json() 之前挂载
// 否则 POST 请求的 body 会被消费，导致代理无法正确转发
if (SESSION_KEY) {
  // 创建一次代理实例并复用，避免内存泄漏警告
  // 使用优化版本的代理（双代理策略：流式转发 + 选择性拦截）
  const webProxy = createOptimizedWebProxy(SESSION_KEY, createWebProxy);
  const authMiddleware = createAuthMiddleware();

  // 排除 CLI API 路径和内部路径
  app.use((req, res, next) => {
    const path = req.path;
    // 这些路径需要 express.json() 处理，跳过 Web 代理
    if (path.startsWith('/v1/') || path.startsWith('/__proxy__/')) {
      return next();
    }

    // 拦截第三方服务请求（Sentry 错误上报、Intercom 客服等）
    // 这些服务对 Claude 核心功能无影响，拦截可减少控制台噪音
    const blockedDomains = [
      'sentry.io',           // Sentry 错误追踪
      'api-iam.intercom.io', // Intercom 客服聊天
      'intercom.io'          // Intercom 相关
    ];

    const referer = req.get('referer') || '';
    const host = req.get('host') || '';

    // 检查是否是到被阻止域名的请求
    if (blockedDomains.some(domain =>
        referer.includes(domain) ||
        host.includes(domain) ||
        path.includes(domain)
    )) {
      // 返回空响应，避免控制台错误
      return res.status(204).end();
    }

    // 先验证认证，再走 Web 代理
    authMiddleware(req, res, (err?: any) => {
      if (err) return next(err);
      return webProxy(req, res, next);
    });
  });
}

// Anthropic API 通用代理 - 解决 CORS 问题
// 前端需要访问 api.anthropic.com 的各种 API，但会遇到 CORS 限制
// 通过代理服务器转发这些请求（支持 MCP Registry、模型配置等）
import https from 'https';

// 创建通用的 API 代理处理函数
function createAnthropicApiProxy() {
  return (req: express.Request, res: express.Response) => {
    const path = req.path;
    const queryString = Object.keys(req.query).length > 0
      ? '?' + new URLSearchParams(req.query as Record<string, string>).toString()
      : '';
    const fullPath = `${path}${queryString}`;

    console.log(`[Anthropic API Proxy] 转发请求: https://api.anthropic.com${fullPath}`);

    const options = {
      hostname: 'api.anthropic.com',
      path: fullPath,
      method: req.method,
      headers: {
        'User-Agent': 'Claude-Proxy/1.0',
        'Accept': 'application/json',
        'Content-Type': req.headers['content-type'] || 'application/json',
      }
    };

    const proxyReq = https.request(options, (proxyRes) => {
      // 设置 CORS 头，允许前端访问
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Content-Type', proxyRes.headers['content-type'] || 'application/json');

      res.status(proxyRes.statusCode || 200);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
      console.error('[Anthropic API Proxy] 错误:', err.message);
      res.status(500).json({ error: 'Anthropic API proxy error', message: err.message });
    });

    // 如果有请求体，转发它
    if (req.body && Object.keys(req.body).length > 0) {
      proxyReq.write(JSON.stringify(req.body));
    }

    proxyReq.end();
  };
}

// MCP Registry API 代理
app.get('/mcp-registry/*', createAnthropicApiProxy());

// 其他可能的 Anthropic API 端点
app.all('/v1/*', createAnthropicApiProxy());

// OPTIONS 预检请求（支持所有可能的 API 路径）
app.options(['/mcp-registry/*', '/v1/*'], (_req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.status(204).end();
});

// 提供自定义注入脚本
app.get('/__proxy__/inject.js', (_req, res) => {
  // 禁用缓存，确保每次都获取最新脚本
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.type('application/javascript').send(`
    (function() {
      // ========== 修复 crypto.randomUUID 缺失问题 ==========
      // HTTP 环境下 crypto.randomUUID 不可用，提供 polyfill
      if (!crypto.randomUUID) {
        console.log('[Proxy] 注入 crypto.randomUUID polyfill');
        crypto.randomUUID = function() {
          return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
            (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
          );
        };
      }

      // ========== 浏览器指纹伪装（调试模式：暂时禁用） ==========
      // 如果遇到 Claude 阻止访问，可以临时注释掉指纹伪装，只保留 UI 隐藏
      const ENABLE_FINGERPRINT_SPOOFING = true; // 设为 false 禁用指纹伪装

      if (ENABLE_FINGERPRINT_SPOOFING) {
      // ========== 浏览器指纹伪装 ==========
      // 伪装的浏览器信息 - 从服务端配置动态加载
      const SPOOFED = ${JSON.stringify({
        userAgent: FINGERPRINT.userAgent,
        platform: FINGERPRINT.platform,
        language: FINGERPRINT.language,
        languages: FINGERPRINT.languages,
        hardwareConcurrency: FINGERPRINT.hardwareConcurrency,
        deviceMemory: FINGERPRINT.deviceMemory,
        maxTouchPoints: FINGERPRINT.maxTouchPoints,
        vendor: FINGERPRINT.vendor,
        appVersion: FINGERPRINT.appVersion,
        screenWidth: FINGERPRINT.screen.width,
        screenHeight: FINGERPRINT.screen.height,
        screenColorDepth: FINGERPRINT.screen.colorDepth,
        screenPixelDepth: FINGERPRINT.screen.pixelDepth,
        timezoneOffset: FINGERPRINT.timezoneOffset,
        timezone: FINGERPRINT.timezone
      })};

      // 保存原始的 clipboard API（修复剪贴板功能）
      const originalClipboard = navigator.clipboard;

      // 伪装 navigator 属性
      const navigatorProps = {
        userAgent: { get: () => SPOOFED.userAgent },
        platform: { get: () => SPOOFED.platform },
        language: { get: () => SPOOFED.language },
        languages: { get: () => Object.freeze([...SPOOFED.languages]) },
        hardwareConcurrency: { get: () => SPOOFED.hardwareConcurrency },
        deviceMemory: { get: () => SPOOFED.deviceMemory },
        maxTouchPoints: { get: () => SPOOFED.maxTouchPoints },
        vendor: { get: () => SPOOFED.vendor },
        appVersion: { get: () => SPOOFED.appVersion },
        webdriver: { get: () => false }
      };

      for (const [prop, descriptor] of Object.entries(navigatorProps)) {
        try {
          Object.defineProperty(navigator, prop, { ...descriptor, configurable: true });
        } catch (e) {}
      }

      // 恢复 clipboard API（确保剪贴板功能正常工作）
      if (originalClipboard) {
        try {
          Object.defineProperty(navigator, 'clipboard', {
            get: () => originalClipboard,
            configurable: true
          });
        } catch (e) {
          console.warn('[Proxy] 无法恢复 clipboard API:', e);
        }
      }

      // 伪装 screen 属性
      const screenProps = {
        width: { get: () => SPOOFED.screenWidth },
        height: { get: () => SPOOFED.screenHeight },
        availWidth: { get: () => SPOOFED.screenWidth },
        availHeight: { get: () => SPOOFED.screenHeight - 40 },
        colorDepth: { get: () => SPOOFED.screenColorDepth },
        pixelDepth: { get: () => SPOOFED.screenPixelDepth }
      };

      for (const [prop, descriptor] of Object.entries(screenProps)) {
        try {
          Object.defineProperty(screen, prop, { ...descriptor, configurable: true });
        } catch (e) {}
      }

      // 伪装 screen.orientation
      try {
        Object.defineProperty(screen, 'orientation', {
          get: () => ({
            type: 'landscape-primary',
            angle: 0,
            addEventListener: () => {},
            removeEventListener: () => {},
            dispatchEvent: () => true,
            lock: () => Promise.resolve(),
            unlock: () => {}
          }),
          configurable: true
        });
      } catch (e) {}

      // 伪装 window.matchMedia
      try {
        const originalMatchMedia = window.matchMedia;
        window.matchMedia = function(query) {
          const result = originalMatchMedia.call(window, query);
          // 对于可能泄露信息的查询，返回统一值
          if (query.includes('prefers-color-scheme')) {
            return {
              matches: false, // 假装不是暗色模式
              media: query,
              addEventListener: result.addEventListener.bind(result),
              removeEventListener: result.removeEventListener.bind(result),
              addListener: result.addListener ? result.addListener.bind(result) : () => {},
              removeListener: result.removeListener ? result.removeListener.bind(result) : () => {},
              dispatchEvent: result.dispatchEvent.bind(result),
              onchange: null
            };
          }
          if (query.includes('prefers-reduced-motion')) {
            return {
              matches: false,
              media: query,
              addEventListener: result.addEventListener.bind(result),
              removeEventListener: result.removeEventListener.bind(result),
              addListener: result.addListener ? result.addListener.bind(result) : () => {},
              removeListener: result.removeListener ? result.removeListener.bind(result) : () => {},
              dispatchEvent: result.dispatchEvent.bind(result),
              onchange: null
            };
          }
          return result;
        };
      } catch (e) {}

      // 伪装时区
      const originalDateTimeFormat = Intl.DateTimeFormat;
      Intl.DateTimeFormat = function(...args) {
        const instance = new originalDateTimeFormat(...args);
        const originalResolvedOptions = instance.resolvedOptions.bind(instance);
        instance.resolvedOptions = function() {
          const options = originalResolvedOptions();
          options.timeZone = SPOOFED.timezone;
          return options;
        };
        return instance;
      };
      // 关键：保留原型和静态方法
      Intl.DateTimeFormat.prototype = originalDateTimeFormat.prototype;
      Intl.DateTimeFormat.supportedLocalesOf = originalDateTimeFormat.supportedLocalesOf;
      // 复制所有其他静态属性
      Object.keys(originalDateTimeFormat).forEach(key => {
        if (key !== 'prototype' && key !== 'supportedLocalesOf') {
          try {
            Intl.DateTimeFormat[key] = originalDateTimeFormat[key];
          } catch (e) {}
        }
      });

      Date.prototype.getTimezoneOffset = function() {
        return SPOOFED.timezoneOffset;
      };

      // 伪装 window 尺寸 (与 screen 保持一致)
      try {
        Object.defineProperty(window, 'innerWidth', { get: () => SPOOFED.screenWidth, configurable: true });
        Object.defineProperty(window, 'innerHeight', { get: () => SPOOFED.screenHeight - 100, configurable: true });
        Object.defineProperty(window, 'outerWidth', { get: () => SPOOFED.screenWidth, configurable: true });
        Object.defineProperty(window, 'outerHeight', { get: () => SPOOFED.screenHeight, configurable: true });
        Object.defineProperty(window, 'devicePixelRatio', { get: () => 1, configurable: true });
        // documentElement 可能还不存在，延迟处理
        if (document.documentElement) {
          Object.defineProperty(document.documentElement, 'clientWidth', { get: () => SPOOFED.screenWidth, configurable: true });
          Object.defineProperty(document.documentElement, 'clientHeight', { get: () => SPOOFED.screenHeight - 100, configurable: true });
        }
      } catch (e) {}

      // 伪装 navigator.doNotTrack
      try {
        Object.defineProperty(navigator, 'doNotTrack', { get: () => '1', configurable: true });
      } catch (e) {}

      // 伪装 navigator.userAgentData (User-Agent Client Hints API)
      try {
        const spoofedUserAgentData = {
          brands: [
            { brand: 'Not_A Brand', version: '8' },
            { brand: 'Chromium', version: '120' },
            { brand: 'Google Chrome', version: '120' }
          ],
          mobile: false,
          platform: 'Windows',
          getHighEntropyValues: (hints) => Promise.resolve({
            brands: spoofedUserAgentData.brands,
            mobile: false,
            platform: 'Windows',
            platformVersion: '10.0.0',
            architecture: 'x86',
            bitness: '64',
            model: '',
            uaFullVersion: '120.0.0.0',
            fullVersionList: spoofedUserAgentData.brands.map(b => ({ ...b }))
          })
        };
        Object.defineProperty(navigator, 'userAgentData', {
          get: () => spoofedUserAgentData,
          configurable: true
        });
      } catch (e) {}

      // 伪装 WebGL 指纹 (必须在 Canvas 之前定义，因为 Canvas 会引用)
      // 从服务端配置动态加载
      const SPOOFED_WEBGL = ${JSON.stringify(FINGERPRINT.webgl)};

      // 保存原始 getContext (Canvas 伪装需要引用)
      const originalGetContext = HTMLCanvasElement.prototype.getContext;

      // 伪装 Canvas 指纹 - 使用噪点注入而非修改原始数据
      const canvasNoiseSeed = 12345;
      const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
      const originalToBlob = HTMLCanvasElement.prototype.toBlob;

      HTMLCanvasElement.prototype.toDataURL = function(type, quality) {
        // 只对指纹检测用的小 canvas 添加噪点，且只处理 2d canvas
        if (this.width <= 300 && this.height <= 150) {
          try {
            const existingContext = this.__existingContextType__;
            if (!existingContext || existingContext === '2d') {
              const ctx = originalGetContext.call(this, '2d');
              if (ctx) {
                const imageData = ctx.getImageData(0, 0, this.width, this.height);
                for (let i = 0; i < Math.min(10, imageData.data.length); i += 4) {
                  imageData.data[i] = (imageData.data[i] + canvasNoiseSeed % 3) % 256;
                }
                ctx.putImageData(imageData, 0, 0);
              }
            }
          } catch (e) {}
        }
        return originalToDataURL.call(this, type, quality);
      };

      // 伪装 toBlob (另一种 Canvas 指纹收集方式)
      HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {
        if (this.width <= 300 && this.height <= 150) {
          try {
            const existingContext = this.__existingContextType__;
            if (!existingContext || existingContext === '2d') {
              const ctx = originalGetContext.call(this, '2d');
              if (ctx) {
                const imageData = ctx.getImageData(0, 0, this.width, this.height);
                for (let i = 0; i < Math.min(10, imageData.data.length); i += 4) {
                  imageData.data[i] = (imageData.data[i] + canvasNoiseSeed % 3) % 256;
                }
                ctx.putImageData(imageData, 0, 0);
              }
            }
          } catch (e) {}
        }
        return originalToBlob.call(this, callback, type, quality);
      };

      // 伪装 getContext
      HTMLCanvasElement.prototype.getContext = function(type, attributes) {
        const context = originalGetContext.call(this, type, attributes);
        // 记录 context 类型，避免冲突
        this.__existingContextType__ = type;

        if (context && (type === 'webgl' || type === 'webgl2' || type === 'experimental-webgl')) {
          // 伪装 getParameter
          const originalGetParameter = context.getParameter.bind(context);
          context.getParameter = function(param) {
            if (param === 37445) return SPOOFED_WEBGL.vendor;
            if (param === 37446) return SPOOFED_WEBGL.renderer;
            return originalGetParameter(param);
          };

          // 伪装 getSupportedExtensions
          context.getSupportedExtensions = function() {
            return [...SPOOFED_WEBGL.extensions];
          };

          // 伪装 getExtension
          const originalGetExtension = context.getExtension.bind(context);
          context.getExtension = function(name) {
            if (name === 'WEBGL_debug_renderer_info') {
              return { UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446 };
            }
            return originalGetExtension(name);
          };
        }
        return context;
      };

      // 伪装 AudioContext 指纹
      if (window.AudioContext || window.webkitAudioContext) {
        const OriginalAudioContext = window.AudioContext || window.webkitAudioContext;
        window.AudioContext = window.webkitAudioContext = function(...args) {
          const context = new OriginalAudioContext(...args);
          const originalCreateOscillator = context.createOscillator.bind(context);
          context.createOscillator = function() {
            const oscillator = originalCreateOscillator();
            const originalFrequency = oscillator.frequency;
            Object.defineProperty(oscillator, 'frequency', {
              get: () => originalFrequency,
              configurable: true
            });
            return oscillator;
          };
          return context;
        };
      }

      // 伪装 ClientRects 指纹 - 使用更保守的策略,避免影响 React
      const originalGetBoundingClientRect = Element.prototype.getBoundingClientRect;
      Element.prototype.getBoundingClientRect = function() {
        const rect = originalGetBoundingClientRect.call(this);
        // 只对非常小的元素(可能用于指纹)进行舍入,避免影响正常布局
        if (rect.width < 50 && rect.height < 50) {
          const roundedRect = {
            x: Math.round(rect.x),
            y: Math.round(rect.y),
            width: Math.round(rect.width),
            height: Math.round(rect.height),
            top: Math.round(rect.top),
            right: Math.round(rect.right),
            bottom: Math.round(rect.bottom),
            left: Math.round(rect.left),
            toJSON: function() {
              return { x: this.x, y: this.y, width: this.width, height: this.height,
                       top: this.top, right: this.right, bottom: this.bottom, left: this.left };
            }
          };
          try {
            Object.setPrototypeOf(roundedRect, DOMRect.prototype);
          } catch (e) {}
          return roundedRect;
        }
        // 正常大小的元素返回原始值,不影响 React
        return rect;
      };

      // 伪装 Plugins 和 MimeTypes
      try {
        const createPluginArray = () => {
          const arr = [];
          Object.defineProperty(arr, 'length', { value: 0, writable: false });
          arr.item = (index) => null;
          arr.namedItem = (name) => null;
          arr.refresh = () => {};
          return arr;
        };

        const createMimeTypeArray = () => {
          const arr = [];
          Object.defineProperty(arr, 'length', { value: 0, writable: false });
          arr.item = (index) => null;
          arr.namedItem = (name) => null;
          return arr;
        };

        Object.defineProperty(navigator, 'plugins', {
          get: createPluginArray,
          configurable: true
        });

        Object.defineProperty(navigator, 'mimeTypes', {
          get: createMimeTypeArray,
          configurable: true
        });

        // 伪装 navigator.pdfViewerEnabled (Chrome 120+)
        Object.defineProperty(navigator, 'pdfViewerEnabled', {
          get: () => true,
          configurable: true
        });
      } catch (e) {}

      // 隐藏自动化检测标志 (保留 window.chrome，因为真实 Chrome 有这个对象)
      try {
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
        // 如果不存在 window.chrome，伪装一个基本的
        if (!window.chrome) {
          window.chrome = { runtime: {} };
        }
      } catch (e) {}

      // 伪装 navigator.connection (网络信息 API)
      try {
        Object.defineProperty(navigator, 'connection', {
          get: () => ({
            effectiveType: '4g',
            rtt: 50,
            downlink: 10,
            saveData: false
          }),
          configurable: true
        });
      } catch (e) {}

      // 伪装 navigator.getBattery (电池 API)
      try {
        navigator.getBattery = () => Promise.resolve({
          charging: true,
          chargingTime: 0,
          dischargingTime: Infinity,
          level: 1,
          addEventListener: () => {},
          removeEventListener: () => {}
        });
      } catch (e) {}

      // 伪装 Performance API
      try {
        // 降低时间精度，防止时序攻击指纹
        const originalNow = Performance.prototype.now;
        Performance.prototype.now = function() {
          return Math.round(originalNow.call(this) * 10) / 10; // 精度降到 0.1ms
        };

        // 伪装 performance.memory (仅 Chrome)
        if (performance.memory) {
          Object.defineProperty(performance, 'memory', {
            get: () => ({
              jsHeapSizeLimit: 2172649472,
              totalJSHeapSize: 50000000,
              usedJSHeapSize: 40000000
            }),
            configurable: true
          });
        }
      } catch (e) {}

      // 伪装 navigator.mediaDevices (防止枚举摄像头/麦克风)
      try {
        if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
          navigator.mediaDevices.enumerateDevices = () => Promise.resolve([]);
        }
      } catch (e) {}

      // 伪装 speechSynthesis.getVoices (语音合成指纹)
      try {
        if (window.speechSynthesis) {
          window.speechSynthesis.getVoices = () => [];
        }
      } catch (e) {}

      // 伪装 OffscreenCanvas (如果存在)
      try {
        if (typeof OffscreenCanvas !== 'undefined') {
          const originalOffscreenGetContext = OffscreenCanvas.prototype.getContext;
          OffscreenCanvas.prototype.getContext = function(type, attributes) {
            const context = originalOffscreenGetContext.call(this, type, attributes);
            if (context && (type === 'webgl' || type === 'webgl2')) {
              const origGetParam = context.getParameter.bind(context);
              context.getParameter = function(param) {
                if (param === 37445) return SPOOFED_WEBGL.vendor;
                if (param === 37446) return SPOOFED_WEBGL.renderer;
                return origGetParam(param);
              };
            }
            return context;
          };
        }
      } catch (e) {}

      // 伪装字体检测 - 使用更严格的条件,避免影响 React
      try {
        const originalOffsetWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth');
        const originalOffsetHeight = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetHeight');

        if (originalOffsetWidth && originalOffsetHeight) {
          // 只对明显用于指纹检测的隐藏小元素标准化尺寸
          Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
            get: function() {
              const width = originalOffsetWidth.get.call(this);
              // 更严格的条件:必须是绝对定位且完全隐藏的超小元素
              if (this.style && this.style.position === 'absolute' &&
                  (this.style.left === '-9999px' || this.style.visibility === 'hidden') &&
                  width < 100) {
                return Math.round(width / 10) * 10;
              }
              return width;
            },
            configurable: true
          });

          Object.defineProperty(HTMLElement.prototype, 'offsetHeight', {
            get: function() {
              const height = originalOffsetHeight.get.call(this);
              if (this.style && this.style.position === 'absolute' &&
                  (this.style.left === '-9999px' || this.style.visibility === 'hidden') &&
                  height < 100) {
                return Math.round(height / 10) * 10;
              }
              return height;
            },
            configurable: true
          });
        }
      } catch (e) {}

      } // 结束 if (ENABLE_FINGERPRINT_SPOOFING)

      // ========== 拦截第三方服务请求 ==========
      // 拦截 Sentry、Intercom 等第三方服务，减少控制台噪音
      (function() {
        const blockedDomains = [
          'sentry.io',
          'intercom.io',
          'intercom.com',
          'api-iam.intercom.io',
          'widget.intercom.io'
        ];

        const blockedPaths = [
          '/sentry?',  // Sentry 错误上报路径
          '/sentry/'
        ];

        const isBlocked = (url) => {
          if (!url) return false;
          const urlStr = typeof url === 'string' ? url : url.toString();

          // 检查域名
          if (blockedDomains.some(domain => urlStr.includes(domain))) {
            return true;
          }

          // 检查路径（用于代理内的 Sentry 请求）
          if (blockedPaths.some(path => urlStr.includes(path))) {
            return true;
          }

          return false;
        };

        // 拦截 fetch 请求
        try {
          const originalFetch = window.fetch;
          window.fetch = function(input, init) {
            const url = typeof input === 'string' ? input : (input instanceof Request ? input.url : '');

            // 拦截被阻止的第三方服务
            if (isBlocked(url)) {
              console.log('[Proxy] 拦截第三方请求:', url);
              // 返回一个空的成功响应
              return Promise.resolve(new Response('{}', {
                status: 200,
                statusText: 'OK',
                headers: new Headers({ 'Content-Type': 'application/json' })
              }));
            }

            // 重定向 api.anthropic.com 请求到本地代理
            if (url && url.includes('api.anthropic.com')) {
              // 提取路径和查询参数
              const apiUrl = new URL(url);
              const proxyPath = apiUrl.pathname + apiUrl.search;
              console.log('[Proxy] 重定向 API 请求到本地代理:', proxyPath);

              // 重定向到本地代理路由
              const newUrl = window.location.origin + proxyPath;
              const newInput = typeof input === 'string' ? newUrl : new Request(newUrl, input);
              return originalFetch.call(this, newInput, init);
            }

            return originalFetch.apply(this, arguments);
          };
        } catch (e) {
          console.error('[Proxy] fetch 拦截失败:', e);
        }

        // 拦截 XMLHttpRequest
        try {
          const originalOpen = XMLHttpRequest.prototype.open;
          const originalSend = XMLHttpRequest.prototype.send;

          XMLHttpRequest.prototype.open = function(method, url, ...rest) {
            this._isBlocked = isBlocked(url);
            if (this._isBlocked) {
              console.log('[Proxy] 拦截 XHR 请求:', url);
            }
            return originalOpen.apply(this, [method, url, ...rest]);
          };

          XMLHttpRequest.prototype.send = function(body) {
            if (this._isBlocked) {
              // 模拟成功响应
              Object.defineProperty(this, 'readyState', { writable: true, value: 4 });
              Object.defineProperty(this, 'status', { writable: true, value: 200 });
              Object.defineProperty(this, 'statusText', { writable: true, value: 'OK' });
              Object.defineProperty(this, 'responseText', { writable: true, value: '{}' });
              Object.defineProperty(this, 'response', { writable: true, value: '{}' });

              setTimeout(() => {
                if (this.onload) this.onload({ target: this });
                if (this.onreadystatechange) this.onreadystatechange({ target: this });
              }, 0);
              return;
            }
            return originalSend.apply(this, arguments);
          };
        } catch (e) {
          console.error('[Proxy] XHR 拦截失败:', e);
        }

        // 拦截动态脚本加载
        try {
          const originalCreateElement = document.createElement;
          document.createElement = function(tagName) {
            const element = originalCreateElement.apply(this, arguments);

            if (tagName && typeof tagName === 'string' && tagName.toLowerCase() === 'script') {
              const originalSetAttribute = element.setAttribute;
              element.setAttribute = function(name, value) {
                if (name === 'src' && isBlocked(value)) {
                  console.log('[Proxy] 拦截脚本加载:', value);
                  return; // 不设置 src，阻止加载
                }
                return originalSetAttribute.apply(this, arguments);
              };

              const srcDescriptor = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
              if (srcDescriptor && srcDescriptor.set) {
                Object.defineProperty(element, 'src', {
                  set: function(value) {
                    if (isBlocked(value)) {
                      console.log('[Proxy] 拦截脚本 src:', value);
                      return;
                    }
                    srcDescriptor.set.call(this, value);
                  },
                  get: srcDescriptor.get
                });
              }
            }

            return element;
          };
        } catch (e) {
          console.error('[Proxy] 脚本拦截失败:', e);
        }
      })();

      // ========== UI 元素隐藏（仅非管理员） ==========
      // 检查是否为管理员，管理员跳过UI隐藏
      const isAdmin = window.__PROXY_IS_ADMIN__ === true;
      if (isAdmin) {
        console.log('[Proxy] 管理员模式，跳过UI隐藏');
      } else {
      // 普通用户执行UI隐藏
      function injectStyles() {
        if (document.getElementById('proxy-hide-styles')) return;

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

        // 优先插入到 head，如果 head 不存在则插入到 documentElement
        const target = document.head || document.documentElement;
        if (target) {
          target.appendChild(style);
        } else {
          // 如果都不存在，等待 DOM 准备好
          document.addEventListener('DOMContentLoaded', () => {
            (document.head || document.documentElement).appendChild(style);
          });
        }
      }
      injectStyles();

      function hideElements() {
        const userMenuBtn = document.querySelector('[data-testid="user-menu-button"]');
        if (userMenuBtn) {
          const container = userMenuBtn.closest('.flex.items-center.gap-2');
          if (container && container.style.display !== 'none') {
            container.style.display = 'none';
          }
        }

        const artifactsLink = document.querySelector('a[href="/artifacts"]');
        if (artifactsLink) {
          const container = artifactsLink.closest('.relative.group');
          if (container && container.style.display !== 'none') {
            container.style.display = 'none';
          }
        }

        const codeLink = document.querySelector('a[href="/code"]');
        if (codeLink) {
          const container = codeLink.closest('.relative.group');
          if (container && container.style.display !== 'none') {
            container.style.display = 'none';
          }
        }
      }

      hideElements();

      const observer = new MutationObserver(() => {
        hideElements();
      });

      if (document.documentElement) {
        observer.observe(document.documentElement, {
          childList: true,
          subtree: true,
          attributes: false,
          characterData: false
        });
      }

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
          setTimeout(setupUrlObserver, 50);
        }
      }
      setupUrlObserver();

      setInterval(hideElements, 1000);
      } // 结束非管理员UI隐藏代码块
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

// 启动服务器
const mainServer = app.listen(PORT, '0.0.0.0', () => {
  const cache = getCache();
  const stats = cache.getStats();

  console.log('========================================');
  console.log('  Claude Max 反向代理已启动');
  console.log('========================================');
  console.log(`  本地访问: http://localhost:${PORT}`);
  console.log(`  局域网访问: http://<你的IP>:${PORT}`);
  console.log('');
  if (SESSION_KEY) {
    console.log('  Web 代理: /* -> claude.ai');
  }
  console.log('');
  console.log(`  静态资源缓存: ${stats.count} 个文件, ${stats.sizeMB.toFixed(2)} MB`);
  console.log(`  缓存管理: GET /__proxy__/cache/stats`);
  console.log(`            POST /__proxy__/cache/clear`);
  console.log('');
  if (isAuthEnabled()) {
    console.log('  认证: 已启用 (需要 API Key)');
    console.log('  管理: npm run auth list');
  } else {
    console.log('  认证: 未启用');
    console.log('  启用: npm run auth create "名称"');
  }
  console.log('========================================');
});

// 启动管理员服务器（独立端口，仅本地访问）
const adminServer = startAdminServer();

// 优雅关闭：处理进程退出信号
let isShuttingDown = false;

function gracefulShutdown(signal: string) {
  if (isShuttingDown) {
    console.log('[Server] 已在关闭中，请稍候...');
    return;
  }
  isShuttingDown = true;

  console.log(`\n[Server] 收到 ${signal} 信号，正在关闭服务...`);

  let mainClosed = false;
  let adminClosed = false;

  const checkAndExit = () => {
    if (mainClosed && adminClosed) {
      console.log('[Server] 所有服务已关闭，退出进程');
      process.exit(0);
    }
  };

  // 关闭主服务器
  mainServer.close((err) => {
    if (err) console.error('[Server] 主服务器关闭错误:', err.message);
    else console.log('[Server] 主服务器已关闭');
    mainClosed = true;
    checkAndExit();
  });

  // 关闭管理服务器
  adminServer.close((err) => {
    if (err) console.error('[Server] 管理服务器关闭错误:', err.message);
    else console.log('[Server] 管理服务器已关闭');
    adminClosed = true;
    checkAndExit();
  });

  // 强制超时退出（3秒）
  setTimeout(() => {
    console.log('[Server] 关闭超时，强制退出');
    process.exit(1);
  }, 3000);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Windows 系统下处理 Ctrl+C
if (process.platform === 'win32') {
  process.on('SIGBREAK', () => gracefulShutdown('SIGBREAK'));
}
