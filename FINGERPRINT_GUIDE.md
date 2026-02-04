# 浏览器指纹伪装指南

本项目支持自定义浏览器指纹,以更好地模拟真实浏览器环境。

## 快速开始

### 1. 获取你的浏览器指纹

在你想要模拟的浏览器中,打开开发者控制台 (F12),粘贴以下代码:

```javascript
console.log(JSON.stringify({
  userAgent: navigator.userAgent,
  platform: navigator.platform,
  language: navigator.language,
  languages: navigator.languages,
  hardwareConcurrency: navigator.hardwareConcurrency,
  deviceMemory: navigator.deviceMemory,
  maxTouchPoints: navigator.maxTouchPoints,
  vendor: navigator.vendor,
  appVersion: navigator.appVersion,
  screen: {
    width: screen.width,
    height: screen.height,
    colorDepth: screen.colorDepth,
    pixelDepth: screen.pixelDepth
  },
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  timezoneOffset: new Date().getTimezoneOffset()
}, null, 2));
```

### 2. 创建指纹配置文件

将上面获取的指纹数据复制到 `fingerprint.json`:

```bash
# 从模板创建
cp fingerprint.example.json fingerprint.json

# 编辑文件,替换为你的指纹数据
```

### 3. 配置 WebGL 指纹 (可选)

WebGL 指纹需要额外配置。你可以:

**方式A: 使用在线工具**
- 访问 https://browserleaks.com/webgl
- 查看 "Unmasked Vendor" 和 "Unmasked Renderer"
- 更新 `fingerprint.json` 中的 `webgl.vendor` 和 `webgl.renderer`

**方式B: 控制台获取**
```javascript
const canvas = document.createElement('canvas');
const gl = canvas.getContext('webgl');
const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
console.log({
  vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
  renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
});
```

### 4. 重启服务

```bash
npm run build
npm start
```

服务启动时会显示:
```
[Fingerprint] 已加载自定义浏览器指纹
```

## 配置文件说明

### `fingerprint.json` 结构

```json
{
  "userAgent": "浏览器 User-Agent 字符串",
  "platform": "操作系统平台 (Win32, MacIntel, Linux x86_64)",
  "language": "主要语言 (zh-CN, en-US)",
  "languages": ["语言列表数组"],
  "hardwareConcurrency": 8,  // CPU 核心数
  "deviceMemory": 8,          // 设备内存 (GB)
  "maxTouchPoints": 0,        // 触摸点数量 (0=非触摸屏)
  "vendor": "浏览器厂商",
  "appVersion": "浏览器版本信息",
  "screen": {
    "width": 1920,            // 屏幕宽度
    "height": 1080,           // 屏幕高度
    "colorDepth": 24,         // 颜色深度
    "pixelDepth": 24          // 像素深度
  },
  "timezone": "时区标识符",
  "timezoneOffset": -480,     // 时区偏移 (分钟)
  "secChUa": "Sec-CH-UA 请求头",
  "secChUaPlatform": "Sec-CH-UA-Platform 请求头",
  "secChUaMobile": "Sec-CH-UA-Mobile 请求头",
  "acceptLanguage": "Accept-Language 请求头",
  "webgl": {
    "vendor": "WebGL 厂商",
    "renderer": "WebGL 渲染器",
    "extensions": ["WebGL 扩展列表"]
  }
}
```

## 常见浏览器配置示例

### Windows 10 + Chrome 144
```json
{
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
  "platform": "Win32",
  "language": "en-US",
  "languages": ["en-US", "en"],
  "hardwareConcurrency": 8,
  "deviceMemory": 8,
  "maxTouchPoints": 0,
  "vendor": "Google Inc."
}
```

### macOS + Safari
```json
{
  "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "platform": "MacIntel",
  "language": "en-US",
  "languages": ["en-US", "en"],
  "hardwareConcurrency": 8,
  "deviceMemory": 8,
  "maxTouchPoints": 0,
  "vendor": "Apple Computer, Inc."
}
```

### Linux + Firefox
```json
{
  "userAgent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
  "platform": "Linux x86_64",
  "language": "en-US",
  "languages": ["en-US", "en"],
  "hardwareConcurrency": 8,
  "deviceMemory": 8,
  "maxTouchPoints": 0,
  "vendor": ""
}
```

## 注意事项

1. **时区一致性**: `timezone` 和 `timezoneOffset` 必须匹配你的实际位置
2. **硬件合理性**: `hardwareConcurrency` 和 `deviceMemory` 应该是常见配置
3. **WebGL 匹配**: WebGL 指纹应该与你的 User-Agent 匹配 (Chrome/Edge 通常是 ANGLE)
4. **定期更新**: 浏览器版本会更新,建议定期更新指纹配置

## 验证指纹

重启服务后,访问以下网站验证你的指纹:
- https://abrahamjuliot.github.io/creepjs/
- https://browserleaks.com/canvas
- https://amiunique.org/fingerprint

## 故障排除

### 问题: 服务启动后没有显示 "已加载自定义浏览器指纹"
**解决**: 检查 `fingerprint.json` 文件是否存在且格式正确

### 问题: 某些网站检测到异常指纹
**解决**:
1. 确保所有字段都已正确填写
2. 检查 WebGL 配置是否与 User-Agent 匹配
3. 时区设置是否与你的网络位置一致

### 问题: JSON 格式错误
**解决**: 使用在线工具验证 JSON: https://jsonlint.com/

## 高级用法

### 多指纹轮换 (未来功能)
计划支持配置多个指纹,每次请求随机选择,增加隐蔽性。

### 动态指纹 (未来功能)
根据目标网站自动调整指纹特征。

## 安全建议

1. **不要共享**: `fingerprint.json` 包含你的真实浏览器特征,不要公开分享
2. **已加入 .gitignore**: 该文件已被忽略,不会被提交到 Git
3. **定期更换**: 建议定期更新指纹配置,避免被长期追踪

## 技术原理

本项目通过以下方式伪装浏览器指纹:
1. **HTTP 请求头伪装**: 修改 User-Agent, Sec-CH-UA 等请求头
2. **JavaScript API 劫持**: 覆盖 navigator, screen, WebGL 等 API
3. **Canvas 指纹混淆**: 在 Canvas 输出中注入微小噪点
4. **时区伪装**: 修改 Date, Intl.DateTimeFormat 行为

## 更新日志

- **2026-02-02**: 初始版本,支持自定义指纹配置
