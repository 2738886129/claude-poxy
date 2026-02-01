import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync, readdirSync, unlinkSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';

// 缓存配置
interface CacheConfig {
  enabled: boolean;
  cacheDir: string;
  maxSizeMB: number;  // 最大缓存大小 (MB)
  maxAgeDays: number; // 最大缓存时间 (天)
}

// 缓存条目元数据
interface CacheEntry {
  url: string;
  contentType: string;
  statusCode: number;
  headers: Record<string, string>;
  size: number;
  createdAt: number;
  lastAccessed: number;
}

// 缓存索引
interface CacheIndex {
  entries: Record<string, CacheEntry>;
  totalSize: number;
}

// 默认配置
const defaultConfig: CacheConfig = {
  enabled: true,
  cacheDir: join(process.cwd(), '.cache'),
  maxSizeMB: 500,  // 500MB
  maxAgeDays: 7,   // 7 天
};

// 可缓存的静态资源模式
const CACHEABLE_PATTERNS = [
  /^\/_next\/static\//,           // Next.js 静态资源
  /^\/_next\/image/,              // Next.js 图片
  /\.js(\?.*)?$/,                 // JavaScript
  /\.css(\?.*)?$/,                // CSS
  /\.woff2?(\?.*)?$/,             // 字体
  /\.ttf(\?.*)?$/,                // 字体
  /\.otf(\?.*)?$/,                // 字体
  /\.eot(\?.*)?$/,                // 字体
  /\.svg(\?.*)?$/,                // SVG
  /\.png(\?.*)?$/,                // PNG
  /\.jpg(\?.*)?$/,                // JPG
  /\.jpeg(\?.*)?$/,               // JPEG
  /\.gif(\?.*)?$/,                // GIF
  /\.ico(\?.*)?$/,                // ICO
  /\.webp(\?.*)?$/,               // WebP
  /\.avif(\?.*)?$/,               // AVIF
  /\/manifest\.json/,             // Manifest
  /\/favicon\./,                  // Favicon
];

// 不缓存的模式
const NON_CACHEABLE_PATTERNS = [
  /\/api\//,                      // API 请求
  /\/sentry/,                     // Sentry
  /\/_rsc=/,                      // React Server Components
  /\.well-known/,                 // Well-known
];

class StaticCache {
  private config: CacheConfig;
  private index: CacheIndex;
  private indexPath: string;
  private dirty: boolean = false;
  private saveTimer: NodeJS.Timeout | null = null;

  constructor(config?: Partial<CacheConfig>) {
    this.config = { ...defaultConfig, ...config };
    this.indexPath = join(this.config.cacheDir, 'index.json');
    this.index = { entries: {}, totalSize: 0 };

    if (this.config.enabled) {
      this.initialize();
    }
  }

  private initialize(): void {
    // 创建缓存目录
    if (!existsSync(this.config.cacheDir)) {
      mkdirSync(this.config.cacheDir, { recursive: true });
      console.log(`[Cache] 创建缓存目录: ${this.config.cacheDir}`);
    }

    // 加载索引
    this.loadIndex();

    // 清理过期缓存
    this.cleanExpired();

    // 定期保存索引
    setInterval(() => this.saveIndex(), 30000); // 30秒保存一次

    console.log(`[Cache] 静态资源缓存已启用，当前缓存: ${(this.index.totalSize / 1024 / 1024).toFixed(2)} MB`);
  }

  private loadIndex(): void {
    try {
      if (existsSync(this.indexPath)) {
        const content = readFileSync(this.indexPath, 'utf-8');
        this.index = JSON.parse(content);
      }
    } catch (err) {
      console.error('[Cache] 加载索引失败:', err);
      this.index = { entries: {}, totalSize: 0 };
    }
  }

  private saveIndex(): void {
    if (!this.dirty) return;

    try {
      writeFileSync(this.indexPath, JSON.stringify(this.index, null, 2));
      this.dirty = false;
    } catch (err) {
      console.error('[Cache] 保存索引失败:', err);
    }
  }

  private markDirty(): void {
    this.dirty = true;
  }

  private getHashedFilename(url: string): string {
    const hash = createHash('md5').update(url).digest('hex');
    return hash;
  }

  private getFilePath(url: string): string {
    const filename = this.getHashedFilename(url);
    // 使用前两位作为子目录，避免单目录文件过多
    const subdir = filename.substring(0, 2);
    const dir = join(this.config.cacheDir, subdir);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    return join(dir, filename);
  }

  // 检查 URL 是否可缓存
  isCacheable(url: string, method: string): boolean {
    if (!this.config.enabled) return false;
    if (method !== 'GET') return false;

    // 检查是否匹配不缓存的模式
    for (const pattern of NON_CACHEABLE_PATTERNS) {
      if (pattern.test(url)) return false;
    }

    // 检查是否匹配可缓存的模式
    for (const pattern of CACHEABLE_PATTERNS) {
      if (pattern.test(url)) return true;
    }

    return false;
  }

  // 获取缓存
  get(url: string): { data: Buffer; entry: CacheEntry } | null {
    if (!this.config.enabled) return null;

    const entry = this.index.entries[url];
    if (!entry) return null;

    const filePath = this.getFilePath(url);
    if (!existsSync(filePath)) {
      // 文件不存在，清理索引
      delete this.index.entries[url];
      this.index.totalSize -= entry.size;
      this.markDirty();
      return null;
    }

    try {
      const data = readFileSync(filePath);

      // 更新最后访问时间
      entry.lastAccessed = Date.now();
      this.markDirty();

      return { data, entry };
    } catch (err) {
      console.error(`[Cache] 读取缓存失败: ${url}`, err);
      return null;
    }
  }

  // 设置缓存
  set(url: string, data: Buffer, statusCode: number, contentType: string, headers: Record<string, string>): void {
    if (!this.config.enabled) return;

    const filePath = this.getFilePath(url);
    const size = data.length;

    // 检查是否需要清理空间
    const maxSize = this.config.maxSizeMB * 1024 * 1024;
    while (this.index.totalSize + size > maxSize && Object.keys(this.index.entries).length > 0) {
      this.evictOldest();
    }

    try {
      writeFileSync(filePath, data);

      // 如果已存在，先减去旧的大小
      const existingEntry = this.index.entries[url];
      if (existingEntry) {
        this.index.totalSize -= existingEntry.size;
      }

      // 添加新条目
      const entry: CacheEntry = {
        url,
        contentType,
        statusCode,
        headers: this.filterHeaders(headers),
        size,
        createdAt: Date.now(),
        lastAccessed: Date.now(),
      };

      this.index.entries[url] = entry;
      this.index.totalSize += size;
      this.markDirty();

      // console.log(`[Cache] 缓存: ${url} (${(size / 1024).toFixed(2)} KB)`);
    } catch (err) {
      console.error(`[Cache] 写入缓存失败: ${url}`, err);
    }
  }

  // 过滤需要保存的响应头
  private filterHeaders(headers: Record<string, string>): Record<string, string> {
    const keepHeaders = [
      'content-type',
      'cache-control',
      'etag',
      'last-modified',
      'content-encoding',
    ];

    const filtered: Record<string, string> = {};
    for (const key of keepHeaders) {
      if (headers[key]) {
        filtered[key] = headers[key];
      }
    }
    return filtered;
  }

  // 驱逐最旧的缓存
  private evictOldest(): void {
    let oldest: { url: string; entry: CacheEntry } | null = null;

    for (const [url, entry] of Object.entries(this.index.entries)) {
      if (!oldest || entry.lastAccessed < oldest.entry.lastAccessed) {
        oldest = { url, entry };
      }
    }

    if (oldest) {
      this.delete(oldest.url);
    }
  }

  // 删除缓存
  delete(url: string): void {
    const entry = this.index.entries[url];
    if (!entry) return;

    const filePath = this.getFilePath(url);
    try {
      if (existsSync(filePath)) {
        unlinkSync(filePath);
      }
    } catch (err) {
      console.error(`[Cache] 删除缓存文件失败: ${url}`, err);
    }

    this.index.totalSize -= entry.size;
    delete this.index.entries[url];
    this.markDirty();
  }

  // 清理过期缓存
  private cleanExpired(): void {
    const now = Date.now();
    const maxAge = this.config.maxAgeDays * 24 * 60 * 60 * 1000;
    let cleanedCount = 0;
    let cleanedSize = 0;

    for (const [url, entry] of Object.entries(this.index.entries)) {
      if (now - entry.createdAt > maxAge) {
        cleanedSize += entry.size;
        cleanedCount++;
        this.delete(url);
      }
    }

    if (cleanedCount > 0) {
      console.log(`[Cache] 清理过期缓存: ${cleanedCount} 个文件, ${(cleanedSize / 1024 / 1024).toFixed(2)} MB`);
    }
  }

  // 获取缓存统计信息
  getStats(): { count: number; sizeMB: number; maxSizeMB: number } {
    return {
      count: Object.keys(this.index.entries).length,
      sizeMB: this.index.totalSize / 1024 / 1024,
      maxSizeMB: this.config.maxSizeMB,
    };
  }

  // 清空所有缓存
  clear(): void {
    for (const url of Object.keys(this.index.entries)) {
      this.delete(url);
    }
    console.log('[Cache] 缓存已清空');
  }
}

// 单例实例
let cacheInstance: StaticCache | null = null;

export function getCache(config?: Partial<CacheConfig>): StaticCache {
  if (!cacheInstance) {
    cacheInstance = new StaticCache(config);
  }
  return cacheInstance;
}

export { StaticCache, CacheConfig, CacheEntry };
