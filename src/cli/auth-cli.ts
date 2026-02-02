import {
  createApiKey,
  revokeApiKey,
  listApiKeys,
  enableAuth,
  disableAuth,
  loadAuthConfig,
  setAdminPassword,
  hasAdminPassword,
  getFullApiKey,
  KeyPermission
} from '../auth.js';
import { markKeyAsRevoked } from '../webProxy.js';

const args = process.argv.slice(2);
const command = args[0];

function printHelp() {
  console.log(`
Claude Proxy 认证管理工具

用法:
  npm run auth <command> [options]

命令:
  create <name> [days] [perms]  创建新的 API Key
                                name: Key 名称
                                days: Cookie 有效期（天），默认 7 天
                                perms: 权限类型，可选值:
                                  web  - 仅 Web 访问
                                  api  - 仅 Claude Code API
                                  all  - 两者都允许（默认）
  list                          列出所有 API Key
  show <id>                     显示指定 Key 的完整内容
  revoke <id>                   撤销指定的 API Key
  enable                        启用认证
  disable                       禁用认证
  status                        查看认证状态
  set-password                  设置管理员密码（用于 Web 管理面板）
  help                          显示帮助信息

示例:
  npm run auth create "小明" 30         # 创建有效期 30 天的 Key（默认全部权限）
  npm run auth create "网页用户" 7 web  # 仅允许 Web 访问
  npm run auth create "开发者" 30 api   # 仅允许 Claude Code API
  npm run auth create "VIP" 365 all     # 两者都允许
  npm run auth show key_abc123          # 查看完整 Key
  npm run auth set-password             # 设置管理员密码
  npm run auth list
  npm run auth revoke key_abc123
`);
}

switch (command) {
  case 'create': {
    const name = args[1];
    if (!name) {
      console.error('错误: 请提供 API Key 名称');
      console.error('用法: npm run auth create "名称" [有效期天数] [权限类型]');
      process.exit(1);
    }

    // 解析有效期参数
    let expiresInDays = 7; // 默认 7 天
    if (args[2]) {
      const days = parseInt(args[2], 10);
      if (isNaN(days) || days < 1) {
        console.error('错误: 有效期必须是大于 0 的整数');
        process.exit(1);
      }
      expiresInDays = days;
    }

    // 解析权限参数
    let permissions: KeyPermission[] = ['web', 'api']; // 默认全部权限
    if (args[3]) {
      const permArg = args[3].toLowerCase();
      if (permArg === 'web') {
        permissions = ['web'];
      } else if (permArg === 'api') {
        permissions = ['api'];
      } else if (permArg === 'all') {
        permissions = ['web', 'api'];
      } else {
        console.error('错误: 无效的权限类型，可选值: web, api, all');
        process.exit(1);
      }
    }

    const { id, key } = createApiKey(name, expiresInDays, permissions);
    const permStr = permissions.map(p => p === 'web' ? 'Web' : 'API').join(' + ');
    console.log('');
    console.log('========================================');
    console.log('  API Key 创建成功');
    console.log('========================================');
    console.log(`  ID:     ${id}`);
    console.log(`  名称:   ${name}`);
    console.log(`  有效期: ${expiresInDays} 天`);
    console.log(`  权限:   ${permStr}`);
    console.log(`  Key:    ${key}`);
    console.log('');
    console.log('  提示: 可随时通过管理面板或 CLI 查看完整 Key');
    console.log('========================================');
    console.log('');
    break;
  }

  case 'list': {
    const keys = listApiKeys();
    const config = loadAuthConfig();
    console.log('');
    console.log(`认证状态: ${config.enabled ? '已启用' : '已禁用'}`);
    console.log(`管理员密码: ${hasAdminPassword() ? '已设置' : '未设置'}`);
    console.log('');
    if (keys.length === 0) {
      console.log('暂无 API Key');
      console.log('使用 "npm run auth create <名称> [天数]" 创建一个');
    } else {
      console.log(`当前共有 ${keys.length} 个 API Key:`);
      console.log('');
      for (const k of keys) {
        const permStr = k.permissions.map(p => p === 'web' ? 'Web' : 'API').join(' + ');
        console.log(`  ID:       ${k.id}`);
        console.log(`  名称:     ${k.name}`);
        console.log(`  前缀:     ${k.keyPrefix}`);
        console.log(`  权限:     ${permStr}`);
        console.log(`  有效期:   ${k.expiresInDays || 7} 天`);
        console.log(`  创建时间: ${k.createdAt}`);
        console.log(`  最后使用: ${k.lastUsedAt || '从未使用'}`);
        console.log('  ---');
      }
    }
    console.log('');
    break;
  }

  case 'show': {
    const id = args[1];
    if (!id) {
      console.error('错误: 请提供 API Key ID');
      console.error('用法: npm run auth show <id>');
      process.exit(1);
    }
    const fullKey = getFullApiKey(id);
    if (fullKey) {
      console.log('');
      console.log(`Key ${id} 的完整内容:`);
      console.log(`  ${fullKey}`);
      console.log('');
    } else {
      console.error(`未找到 API Key: ${id}`);
      process.exit(1);
    }
    break;
  }

  case 'revoke': {
    const id = args[1];
    if (!id) {
      console.error('错误: 请提供 API Key ID');
      console.error('用法: npm run auth revoke <id>');
      console.error('提示: 使用 "npm run auth list" 查看所有 Key');
      process.exit(1);
    }
    if (revokeApiKey(id)) {
      // 撤销成功后，标记配置为已撤销（而不是删除）
      markKeyAsRevoked(id);
      console.log(`API Key ${id} 已撤销并标记`);
    } else {
      console.error(`未找到 API Key: ${id}`);
      process.exit(1);
    }
    break;
  }

  case 'enable':
    enableAuth();
    console.log('认证已启用');
    break;

  case 'disable':
    disableAuth();
    console.log('认证已禁用（所有请求将被允许）');
    break;

  case 'status': {
    const config = loadAuthConfig();
    console.log('');
    console.log('认证配置状态:');
    console.log(`  认证启用: ${config.enabled ? '是' : '否'}`);
    console.log(`  Key 数量: ${config.apiKeys.length}`);
    console.log(`  管理员密码: ${hasAdminPassword() ? '已设置' : '未设置'}`);
    console.log('');
    if (!hasAdminPassword()) {
      console.log('提示: 运行 "npm run auth set-password" 设置管理员密码');
      console.log('      设置后可通过 Web 管理面板管理 Key');
      console.log('');
    }
    break;
  }

  case 'set-password': {
    // 从命令行参数或交互式输入获取密码
    const password = args[1];
    if (!password) {
      console.error('用法: npm run auth set-password <密码>');
      console.error('');
      console.error('示例: npm run auth set-password mySecretPassword123');
      console.error('');
      console.error('注意: 设置后可通过 http://localhost:3002 访问 Web 管理面板');
      process.exit(1);
    }

    if (password.length < 6) {
      console.error('错误: 密码长度至少 6 位');
      process.exit(1);
    }

    setAdminPassword(password);
    console.log('');
    console.log('========================================');
    console.log('  管理员密码设置成功');
    console.log('========================================');
    console.log('');
    console.log('  现在可以通过以下地址访问管理面板:');
    console.log('  http://localhost:3002');
    console.log('');
    console.log('========================================');
    break;
  }

  case 'help':
  default:
    printHelp();
}
