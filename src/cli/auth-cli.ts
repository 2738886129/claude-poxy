import { createApiKey, revokeApiKey, listApiKeys, enableAuth, disableAuth, loadAuthConfig } from '../auth.js';

const args = process.argv.slice(2);
const command = args[0];

function printHelp() {
  console.log(`
Claude Proxy 认证管理工具

用法:
  npm run auth <command> [options]

命令:
  create <name> [days]  创建新的 API Key
                        name: Key 名称
                        days: Cookie 有效期（天），默认 7 天
  list                  列出所有 API Key
  revoke <id>           撤销指定的 API Key
  enable                启用认证
  disable               禁用认证
  status                查看认证状态
  help                  显示帮助信息

示例:
  npm run auth create "小明" 30      # 创建有效期 30 天的 Key
  npm run auth create "临时访客" 1   # 创建有效期 1 天的 Key
  npm run auth create "长期用户" 365 # 创建有效期 1 年的 Key
  npm run auth list
  npm run auth revoke key_abc123
`);
}

switch (command) {
  case 'create': {
    const name = args[1];
    if (!name) {
      console.error('错误: 请提供 API Key 名称');
      console.error('用法: npm run auth create "名称" [有效期天数]');
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

    const { id, key } = createApiKey(name, expiresInDays);
    console.log('');
    console.log('========================================');
    console.log('  API Key 创建成功');
    console.log('========================================');
    console.log(`  ID:     ${id}`);
    console.log(`  名称:   ${name}`);
    console.log(`  有效期: ${expiresInDays} 天`);
    console.log(`  Key:    ${key}`);
    console.log('');
    console.log('  重要: 请妥善保存此 Key，它只会显示一次！');
    console.log('========================================');
    console.log('');
    break;
  }

  case 'list': {
    const keys = listApiKeys();
    const config = loadAuthConfig();
    console.log('');
    console.log(`认证状态: ${config.enabled ? '已启用' : '已禁用'}`);
    console.log('');
    if (keys.length === 0) {
      console.log('暂无 API Key');
      console.log('使用 "npm run auth create <名称> [天数]" 创建一个');
    } else {
      console.log(`当前共有 ${keys.length} 个 API Key:`);
      console.log('');
      for (const k of keys) {
        console.log(`  ID:       ${k.id}`);
        console.log(`  名称:     ${k.name}`);
        console.log(`  前缀:     ${k.keyPrefix}`);
        console.log(`  有效期:   ${k.expiresInDays || 7} 天`);
        console.log(`  创建时间: ${k.createdAt}`);
        console.log(`  最后使用: ${k.lastUsedAt || '从未使用'}`);
        console.log('  ---');
      }
    }
    console.log('');
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
      console.log(`API Key ${id} 已撤销`);
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
    console.log(`  启用: ${config.enabled ? '是' : '否'}`);
    console.log(`  Key 数量: ${config.apiKeys.length}`);
    console.log('');
    break;
  }

  case 'help':
  default:
    printHelp();
}
