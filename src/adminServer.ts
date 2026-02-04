import express from 'express';
import {
  hasAdminPassword,
  verifyAdminPassword,
  setAdminPassword,
  getAdminLoginHtml,
  getAdminDashboardHtml,
  listApiKeysWithFullKey,
  createApiKey,
  revokeApiKey
} from './auth.js';

const ADMIN_PORT = parseInt(process.env.ADMIN_PORT || '3002', 10);

import { Server } from 'http';

export function startAdminServer(): Server {
  const app = express();

  // 管理员登录页面
  app.get('/', (req, res) => {
    // 检查是否已登录
    const adminCookie = req.headers.cookie?.match(/admin_session=([^;]+)/);
    if (adminCookie && adminCookie[1] === 'authenticated') {
      return res.redirect('/dashboard');
    }

    if (!hasAdminPassword()) {
      return res.type('html').send(getAdminLoginHtml('not_set'));
    }

    const error = req.query.error as string | undefined;
    const message = req.query.message as string | undefined;
    res.type('html').send(getAdminLoginHtml(error || message));
  });

  // 首次设置密码 API（仅在未设置密码时可用）
  app.use('/setup-password', express.urlencoded({ extended: false }));
  app.use('/setup-password', express.json());
  app.post('/setup-password', (req, res) => {
    // 如果已经有密码，拒绝请求
    if (hasAdminPassword()) {
      return res.status(403).json({ success: false, message: '管理员密码已设置' });
    }

    const password = req.body.password;

    if (!password || password.length < 6) {
      return res.status(400).json({ success: false, message: '密码至少需要 6 个字符' });
    }

    setAdminPassword(password);
    console.log('[Admin] 管理员密码首次设置成功');

    res.json({ success: true, message: '密码设置成功' });
  });

  // 管理员登录处理
  app.use('/login', express.urlencoded({ extended: false }));
  app.post('/login', (req, res) => {
    const password = req.body.password;

    if (!hasAdminPassword()) {
      return res.redirect('/?error=not_set');
    }

    if (!verifyAdminPassword(password)) {
      return res.redirect('/?error=invalid');
    }

    // 设置管理员会话 Cookie（24小时有效）
    res.cookie('admin_session', 'authenticated', {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: 'lax'
    });

    console.log('[Admin] 管理员登录成功');
    res.redirect('/dashboard');
  });

  // 管理员登出
  app.get('/logout', (_req, res) => {
    res.clearCookie('admin_session');
    res.redirect('/');
  });

  // 管理员面板（需要认证）
  app.get('/dashboard', (req, res) => {
    const adminCookie = req.headers.cookie?.match(/admin_session=([^;]+)/);
    if (!adminCookie || adminCookie[1] !== 'authenticated') {
      return res.redirect('/');
    }

    const message = req.query.message as string | undefined;
    const keys = listApiKeysWithFullKey();
    res.type('html').send(getAdminDashboardHtml(keys, message));
  });

  // 创建 Key（管理员操作）
  app.use('/create', express.urlencoded({ extended: false }));
  app.post('/create', (req, res) => {
    const adminCookie = req.headers.cookie?.match(/admin_session=([^;]+)/);
    if (!adminCookie || adminCookie[1] !== 'authenticated') {
      return res.redirect('/');
    }

    const name = req.body.name;
    const days = parseInt(req.body.days, 10) || 7;

    // 解析是否为管理员
    const isAdmin = req.body.isAdmin === 'on';

    if (!name) {
      return res.redirect('/dashboard?message=名称不能为空');
    }

    createApiKey(name, days, ['web'], isAdmin);
    const adminStr = isAdmin ? ' [管理员]' : '';
    res.redirect(`/dashboard?message=Key "${name}" 创建成功${adminStr}`);
  });

  // 撤销 Key（管理员操作）
  app.use('/revoke', express.urlencoded({ extended: false }));
  app.post('/revoke', (req, res) => {
    const adminCookie = req.headers.cookie?.match(/admin_session=([^;]+)/);
    if (!adminCookie || adminCookie[1] !== 'authenticated') {
      return res.redirect('/');
    }

    const id = req.body.id;
    if (id && revokeApiKey(id)) {
      res.redirect('/dashboard?message=Key 已撤销');
    } else {
      res.redirect('/dashboard?message=撤销失败');
    }
  });

  // 修改管理员密码
  app.use('/change-password', express.urlencoded({ extended: false }));
  app.post('/change-password', (req, res) => {
    const adminCookie = req.headers.cookie?.match(/admin_session=([^;]+)/);
    if (!adminCookie || adminCookie[1] !== 'authenticated') {
      return res.redirect('/');
    }

    const { current_password, new_password, confirm_password } = req.body;

    // 验证当前密码
    if (!verifyAdminPassword(current_password)) {
      return res.redirect('/dashboard?message=当前密码错误');
    }

    // 验证新密码
    if (!new_password || new_password.length < 6) {
      return res.redirect('/dashboard?message=新密码至少需要6个字符');
    }

    if (new_password !== confirm_password) {
      return res.redirect('/dashboard?message=两次输入的新密码不一致');
    }

    // 更新密码
    setAdminPassword(new_password);
    console.log('[Admin] 管理员密码已修改');

    // 清除会话，要求重新登录
    res.clearCookie('admin_session');
    res.redirect('/?message=password_changed');
  });

  // 启动管理服务器（允许远程访问）
  const server = app.listen(ADMIN_PORT, '0.0.0.0', () => {
    console.log(`[Admin] 管理面板已启动: http://0.0.0.0:${ADMIN_PORT} (允许远程访问)`);
  });

  return server;
}
