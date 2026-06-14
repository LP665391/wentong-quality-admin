/**
 * ═══════════════════════════════════════════════════════════════
 *  文安档案 · 商业授权管理系统
 *
 *  技术栈: Express + JSON文件存储（带写入锁）
 *  部署: 服务器 / 云平台 / Docker
 * ═══════════════════════════════════════════════════════════════
 */

const express = require('express');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// ================================================================
// 配置
// ================================================================

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, '..', 'data');

const SECRET_KEY = Buffer.from(
  process.env.WENTONG_SECRET_KEY || 'V2VuVG9uZ1F1YWxpdHlQbGF0Zm9ybVNlY3JldEtleTIwMjU=',
  'base64'
);

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ================================================================
// 带锁的 JSON 文件数据库（防止并发写入冲突）
// ================================================================

const writeLocks = {};

function readDB(name) {
  const fp = path.join(DATA_DIR, `${name}.json`);
  if (!fs.existsSync(fp)) return [];
  try { return JSON.parse(fs.readFileSync(fp, 'utf-8')); } catch { return []; }
}

function writeDB(name, data) {
  const fp = path.join(DATA_DIR, `${name}.json`);
  // 简单的排队锁：同一文件的写入串行化
  if (!writeLocks[name]) writeLocks[name] = Promise.resolve();
  writeLocks[name] = writeLocks[name].then(() => {
    fs.writeFileSync(fp, JSON.stringify(data, null, 2), 'utf-8');
  });
}

// ================================================================
// 初始化种子数据
// ================================================================

function initDB() {
  if (readDB('admins').length === 0) {
    const hash = crypto.createHash('sha256').update('admin123').digest('hex');
    writeDB('admins', [{
      username: 'admin', passwordHash: hash, passwordPlain: 'admin123',
      role: 'super', name: '超级管理员', createdAt: new Date().toLocaleString('zh-CN'),
    }]);
  }
  if (readDB('plans').length === 0) {
    writeDB('plans', [
      { id: 'basic', name: '基础版', price: 299, unit: '年', maxUsers: 1, maxFiles: 1000, features: ['PDF处理', '数据校验', 'MD5校验'], popular: false },
      { id: 'pro', name: '专业版', price: 899, unit: '年', maxUsers: 5, maxFiles: 10000, features: ['PDF处理', '数据校验', 'MD5校验', '图像检测', '元数据封装'], popular: true },
      { id: 'enterprise', name: '企业版', price: 2999, unit: '年', maxUsers: -1, maxFiles: -1, features: ['全部功能', '私有化部署', '专属客服', '定制开发'], popular: false },
    ]);
  }
  if (readDB('auth_codes').length === 0) {
    writeDB('auth_codes', [{
      code: 'WT-DEMO-2024', planId: 'pro', customerName: '演示用户', company: '文安档案',
      used: false, boundMachineId: null, activatedAt: null,
      createdAt: new Date().toLocaleString('zh-CN'),
    }]);
  }
}
initDB();

// ================================================================
// 工具函数
// ================================================================

function hashPwd(pwd) { return crypto.createHash('sha256').update(pwd).digest('hex'); }

function signContent(content) {
  const h = crypto.createHmac('sha256', SECRET_KEY);
  h.update(JSON.stringify(content), 'utf-8');
  return h.digest('base64');
}

function genId(prefix = 'WT') {
  return `${prefix}-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

function genCode() {
  return `WT-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

function log(action, detail, operator = 'system') {
  const logs = readDB('logs');
  logs.unshift({ action, detail, operator, time: new Date().toLocaleString('zh-CN') });
  if (logs.length > 500) logs.length = 500;
  writeDB('logs', logs);
}

// ================================================================
// 认证
// ================================================================

const TOKENS = new Map();

function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !TOKENS.has(token)) return res.status(401).json({ error: '未登录' });
  req.admin = TOKENS.get(token);
  next();
}

// ================================================================
// Express
// ================================================================

const app = express();
app.use(express.json());

// 全局错误处理
app.use((err, _req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: '服务器内部错误' });
});

// ================================================================
// 认证 API
// ================================================================

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const admins = readDB('admins');
  const admin = admins.find(a => a.username === username);
  if (!admin || admin.passwordHash !== hashPwd(password)) {
    return res.status(400).json({ error: '账号或密码错误' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  TOKENS.set(token, admin);
  log('登录', `管理员 ${username} 登录`, username);
  res.json({ success: true, token, admin: { username: admin.username, role: admin.role, name: admin.name } });
});

app.post('/api/change-password', requireAuth, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const admins = readDB('admins');
  const admin = admins.find(a => a.username === req.admin.username);
  if (admin.passwordHash !== hashPwd(oldPassword)) return res.status(400).json({ error: '原密码错误' });
  admin.passwordHash = hashPwd(newPassword);
  writeDB('admins', admins);
  log('修改密码', `管理员 ${req.admin.username} 修改了密码`, req.admin.username);
  res.json({ success: true });
});

// ================================================================
// 管理员管理
// ================================================================

app.get('/api/admins', requireAuth, (req, res) => {
  const admins = readDB('admins').map(a => ({
    username: a.username, name: a.name, role: a.role,
    password: a.passwordPlain || '已加密', createdAt: a.createdAt,
  }));
  res.json({ success: true, data: admins });
});

app.post('/api/admins', requireAuth, (req, res) => {
  const { username, password, name, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: '账号和密码不能为空' });
  if (password.length < 6) return res.status(400).json({ error: '密码至少6位' });
  if (role === 'super' && req.admin.role !== 'super') {
    return res.status(403).json({ error: '仅超级管理员可创建超级管理员账号' });
  }
  const admins = readDB('admins');
  if (admins.find(a => a.username === username)) return res.status(400).json({ error: '账号已存在' });

  admins.push({
    username, passwordHash: hashPwd(password), passwordPlain: password,
    name: name || username, role: role || 'admin',
    createdAt: new Date().toLocaleString('zh-CN'),
  });
  writeDB('admins', admins);
  log('添加成员', `添加管理员 ${username}（${role}）`, req.admin.username);
  res.json({ success: true, data: { username, name, role, password } });
});

app.put('/api/admins/:username', requireAuth, (req, res) => {
  if (req.admin.role !== 'super') return res.status(403).json({ error: '仅超级管理员可修改成员' });
  const admins = readDB('admins');
  const admin = admins.find(a => a.username === req.params.username);
  if (!admin) return res.status(404).json({ error: '成员不存在' });
  const { name, role, password } = req.body;
  if (name) admin.name = name;
  if (role) admin.role = role;
  if (password) admin.passwordHash = hashPwd(password);
  writeDB('admins', admins);
  log('修改成员', `修改管理员 ${req.params.username}`, req.admin.username);
  res.json({ success: true, data: { username: admin.username, name: admin.name, role: admin.role } });
});

app.delete('/api/admins/:username', requireAuth, (req, res) => {
  if (req.admin.role !== 'super') return res.status(403).json({ error: '仅超级管理员可删除成员' });
  if (req.params.username === 'admin') return res.status(400).json({ error: '不能删除初始管理员' });
  if (req.params.username === req.admin.username) return res.status(400).json({ error: '不能删除自己' });
  let admins = readDB('admins');
  const admin = admins.find(a => a.username === req.params.username && !a.deleted);
  if (!admin) return res.status(404).json({ error: '成员不存在' });
  admin.deleted = true;
  admin.deletedAt = new Date().toLocaleString('zh-CN');
  admin.deletedBy = req.admin.username;
  writeDB('admins', admins);
  log('删除成员', `删除管理员 ${req.params.username}`, req.admin.username);
  res.json({ success: true });
});

// ================================================================
// 授权码管理（在线激活用）
// ================================================================

app.get('/api/auth-codes', requireAuth, (req, res) => {
  let codes = readDB('auth_codes').filter(c => !c.deleted);
  const { search, used } = req.query;
  if (search) {
    const kw = search.toLowerCase();
    codes = codes.filter(c => c.code.toLowerCase().includes(kw) || c.customerName?.toLowerCase().includes(kw));
  }
  if (used === 'true') codes = codes.filter(c => c.used);
  if (used === 'false') codes = codes.filter(c => !c.used);
  res.json({ success: true, data: codes.reverse() });
});

app.post('/api/auth-codes', requireAuth, (req, res) => {
  const { customerName, company, planId, count } = req.body;
  if (!customerName) return res.status(400).json({ error: '客户名称不能为空' });
  const num = Math.min(count || 1, 500);
  const codes = readDB('auth_codes');
  const created = [];
  for (let i = 0; i < num; i++) {
    const code = {
      code: genCode(), planId: planId || 'pro', customerName, company: company || '',
      used: false, boundMachineId: null, activatedAt: null,
      createdAt: new Date().toLocaleString('zh-CN'), createdBy: req.admin.username,
    };
    codes.push(code);
    created.push(code);
  }
  writeDB('auth_codes', codes);
  log('批量生成授权码', `为客户 ${customerName} 生成 ${num} 个授权码（${planId}）`, req.admin.username);
  res.json({ success: true, data: created, count: num });
});

app.delete('/api/auth-codes/:code', requireAuth, (req, res) => {
  let codes = readDB('auth_codes');
  const code = codes.find(c => c.code === req.params.code);
  if (!code) return res.status(404).json({ error: '授权码不存在' });
  if (code.deleted) return res.status(404).json({ error: '授权码不存在' });
  code.deleted = true;
  code.deletedAt = new Date().toLocaleString('zh-CN');
  code.deletedBy = req.admin.username;
  writeDB('auth_codes', codes);
  log('删除授权码', `授权码 ${req.params.code} 已标记删除`, req.admin.username);
  res.json({ success: true });
});

// ================================================================
// 许可证
// ================================================================

app.get('/api/licenses', requireAuth, (req, res) => {
  let licenses = readDB('licenses').filter(l => !l.deleted);
  const { search, status } = req.query;
  const now = new Date();
  if (search) {
    const kw = search.toLowerCase();
    licenses = licenses.filter(l =>
      l.customerName?.toLowerCase().includes(kw) || l.licenseId?.toLowerCase().includes(kw) || l.machineId?.toLowerCase().includes(kw)
    );
  }
  if (status === 'active') licenses = licenses.filter(l => !l.expireDate || new Date(l.expireDate) >= now);
  if (status === 'expired') licenses = licenses.filter(l => l.expireDate && new Date(l.expireDate) < now);
  res.json({ success: true, data: licenses.reverse() });
});

app.post('/api/licenses', requireAuth, (req, res) => {
  const { customerName, company, machineId, type, expireDate, planName } = req.body;
  if (!customerName) return res.status(400).json({ error: '客户名称不能为空' });
  if (!machineId) return res.status(400).json({ error: '机器码不能为空' });

  const licenseId = genId();
  const content = {
    licenseId, customerName, company: company || '',
    type: type || 'permanent', machineId,
    issueDate: new Date().toISOString().split('T')[0], planName: planName || '',
  };
  if (expireDate) content.expireDate = expireDate;

  const signature = signContent(content);
  const licenses = readDB('licenses');
  licenses.push({ ...content, signature, createdAt: new Date().toLocaleString('zh-CN'), createdBy: req.admin.username });
  writeDB('licenses', licenses);
  log('生成许可证', `为客户 ${customerName} 生成许可证 ${licenseId}`, req.admin.username);
  res.json({ success: true, data: { content, signature } });
});

app.delete('/api/licenses/:id', requireAuth, (req, res) => {
  let licenses = readDB('licenses');
  const license = licenses.find(l => (l.licenseId === req.params.id || l.id === req.params.id) && !l.deleted);
  if (!license) return res.status(404).json({ error: '许可证不存在' });
  license.deleted = true;
  license.deletedAt = new Date().toLocaleString('zh-CN');
  license.deletedBy = req.admin.username;
  writeDB('licenses', licenses);
  log('删除许可证', `许可证 ${req.params.id} 已标记删除`, req.admin.username);
  res.json({ success: true });
});

app.get('/api/licenses/:id/download', requireAuth, (req, res) => {
  const licenses = readDB('licenses');
  const license = licenses.find(l => l.licenseId === req.params.id);
  if (!license) return res.status(404).json({ error: '许可证不存在' });
  const content = { ...license };
  delete content.createdAt; delete content.createdBy; delete content.signature;
  const data = { content, signature: license.signature };
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="license-${license.customerName}.dat"`);
  res.send(JSON.stringify(data, null, 2));
});

// ================================================================
// 在线激活接口（桌面端调用，不需登录）
// ================================================================

app.post('/api/activate', (req, res) => {
  const { licenseKey, machineId } = req.body;
  if (!licenseKey) return res.status(400).json({ error: '授权码不能为空' });
  if (!machineId) return res.status(400).json({ error: '机器码不能为空' });

  const codes = readDB('auth_codes');
  const code = codes.find(c => c.code === licenseKey && !c.deleted);
  if (!code) return res.status(400).json({ error: '授权码无效' });
  if (code.used && code.boundMachineId !== machineId) {
    return res.status(400).json({ error: `该授权码已于 ${code.activatedAt} 绑定到其他机器` });
  }

  const plans = readDB('plans');
  const plan = plans.find(p => p.id === (code.planId || 'pro'));
  const content = {
    licenseId: licenseKey, customerName: code.customerName, company: code.company,
    type: 'permanent', machineId, issueDate: new Date().toISOString().split('T')[0],
    planName: plan?.name || code.planId || '专业版',
  };

  const signature = signContent(content);
  code.used = true; code.boundMachineId = machineId;
  code.activatedAt = new Date().toLocaleString('zh-CN');
  writeDB('auth_codes', codes);

  const licenses = readDB('licenses');
  licenses.push({ ...content, signature, createdAt: code.activatedAt, createdBy: 'online_activation' });
  writeDB('licenses', licenses);

  log('在线激活', `授权码 ${licenseKey} 激活 → ${code.customerName}（${machineId.slice(0, 8)}...）`, 'system');
  res.json({ success: true, content, signature });
});

app.get('/api/activate/check/:code', (req, res) => {
  const codes = readDB('auth_codes');
  const code = codes.find(c => c.code === req.params.code);
  if (!code) return res.json({ exists: false });
  res.json({ exists: true, used: code.used, customerName: code.customerName });
});

// ================================================================
// 统计报表
// ================================================================

app.get('/api/stats', requireAuth, (req, res) => {
  const licenses = readDB('licenses').filter(l => !l.deleted);
  const orders = readDB('orders').filter(o => !o.deleted);
  const customers = readDB('customers').filter(c => !c.deleted);
  const codes = readDB('auth_codes').filter(c => !c.deleted);
  const now = new Date();
  const thisMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

  const totalLicenses = licenses.length;
  const activeLicenses = licenses.filter(l => !l.expireDate || new Date(l.expireDate) >= now).length;
  const expiredLicenses = licenses.filter(l => l.expireDate && new Date(l.expireDate) < now).length;
  const monthlyNewLicenses = licenses.filter(l => l.issueDate?.startsWith(thisMonth)).length;
  const monthlyRevenue = orders.filter(o => o.paidAt?.includes(thisMonth)).reduce((s, o) => s + (o.amount || 0), 0);
  const totalRevenue = orders.reduce((s, o) => s + (o.amount || 0), 0);
  const totalOrders = orders.length;
  const totalCodes = codes.length;
  const usedCodes = codes.filter(c => c.used).length;

  const expiringSoon = [];
  for (const l of licenses) {
    if (!l.expireDate) continue;
    const days = Math.ceil((new Date(l.expireDate) - now) / (1000 * 60 * 60 * 24));
    if (days > 0 && days <= 30) expiringSoon.push({ licenseId: l.licenseId, customerName: l.customerName, expireDate: l.expireDate, daysLeft: days });
  }

  const revenueTrend = [];
  for (let i = 11; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const m = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    const amount = orders.filter(o => o.paidAt?.includes(m)).reduce((s, o) => s + (o.amount || 0), 0);
    revenueTrend.push({ month: m, amount });
  }

  const recent = licenses.slice(-5).reverse().map(l => ({
    licenseId: l.licenseId, customerName: l.customerName, type: l.type, issueDate: l.issueDate,
  }));

  res.json({
    success: true, data: {
      licenses: { total: totalLicenses, active: activeLicenses, expired: expiredLicenses, monthlyNew: monthlyNewLicenses, recent },
      finance: { totalRevenue, totalOrders, monthlyRevenue },
      codes: { total: totalCodes, used: usedCodes, unused: totalCodes - usedCodes },
      customers: { total: customers.length },
      expiringSoon: expiringSoon.slice(0, 10),
      revenueTrend,
    }
  });
});

// ================================================================
// 操作日志
// ================================================================

app.get('/api/logs', requireAuth, (req, res) => {
  res.json({ success: true, data: readDB('logs') });
});

// ================================================================
// 健康检查
// ================================================================

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// ================================================================
// 静态文件 & 启动
// ================================================================

app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════════════════════╗
  ║        文安档案 · 商业授权管理系统 v2.0              ║
  ╠══════════════════════════════════════════════════════╣
  ║  管理后台:  http://localhost:${PORT}                   ║
  ║  API接口:   http://localhost:${PORT}/api               ║
  ║                                                      ║
  ║  管理员: admin / admin123                            ║
  ╚══════════════════════════════════════════════════════╝
  `);
});
