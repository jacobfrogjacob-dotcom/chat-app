const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, 'chat.db');

async function main() {
  const SQL = await initSqlJs();
  let db;
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }

  function saveDb() {
    fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
  }

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nickname TEXT NOT NULL DEFAULT '',
    bio TEXT NOT NULL DEFAULT '這個人很懶，什麼都沒寫',
    avatar TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    nickname TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'text',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS announcement (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    content TEXT NOT NULL DEFAULT '',
    updated_by TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run('INSERT OR IGNORE INTO announcement (id, content) VALUES (1, "")');

  // migrate old tables
  try { db.run('ALTER TABLE users ADD COLUMN nickname TEXT NOT NULL DEFAULT ""'); } catch(e) {}
  try { db.run('ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT "這個人很懶，什麼都沒寫"'); } catch(e) {}
  try { db.run('ALTER TABLE users ADD COLUMN avatar TEXT NOT NULL DEFAULT ""'); } catch(e) {}
  try { db.run('ALTER TABLE messages ADD COLUMN nickname TEXT NOT NULL DEFAULT ""'); } catch(e) {}
  try { db.run('ALTER TABLE messages ADD COLUMN reply_to_id INTEGER DEFAULT NULL'); } catch(e) {}
  try { db.run('ALTER TABLE messages ADD COLUMN reply_to_content TEXT DEFAULT NULL'); } catch(e) {}
  try { db.run('ALTER TABLE messages ADD COLUMN reply_to_nickname TEXT DEFAULT NULL'); } catch(e) {}
  saveDb();

  // Auto-create admin account if not exists
  try {
    const adminUser = queryOne('SELECT id FROM users WHERE username = ?', ['admin']);
    if (!adminUser) {
      const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'qawsed', 10);
      runSql('INSERT INTO users (username, password, nickname, role) VALUES (?, ?, ?, ?)', ['admin', adminHash, '管理員', 'admin']);
      console.log('Auto-created admin account');
    } else {
      console.log('Admin account already exists');
    }
  } catch(e) {
    console.error('Admin auto-create failed:', e.message);
    // Fallback: create directly
    try {
      const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'qawsed', 10);
      db.run('INSERT OR IGNORE INTO users (username, password, nickname, role) VALUES (?, ?, ?, ?)', ['admin', adminHash, '管理員', 'admin']);
      saveDb();
      console.log('Admin created via fallback');
    } catch(e2) { console.error('Fallback also failed:', e2.message); }
  }

  const app = express();
  const server = http.createServer(app);
  const io = new Server(server);
  const PORT = process.env.PORT || 3000;

  app.use(express.json({ limit: '5mb' }));
  app.use(express.static(path.join(__dirname, 'public')));

  const sessions = new Map();
  const USERNAME_RE = /^[a-z0-9]+$/;

  function createSession(userId, username, role) {
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { userId, username, role, createdAt: Date.now() });
    return token;
  }
  function destroySession(token) { sessions.delete(token); }
  function getSession(token) { return sessions.get(token) || null; }
  function extractToken(req) {
    const m = (req.headers.cookie || '').match(/chat_token=([^;]+)/);
    return m ? m[1] : null;
  }

  function queryAll(sql, params = []) {
    const s = db.prepare(sql);
    if (params.length) s.bind(params);
    const rows = [];
    while (s.step()) rows.push(s.getAsObject());
    s.free();
    return rows;
  }
  function queryOne(sql, params = []) {
    const r = queryAll(sql, params);
    return r[0] || null;
  }
  function runSql(sql, params = []) {
    db.run(sql, params);
    saveDb();
  }

  // ===== Auth =====
  app.post('/api/register', (req, res) => {
    try {
      let { username, password, nickname } = req.body;
      if (!username || !password) return res.status(400).json({ error: '請填寫帳號與密碼' });
      username = username.toLowerCase().trim();
      if (!USERNAME_RE.test(username)) return res.status(400).json({ error: '帳號僅限英文小寫與數字' });
      if (username.length < 2 || username.length > 20) return res.status(400).json({ error: '帳號需 2~20 字元' });
      if (password.length < 4) return res.status(400).json({ error: '密碼至少 4 字元' });

      const existing = queryOne('SELECT id FROM users WHERE username = ?', [username]);
      if (existing) return res.status(409).json({ error: '帳號已被註冊' });

      const hash = bcrypt.hashSync(password, 10);
      const role = username === 'admin' ? 'admin' : 'user';
      const nick = (nickname && nickname.trim()) ? nickname.trim() : username;
      runSql('INSERT INTO users (username, password, nickname, role) VALUES (?, ?, ?, ?)', [username, hash, nick, role]);
      const user = queryOne('SELECT * FROM users WHERE username = ?', [username]);
      const token = createSession(user.id, username, role);
      res.cookie('chat_token', token, { httpOnly: true, maxAge: 86400000 });
      res.json({ ok: true, username, nickname: user.nickname, role });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/login', (req, res) => {
    try {
      let { username, password } = req.body;
      if (!username || !password) return res.status(400).json({ error: '請填寫帳號與密碼' });
      username = username.toLowerCase().trim();
      const user = queryOne('SELECT * FROM users WHERE username = ?', [username]);
      if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ error: '帳號或密碼錯誤' });
      }
      const token = createSession(user.id, user.username, user.role);
      res.cookie('chat_token', token, { httpOnly: true, maxAge: 86400000 });
      res.json({ ok: true, username: user.username, nickname: user.nickname, role: user.role });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/logout', (req, res) => {
    const t = extractToken(req);
    if (t) destroySession(t);
    res.clearCookie('chat_token');
    res.json({ ok: true });
  });

  app.get('/api/me', (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s) return res.status(401).json({ error: '未登入' });
    const user = queryOne('SELECT id, username, nickname, bio, avatar, role FROM users WHERE id = ?', [s.userId]);
    if (!user) return res.status(401).json({ error: '用戶不存在' });
    res.json(user);
  });

  // ===== Profile =====
  app.get('/api/user/:username', (req, res) => {
    const user = queryOne(
      'SELECT id, username, nickname, bio, avatar, role, created_at FROM users WHERE username = ?',
      [req.params.username]
    );
    if (!user) return res.status(404).json({ error: '找不到用戶' });
    const msgCount = queryOne('SELECT COUNT(*) as count FROM messages WHERE username = ?', [req.params.username]);
    user.message_count = msgCount ? msgCount.count : 0;
    user.is_online = false;
    for (const [, u] of onlineUsers) {
      if (u.username === req.params.username) { user.is_online = true; break; }
    }
    res.json(user);
  });

  app.post('/api/profile/nickname', (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s) return res.status(401).json({ error: '未登入' });
    const { nickname } = req.body;
    if (!nickname || !nickname.trim()) return res.status(400).json({ error: '暱稱不能為空' });
    if (nickname.length > 20) return res.status(400).json({ error: '暱稱最多 20 字元' });
    runSql('UPDATE users SET nickname = ? WHERE id = ?', [nickname.trim(), s.userId]);
    io.emit('nickname_updated', { username: s.username, nickname: nickname.trim() });
    res.json({ ok: true, nickname: nickname.trim() });
  });

  app.post('/api/profile/bio', (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s) return res.status(401).json({ error: '未登入' });
    const { bio } = req.body;
    if (bio && bio.length > 100) return res.status(400).json({ error: '簡介最多 100 字元' });
    runSql('UPDATE users SET bio = ? WHERE id = ?', [(bio || '').trim(), s.userId]);
    res.json({ ok: true, bio: (bio || '').trim() });
  });

  app.post('/api/profile/avatar', (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s) return res.status(401).json({ error: '未登入' });
    const { avatar } = req.body;
    if (!avatar) return res.status(400).json({ error: '請選擇圖片' });
    if (avatar.length > 2000000) return res.status(400).json({ error: '圖片不能超過 2MB' });
    runSql('UPDATE users SET avatar = ? WHERE id = ?', [avatar, s.userId]);
    res.json({ ok: true, avatar });
  });

  app.post('/api/profile/password', (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s) return res.status(401).json({ error: '未登入' });
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ error: '請填寫所有欄位' });
    if (newPassword.length < 4) return res.status(400).json({ error: '新密碼至少 4 字元' });
    const user = queryOne('SELECT password FROM users WHERE id = ?', [s.userId]);
    if (!bcrypt.compareSync(oldPassword, user.password)) {
      return res.status(401).json({ error: '舊密碼不正確' });
    }
    const hash = bcrypt.hashSync(newPassword, 10);
    runSql('UPDATE users SET password = ? WHERE id = ?', [hash, s.userId]);
    res.json({ ok: true });
  });

  app.get('/api/messages', (req, res) => {
    const rows = queryAll(`
      SELECT m.*, u.avatar, u.nickname as live_nickname
      FROM messages m LEFT JOIN users u ON m.username = u.username
      ORDER BY m.id DESC LIMIT 100
    `);
    res.json(rows.reverse());
  });

  app.get('/api/messages/:username', (req, res) => {
    const rows = queryAll(
      `SELECT m.*, u.avatar, u.nickname as live_nickname
       FROM messages m LEFT JOIN users u ON m.username = u.username
       WHERE m.username = ? ORDER BY m.id DESC LIMIT 20`,
      [req.params.username]
    );
    res.json(rows.reverse());
  });

  app.delete('/api/messages/:id', (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s || s.role !== 'admin') return res.status(403).json({ error: '僅管理員可刪訊息' });
    const msg = queryOne('SELECT id FROM messages WHERE id = ?', [parseInt(req.params.id)]);
    if (!msg) return res.status(404).json({ error: '訊息不存在' });
    runSql('DELETE FROM messages WHERE id = ?', [parseInt(req.params.id)]);
    io.emit('message_deleted', { id: parseInt(req.params.id) });
    res.json({ ok: true });
  });

  app.post('/api/messages/batch-delete', (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s || s.role !== 'admin') return res.status(403).json({ error: '僅管理員可刪訊息' });
    const { ids } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: '未選擇訊息' });
    const placeholders = ids.map(() => '?').join(',');
    runSql(`DELETE FROM messages WHERE id IN (${placeholders})`, ids);
    io.emit('messages_deleted', { ids });
    res.json({ ok: true, deleted: ids.length });
  });

  app.get('/api/announcement', (req, res) => {
    const row = queryOne('SELECT * FROM announcement WHERE id = 1');
    res.json(row || { content: '' });
  });

  // ===== Socket.io =====
  const onlineUsers = new Map();

  io.use((socket, next) => {
    try {
      const raw = socket.handshake.headers.cookie || '';
      const m = raw.match(/chat_token=([^;]+)/);
      if (!m) return next(new Error('未登入'));
      const sess = getSession(m[1]);
      if (!sess) return next(new Error('登入已過期'));
      socket.session = sess;
      next();
    } catch (e) { next(new Error('認證失敗')); }
  });

  io.on('connection', (socket) => {
    const user = { id: socket.session.userId, username: socket.session.username, role: socket.session.role };
    onlineUsers.set(socket.id, user);

    const userInfo = queryOne('SELECT username, nickname, avatar FROM users WHERE id = ?', [user.id]);
    const onlineList = [];
    const seen = new Set();
    for (const [, u] of onlineUsers) {
      if (!seen.has(u.username)) {
        seen.add(u.username);
        const info = queryOne('SELECT username, nickname, avatar FROM users WHERE username = ?', [u.username]);
        if (info) onlineList.push(info);
      }
    }

    io.emit('online_count', onlineUsers.size);
    io.emit('user_joined', { username: user.username, online: onlineUsers.size, user_info: userInfo });
    socket.emit('online_users', onlineList);

    socket.on('send_message', (data) => {
      const { content, type, replyToId, replyToContent, replyToNickname } = data;
      if (!content || !content.trim()) return;
      const u = queryOne('SELECT nickname, avatar FROM users WHERE username = ?', [user.username]);
      const nickname = u ? u.nickname : user.username;
      const avatar = u ? u.avatar : '';
      const now = new Date().toISOString();
      runSql(
        'INSERT INTO messages (user_id, username, nickname, role, content, type, created_at, reply_to_id, reply_to_content, reply_to_nickname) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [user.id, user.username, nickname, user.role, content, type || 'text', now, replyToId || null, replyToContent || null, replyToNickname || null]
      );
      const newMsg = queryOne('SELECT * FROM messages WHERE created_at = ? AND username = ? ORDER BY id DESC', [now, user.username]);
      io.emit('new_message', { id: newMsg.id, username: user.username, nickname, avatar, role: user.role, content, type: type || 'text', created_at: now, reply_to_id: replyToId || null, reply_to_content: replyToContent || null, reply_to_nickname: replyToNickname || null });
    });

    socket.on('update_announcement', (data) => {
      if (user.role !== 'admin') return;
      const { content } = data;
      const now = new Date().toISOString();
      runSql('UPDATE announcement SET content = ?, updated_by = ?, updated_at = ? WHERE id = 1', [content || '', user.username, now]);
      io.emit('announcement_updated', { content: content || '', updated_by: user.username, updated_at: now });
    });

    socket.on('disconnect', () => {
      onlineUsers.delete(socket.id);
      io.emit('online_count', onlineUsers.size);
      io.emit('user_left', { username: user.username, online: onlineUsers.size });
    });
  });

  server.listen(PORT, () => console.log(`伺服器運行於 http://localhost:${PORT}`));
}

main().catch(console.error);
