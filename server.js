const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

const USERNAME_RE = /^[a-z0-9]+$/;

async function main() {
  // Create tables
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      nickname TEXT NOT NULL DEFAULT '',
      bio TEXT NOT NULL DEFAULT '這個人很懶，什麼都沒寫',
      avatar TEXT NOT NULL DEFAULT '',
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      nickname TEXT NOT NULL DEFAULT '',
      role TEXT NOT NULL,
      content TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'text',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      reply_to_id INTEGER DEFAULT NULL,
      reply_to_content TEXT DEFAULT NULL,
      reply_to_nickname TEXT DEFAULT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS announcement (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      content TEXT NOT NULL DEFAULT '',
      updated_by TEXT,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query('INSERT INTO announcement (id, content) VALUES (1, \'\') ON CONFLICT (id) DO NOTHING');

  // Auto-create admin
  const adminCheck = await pool.query('SELECT id FROM users WHERE username = $1', ['admin']);
  if (adminCheck.rows.length === 0) {
    const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'qawsed', 10);
    await pool.query('INSERT INTO users (username, password, nickname, role) VALUES ($1, $2, $3, $4)', ['admin', hash, '管理員', 'admin']);
    console.log('Auto-created admin account');
  }

  const app = express();
  const server = http.createServer(app);
  const io = new Server(server);
  const PORT = process.env.PORT || 3000;

  app.use(express.json({ limit: '5mb' }));
  app.use(express.static(path.join(__dirname, 'public')));

  const sessions = new Map();
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

  // ===== Auth =====
  app.post('/api/register', async (req, res) => {
    try {
      let { username, password, nickname } = req.body;
      if (!username || !password) return res.status(400).json({ error: '請填寫帳號與密碼' });
      username = username.toLowerCase().trim();
      if (!USERNAME_RE.test(username)) return res.status(400).json({ error: '帳號僅限英文小寫與數字' });
      if (username.length < 2 || username.length > 20) return res.status(400).json({ error: '帳號需 2~20 字元' });
      if (password.length < 4) return res.status(400).json({ error: '密碼至少 4 字元' });
      const existing = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
      if (existing.rows.length > 0) return res.status(409).json({ error: '帳號已被註冊' });
      const hash = bcrypt.hashSync(password, 10);
      const role = username === 'admin' ? 'admin' : 'user';
      const nick = (nickname && nickname.trim()) ? nickname.trim() : username;
      const result = await pool.query('INSERT INTO users (username, password, nickname, role) VALUES ($1, $2, $3, $4) RETURNING id, nickname', [username, hash, nick, role]);
      const token = createSession(result.rows[0].id, username, role);
      res.cookie('chat_token', token, { httpOnly: true, maxAge: 86400000 });
      res.json({ ok: true, username, nickname: result.rows[0].nickname, role });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/login', async (req, res) => {
    try {
      let { username, password } = req.body;
      if (!username || !password) return res.status(400).json({ error: '請填寫帳號與密碼' });
      username = username.toLowerCase().trim();
      const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      if (result.rows.length === 0 || !bcrypt.compareSync(password, result.rows[0].password)) {
        return res.status(401).json({ error: '帳號或密碼錯誤' });
      }
      const user = result.rows[0];
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

  app.get('/api/me', async (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s) return res.status(401).json({ error: '未登入' });
    const result = await pool.query('SELECT id, username, nickname, bio, avatar, role FROM users WHERE id = $1', [s.userId]);
    if (result.rows.length === 0) return res.status(401).json({ error: '用戶不存在' });
    res.json(result.rows[0]);
  });

  // ===== Profile =====
  app.get('/api/user/:username', async (req, res) => {
    const result = await pool.query('SELECT id, username, nickname, bio, avatar, role, created_at FROM users WHERE username = $1', [req.params.username]);
    if (result.rows.length === 0) return res.status(404).json({ error: '找不到用戶' });
    const user = result.rows[0];
    const msgCount = await pool.query('SELECT COUNT(*)::int as count FROM messages WHERE username = $1', [req.params.username]);
    user.message_count = msgCount.rows[0].count;
    user.is_online = false;
    for (const [, u] of onlineUsers) {
      if (u.username === req.params.username) { user.is_online = true; break; }
    }
    res.json(user);
  });

  app.post('/api/profile/nickname', async (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s) return res.status(401).json({ error: '未登入' });
    const { nickname } = req.body;
    if (!nickname || !nickname.trim()) return res.status(400).json({ error: '暱稱不能為空' });
    if (nickname.length > 20) return res.status(400).json({ error: '暱稱最多 20 字元' });
    await pool.query('UPDATE users SET nickname = $1 WHERE id = $2', [nickname.trim(), s.userId]);
    io.emit('nickname_updated', { username: s.username, nickname: nickname.trim() });
    res.json({ ok: true, nickname: nickname.trim() });
  });

  app.post('/api/profile/bio', async (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s) return res.status(401).json({ error: '未登入' });
    const { bio } = req.body;
    if (bio && bio.length > 100) return res.status(400).json({ error: '簡介最多 100 字元' });
    await pool.query('UPDATE users SET bio = $1 WHERE id = $2', [(bio || '').trim(), s.userId]);
    res.json({ ok: true, bio: (bio || '').trim() });
  });

  app.post('/api/profile/avatar', async (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s) return res.status(401).json({ error: '未登入' });
    const { avatar } = req.body;
    if (!avatar) return res.status(400).json({ error: '請選擇圖片' });
    await pool.query('UPDATE users SET avatar = $1 WHERE id = $2', [avatar, s.userId]);
    res.json({ ok: true, avatar });
  });

  app.post('/api/profile/password', async (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s) return res.status(401).json({ error: '未登入' });
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ error: '請填寫所有欄位' });
    if (newPassword.length < 4) return res.status(400).json({ error: '新密碼至少 4 字元' });
    const result = await pool.query('SELECT password FROM users WHERE id = $1', [s.userId]);
    if (!bcrypt.compareSync(oldPassword, result.rows[0].password)) {
      return res.status(401).json({ error: '舊密碼不正確' });
    }
    const hash = bcrypt.hashSync(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hash, s.userId]);
    res.json({ ok: true });
  });

  app.get('/api/messages', async (req, res) => {
    const result = await pool.query(`
      SELECT m.*, u.avatar, u.nickname as live_nickname
      FROM messages m LEFT JOIN users u ON m.username = u.username
      ORDER BY m.id DESC LIMIT 100
    `);
    res.json(result.rows.reverse());
  });

  app.get('/api/messages/:username', async (req, res) => {
    const result = await pool.query(
      `SELECT m.*, u.avatar, u.nickname as live_nickname
       FROM messages m LEFT JOIN users u ON m.username = u.username
       WHERE m.username = $1 ORDER BY m.id DESC LIMIT 20`,
      [req.params.username]
    );
    res.json(result.rows.reverse());
  });

  app.delete('/api/messages/:id', async (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s || s.role !== 'admin') return res.status(403).json({ error: '僅管理員可刪訊息' });
    const msgId = parseInt(req.params.id);
    const check = await pool.query('SELECT id FROM messages WHERE id = $1', [msgId]);
    if (check.rows.length === 0) return res.status(404).json({ error: '訊息不存在' });
    await pool.query('DELETE FROM messages WHERE id = $1', [msgId]);
    io.emit('message_deleted', { id: msgId });
    res.json({ ok: true });
  });

  app.post('/api/messages/batch-delete', async (req, res) => {
    const t = extractToken(req);
    const s = t ? getSession(t) : null;
    if (!s || s.role !== 'admin') return res.status(403).json({ error: '僅管理員可刪訊息' });
    const { ids } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: '未選擇訊息' });
    const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');
    await pool.query(`DELETE FROM messages WHERE id IN (${placeholders})`, ids);
    io.emit('messages_deleted', { ids });
    res.json({ ok: true, deleted: ids.length });
  });

  app.get('/api/announcement', async (req, res) => {
    const result = await pool.query('SELECT * FROM announcement WHERE id = 1');
    res.json(result.rows[0] || { content: '' });
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

  io.on('connection', async (socket) => {
    const user = { id: socket.session.userId, username: socket.session.username, role: socket.session.role };
    onlineUsers.set(socket.id, user);

    try {
      const userInfoResult = await pool.query('SELECT username, nickname, avatar FROM users WHERE id = $1', [user.id]);
      const userInfo = userInfoResult.rows[0];
      const onlineList = [];
      const seen = new Set();
      for (const [, u] of onlineUsers) {
        if (!seen.has(u.username)) {
          seen.add(u.username);
          const infoResult = await pool.query('SELECT username, nickname, avatar FROM users WHERE username = $1', [u.username]);
          if (infoResult.rows[0]) onlineList.push(infoResult.rows[0]);
        }
      }
      io.emit('online_count', onlineUsers.size);
      io.emit('user_joined', { username: user.username, online: onlineUsers.size, user_info: userInfo });
      socket.emit('online_users', onlineList);
    } catch(e) { console.error('Socket init error:', e.message); }

    socket.on('send_message', async (data) => {
      const { content, type, replyToId, replyToContent, replyToNickname } = data;
      if (!content || !content.trim()) return;
      try {
        const uResult = await pool.query('SELECT nickname, avatar FROM users WHERE username = $1', [user.username]);
        const u = uResult.rows[0];
        const nickname = u ? u.nickname : user.username;
        const avatar = u ? u.avatar : '';
        const result = await pool.query(
          'INSERT INTO messages (user_id, username, nickname, role, content, type, reply_to_id, reply_to_content, reply_to_nickname) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, created_at',
          [user.id, user.username, nickname, user.role, content, type || 'text', replyToId || null, replyToContent || null, replyToNickname || null]
        );
        const msg = result.rows[0];
        io.emit('new_message', { id: msg.id, username: user.username, nickname, avatar, role: user.role, content, type: type || 'text', created_at: msg.created_at, reply_to_id: replyToId || null, reply_to_content: replyToContent || null, reply_to_nickname: replyToNickname || null });
      } catch(e) { console.error('Send message error:', e.message); }
    });

    socket.on('update_announcement', async (data) => {
      if (user.role !== 'admin') return;
      const { content } = data;
      try {
        await pool.query('UPDATE announcement SET content = $1, updated_by = $2, updated_at = NOW() WHERE id = 1', [content || '', user.username]);
        io.emit('announcement_updated', { content: content || '', updated_by: user.username, updated_at: new Date().toISOString() });
      } catch(e) { console.error('Announcement error:', e.message); }
    });

    socket.on('disconnect', () => {
      onlineUsers.delete(socket.id);
      io.emit('online_count', onlineUsers.size);
      io.emit('user_left', { username: user.username, online: onlineUsers.size });
    });
  });

  server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
