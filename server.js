const fs = require('fs');
const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const SB_URL = process.env.SUPABASE_URL;
const SB_KEY = process.env.SUPABASE_SERVICE_KEY;
const MESSAGE_KEY = process.env.MESSAGE_KEY;
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || '').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

if (!SB_URL || !SB_KEY || !MESSAGE_KEY || !/^[0-9a-f]{64}$/i.test(MESSAGE_KEY)) {
  console.error('Eksik ya da hatalÄ± ortam deÄŸiÅŸkeni: SUPABASE_URL, SUPABASE_SERVICE_KEY, MESSAGE_KEY (64 karakter onaltÄ±lÄ±k)');
  process.exit(1);
}
const KEY = Buffer.from(MESSAGE_KEY, 'hex');
const UUID_RE = /^[0-9a-f-]{36}$/i;
const USERNAME_RE = /^[a-z0-9_]{3,20}$/;

// ---------- Supabase REST ----------
async function sb(table, { method = 'GET', query = '', body } = {}) {
  const res = await fetch(`${SB_URL}/rest/v1/${table}${query}`, {
    method,
    headers: {
      apikey: SB_KEY,
      Authorization: `Bearer ${SB_KEY}`,
      'Content-Type': 'application/json',
      Prefer: 'return=representation'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${res.status}: ${text}`);
  return text ? JSON.parse(text) : [];
}
const inList = ids => `in.(${ids.join(',')})`;

// ---------- Åifreleme ----------
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), enc].map(b => b.toString('base64')).join('.');
}
function decrypt(s) {
  const [iv, tag, enc] = s.split('.').map(x => Buffer.from(x, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
}

// ---------- Parola ----------
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function safeEqual(a, b) {
  const x = Buffer.from(a, 'hex');
  const y = Buffer.from(b, 'hex');
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// ---------- YÃ¶netici hesabÄ± (ortam deÄŸiÅŸkenlerinden her aÃ§Ä±lÄ±ÅŸta eÅŸitlenir) ----------
async function ensureAdmin() {
  if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    console.warn('ADMIN_USERNAME / ADMIN_PASSWORD tanÄ±mlÄ± deÄŸil, yÃ¶netici hesabÄ± oluÅŸturulmadÄ±');
    return;
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const fields = { salt, password_hash: hashPassword(ADMIN_PASSWORD, salt), is_admin: true };
  const rows = await sb('users', { query: `?username=eq.${ADMIN_USERNAME}&select=id` });
  if (rows.length) {
    await sb('users', { method: 'PATCH', query: `?username=eq.${ADMIN_USERNAME}`, body: fields });
  } else {
    await sb('users', { method: 'POST', body: { username: ADMIN_USERNAME, ...fields } });
  }
  console.log('YÃ¶netici hesabÄ± hazÄ±r:', ADMIN_USERNAME);
}

// ---------- Oturum ----------
async function userFromToken(token) {
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return null;
  const s = await sb('sessions', { query: `?token=eq.${token}&select=user_id` });
  if (!s.length) return null;
  const u = await sb('users', { query: `?id=eq.${s[0].user_id}&select=id,username,is_admin` });
  return u[0] || null;
}
async function isMember(convId, userId) {
  const r = await sb('conversation_members', {
    query: `?conversation_id=eq.${convId}&user_id=eq.${userId}&select=user_id`
  });
  return r.length > 0;
}
async function usernamesById(ids) {
  const unique = [...new Set(ids.filter(Boolean))];
  if (!unique.length) return {};
  const rows = await sb('users', { query: `?id=${inList(unique)}&select=id,username` });
  return Object.fromEntries(rows.map(u => [u.id, u.username]));
}

// ---------- Uygulama ----------
fs.mkdirSync(path.join(__dirname, 'public', 'uploads'), { recursive: true });
const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.diskStorage({
    destination: path.join(__dirname, 'public', 'uploads'),
    filename: (req, file, cb) => {
      cb(null, crypto.randomBytes(12).toString('hex') + path.extname(file.originalname).toLowerCase());
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/^image\/(png|jpeg|gif|webp)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Sadece PNG, JPEG, GIF veya WEBP yÃ¼klenebilir'));
  }
});

const wrap = fn => (req, res) => fn(req, res).catch(err => {
  console.error(err);
  res.status(500).json({ error: 'Sunucu hatasÄ±' });
});

async function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const user = await userFromToken(token);
    if (!user) return res.status(401).json({ error: 'GiriÅŸ yapmalÄ±sÄ±nÄ±z' });
    req.user = user;
    req.token = token;
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Sunucu hatasÄ±' });
  }
}
function adminOnly(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Yetkiniz yok' });
  next();
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await sb('sessions', { method: 'POST', body: { token, user_id: userId } });
  return token;
}

// Hesap
app.post('/api/register', wrap(async (req, res) => {
  const username = String((req.body && req.body.username) || '').trim().toLowerCase();
  const password = String((req.body && req.body.password) || '');
  if (!USERNAME_RE.test(username))
    return res.status(400).json({ error: 'KullanÄ±cÄ± adÄ± 3-20 karakter, yalnÄ±zca kÃ¼Ã§Ã¼k harf/rakam/_ olmalÄ±' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Åifre en az 6 karakter olmalÄ±' });
  if (username === ADMIN_USERNAME)
    return res.status(409).json({ error: 'Bu kullanÄ±cÄ± adÄ± alÄ±nmÄ±ÅŸ' });
  const exists = await sb('users', { query: `?username=eq.${username}&select=id` });
  if (exists.length) return res.status(409).json({ error: 'Bu kullanÄ±cÄ± adÄ± alÄ±nmÄ±ÅŸ' });

  const salt = crypto.randomBytes(16).toString('hex');
  const [user] = await sb('users', {
    method: 'POST',
    body: { username, salt, password_hash: hashPassword(password, salt) }
  });
  const token = await createSession(user.id);
  res.json({ token, user: { id: user.id, username: user.username, is_admin: user.is_admin } });
}));

app.post('/api/login', wrap(async (req, res) => {
  const username = String((req.body && req.body.username) || '').trim().toLowerCase();
  const password = String((req.body && req.body.password) || '');
  const rows = await sb('users', { query: `?username=eq.${username}&select=*` });
  const user = rows[0];
  if (!user || !safeEqual(hashPassword(password, user.salt), user.password_hash))
    return res.status(401).json({ error: 'KullanÄ±cÄ± adÄ± veya ÅŸifre hatalÄ±' });
  const token = await createSession(user.id);
  res.json({ token, user: { id: user.id, username: user.username, is_admin: user.is_admin } });
}));

app.post('/api/logout', auth, wrap(async (req, res) => {
  await sb('sessions', { method: 'DELETE', query: `?token=eq.${req.token}` });
  res.json({ ok: true });
}));

app.get('/api/me', auth, (req, res) => {
  res.json({ user: { id: req.user.id, username: req.user.username, is_admin: req.user.is_admin } });
});

// KullanÄ±cÄ± arama (birine kullanÄ±cÄ± adÄ±yla sohbet aÃ§mak iÃ§in)
app.get('/api/users', auth, wrap(async (req, res) => {
  const q = String(req.query.q || '').toLowerCase().replace(/[^a-z0-9_]/g, '');
  if (!q) return res.json({ users: [] });
  const rows = await sb('users', {
    query: `?username=ilike.${q}*&select=id,username&limit=20&order=username.asc`
  });
  res.json({ users: rows.filter(u => u.id !== req.user.id) });
}));

// Sohbet listesi
app.get('/api/conversations', auth, wrap(async (req, res) => {
  const mine = await sb('conversation_members', { query: `?user_id=eq.${req.user.id}&select=conversation_id` });
  const ids = mine.map(m => m.conversation_id);
  if (!ids.length) return res.json({ conversations: [] });

  const convs = await sb('conversations', { query: `?id=${inList(ids)}&select=*&order=created_at.desc` });
  const members = await sb('conversation_members', { query: `?conversation_id=${inList(ids)}&select=conversation_id,user_id` });
  const names = await usernamesById(members.map(m => m.user_id));

  const result = convs.map(c => {
    const others = members
      .filter(m => m.conversation_id === c.id && m.user_id !== req.user.id)
      .map(m => names[m.user_id]);
    return {
      id: c.id,
      type: c.type,
      title: c.type === 'group' ? c.name : others[0] || 'Bilinmeyen',
      members: members.filter(m => m.conversation_id === c.id).map(m => names[m.user_id])
    };
  });
  res.json({ conversations: result });
}));

// Birebir sohbet (varsa mevcut olan dÃ¶ner)
app.post('/api/conversations/direct', auth, wrap(async (req, res) => {
  const target = String((req.body && req.body.username) || '').trim().toLowerCase();
  if (!USERNAME_RE.test(target)) return res.status(400).json({ error: 'GeÃ§ersiz kullanÄ±cÄ± adÄ±' });
  if (target === req.user.username) return res.status(400).json({ error: 'Kendinizle sohbet aÃ§amazsÄ±nÄ±z' });
  const [other] = await sb('users', { query: `?username=eq.${target}&select=id,username` });
  if (!other) return res.status(404).json({ error: 'KullanÄ±cÄ± bulunamadÄ±' });

  const mine = await sb('conversation_members', { query: `?user_id=eq.${req.user.id}&select=conversation_id` });
  const myIds = mine.map(m => m.conversation_id);
  if (myIds.length) {
    const shared = await sb('conversation_members', {
      query: `?user_id=eq.${other.id}&conversation_id=${inList(myIds)}&select=conversation_id`
    });
    const sharedIds = shared.map(s => s.conversation_id);
    if (sharedIds.length) {
      const direct = await sb('conversations', { query: `?id=${inList(sharedIds)}&type=eq.direct&select=id` });
      if (direct.length) return res.json({ id: direct[0].id });
    }
  }

  const [conv] = await sb('conversations', {
    method: 'POST', body: { type: 'direct', created_by: req.user.id }
  });
  await sb('conversation_members', {
    method: 'POST',
    body: [{ conversation_id: conv.id, user_id: req.user.id }, { conversation_id: conv.id, user_id: other.id }]
  });
  io.emit('conversations:changed');
  res.json({ id: conv.id });
}));

// Grup sohbeti
app.post('/api/conversations/group', auth, wrap(async (req, res) => {
  const name = String((req.body && req.body.name) || '').trim().slice(0, 50);
  const names = Array.isArray(req.body && req.body.members) ? req.body.members : [];
  if (!name) return res.status(400).json({ error: 'Grup adÄ± gerekli' });
  const usernames = [...new Set(names.map(n => String(n).trim().toLowerCase()).filter(n => USERNAME_RE.test(n)))];
  const users = usernames.length
    ? await sb('users', { query: `?username=${inList(usernames)}&select=id,username` })
    : [];
  const memberIds = new Set([req.user.id, ...users.map(u => u.id)]);
  if (memberIds.size < 3) return res.status(400).json({ error: 'Grupta en az 3 kiÅŸi olmalÄ± (siz dahil)' });

  const [conv] = await sb('conversations', {
    method: 'POST', body: { type: 'group', name, created_by: req.user.id }
  });
  await sb('conversation_members', {
    method: 'POST',
    body: [...memberIds].map(id => ({ conversation_id: conv.id, user_id: id }))
  });
  io.emit('conversations:changed');
  res.json({ id: conv.id });
}));

// Mesaj geÃ§miÅŸi (yalnÄ±zca Ã¼yeler ve yÃ¶netici)
app.get('/api/conversations/:id/messages', auth, wrap(async (req, res) => {
  const convId = req.params.id;
  if (!UUID_RE.test(convId)) return res.status(400).json({ error: 'GeÃ§ersiz sohbet' });
  if (!req.user.is_admin && !(await isMember(convId, req.user.id)))
    return res.status(403).json({ error: 'Bu sohbete eriÅŸiminiz yok' });

  const rows = await sb('messages', {
    query: `?conversation_id=eq.${convId}&select=*&order=created_at.desc&limit=200`
  });
  const names = await usernamesById(rows.map(r => r.sender_id));
  const messages = rows.reverse().map(r => toClient(r, names, convId));
  res.json({ messages });
}));

function toClient(row, names, convId) {
  return {
    id: row.id,
    conversationId: convId || row.conversation_id,
    from: names[row.sender_id] || 'silinmiÅŸ kullanÄ±cÄ±',
    userId: row.sender_id,
    text: row.body_encrypted ? decrypt(row.body_encrypted) : '',
    image: row.image_path || null,
    createdAt: new Date(row.created_at).getTime()
  };
}

app.post('/api/upload', auth, (req, res) => {
  upload.single('photo')(req, res, err => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'Dosya seÃ§ilmedi' });
    res.json({ url: '/uploads/' + req.file.filename });
  });
});

// YÃ¶netici
app.get('/api/admin/users', auth, adminOnly, wrap(async (req, res) => {
  const users = await sb('users', { query: '?select=id,username,is_admin,created_at&order=created_at.asc' });
  res.json({ users });
}));

app.get('/api/admin/messages', auth, adminOnly, wrap(async (req, res) => {
  const rows = await sb('messages', { query: '?select=*&order=created_at.desc&limit=500' });
  const names = await usernamesById(rows.map(r => r.sender_id));
  const convs = await sb('conversations', { query: '?select=id,type,name' });
  const convName = Object.fromEntries(convs.map(c => [c.id, c.type === 'group' ? c.name : 'Birebir']));
  const messages = rows.map(r => ({
    ...toClient(r, names),
    conversation: convName[r.conversation_id] || '?'
  }));
  res.json({ messages });
}));

// ---------- Socket.IO ----------
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e6 });
const sharers = new Map();

io.use(async (socket, next) => {
  try {
    const user = await userFromToken(socket.handshake.auth && socket.handshake.auth.token);
    if (!user) return next(new Error('unauthorized'));
    socket.user = { id: user.id, username: user.username, is_admin: user.is_admin };
    next();
  } catch (err) {
    next(err);
  }
});

io.on('connection', async socket => {
  try {
    const mine = await sb('conversation_members', { query: `?user_id=eq.${socket.user.id}&select=conversation_id` });
    mine.forEach(m => socket.join('conv:' + m.conversation_id));
  } catch (err) {
    console.error(err);
  }
  socket.emit('sharers', [...sharers].map(([id, s]) => ({ socketId: id, username: s.username })));
  io.emit('presence', io.engine.clientsCount);

  socket.on('message', async (payload, ack) => {
    try {
      const convId = payload && payload.conversationId;
      if (!UUID_RE.test(convId || '')) return ack && ack({ error: 'GeÃ§ersiz sohbet' });
      if (!(await isMember(convId, socket.user.id))) return ack && ack({ error: 'Bu sohbete eriÅŸiminiz yok' });

      const text = String((payload && payload.text) || '').trim().slice(0, 2000);
      const image = payload && typeof payload.image === 'string' && /^\/uploads\/[a-f0-9]+\.(png|jpe?g|gif|webp)$/.test(payload.image)
        ? payload.image : null;
      if (!text && !image) return ack && ack({ error: 'BoÅŸ mesaj gÃ¶nderilemez' });

      const [row] = await sb('messages', {
        method: 'POST',
        body: {
          conversation_id: convId,
          sender_id: socket.user.id,
          body_encrypted: text ? encrypt(text) : null,
          image_path: image
        }
      });
      io.to('conv:' + convId).emit('message', toClient(row, { [socket.user.id]: socket.user.username }, convId));
      ack && ack({ ok: true });
    } catch (err) {
      console.error(err);
      ack && ack({ error: 'Mesaj gÃ¶nderilemedi' });
    }
  });

  // Yeni sohbet/grup oluÅŸturulduÄŸunda ya da birine eklendiÄŸinde odaya katÄ±lma
  socket.on('join:conversation', async convId => {
    if (UUID_RE.test(convId || '') && (await isMember(convId, socket.user.id))) socket.join('conv:' + convId);
  });

  // Ekran paylaÅŸÄ±mÄ± (sohbetten baÄŸÄ±msÄ±z, herkese aÃ§Ä±k)
  socket.on('screen:start', () => {
    sharers.set(socket.id, { username: socket.user.username });
    io.emit('screen:started', { socketId: socket.id, username: socket.user.username });
  });
  socket.on('screen:stop', () => stopSharing(socket));
  socket.on('screen:join', ({ to }) => {
    if (sharers.has(to)) io.to(to).emit('screen:viewer', { viewerId: socket.id, username: socket.user.username });
  });
  socket.on('webrtc:signal', ({ to, data }) => {
    io.to(to).emit('webrtc:signal', { from: socket.id, data });
  });

  // ---------- Sesli arama odası (sohbet başına) ----------
  socket.on('call:join', async convId => {
    try {
      if (!UUID_RE.test(convId || '') || !(await isMember(convId, socket.user.id))) return;
      if (socket.callConv) leaveCall(socket);
      const room = callRooms.get(convId) || new Map();
      callRooms.set(convId, room);
      const peers = [...room].map(([id, name]) => ({ socketId: id, username: name }));
      room.set(socket.id, socket.user.username);
      socket.callConv = convId;
      socket.emit('call:peers', peers);
      peers.forEach(p => io.to(p.socketId).emit('call:peer-joined', { socketId: socket.id, username: socket.user.username }));
    } catch (err) {
      console.error(err);
    }
  });

  socket.on('call:leave', () => leaveCall(socket));

  // Ses sinyalleri yalnızca aynı çağrı odasındaki kişiye iletilir
  socket.on('call:signal', ({ to, data }) => {
    const target = io.sockets.sockets.get(to);
    if (!target || !socket.callConv || target.callConv !== socket.callConv) return;
    io.to(to).emit('call:signal', { from: socket.id, data });
  });

  socket.on('disconnect', () => {
    leaveCall(socket);
    stopSharing(socket);
    io.emit('presence', io.engine.clientsCount);
  });
});

const callRooms = new Map();
function leaveCall(socket) {
  const convId = socket.callConv;
  if (!convId) return;
  socket.callConv = null;
  const room = callRooms.get(convId);
  if (room) {
    room.delete(socket.id);
    if (!room.size) callRooms.delete(convId);
  }
  io.to('conv:' + convId).emit('call:peer-left', { socketId: socket.id });
}

function stopSharing(socket) {
  if (!sharers.has(socket.id)) return;
  sharers.delete(socket.id);
  io.emit('screen:stopped', { socketId: socket.id });
}

ensureAdmin()
  .catch(err => console.error('YÃ¶netici hesabÄ± oluÅŸturulamadÄ±:', err.message))
  .finally(() => {
    server.listen(PORT, () => console.log(`Sunucu Ã§alÄ±ÅŸÄ±yor: port ${PORT}`));
  });


