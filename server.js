const fs = require('fs');
const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const { Server } = require('socket.io');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

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
async function sbRpc(name, body) {
  const res = await fetch(`${SB_URL}/rest/v1/rpc/${name}`, {
    method: 'POST',
    headers: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase RPC ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
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
  if (ADMIN_PASSWORD.length < 12) {
    console.error('Yönetici parolası en az 12 karakter olmalı; yönetici hesabı güncellenmedi.');
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
  const s = await sb('sessions', { query: `?token=eq.${token}&expires_at=gt.${encodeURIComponent(new Date().toISOString())}&select=user_id` });
  if (!s.length) return null;
  const u = await sb('users', { query: `?id=eq.${s[0].user_id}&select=id,username,is_admin,profile_photo,status_message,last_seen_at` });
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

const onlineUsers = new Map();
async function profilesById(ids) {
  const unique = [...new Set(ids.filter(Boolean))];
  if (!unique.length) return {};
  const rows = await sb('users', { query: `?id=${inList(unique)}&select=id,username,profile_photo,status_message,last_seen_at` });
  return Object.fromEntries(rows.map(u => [u.id, u]));
}

// ---------- Uygulama ----------
fs.mkdirSync(path.join(__dirname, 'public', 'uploads'), { recursive: true });
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // Existing UI uses inline event handlers; remove these before switching to a nonce-only policy.
      scriptSrcAttr: ["'unsafe-inline'"], // Keep the current onclick/onchange controls working under Helmet's default CSP.
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'blob:', new URL(SB_URL).origin],
      connectSrc: ["'self'", new URL(SB_URL).origin],
      mediaSrc: ["'self'", 'blob:'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"]
    }
  }
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function cookieValue(req, name) {
  const prefix = `${name}=`;
  return String(req.headers.cookie || '').split(';').map(part => part.trim()).find(part => part.startsWith(prefix))?.slice(prefix.length) || '';
}
function setSessionCookie(req, res, token) {
  const secure = req.secure || process.env.NODE_ENV === 'production';
  res.cookie('gridchat_session', token, { httpOnly: true, secure, sameSite: 'strict', path: '/', maxAge: 30 * 24 * 60 * 60 * 1000 });
}
function clearSessionCookie(req, res) {
  res.clearCookie('gridchat_session', { httpOnly: true, secure: req.secure || process.env.NODE_ENV === 'production', sameSite: 'strict', path: '/' });
}
app.use('/api', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.get('origin');
  const expectedOrigin = `${req.protocol}://${req.get('host')}`;
  if (!origin || origin !== expectedOrigin) return res.status(403).json({ error: 'İstek kaynağı doğrulanamadı' });
  next();
});
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Çok fazla giriş denemesi. Biraz sonra tekrar deneyin.' } });
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Çok fazla hesap oluşturma denemesi. Daha sonra tekrar deneyin.' } });
const uploadLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Saatlik fotoğraf yükleme sınırına ulaştınız.' } });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 600, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Çok fazla istek. Biraz sonra tekrar deneyin.' } });
app.use('/api', apiLimiter);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/^image\/(png|jpeg|gif|webp)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Sadece PNG, JPEG, GIF veya WEBP yÃ¼klenebilir'));
  }
});
function imageHasValidSignature(file) {
  const b = file.buffer;
  if (file.mimetype === 'image/png') return b.length >= 8 && b.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  if (file.mimetype === 'image/jpeg') return b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
  if (file.mimetype === 'image/gif') return b.length >= 6 && ['GIF87a', 'GIF89a'].includes(b.subarray(0, 6).toString('ascii'));
  if (file.mimetype === 'image/webp') return b.length >= 12 && b.subarray(0, 4).toString('ascii') === 'RIFF' && b.subarray(8, 12).toString('ascii') === 'WEBP';
  return false;
}

const wrap = fn => (req, res) => fn(req, res).catch(err => {
  console.error(err);
  res.status(500).json({ error: 'Sunucu hatasÄ±' });
});

async function auth(req, res, next) {
  try {
    const token = cookieValue(req, 'gridchat_session');
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
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  await sb('sessions', { method: 'POST', body: { token, user_id: userId, expires_at: expiresAt } });
  return token;
}

// Uyku önleme için sağlık kontrolü
app.get('/health', (req, res) => res.json({ ok: true }));

// Hesap
app.post('/api/register', registerLimiter, wrap(async (req, res) => {
  const username = String((req.body && req.body.username) || '').trim().toLowerCase();
  const password = String((req.body && req.body.password) || '');
  if (!USERNAME_RE.test(username))
    return res.status(400).json({ error: 'KullanÄ±cÄ± adÄ± 3-20 karakter, yalnÄ±zca kÃ¼Ã§Ã¼k harf/rakam/_ olmalÄ±' });
  if (password.length < 12)
    return res.status(400).json({ error: 'Şifre en az 12 karakter olmalı' });
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
  setSessionCookie(req, res, token);
  res.json({ user: { id: user.id, username: user.username, is_admin: user.is_admin, profile_photo: user.profile_photo, status_message: user.status_message, last_seen_at: user.last_seen_at } });
}));

app.post('/api/login', loginLimiter, wrap(async (req, res) => {
  const username = String((req.body && req.body.username) || '').trim().toLowerCase();
  const password = String((req.body && req.body.password) || '');
  const rows = await sb('users', { query: `?username=eq.${username}&select=*` });
  const user = rows[0];
  if (!user || !safeEqual(hashPassword(password, user.salt), user.password_hash))
    return res.status(401).json({ error: 'KullanÄ±cÄ± adÄ± veya ÅŸifre hatalÄ±' });
  const token = await createSession(user.id);
  setSessionCookie(req, res, token);
  res.json({ user: { id: user.id, username: user.username, is_admin: user.is_admin, profile_photo: user.profile_photo, status_message: user.status_message, last_seen_at: user.last_seen_at } });
}));

app.post('/api/logout', auth, wrap(async (req, res) => {
  await sb('sessions', { method: 'DELETE', query: `?token=eq.${req.token}` });
  clearSessionCookie(req, res);
  res.json({ ok: true });
}));

app.get('/api/me', auth, (req, res) => {
  res.json({ user: { id: req.user.id, username: req.user.username, is_admin: req.user.is_admin, profile_photo: req.user.profile_photo, status_message: req.user.status_message, last_seen_at: req.user.last_seen_at } });
});

app.patch('/api/me/password', auth, wrap(async (req, res) => {
  const currentPassword = String((req.body && req.body.current_password) || '');
  const newPassword = String((req.body && req.body.new_password) || '');
  if (newPassword.length < 12) return res.status(400).json({ error: 'Yeni şifre en az 12 karakter olmalı' });
  const [account] = await sb('users', { query: `?id=eq.${req.user.id}&select=id,salt,password_hash` });
  if (!account || !safeEqual(hashPassword(currentPassword, account.salt), account.password_hash))
    return res.status(401).json({ error: 'Mevcut şifre hatalı' });
  const salt = crypto.randomBytes(16).toString('hex');
  await sb('users', { method: 'PATCH', query: `?id=eq.${req.user.id}`, body: { salt, password_hash: hashPassword(newPassword, salt) } });
  await sb('sessions', { method: 'DELETE', query: `?user_id=eq.${req.user.id}&token=neq.${req.token}` });
  res.json({ ok: true });
}));

app.patch('/api/me/profile', auth, wrap(async (req, res) => {
  const status = String((req.body && req.body.status_message) || '').trim().slice(0, 160);
  const photo = String((req.body && req.body.profile_photo) || '').trim();
  if (photo && !photo.startsWith(PUBLIC_BASE)) return res.status(400).json({ error: 'Profil fotoğrafı geçersiz' });
  const [user] = await sb('users', { method: 'PATCH', query: `?id=eq.${req.user.id}&select=id,username,is_admin,profile_photo,status_message,last_seen_at`, body: { profile_photo: photo || null, status_message: status || null } });
  io.emit('profile:updated', { userId: user.id, profile_photo: user.profile_photo, status_message: user.status_message });
  res.json({ user });
}));

// KullanÄ±cÄ± arama (birine kullanÄ±cÄ± adÄ±yla sohbet aÃ§mak iÃ§in)
app.get('/api/users', auth, wrap(async (req, res) => {
  const q = String(req.query.q || '').toLowerCase().replace(/[^a-z0-9_]/g, '');
  if (!q) return res.json({ users: [] });
  const rows = await sb('users', {
    query: `?username=ilike.${q}*&select=id,username,profile_photo,status_message,last_seen_at&limit=20&order=username.asc`
  });
  res.json({ users: rows.filter(u => u.id !== req.user.id).map(u => ({ ...u, online: onlineUsers.has(u.id) })) });
}));

// Sohbet listesi
app.get('/api/conversations', auth, wrap(async (req, res) => {
  const mine = await sb('conversation_members', { query: `?user_id=eq.${req.user.id}&select=conversation_id` });
  const ids = mine.map(m => m.conversation_id);
  if (!ids.length) return res.json({ conversations: [] });

  const convs = await sb('conversations', { query: `?id=${inList(ids)}&select=*&order=created_at.desc` });
  const members = await sb('conversation_members', { query: `?conversation_id=${inList(ids)}&select=conversation_id,user_id,role` });
  const profiles = await profilesById(members.map(m => m.user_id));

  const result = convs.map(c => {
    const others = members
      .filter(m => m.conversation_id === c.id && m.user_id !== req.user.id)
      .map(m => profiles[m.user_id]?.username);
    const convMembers = members.filter(m => m.conversation_id === c.id);
    return {
      id: c.id,
      type: c.type,
      createdByMe: c.created_by === req.user.id,
      title: c.type === 'group' ? c.name : others[0] || 'Bilinmeyen',
      members: convMembers.map(m => profiles[m.user_id]?.username).filter(Boolean),
      memberDetails: convMembers.map(m => ({ ...profiles[m.user_id], role: m.role, online: onlineUsers.has(m.user_id) })).filter(m => m.id),
      peer: c.type === 'direct' ? convMembers.map(m => profiles[m.user_id]).find(p => p && p.id !== req.user.id) || null : null
    };
  });
  res.json({ conversations: result });
}));

// Reconcile messages missed while this browser was disconnected or closed.
app.get('/api/notifications/missed', auth, wrap(async (req, res) => {
  const memberships = await sb('conversation_members', { query: `?user_id=eq.${req.user.id}&select=conversation_id` });
  const convIds = memberships.map(m => m.conversation_id);
  if (!convIds.length) return res.json({ messages: [] });
  const [rows, convs] = await Promise.all([
    sb('messages', { query: `?conversation_id=${inList(convIds)}&sender_id=neq.${req.user.id}&select=*&order=created_at.desc&limit=100` }),
    sb('conversations', { query: `?id=${inList(convIds)}&select=id,type,name` })
  ]);
  if (!rows.length) return res.json({ messages: [] });
  const [reads, names] = await Promise.all([
    sb('message_reads', { query: `?user_id=eq.${req.user.id}&message_id=${inList(rows.map(m => m.id))}&select=message_id` }),
    usernamesById(rows.map(m => m.sender_id))
  ]);
  const readIds = new Set(reads.map(r => r.message_id));
  const titles = Object.fromEntries(convs.map(c => [c.id, c.type === 'group' ? c.name : 'Birebir sohbet']));
  const messages = rows.filter(m => !readIds.has(m.id)).map(m => ({
    ...toClient(m, names),
    conversation: titles[m.conversation_id] || 'GridChat'
  }));
  res.json({ messages });
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
    body: [{ conversation_id: conv.id, user_id: req.user.id, role: 'member' }, { conversation_id: conv.id, user_id: other.id, role: 'member' }]
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
    body: [...memberIds].map(id => ({ conversation_id: conv.id, user_id: id, role: id === req.user.id ? 'owner' : 'member' }))
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
  const ordered = rows.reverse();
  const messageIds = ordered.map(r => r.id);
  const [reads, reactions] = messageIds.length ? await Promise.all([
    sb('message_reads', { query: `?message_id=${inList(messageIds)}&select=message_id,user_id,read_at` }),
    sb('message_reactions', { query: `?message_id=${inList(messageIds)}&select=message_id,user_id,emoji` })
  ]) : [[], []];
  const messages = ordered.map(row => ({
    ...toClient(row, names, convId),
    readBy: reads.filter(r => r.message_id === row.id).map(r => r.user_id),
    reactions: reactions.filter(r => r.message_id === row.id).map(r => ({ userId: r.user_id, emoji: r.emoji }))
  }));
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

const REACTION_EMOJIS = new Set(['👍', '❤️', '😂', '😮', '😢', '🔥', '🎉', '👎']);
async function conversationForMessage(messageId, userId) {
  const rows = await sb('messages', { query: `?id=eq.${messageId}&select=id,conversation_id` });
  const msg = rows[0];
  if (!msg) return null;
  return await isMember(msg.conversation_id, userId) ? msg.conversation_id : false;
}

app.post('/api/messages/:id/reactions', auth, wrap(async (req, res) => {
  const messageId = req.params.id;
  if (!UUID_RE.test(messageId)) return res.status(400).json({ error: 'Geçersiz mesaj' });
  const emoji = String((req.body && req.body.emoji) || '');
  if (!REACTION_EMOJIS.has(emoji)) return res.status(400).json({ error: 'Bu tepki desteklenmiyor' });
  const convId = await conversationForMessage(messageId, req.user.id);
  if (convId === null) return res.status(404).json({ error: 'Mesaj bulunamadı' });
  if (convId === false) return res.status(403).json({ error: 'Bu sohbete erişiminiz yok' });
  const existing = await sb('message_reactions', { query: `?message_id=eq.${messageId}&user_id=eq.${req.user.id}&emoji=eq.${encodeURIComponent(emoji)}&select=message_id` });
  const active = existing.length === 0;
  if (active) await sb('message_reactions', { method: 'POST', body: { message_id: messageId, user_id: req.user.id, emoji } });
  else await sb('message_reactions', { method: 'DELETE', query: `?message_id=eq.${messageId}&user_id=eq.${req.user.id}&emoji=eq.${encodeURIComponent(emoji)}` });
  const all = await sb('message_reactions', { query: `?message_id=eq.${messageId}&select=user_id,emoji` });
  io.to('conv:' + convId).emit('reaction:update', { messageId, conversationId: convId, reactions: all.map(r => ({ userId: r.user_id, emoji: r.emoji })) });
  res.json({ ok: true, active });
}));

const BUCKET = 'chat-images';
const PUBLIC_BASE = `${SB_URL}/storage/v1/object/public/${BUCKET}/`;
function extFor(mime) {
  return { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/gif': '.gif', 'image/webp': '.webp' }[mime] || '';
}
async function uploadImage(file) {
  const name = crypto.randomBytes(16).toString('hex') + extFor(file.mimetype);
  const res = await fetch(`${SB_URL}/storage/v1/object/${BUCKET}/${name}`, {
    method: 'POST',
    headers: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`, 'Content-Type': file.mimetype },
    body: file.buffer
  });
  if (!res.ok) throw new Error('Storage ' + res.status + ': ' + (await res.text()));
  return PUBLIC_BASE + name;
}

// Supabase Storage'daki bir fotoğrafı sil
async function deleteStorageObject(url) {
  if (!url || !url.startsWith(PUBLIC_BASE)) return;
  const name = url.slice(PUBLIC_BASE.length);
  await fetch(`${SB_URL}/storage/v1/object/${BUCKET}/${name}`, {
    method: 'DELETE',
    headers: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}` }
  }).catch(() => {});
}

app.post('/api/upload', uploadLimiter, auth, (req, res) => {
  upload.single('photo')(req, res, async err => {
    try {
      if (err) return res.status(400).json({ error: err.message });
      if (!req.file) return res.status(400).json({ error: 'Dosya seçilmedi' });
      if (!imageHasValidSignature(req.file)) return res.status(400).json({ error: 'Dosya içeriği geçerli bir görsel değil' });
      const url = await uploadImage(req.file);
      res.json({ url });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Fotoğraf yüklenemedi' });
    }
  });
});

// YÃ¶netici
// Mesaj silme: gönderen kişi veya yönetici
app.delete('/api/messages/:id', auth, wrap(async (req, res) => {
  const id = req.params.id;
  if (!UUID_RE.test(id)) return res.status(400).json({ error: 'Geçersiz mesaj' });
  const rows = await sb('messages', { query: `?id=eq.${id}&select=*` });
  const msg = rows[0];
  if (!msg) return res.status(404).json({ error: 'Mesaj bulunamadı' });
  if (msg.sender_id !== req.user.id && !req.user.is_admin)
    return res.status(403).json({ error: 'Bu mesajı silemezsiniz' });
  await sb('messages', { method: 'DELETE', query: `?id=eq.${id}` });
  await deleteStorageObject(msg.image_path);
  io.to('conv:' + msg.conversation_id).emit('message:deleted', { id, conversationId: msg.conversation_id });
  res.json({ ok: true });
}));

async function getGroupAndRole(convId, userId) {
  const [convs, members] = await Promise.all([
    sb('conversations', { query: `?id=eq.${convId}&select=id,type,name,created_by` }),
    sb('conversation_members', { query: `?conversation_id=eq.${convId}&user_id=eq.${userId}&select=role` })
  ]);
  return { conv: convs[0], role: members[0]?.role || null };
}
function canManageGroup(user, role) {
  return user.is_admin || role === 'owner' || role === 'admin';
}

app.patch('/api/conversations/:id', auth, wrap(async (req, res) => {
  const convId = req.params.id;
  if (!UUID_RE.test(convId)) return res.status(400).json({ error: 'Geçersiz sohbet' });
  const { conv, role } = await getGroupAndRole(convId, req.user.id);
  if (!conv || conv.type !== 'group') return res.status(404).json({ error: 'Grup bulunamadı' });
  if (!canManageGroup(req.user, role)) return res.status(403).json({ error: 'Grubu yönetme yetkiniz yok' });
  const name = String((req.body && req.body.name) || '').trim().slice(0, 50);
  if (!name) return res.status(400).json({ error: 'Grup adı boş olamaz' });
  await sb('conversations', { method: 'PATCH', query: `?id=eq.${convId}`, body: { name } });
  io.to('conv:' + convId).emit('group:updated', { id: convId, name });
  io.emit('conversations:changed');
  res.json({ ok: true, name });
}));

app.post('/api/conversations/:id/members', auth, wrap(async (req, res) => {
  const convId = req.params.id;
  if (!UUID_RE.test(convId)) return res.status(400).json({ error: 'Geçersiz sohbet' });
  const { conv, role } = await getGroupAndRole(convId, req.user.id);
  if (!conv || conv.type !== 'group') return res.status(404).json({ error: 'Grup bulunamadı' });
  if (!canManageGroup(req.user, role)) return res.status(403).json({ error: 'Üye ekleme yetkiniz yok' });
  const username = String((req.body && req.body.username) || '').trim().toLowerCase();
  if (!USERNAME_RE.test(username)) return res.status(400).json({ error: 'Geçersiz kullanıcı adı' });
  const users = await sb('users', { query: `?username=eq.${username}&select=id,username` });
  const user = users[0];
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
  if (await isMember(convId, user.id)) return res.status(409).json({ error: 'Bu kullanıcı zaten grupta' });
  await sb('conversation_members', { method: 'POST', body: { conversation_id: convId, user_id: user.id, role: 'member' } });
  for (const sock of io.sockets.sockets.values()) {
    if (sock.user?.id === user.id) {
      sock.join('conv:' + convId);
      sock.conversationIds?.add(convId);
      sock.emit('conversations:changed');
    }
  }
  io.to('conv:' + convId).emit('group:members-changed', { conversationId: convId });
  io.emit('conversations:changed');
  res.json({ ok: true });
}));

app.patch('/api/conversations/:id/members/:userId', auth, wrap(async (req, res) => {
  const { id: convId, userId } = req.params;
  if (!UUID_RE.test(convId) || !UUID_RE.test(userId)) return res.status(400).json({ error: 'Geçersiz bilgi' });
  const { conv, role } = await getGroupAndRole(convId, req.user.id);
  if (!conv || conv.type !== 'group') return res.status(404).json({ error: 'Grup bulunamadı' });
  const target = await getGroupAndRole(convId, userId);
  if (!target.role) return res.status(404).json({ error: 'Üye bulunamadı' });
  if (role !== 'owner' && !req.user.is_admin) return res.status(403).json({ error: 'Yalnızca grup sahibi rol değiştirebilir' });
  if (target.role === 'owner') return res.status(400).json({ error: 'Grup sahibinin rolü değiştirilemez' });
  const nextRole = String((req.body && req.body.role) || '');
  if (!['owner', 'admin', 'member'].includes(nextRole)) return res.status(400).json({ error: 'Geçersiz grup rolü' });
  if (nextRole === 'owner') {
    if (role !== 'owner') return res.status(403).json({ error: 'Sahipliği yalnızca grup sahibi devredebilir' });
    await sbRpc('transfer_group_owner', { p_conversation_id: convId, p_from_user_id: req.user.id, p_to_user_id: userId });
  } else {
    await sb('conversation_members', { method: 'PATCH', query: `?conversation_id=eq.${convId}&user_id=eq.${userId}`, body: { role: nextRole } });
  }
  io.to('conv:' + convId).emit('group:members-changed', { conversationId: convId });
  io.emit('conversations:changed');
  res.json({ ok: true });
}));

app.delete('/api/conversations/:id/members/:userId', auth, wrap(async (req, res) => {
  const { id: convId, userId } = req.params;
  if (!UUID_RE.test(convId) || !UUID_RE.test(userId)) return res.status(400).json({ error: 'Geçersiz bilgi' });
  const { conv, role } = await getGroupAndRole(convId, req.user.id);
  if (!conv || conv.type !== 'group') return res.status(404).json({ error: 'Grup bulunamadı' });
  const target = await getGroupAndRole(convId, userId);
  if (!target.role) return res.status(404).json({ error: 'Üye bulunamadı' });
  const selfLeave = userId === req.user.id;
  if (target.role === 'owner') return res.status(400).json({ error: 'Grup sahibi gruptan ayrılamaz; önce sahipliği devredin' });
  if (!selfLeave && !canManageGroup(req.user, role)) return res.status(403).json({ error: 'Üye çıkarma yetkiniz yok' });
  await sb('conversation_members', { method: 'DELETE', query: `?conversation_id=eq.${convId}&user_id=eq.${userId}` });
  for (const sock of io.sockets.sockets.values()) {
    if (sock.user?.id === userId) {
      sock.leave('conv:' + convId);
      sock.conversationIds?.delete(convId);
      if (sharers.get(sock.id)?.conversationId === convId) stopSharing(sock);
      sock.emit('group:removed', { conversationId: convId });
      sock.emit('conversations:changed');
    }
  }
  io.to('conv:' + convId).emit('group:members-changed', { conversationId: convId });
  io.emit('conversations:changed');
  res.json({ ok: true });
}));

// Sohbet silme.
// Grup kurucusu ya da yönetici sohbeti tamamen siler.
// Diğer kullanıcılar sohbeti yalnızca kendi listesinden kaldırır.
app.delete('/api/conversations/:id', auth, wrap(async (req, res) => {
  const convId = req.params.id;
  if (!UUID_RE.test(convId)) return res.status(400).json({ error: 'Geçersiz sohbet' });
  const convs = await sb('conversations', { query: `?id=eq.${convId}&select=*` });
  const conv = convs[0];
  if (!conv) return res.status(404).json({ error: 'Sohbet bulunamadı' });

  const member = await isMember(convId, req.user.id);
  if (!member && !req.user.is_admin) return res.status(403).json({ error: 'Bu sohbete erişiminiz yok' });

  const wholeDelete = req.user.is_admin || (conv.type === 'group' && conv.created_by === req.user.id);
  if (wholeDelete) {
    const withImages = await sb('messages', { query: `?conversation_id=eq.${convId}&image_path=not.is.null&select=image_path` });
    await Promise.all(withImages.map(m => deleteStorageObject(m.image_path)));
    io.to('conv:' + convId).emit('conversation:deleted', { id: convId });
    for (const sock of io.sockets.sockets.values()) {
      sock.leave('conv:' + convId);
      sock.conversationIds?.delete(convId);
      if (sharers.get(sock.id)?.conversationId === convId) stopSharing(sock);
    }
    await sb('conversations', { method: 'DELETE', query: `?id=eq.${convId}` });
    io.emit('conversations:changed');
    return res.json({ ok: true, deleted: true });
  }

  await sb('conversation_members', { method: 'DELETE', query: `?conversation_id=eq.${convId}&user_id=eq.${req.user.id}` });
  for (const sock of io.sockets.sockets.values()) {
    if (sock.user && sock.user.id === req.user.id) {
      sock.leave('conv:' + convId);
      sock.conversationIds?.delete(convId);
      sock.emit('conversations:changed');
    }
  }
  const left = await sb('conversation_members', { query: `?conversation_id=eq.${convId}&select=user_id` });
  if (!left.length) await sb('conversations', { method: 'DELETE', query: `?id=eq.${convId}` });
  res.json({ ok: true, deleted: false });
}));

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
const io = new Server(server, {
  maxHttpBufferSize: 1e6,
  allowRequest: (req, callback) => {
    try {
      const origin = new URL(req.headers.origin || '');
      callback(null, origin.host === req.headers.host && ['http:', 'https:'].includes(origin.protocol));
    } catch {
      callback(null, false);
    }
  }
});
const sharers = new Map();
const screenLinks = new Set();
const screenLinkKey = (a, b) => [a, b].sort().join(':');

io.use(async (socket, next) => {
  try {
    const token = cookieValue({ headers: socket.handshake.headers }, 'gridchat_session');
    const user = await userFromToken(token);
    if (!user) return next(new Error('unauthorized'));
    socket.user = { id: user.id, username: user.username, is_admin: user.is_admin, profile_photo: user.profile_photo, status_message: user.status_message, last_seen_at: user.last_seen_at };
    next();
  } catch (err) {
    next(err);
  }
});

io.on('connection', async socket => {
  socket.conversationIds = new Set();
  try {
    const mine = await sb('conversation_members', { query: `?user_id=eq.${socket.user.id}&select=conversation_id` });
    mine.forEach(m => { socket.conversationIds.add(m.conversation_id); socket.join('conv:' + m.conversation_id); });
  } catch (err) {
    console.error(err);
  }
  socket.emit('sharers', [...sharers].filter(([, s]) => socket.conversationIds.has(s.conversationId)).map(([id, s]) => ({ socketId: id, username: s.username })));
  const presence = onlineUsers.get(socket.user.id) || { userId: socket.user.id, username: socket.user.username, sockets: new Set(), lastSeenAt: socket.user.last_seen_at || null };
  presence.sockets.add(socket.id);
  onlineUsers.set(socket.user.id, presence);
  socket.emit('presence:snapshot', [...onlineUsers.values()].map(u => ({ userId: u.userId, username: u.username, lastSeenAt: u.lastSeenAt })));
  io.emit('presence:user', { userId: socket.user.id, username: socket.user.username, online: true, lastSeenAt: presence.lastSeenAt });
  io.emit('presence', onlineUsers.size);

  socket.on('conversation:read', async convId => {
    try {
      if (!UUID_RE.test(convId || '') || !(await isMember(convId, socket.user.id))) return;
      const rows = await sb('messages', { query: `?conversation_id=eq.${convId}&sender_id=neq.${socket.user.id}&select=id&order=created_at.desc&limit=200` });
      if (!rows.length) return;
      const ids = rows.map(r => r.id);
      const existing = await sb('message_reads', { query: `?message_id=${inList(ids)}&user_id=eq.${socket.user.id}&select=message_id` });
      const known = new Set(existing.map(r => r.message_id));
      const unreadIds = ids.filter(id => !known.has(id));
      if (!unreadIds.length) return;
      const readAt = new Date().toISOString();
      await sb('message_reads', { method: 'POST', body: unreadIds.map(message_id => ({ message_id, user_id: socket.user.id, read_at: readAt })) });
      io.to('conv:' + convId).emit('read:update', { conversationId: convId, userId: socket.user.id, messageIds: unreadIds, readAt });
    } catch (err) {
      console.error('Okundu bilgisi kaydedilemedi:', err);
    }
  });

  socket.on('message', async (payload, ack) => {
    try {
      const now = Date.now();
      socket.messageTimes = (socket.messageTimes || []).filter(time => now - time < 60_000);
      if (socket.messageTimes.length >= 30) return ack && ack({ error: 'Çok hızlı mesaj gönderiyorsunuz. Biraz bekleyin.' });
      socket.messageTimes.push(now);
      const convId = payload && payload.conversationId;
      if (!UUID_RE.test(convId || '')) return ack && ack({ error: 'GeÃ§ersiz sohbet' });
      if (!(await isMember(convId, socket.user.id))) return ack && ack({ error: 'Bu sohbete eriÅŸiminiz yok' });

      const text = String((payload && payload.text) || '').trim().slice(0, 2000);
      const image = payload && typeof payload.image === 'string' && payload.image.startsWith(PUBLIC_BASE)
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
    if (UUID_RE.test(convId || '') && (await isMember(convId, socket.user.id))) {
      socket.conversationIds.add(convId);
      socket.join('conv:' + convId);
    }
  });

  // Ekran paylaÅŸÄ±mÄ± (sohbetten baÄŸÄ±msÄ±z, herkese aÃ§Ä±k)
  socket.on('screen:start', async (payload, ack) => {
    try {
      const conversationId = payload && payload.conversationId;
      if (!UUID_RE.test(conversationId || '') || !(await isMember(conversationId, socket.user.id))) return ack && ack({ error: 'Önce üyesi olduğunuz bir sohbeti açın' });
      stopSharing(socket);
      const share = { username: socket.user.username, userId: socket.user.id, conversationId };
      sharers.set(socket.id, share);
      io.to('conv:' + conversationId).emit('screen:started', { socketId: socket.id, username: socket.user.username });
      ack && ack({ ok: true });
    } catch (err) { ack && ack({ error: 'Ekran paylaşımı başlatılamadı' }); }
  });
  socket.on('screen:stop', () => stopSharing(socket));
  socket.on('screen:join', async (payload, ack) => {
    try {
      const to = payload && payload.to;
      const share = sharers.get(to);
      if (!share || to === socket.id || !(await isMember(share.conversationId, socket.user.id))) return ack && ack({ error: 'Bu ekran paylaşımına erişiminiz yok' });
      screenLinks.add(screenLinkKey(socket.id, to));
      io.to(to).emit('screen:viewer', { viewerId: socket.id, username: socket.user.username });
      ack && ack({ ok: true });
    } catch (err) { ack && ack({ error: 'Ekran paylaşımına bağlanılamadı' }); }
  });
  socket.on('screen:leave', payload => {
    const to = payload && payload.to;
    if (!to || !screenLinks.has(screenLinkKey(socket.id, to))) return;
    screenLinks.delete(screenLinkKey(socket.id, to));
    io.to(to).emit('screen:viewer-left', { viewerId: socket.id });
  });
  socket.on('webrtc:signal', payload => {
    const to = payload && payload.to;
    const data = payload && payload.data;
    if (!to || !screenLinks.has(screenLinkKey(socket.id, to)) || !data || typeof data !== 'object' || JSON.stringify(data).length > 65536) return;
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
  // Mikrofon ve hoparlör durumu (odadaki herkese)
  socket.on('call:state', ({ muted, deafened }) => {
    const convId = socket.callConv;
    const room = convId && callRooms.get(convId);
    if (!room) return;
    for (const id of room.keys()) {
      if (id !== socket.id) io.to(id).emit('call:state', { socketId: socket.id, muted: !!muted, deafened: !!deafened });
    }
  });

  socket.on('call:signal', ({ to, data }) => {
    const target = io.sockets.sockets.get(to);
    if (!target || !socket.callConv || target.callConv !== socket.callConv) return;
    io.to(to).emit('call:signal', { from: socket.id, data });
  });

  socket.on('disconnect', async () => {
    leaveCall(socket);
    stopSharing(socket);
    for (const link of [...screenLinks]) {
      if (!link.split(':').includes(socket.id)) continue;
      screenLinks.delete(link);
      const [a, b] = link.split(':');
      const other = a === socket.id ? b : a;
      io.to(other).emit('screen:viewer-left', { viewerId: socket.id });
    }
    const presence = onlineUsers.get(socket.user.id);
    if (presence) {
      presence.sockets.delete(socket.id);
      if (!presence.sockets.size) {
        onlineUsers.delete(socket.user.id);
        const lastSeenAt = new Date().toISOString();
        await sb('users', { method: 'PATCH', query: `?id=eq.${socket.user.id}`, body: { last_seen_at: lastSeenAt } }).catch(err => console.error('Son görülme kaydedilemedi:', err));
        io.emit('presence:user', { userId: socket.user.id, username: socket.user.username, online: false, lastSeenAt });
      }
    }
    io.emit('presence', onlineUsers.size);
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
  const share = sharers.get(socket.id);
  if (!share) return;
  sharers.delete(socket.id);
  for (const link of [...screenLinks]) {
    if (!link.split(':').includes(socket.id)) continue;
    screenLinks.delete(link);
  }
  io.to('conv:' + share.conversationId).emit('screen:stopped', { socketId: socket.id });
}

ensureAdmin()
  .catch(err => console.error('YÃ¶netici hesabÄ± oluÅŸturulamadÄ±:', err.message))
  .finally(() => {
    server.listen(PORT, () => console.log(`Sunucu Ã§alÄ±ÅŸÄ±yor: port ${PORT}`));
  });


