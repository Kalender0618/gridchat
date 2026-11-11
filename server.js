const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');

// ---------- basit JSON veritabanı ----------
let db = { users: [], sessions: {}, messages: [] };
if (fs.existsSync(DATA_FILE)) {
  try { db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (e) { console.error('data.json okunamadı', e); }
}
let saveTimer = null;
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => fs.writeFile(DATA_FILE, JSON.stringify(db, null, 2), () => {}), 200);
}

// ---------- şifre (scrypt, ek paket gerektirmez) ----------
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}
function publicUser(u) {
  return { id: u.id, username: u.username };
}
function userFromToken(token) {
  const s = db.sessions[token];
  if (!s) return null;
  return db.users.find(u => u.id === s.userId) || null;
}

// ---------- uygulama ----------
const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, crypto.randomBytes(12).toString('hex') + ext);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/^image\/(png|jpeg|gif|webp)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Sadece PNG, JPEG, GIF veya WEBP yüklenebilir'));
  }
});

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const user = userFromToken(token);
  if (!user) return res.status(401).json({ error: 'Giriş yapmalısınız' });
  req.user = user;
  next();
}

// Hesap oluşturma
app.post('/api/register', (req, res) => {
  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
    return res.status(400).json({ error: 'Kullanıcı adı 3-20 karakter, harf/rakam/_ olmalı' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Şifre en az 6 karakter olmalı' });
  if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(409).json({ error: 'Bu kullanıcı adı alınmış' });

  const salt = crypto.randomBytes(16).toString('hex');
  const user = { id: crypto.randomUUID(), username, salt, hash: hashPassword(password, salt), createdAt: Date.now() };
  db.users.push(user);
  const token = makeToken();
  db.sessions[token] = { userId: user.id, createdAt: Date.now() };
  save();
  res.json({ token, user: publicUser(user) });
});

// Giriş
app.post('/api/login', (req, res) => {
  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı' });
  const given = Buffer.from(hashPassword(password, user.salt), 'hex');
  const real = Buffer.from(user.hash, 'hex');
  if (given.length !== real.length || !crypto.timingSafeEqual(given, real))
    return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı' });
  const token = makeToken();
  db.sessions[token] = { userId: user.id, createdAt: Date.now() };
  save();
  res.json({ token, user: publicUser(user) });
});

// Çıkış
app.post('/api/logout', auth, (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  delete db.sessions[token];
  save();
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// Sohbet geçmişi (son 200 mesaj)
app.get('/api/messages', auth, (req, res) => {
  res.json({ messages: db.messages.slice(-200) });
});

// Fotoğraf yükleme
app.post('/api/upload', auth, (req, res) => {
  upload.single('photo')(req, res, err => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'Dosya seçilmedi' });
    res.json({ url: '/uploads/' + req.file.filename });
  });
});

// ---------- Socket.IO: anlık mesajlaşma + ekran paylaşımı sinyalleşmesi ----------
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e6 });

// Ekran paylaşan kullanıcılar: socketId -> { username }
const sharers = new Map();

io.use((socket, next) => {
  const user = userFromToken(socket.handshake.auth && socket.handshake.auth.token);
  if (!user) return next(new Error('unauthorized'));
  socket.user = publicUser(user);
  next();
});

io.on('connection', socket => {
  socket.emit('sharers', [...sharers].map(([id, s]) => ({ socketId: id, username: s.username })));
  io.emit('presence', countOnline());

  socket.on('message', (payload, ack) => {
    const text = String((payload && payload.text) || '').trim().slice(0, 2000);
    const image = payload && typeof payload.image === 'string' && payload.image.startsWith('/uploads/')
      ? payload.image : null;
    if (!text && !image) return ack && ack({ error: 'Boş mesaj gönderilemez' });
    const msg = {
      id: crypto.randomUUID(),
      from: socket.user.username,
      userId: socket.user.id,
      text,
      image,
      createdAt: Date.now()
    };
    db.messages.push(msg);
    if (db.messages.length > 5000) db.messages.splice(0, db.messages.length - 5000);
    save();
    io.emit('message', msg);
    ack && ack({ ok: true });
  });

  // Ekran paylaşımı başlat / durdur
  socket.on('screen:start', () => {
    sharers.set(socket.id, { username: socket.user.username });
    io.emit('screen:started', { socketId: socket.id, username: socket.user.username });
  });

  socket.on('screen:stop', () => stopSharing(socket));

  // İzleyici, paylaşımı izlemek istediğini bildirir
  socket.on('screen:join', ({ to }) => {
    if (!sharers.has(to)) return;
    io.to(to).emit('screen:viewer', { viewerId: socket.id, username: socket.user.username });
  });

  // WebRTC sinyalleri (offer / answer / ICE) doğrudan karşı tarafa iletilir
  socket.on('webrtc:signal', ({ to, data }) => {
    io.to(to).emit('webrtc:signal', { from: socket.id, data });
  });

  socket.on('disconnect', () => {
    stopSharing(socket);
    io.emit('presence', countOnline());
  });
});

function stopSharing(socket) {
  if (!sharers.has(socket.id)) return;
  sharers.delete(socket.id);
  io.emit('screen:stopped', { socketId: socket.id });
}

function countOnline() {
  return io.engine.clientsCount;
}

server.listen(PORT, () => {
  console.log(`Sunucu çalışıyor: http://localhost:${PORT}`);
});
