#!/usr/bin/env node
// Сервер планировщика: без зависимостей, нужен Node.js 16+.
// Запуск: node server.js   (порт: PORT=8080 node server.js)
// Пароль разработчика: переменная DEV_PASSWORD или случайный пароль, который печатается при первом запуске.
// Данные (студенты, настройки, хэш пароля) лежат в data.json рядом с файлом.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const FILE = path.join(__dirname, 'data.json');
const MAX_BODY = 2e6;
const NAME_RE = /^\p{L}[\p{L}'’.\-]*(\s+\p{L}[\p{L}'’.\-]*)+$/u;

const db = { users: [], config: { serverUrl: '', announcement: '', allowSignup: true }, dev: null };
try {
  const d = JSON.parse(fs.readFileSync(FILE, 'utf8'));
  db.users = d.users || []; Object.assign(db.config, d.config || {}); db.dev = d.dev || null;
} catch (e) {}
function persist() {
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, FILE);
}

/* ---------- пароль разработчика ---------- */
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
function setPw(pw) { const salt = crypto.randomBytes(16).toString('hex'); db.dev = { salt, hash: hashPw(pw, salt) }; persist(); }
function checkPw(pw) {
  if (!db.dev) return false;
  const a = Buffer.from(hashPw(String(pw), db.dev.salt), 'hex'), b = Buffer.from(db.dev.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
if (process.env.DEV_PASSWORD) { setPw(process.env.DEV_PASSWORD); console.log('Пароль разработчика взят из DEV_PASSWORD'); }
else if (!db.dev) { const pw = crypto.randomBytes(6).toString('hex'); setPw(pw); console.log('Пароль разработчика (смените в меню): ' + pw); }

const tokens = new Map();   // токен -> время окончания
const fails = new Map();    // ip -> { n, until }
const authed = req => {
  const m = /^Bearer (\w+)$/.exec(req.headers.authorization || '');
  const exp = m && tokens.get(m[1]);
  if (!exp) return false;
  if (exp < Date.now()) { tokens.delete(m[1]); return false; }
  return true;
};

/* ---------- данные ---------- */
const norm = s => String(s == null ? '' : s).replace(/\s+/g, ' ').trim();
const key = s => norm(s).toLowerCase();
const str = (v, n) => String(v == null ? '' : v).slice(0, n);
const arr = (v, n) => (Array.isArray(v) ? v.slice(0, n) : []);

// Публичный вид: чужие задачи, примечания и комментарии наружу не отдаются
const pub = u => ({
  id: u.id, pub: true, profile: u.profile,
  subjects: u.subjects.map(s => ({ id: s.id, name: s.name, tasks: s.tasks.map(t => ({ status: t.status, due: t.due })) }))
});
function clean(id, b) {
  if (!b || typeof b !== 'object' || !Array.isArray(b.subjects)) return null;
  const p = b.profile || {};
  return {
    id,
    profile: { name: norm(str(p.name, 100)), group: str(p.group, 20), email: str(p.email, 100) },
    subjects: arr(b.subjects, 100).map(s => ({
      id: str(s.id, 40), name: str(s.name, 80), description: str(s.description, 1000),
      comments: arr(s.comments, 500).map(c => ({ id: str(c.id, 40), text: str(c.text, 500), at: str(c.at, 40) })),
      tasks: arr(s.tasks, 500).map(t => ({
        id: str(t.id, 40), title: str(t.title, 120), type: str(t.type, 30),
        due: str(t.due, 10), status: str(t.status, 20), notes: str(t.notes, 400)
      }))
    }))
  };
}

/* ---------- HTTP ---------- */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization'
};
function send(res, code, data) {
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, CORS));
  res.end(data === undefined ? '' : JSON.stringify(data));
}
function readBody(req, cb) {
  let size = 0; const chunks = [];
  req.on('data', c => { size += c.length; if (size > MAX_BODY) req.destroy(); else chunks.push(c); });
  req.on('end', () => { try { cb(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch (e) { cb(null); } });
}

http.createServer((req, res) => {
  const url = req.url.split('?')[0], M = req.method;
  if (M === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }

  if (url === '/' || url === '/index.html') {
    return fs.readFile(path.join(__dirname, 'index.html'), (err, html) => {
      if (err) { res.writeHead(404); return res.end('index.html не найден рядом с server.js'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(html);
    });
  }

  /* --- публичное API --- */
  if (url === '/api/config' && M === 'GET') return send(res, 200, db.config);
  if (url === '/api/users' && M === 'GET') return send(res, 200, db.users.map(pub));

  if (url === '/api/login' && M === 'POST') {
    return readBody(req, b => {
      const name = norm(b && b.name);
      if (!name || name.length > 100 || !NAME_RE.test(name)) return send(res, 400, { error: 'bad name' });
      let u = db.users.find(x => key(x.profile.name) === key(name)), created = false;
      if (!u) {
        if (!db.config.allowSignup) return send(res, 403, { error: 'signup disabled' });
        u = { id: crypto.randomBytes(6).toString('hex'), profile: { name, group: '', email: '' }, subjects: [] };
        db.users.push(u); persist(); created = true;
      }
      send(res, 200, { id: u.id, created });
    });
  }

  let m = url.match(/^\/api\/users\/([A-Za-z0-9_-]{1,40})$/);
  if (m) {
    const id = m[1], i = db.users.findIndex(u => u.id === id);
    if (i < 0) return send(res, 404, { error: 'not found' });
    if (M === 'GET') return send(res, 200, db.users[i]);
    if (M === 'PUT') {
      return readBody(req, b => {
        const u = clean(id, b);
        if (!u) return send(res, 400, { error: 'bad request' });
        if (u.profile.name && db.users.some(o => o.id !== id && key(o.profile.name) === key(u.profile.name))) return send(res, 409, { error: 'name taken' });
        db.users[i] = u; persist(); send(res, 200, { ok: true });
      });
    }
    return send(res, 405, { error: 'method not allowed' });
  }

  /* --- меню разработчика --- */
  if (url === '/api/dev/login' && M === 'POST') {
    const ip = req.socket.remoteAddress, f = fails.get(ip) || { n: 0, until: 0 };
    if (f.until > Date.now()) return send(res, 429, { error: 'too many attempts' });
    return readBody(req, b => {
      if (!b || !checkPw(b.password)) {
        f.n++; if (f.n >= 5) { f.n = 0; f.until = Date.now() + 60000; }
        fails.set(ip, f); return send(res, 401, { error: 'wrong password' });
      }
      fails.delete(ip);
      const token = crypto.randomBytes(24).toString('hex');
      tokens.set(token, Date.now() + 2 * 3600e3);
      send(res, 200, { token });
    });
  }
  if (url.startsWith('/api/dev/')) {
    if (!authed(req)) return send(res, 401, { error: 'unauthorized' });

    if (url === '/api/dev/state' && M === 'GET') {
      return send(res, 200, { config: db.config, users: db.users.map(u => ({
        id: u.id, name: u.profile.name, group: u.profile.group, tasks: u.subjects.reduce((n, s) => n + s.tasks.length, 0) })) });
    }
    if (url === '/api/dev/backup' && M === 'GET') return send(res, 200, { exported: new Date().toISOString(), config: db.config, users: db.users });
    if (url === '/api/dev/config' && M === 'PUT') {
      return readBody(req, b => {
        const su = norm(b && b.serverUrl).replace(/\/+$/, '');
        if (!b || (su && (su.length > 200 || !/^https?:\/\/\S+$/.test(su)))) return send(res, 400, { error: 'bad url' });
        db.config = { serverUrl: su, announcement: str(b.announcement, 300).trim(), allowSignup: !!b.allowSignup };
        persist(); send(res, 200, db.config);
      });
    }
    if (url === '/api/dev/password' && M === 'POST') {
      return readBody(req, b => {
        if (!b || typeof b.password !== 'string' || b.password.length < 8 || b.password.length > 100) return send(res, 400, { error: 'weak password' });
        setPw(b.password); tokens.clear(); send(res, 200, { ok: true });
      });
    }
    m = url.match(/^\/api\/dev\/users\/([A-Za-z0-9_-]{1,40})$/);
    if (m && M === 'DELETE') {
      db.users = db.users.filter(u => u.id !== m[1]); persist(); return send(res, 204);
    }
  }
  send(res, 404, { error: 'not found' });
}).listen(PORT, () => console.log('Планировщик: http://localhost:' + PORT + '  (данные: ' + FILE + ')'));
