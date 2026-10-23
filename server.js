require('dotenv').config();
const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const Database = require('better-sqlite3'), path = require('path'), fs = require('fs');

const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 16) { console.error('JWT_SECRET (16+ chars) is required'); process.exit(1); }
const PROD = process.env.NODE_ENV === 'production';
const dbPath = process.env.DB_PATH || './data/leads.db';
fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL'); db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'sales' CHECK(role IN ('admin','sales')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS leads(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT, company TEXT, service TEXT,
  status TEXT NOT NULL DEFAULT 'New' CHECK(status IN ('New','Contacted','Qualified','Converted','Lost')),
  follow_up_date TEXT, notes TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE INDEX IF NOT EXISTS idx_leads_user_status ON leads(user_id, status);
CREATE INDEX IF NOT EXISTS idx_leads_created ON leads(created_at);`);

const STATUSES = ['New', 'Contacted', 'Qualified', 'Converted', 'Lost'];
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

function validateLead(b, partial) {
  const errs = {}, o = {};
  o.name = str(b.name, 100); if (!o.name) errs.name = 'Name is required';
  o.email = str(b.email, 150).toLowerCase(); if (!EMAIL.test(o.email)) errs.email = 'Valid email is required';
  o.phone = str(b.phone, 20); if (o.phone && !/^[+\d][\d\s()-]{6,19}$/.test(o.phone)) errs.phone = 'Invalid phone number';
  o.company = str(b.company, 100); o.service = str(b.service, 100); o.notes = str(b.notes, 2000);
  o.status = b.status || 'New'; if (!STATUSES.includes(o.status)) errs.status = 'Invalid status';
  o.follow_up_date = str(b.follow_up_date, 10) || null;
  if (o.follow_up_date && !/^\d{4}-\d{2}-\d{2}$/.test(o.follow_up_date)) errs.follow_up_date = 'Use YYYY-MM-DD';
  return { errs, o };
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'],
  styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'] } } }));
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.use('/api/auth/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts, try again later' } }));
app.use('/api/auth/register', rateLimit({ windowMs: 60 * 60 * 1000, max: 20, message: { error: 'Too many attempts, try again later' } }));

const setCookie = (res, u) => res.cookie('token', jwt.sign({ id: u.id, role: u.role }, SECRET, { expiresIn: '8h' }),
  { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge: 8 * 3600 * 1000 });
const pub = u => ({ id: u.id, name: u.name, email: u.email, role: u.role });

function auth(req, res, next) {
  try {
    const p = jwt.verify(req.cookies.token, SECRET);
    const u = db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(p.id);
    if (!u) throw 0; req.user = u; next();
  } catch { res.status(401).json({ error: 'Authentication required' }); }
}

// ---- Auth ----
app.post('/api/auth/register', (req, res) => {
  const name = str(req.body.name, 100), email = str(req.body.email, 150).toLowerCase(), pw = req.body.password;
  const details = {};
  if (!name) details.name = 'Name is required';
  if (!EMAIL.test(email)) details.email = 'Valid email is required';
  if (typeof pw !== 'string' || pw.length < 8 || !/[A-Za-z]/.test(pw) || !/\d/.test(pw)) details.password = 'Min 8 characters with a letter and a number';
  if (Object.keys(details).length) return res.status(400).json({ error: 'Validation failed', details });
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return res.status(409).json({ error: 'Email already registered' });
  const hash = bcrypt.hashSync(pw, 12);
  const first = !db.prepare('SELECT 1 FROM users LIMIT 1').get();
  const id = db.prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)').run(name, email, hash, first ? 'admin' : 'sales').lastInsertRowid;
  const u = db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(id);
  setCookie(res, u); res.status(201).json({ user: pub(u) });
});
app.post('/api/auth/login', (req, res) => {
  const email = str(req.body.email, 150).toLowerCase();
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || typeof req.body.password !== 'string' || !bcrypt.compareSync(req.body.password, u.password_hash))
    return res.status(401).json({ error: 'Invalid email or password' });
  setCookie(res, u); res.json({ user: pub(u) });
});
app.post('/api/auth/logout', (req, res) => { res.clearCookie('token'); res.status(204).end(); });
app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));

// ---- Leads (admins see all leads, sales see their own) ----
const scope = u => (u.role === 'admin' ? { sql: '1=1', args: [] } : { sql: 'user_id=?', args: [u.id] });
function filters(req) {
  const s = scope(req.user), w = [s.sql], a = [...s.args], { q, status, from, to } = req.query;
  if (q) { w.push('(name LIKE ? OR email LIKE ? OR phone LIKE ?)'); const l = `%${String(q).slice(0, 100)}%`; a.push(l, l, l); }
  if (STATUSES.includes(status)) { w.push('status=?'); a.push(status); }
  if (/^\d{4}-\d{2}-\d{2}$/.test(from || '')) { w.push('date(created_at)>=?'); a.push(from); }
  if (/^\d{4}-\d{2}-\d{2}$/.test(to || '')) { w.push('date(created_at)<=?'); a.push(to); }
  return { where: w.join(' AND '), args: a };
}
app.get('/api/leads/stats', auth, (req, res) => {
  const s = scope(req.user);
  const rows = db.prepare(`SELECT status, COUNT(*) c FROM leads WHERE ${s.sql} GROUP BY status`).all(...s.args);
  const by = Object.fromEntries(STATUSES.map(x => [x, 0])); rows.forEach(r => by[r.status] = r.c);
  const daily = db.prepare(`SELECT date(created_at) d, COUNT(*) c FROM leads WHERE ${s.sql} AND created_at>=date('now','-13 days') GROUP BY d ORDER BY d`).all(...s.args);
  res.json({ total: Object.values(by).reduce((x, y) => x + y, 0), byStatus: by, daily });
});
app.get('/api/leads/export.csv', auth, (req, res) => {
  const f = filters(req);
  const rows = db.prepare(`SELECT name,email,phone,company,service,status,follow_up_date,notes,created_at FROM leads WHERE ${f.where} ORDER BY created_at DESC`).all(...f.args);
  const cell = v => { let t = String(v ?? ''); if (/^[=+\-@]/.test(t)) t = "'" + t; return `"${t.replace(/"/g, '""')}"`; };
  const head = 'Name,Email,Phone,Company,Service,Status,Follow-up,Notes,Created';
  res.type('text/csv').attachment('leads.csv').send([head, ...rows.map(r => Object.values(r).map(cell).join(','))].join('\n'));
});
app.get('/api/leads', auth, (req, res) => {
  const f = filters(req), page = Math.max(1, parseInt(req.query.page) || 1), limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 10));
  const total = db.prepare(`SELECT COUNT(*) c FROM leads WHERE ${f.where}`).get(...f.args).c;
  const data = db.prepare(`SELECT * FROM leads WHERE ${f.where} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`).all(...f.args, limit, (page - 1) * limit);
  res.json({ data, page, limit, total, pages: Math.max(1, Math.ceil(total / limit)) });
});
const find = req => { const s = scope(req.user); return db.prepare(`SELECT * FROM leads WHERE id=? AND ${s.sql}`).get(Number(req.params.id) || 0, ...s.args); };
app.get('/api/leads/:id', auth, (req, res) => { const l = find(req); l ? res.json(l) : res.status(404).json({ error: 'Lead not found' }); });
app.post('/api/leads', auth, (req, res) => {
  const { errs, o } = validateLead(req.body);
  if (Object.keys(errs).length) return res.status(400).json({ error: 'Validation failed', details: errs });
  const id = db.prepare('INSERT INTO leads(user_id,name,email,phone,company,service,status,follow_up_date,notes) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(req.user.id, o.name, o.email, o.phone, o.company, o.service, o.status, o.follow_up_date, o.notes).lastInsertRowid;
  res.status(201).json(db.prepare('SELECT * FROM leads WHERE id=?').get(id));
});
app.put('/api/leads/:id', auth, (req, res) => {
  const l = find(req); if (!l) return res.status(404).json({ error: 'Lead not found' });
  const { errs, o } = validateLead({ ...l, ...req.body });
  if (Object.keys(errs).length) return res.status(400).json({ error: 'Validation failed', details: errs });
  db.prepare('UPDATE leads SET name=?,email=?,phone=?,company=?,service=?,status=?,follow_up_date=?,notes=? WHERE id=?')
    .run(o.name, o.email, o.phone, o.company, o.service, o.status, o.follow_up_date, o.notes, l.id);
  res.json(db.prepare('SELECT * FROM leads WHERE id=?').get(l.id));
});
app.delete('/api/leads/:id', auth, (req, res) => {
  const l = find(req); if (!l) return res.status(404).json({ error: 'Lead not found' });
  db.prepare('DELETE FROM leads WHERE id=?').run(l.id); res.status(204).end();
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint not found' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON' });
  console.error(err); res.status(500).json({ error: 'Internal server error' });
});

if (process.env.SEED_DEMO === 'true' && !db.prepare('SELECT 1 FROM users').get()) {
  const id = db.prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)').run('Demo Admin', 'demo@swan.test', bcrypt.hashSync('Demo@1234', 12), 'admin').lastInsertRowid;
  const ins = db.prepare('INSERT INTO leads(user_id,name,email,phone,company,service,status,follow_up_date,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,datetime(\'now\',?))');
  [['Aarav Mehta', 'Brightline Retail', 'SEO', 'New'], ['Priya Nair', 'Kora Foods', 'Social Media', 'Contacted'], ['Rohan Das', 'Nimbus Tech', 'Web Development', 'Qualified'],
   ['Sara Khan', 'Loom Studio', 'Google Ads', 'Converted'], ['Vikram Rao', 'Orbit Labs', 'Branding', 'Lost'], ['Meera Iyer', 'Greenleaf', 'Email Marketing', 'New'],
   ['Kabir Shah', 'Atlas Realty', 'SEO', 'Contacted'], ['Ananya Roy', 'Pixel & Co', 'Web Development', 'Qualified']].forEach((x, i) =>
    ins.run(id, x[0], x[0].split(' ')[0].toLowerCase() + '@example.com', '+91 98765 4' + (3210 + i), x[1], x[2], x[3], null, 'Sample lead', `-${i} days`));
}
app.listen(process.env.PORT || 3000, () => console.log('Lead Management System running'));
