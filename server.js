'use strict';
/**
 * Team Project Tracker — real-time server (Node 22.13+, no npm packages).
 * Data lives in one SQLite database file, DATA_DIR/tracker.db (tasks, attachments, revision).
 *
 *   GET    /api/tasks        -> all tasks (JSON array, board order)
 *   POST   /api/tasks        -> { upsert: [task], bases, delete: [id] }  (merged per task)
 *   GET    /api/live         -> Server-Sent Events; "change" fires whenever the database revision moves
 *   POST   /api/files        -> raw upload (max 5 MB), returns { url, type, size }
 *   GET    /api/files/:id    -> download / view an uploaded file
 *   DELETE /api/files/:id    -> remove an uploaded file
 *   GET    /healthz          -> "ok" (checks the database)
 *
 * Environment variables:
 *   PORT           port to listen on                (default 3000)
 *   DATA_DIR       where the database lives         (default ./data) — put this on a persistent disk!
 *   SITE_USER / SITE_PASSWORD   optional: require a browser password prompt for the whole site
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const PUBLIC_DIR = path.join(__dirname, 'public');
const MIGRATIONS_DIR = path.join(__dirname, 'migrations');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const DB_FILE = path.join(DATA_DIR, 'tracker.db');
// Pre-database layout (tasks.json + files/), imported once on first start.
const LEGACY_TASKS = path.join(DATA_DIR, 'tasks.json');
const LEGACY_FILES = path.join(DATA_DIR, 'files');
const MAX_FILE = 5 * 1024 * 1024;       // 5 MB, same limit as the web app
const MAX_JSON = 20 * 1024 * 1024;      // generous: large Excel imports
const SITE_USER = process.env.SITE_USER || '';
const SITE_PASSWORD = process.env.SITE_PASSWORD || '';

for (const d of [DATA_DIR, BACKUP_DIR]) fs.mkdirSync(d, { recursive: true });

/* ----------------------------------------------------------------- database */
const db = new DatabaseSync(DB_FILE);
db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;');

function tx(fn) {                                       // all-or-nothing, and serialised against other writers
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { try { db.exec('ROLLBACK'); } catch { /* already rolled back */ } throw e; }
}

function migrate() {
  db.exec('CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)');
  const done = new Set(db.prepare('SELECT name FROM schema_migrations').all().map(r => r.name));
  for (const f of fs.readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith('.sql')).sort()) {
    if (done.has(f)) continue;
    tx(() => {
      db.exec(fs.readFileSync(path.join(MIGRATIONS_DIR, f), 'utf8'));
      db.prepare('INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)').run(f, new Date().toISOString());
    });
    console.log('Applied migration ' + f);
  }
}
migrate();

const q = {
  rev: db.prepare("SELECT CAST(value AS INTEGER) AS v FROM meta WHERE key = 'rev'"),
  setRev: db.prepare("UPDATE meta SET value = ? WHERE key = 'rev'"),
  all: db.prepare('SELECT data FROM tasks ORDER BY position, id'),
  one: db.prepare('SELECT data FROM tasks WHERE id = ?'),
  minPos: db.prepare('SELECT COALESCE(MIN(position), 0) AS p FROM tasks'),
  insert: db.prepare('INSERT INTO tasks (id, position, data, rev, updated_at) VALUES (?, ?, ?, ?, ?)'),
  update: db.prepare('UPDATE tasks SET data = ?, rev = ?, updated_at = ? WHERE id = ?'),
  remove: db.prepare('DELETE FROM tasks WHERE id = ?'),
  fileIns: db.prepare('INSERT OR IGNORE INTO files (id, name, type, size, created_at, content) VALUES (?, ?, ?, ?, ?, ?)'),
  fileGet: db.prepare('SELECT name, type, size, content FROM files WHERE id = ?'),
  fileDel: db.prepare('DELETE FROM files WHERE id = ?'),
};
const currentRev = () => q.rev.get().v;
const allTasks = () => q.all.all().map(r => JSON.parse(r.data));

/* One-time import of the old tasks.json + files/ folder (originals are left untouched). */
function importLegacy() {
  if (db.prepare("SELECT 1 FROM meta WHERE key = 'legacy_imported'").get()) return;
  const markDone = () => db.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES ('legacy_imported', ?)").run(new Date().toISOString());
  if (!fs.existsSync(LEGACY_TASKS) && !fs.existsSync(LEGACY_FILES)) return markDone();

  let legacy = [];
  if (fs.existsSync(LEGACY_TASKS)) {
    const readArr = f => { const v = JSON.parse(fs.readFileSync(f, 'utf8')); if (!Array.isArray(v)) throw new Error('not an array'); return v; };
    try { legacy = readArr(LEGACY_TASKS); }
    catch (e) {
      console.error(`tasks.json was unreadable (${e.message}); trying old backups`);
      const olds = fs.readdirSync(BACKUP_DIR).filter(f => /^tasks-.*\.json$/.test(f)).sort().reverse();
      let ok = false;
      for (const b of olds) { try { legacy = readArr(path.join(BACKUP_DIR, b)); console.error('Using backup ' + b); ok = true; break; } catch { /* older */ } }
      if (!ok) { console.error('Could not import tasks.json — fix or remove it and restart. Starting without it.'); return; }
    }
  }
  const stats = tx(() => {
    let t = 0, f = 0;
    if (!q.all.all().length) {
      const now = new Date().toISOString(), seen = new Set();
      legacy.forEach((task, i) => {
        if (!task || typeof task.id !== 'string' || seen.has(task.id)) return;
        seen.add(task.id); q.insert.run(task.id, i, JSON.stringify(task), 0, now); t++;
      });
    }
    if (fs.existsSync(LEGACY_FILES)) {
      for (const name of fs.readdirSync(LEGACY_FILES).filter(n => /^[a-f0-9]{24}\.json$/.test(n))) {
        const id = name.slice(0, -5);
        try {
          const meta = JSON.parse(fs.readFileSync(path.join(LEGACY_FILES, name), 'utf8'));
          const buf = fs.readFileSync(path.join(LEGACY_FILES, id + '.bin'));
          q.fileIns.run(id, String(meta.name || 'file'), String(meta.type || 'application/octet-stream'), buf.length, meta.created || new Date().toISOString(), buf); f++;
        } catch { /* skip a broken pair */ }
      }
    }
    if (t) q.setRev.run(String(currentRev() + 1));
    markDone();
    return { t, f };
  });
  console.log(`Imported ${stats.t} task(s) and ${stats.f} file(s) from the old tasks.json layout (originals kept in ${DATA_DIR}).`);
}
importLegacy();

/* Hourly consistent snapshot of the whole database (tasks + attachments); newest 100 kept. */
function backup() {
  try {
    const f = path.join(BACKUP_DIR, `tracker-${new Date().toISOString().replace(/[:.]/g, '-')}.db`);
    db.exec(`VACUUM INTO '${f.replace(/'/g, "''")}'`);
    const old = fs.readdirSync(BACKUP_DIR).filter(n => /^tracker-.*\.db$/.test(n)).sort().reverse().slice(100);
    for (const n of old) fs.unlinkSync(path.join(BACKUP_DIR, n));
  } catch (e) { console.error('backup failed:', e.message); }
}
{
  const newest = fs.readdirSync(BACKUP_DIR).filter(n => /^tracker-.*\.db$/.test(n)).sort().pop();
  const age = newest ? Date.now() - fs.statSync(path.join(BACKUP_DIR, newest)).mtimeMs : Infinity;
  if (age > 60 * 60 * 1000) backup();
  setInterval(backup, 60 * 60 * 1000).unref();
}

const FILE_ID = /^[a-f0-9]{24}$/;
function fileIdsOf(task) {
  return (task.refs || []).filter(r => r && r.file && typeof r.url === 'string' && r.url.startsWith('/api/files/'))
    .map(r => r.url.slice('/api/files/'.length));
}

/* ------------------------------------------------- real-time (database revision) */
// The revision lives in the database and moves in the same transaction as each change.
// Browsers get it as the event id, and send it back when they reconnect so they catch up.
const clients = new Set();
let announced = currentRev();
const version = () => String(announced);

function announceIfMoved() {
  let r;
  try { r = currentRev(); } catch { return; }
  if (r === announced) return;
  announced = r;
  const msg = `event: change\ndata: ${version()}\n\n`;
  for (const res of clients) { try { res.write(msg); } catch { clients.delete(res); } }
}
// Also notices writes made by anything else touching the same database file.
setInterval(announceIfMoved, 1500).unref();
setInterval(() => { for (const res of clients) { try { res.write(': ping\n\n'); } catch { clients.delete(res); } } }, 20000).unref();

function handleLive(req, res, url) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',                          // stop nginx-style proxies from buffering the stream
  });
  res.write('retry: 1000\n');
  res.write(`event: hello\ndata: ${version()}\n\n`);
  const seen = url.searchParams.get('v');
  if (seen && seen !== version()) res.write(`event: change\ndata: ${version()}\n\n`);   // catch up after a reconnect
  clients.add(res);
  req.on('close', () => clients.delete(res));
}

/* ------------------------------------------------------------------ helpers */
function send(res, status, body, headers = {}) {
  const isObj = body !== null && typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(status, { 'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(isObj ? JSON.stringify(body) : body);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (declared > limit) return reject({ status: 413 });
    const chunks = []; let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject({ status: 413 }); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', () => reject({ status: 400 }));
  });
}

function authorised(req) {
  if (!SITE_USER && !SITE_PASSWORD) return true;
  const h = req.headers.authorization || '';
  if (!h.startsWith('Basic ')) return false;
  const [u, ...rest] = Buffer.from(h.slice(6), 'base64').toString('utf8').split(':');
  const p = rest.join(':');
  const eq = (a, b) => { const x = crypto.createHash('sha256').update(a).digest(), y = crypto.createHash('sha256').update(b).digest(); return crypto.timingSafeEqual(x, y); };
  const okUser = eq(u, SITE_USER), okPass = eq(p, SITE_PASSWORD);   // evaluate both so timing doesn't leak which was wrong
  return okUser && okPass;
}

/* ------------------------------------------------------------- merging edits
 * Every browser sends, for each task it saved, the task as it looked when it last synced
 * ("base") plus the task now. The server works out WHAT THAT PERSON CHANGED and applies
 * only those changes on top of the newest version. So two people editing the same task at
 * the same moment both keep their edits: notes from one, progress from the other, problem
 * reports from both, etc. Only if two people change the very same field at the very same
 * moment does one value win (the one that reaches the server second).
 */
function canon(v) {
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().filter(k => v[k] !== undefined).map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return JSON.stringify(v) === undefined ? 'undefined' : JSON.stringify(v);
}
const same = (a, b) => canon(a) === canon(b);

// Lists whose items have an identity, so additions/removals from different people are combined.
const LISTS = {
  problems: { key: x => x && x.id, addAt: 'front' },
  refs: { key: x => x && x.url, addAt: 'end' },
};

function mergeFields(current, base, mine, lists) {
  const out = { ...current };
  for (const k of new Set([...Object.keys(base), ...Object.keys(mine)])) {
    if (same(base[k], mine[k])) continue;                       // I didn't touch this field: keep the newest value
    if (!(k in mine)) { delete out[k]; continue; }              // I cleared this field
    const spec = lists && LISTS[k];
    if (spec && Array.isArray(mine[k]) && Array.isArray(out[k] === undefined ? [] : out[k]) && (base[k] === undefined || Array.isArray(base[k]))) {
      const merged = mergeList(out[k] || [], base[k] || [], mine[k], spec);
      if (merged) { out[k] = merged; continue; }
    }
    out[k] = mine[k];                                           // I changed it: my value
  }
  return out;
}

function mergeList(current, base, mine, spec) {
  const all = [...current, ...base, ...mine];
  if (all.some(x => spec.key(x) === undefined || spec.key(x) === null)) return null;   // items without identity: replace whole list
  const baseBy = new Map(base.map(x => [spec.key(x), x]));
  const mineBy = new Map(mine.map(x => [spec.key(x), x]));
  const removed = new Set([...baseBy.keys()].filter(k => !mineBy.has(k)));
  const added = mine.filter(x => !baseBy.has(spec.key(x)));
  let out = current.filter(x => !removed.has(spec.key(x)));
  out = out.map(x => {
    const k = spec.key(x), b = baseBy.get(k), m = mineBy.get(k);
    return b && m && !same(b, m) ? mergeFields(x, b, m, false) : x;      // same item edited by two people: merge field by field
  });
  const have = new Set(out.map(spec.key));
  const fresh = added.filter(x => !have.has(spec.key(x)));
  return spec.addAt === 'front' ? [...fresh, ...out] : [...out, ...fresh];
}

/* ---------------------------------------------------------------- API routes */
async function postTasks(req, res) {
  let data;
  try { data = JSON.parse((await readBody(req, MAX_JSON)).toString('utf8')); }
  catch (e) { return send(res, e.status || 400, { error: e.status === 413 ? 'Too large' : 'Invalid JSON' }); }
  const upsert = Array.isArray(data.upsert) ? data.upsert : [];
  const del = Array.isArray(data.delete) ? data.delete : [];
  if (upsert.some(t => !t || typeof t !== 'object' || typeof t.id !== 'string' || !t.id)) return send(res, 400, { error: 'Every task needs a string id' });
  if (del.some(id => typeof id !== 'string')) return send(res, 400, { error: 'delete must be a list of ids' });

  const bases = data.bases && typeof data.bases === 'object' ? data.bases : {};
  try {
    tx(() => {
      const rev = currentRev() + 1, now = new Date().toISOString();
      let changed = false;
      const fresh = [];
      for (const t of upsert) {
        const row = q.one.get(t.id);
        if (row) {
          const current = JSON.parse(row.data);
          const base = bases[t.id] && typeof bases[t.id] === 'object' ? bases[t.id] : {};
          const merged = mergeFields(current, base, t, true);
          if (!same(current, merged)) { q.update.run(JSON.stringify(merged), rev, now, t.id); changed = true; }
        } else if (bases[t.id]) {
          // Someone deleted this task while it was being edited: the deletion stands.
        } else if (!fresh.some(f => f.id === t.id)) { fresh.push(t); }
      }
      if (fresh.length) {                                 // new tasks go on top, matching the app
        const top = q.minPos.get().p - fresh.length;
        fresh.forEach((t, i) => q.insert.run(t.id, top + i, JSON.stringify(t), rev, now));
        changed = true;
      }
      for (const id of new Set(del)) {
        const row = q.one.get(id);
        if (!row) continue;
        q.remove.run(id);
        fileIdsOf(JSON.parse(row.data)).forEach(fid => { if (FILE_ID.test(fid)) q.fileDel.run(fid); });   // no orphaned uploads
        changed = true;
      }
      if (changed) q.setRev.run(String(rev));
    });
  } catch (e) { console.error('save failed:', e); return send(res, 500, { error: 'Could not save' }); }
  announceIfMoved();
  send(res, 200, { ok: true, version: version() });
}

const INLINE_TYPES = /^(image\/(png|jpeg|gif|webp|avif|bmp)|application\/pdf)$/;

async function postFile(req, res) {
  let buf;
  try { buf = await readBody(req, MAX_FILE); }
  catch (e) { res.once('finish', () => req.destroy()); return send(res, e.status || 400, { error: 'File too large (max 5 MB)' }, { Connection: 'close' }); }
  if (!buf.length) return send(res, 400, { error: 'Empty file' });
  let name = 'file';
  try { name = decodeURIComponent(String(req.headers['x-file-name'] || 'file')).slice(0, 200) || 'file'; } catch { /* keep default */ }
  let type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (!/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(type)) type = 'application/octet-stream';
  const id = crypto.randomBytes(12).toString('hex');
  try { q.fileIns.run(id, name, type, buf.length, new Date().toISOString(), buf); }
  catch (e) { console.error('upload failed:', e); return send(res, 500, { error: 'Could not save file' }); }
  send(res, 200, { url: '/api/files/' + id, type, size: buf.length });
}

function getFile(req, res, id) {
  if (!FILE_ID.test(id)) return send(res, 404, 'Not found');
  const f = q.fileGet.get(id);
  if (!f) return send(res, 404, 'Not found');
  const inline = INLINE_TYPES.test(f.type);
  res.writeHead(200, {
    'Content-Type': inline ? f.type : 'application/octet-stream',
    'Content-Length': f.size,
    'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(f.name)}`,
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "sandbox; default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'",   // uploaded files can never run scripts
    'Cache-Control': 'private, max-age=31536000, immutable',
  });
  if (req.method === 'HEAD') return res.end();
  res.end(Buffer.from(f.content));
}

/* ------------------------------------------------------------- static files */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.webp': 'image/webp', '.json': 'application/json', '.woff2': 'font/woff2', '.map': 'application/json',
};
function serveStatic(req, res, pathname) {
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { return send(res, 400, 'Bad request'); }
  if (rel === '/' || rel === '') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (file !== PUBLIC_DIR && !file.startsWith(PUBLIC_DIR + path.sep)) return send(res, 403, 'Forbidden');
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return send(res, 404, 'Not found');
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Content-Length': st.size,
      'Cache-Control': 'no-cache',                      // always revalidate, so new deploys show up immediately
      'Last-Modified': st.mtime.toUTCString(),
      'X-Content-Type-Options': 'nosniff',
    });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

/* ------------------------------------------------------------------- server */
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;
    if (p === '/healthz') { q.rev.get(); return send(res, 200, 'ok'); }
    if (!authorised(req)) return send(res, 401, 'Password required', { 'WWW-Authenticate': 'Basic realm="Team Project Tracker", charset="UTF-8"' });

    if (p === '/api/live' && req.method === 'GET') return handleLive(req, res, url);
    if (p === '/api/tasks') {
      if (req.method === 'GET') return send(res, 200, allTasks());
      if (req.method === 'POST') return await postTasks(req, res);
      return send(res, 405, 'Method not allowed');
    }
    if (p === '/api/files' && req.method === 'POST') return await postFile(req, res);
    if (p.startsWith('/api/files/')) {
      const id = p.slice('/api/files/'.length);
      if (req.method === 'GET' || req.method === 'HEAD') return getFile(req, res, id);
      if (req.method === 'DELETE') { if (FILE_ID.test(id)) q.fileDel.run(id); return send(res, 200, { ok: true }); }
      return send(res, 405, 'Method not allowed');
    }
    if (p.startsWith('/api/')) return send(res, 404, { error: 'Unknown endpoint' });
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
    serveStatic(req, res, p);
  } catch (e) {
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: 'Server error' }); else res.end();
  }
});
server.keepAliveTimeout = 65000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Team Project Tracker running on http://localhost:${PORT}`);
  console.log(`Database: ${DB_FILE} (revision ${announced})`);
  console.log(SITE_USER || SITE_PASSWORD ? 'Site password: ON' : 'Site password: OFF (set SITE_USER and SITE_PASSWORD to turn on)');
});

function shutdown() {
  for (const res of clients) { try { res.end(); } catch { /* ignore */ } }
  server.close(() => { try { db.close(); } catch { /* ignore */ } process.exit(0); });
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
