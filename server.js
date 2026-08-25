// Jerrick Cloud — minimal real deploy engine.
// Give it a Git URL or a local folder; it runs `npm install` then `npm start`
// on a free port (PORT injected) and the app is live at http://localhost:<port>.
// Scope: Node web apps, single-user local tool. It runs your code by design.
// ponytail: no sandboxing / multi-tenant isolation — that's the "big cloud" version.

const http = require('http');
const os = require('os');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const tls = require('tls');
const https = require('https');
const crypto = require('crypto');
const Anthropic = require('@anthropic-ai/sdk');
const { betaTool } = require('@anthropic-ai/sdk/helpers/beta/json-schema');

const ROOT = __dirname;
const STATE_FILE = path.join(ROOT, 'apps.json');
const WORKSPACES = path.join(ROOT, 'workspaces');
const PORT = process.env.PORT || 8080;
const PORT_BASE = 3001;
const LOG_CAP = 500; // ponytail: keep last 500 log lines/app in memory; add a real log store if it matters
const IS_WIN = process.platform === 'win32';
const LOG_DIR = path.join(ROOT, 'logs');       // persisted per-app logs (survive restarts, downloadable)
const LOG_FILE_CAP = 2 * 1024 * 1024;          // trim on-disk log to last ~1MB once it passes 2MB
const RESTART_MAX = 5;                          // crash-loop guard: give up after this many restarts...
const RESTART_WINDOW = 60_000;                  // ...within this window
const HEALTH_INTERVAL = 20_000;                 // TCP health probe cadence
const METRIC_INTERVAL = 15_000;                 // host metric sampling cadence
const METRIC_HISTORY = 240;                     // ~1h of samples at 15s
const ALERT_PCT = Number(process.env.ALERT_PCT || 85);   // email when mem/disk crosses this %
const ALERT_EVERY = 30 * 60_000;                // re-alert at most this often, per resource
const SSL = (process.env.SSL_CERT && process.env.SSL_KEY)   // optional HTTPS — point these at a cert/key pair
  ? { cert: fs.readFileSync(process.env.SSL_CERT), key: fs.readFileSync(process.env.SSL_KEY) } : null;
const PROTO = SSL ? 'https' : 'http';

// ---- feature config (all fit the zero-dep, single-user, home-server design) ----
const SESS_FILE = path.join(LOG_DIR, 'sessions.json');   // persisted logins (survive a server restart)
const TOKENS_FILE = path.join(LOG_DIR, 'tokens.json');   // API bearer token -> owner email
const ROLES_FILE = path.join(LOG_DIR, 'roles.json');     // subscription role assignments: email -> role
const METRICS_FILE = path.join(LOG_DIR, 'metrics.json'); // persisted host + per-app metric history
const SECRET_FILE = path.join(LOG_DIR, '.secret');       // 32-byte key for env-var-at-rest encryption
const APP_METRIC_HISTORY = 240;                          // per-app samples kept (~1h at 15s)
const HEALTH_TIMEOUT = 30_000;                           // zero-downtime: max wait for a new version to go healthy
const STATIC_SERVER = path.join(ROOT, 'static-server.js'); // runtime for static sites (index.html, no other stack)
const STATIC_DIRS = ['', 'dist', 'public', 'build', 'out', 'www']; // where a built site's index.html usually lands
const CRON_INTERVAL = 30_000;                            // scheduled jobs tick — twice a minute so drift can't skip a minute
// App Service plans -> a real memory ceiling (MB). Node also gets --max-old-space-size; any runtime is RSS-capped.
const PLANS = { free: 512, basic: 1024, standard: 2048, premium: 4096 };
const planMem = size => PLANS[String(size || 'free').toLowerCase()] || PLANS.free;

// Parse one .env line -> [key, value] or null (blank/comment/invalid). Strips surrounding quotes.
const parseEnvLine = line => {
  const m = String(line).match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
  return m ? [m[1], m[2].trim().replace(/^["']|["']$/g, '')] : null;
};
// Minimal zero-dep .env loader: load KEY=VALUE lines from .env into process.env so secrets
// (GOOGLE_CLIENT_ID/SECRET) stay out of the code and out of git. Real env vars always win.
try {
  for (const line of fs.readFileSync(path.join(ROOT, '.env'), 'utf8').split(/\r?\n/)) {
    const kv = parseEnvLine(line);
    if (kv && process.env[kv[0]] === undefined && kv[1] !== '') process.env[kv[0]] = kv[1];
  }
} catch (_) {} // no .env -> fine, fall back to real env vars

// Google Sign-In: enforced only when both env vars are set, so the tool still runs open on localhost until you configure it.
const AUTH_ON = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
const REDIRECT_URI = process.env.OAUTH_REDIRECT || `http://localhost:${PORT}/auth/callback`;
// ponytail: in-memory sessions + pending OAuth states, no expiry/eviction. Fine for a single-user localhost tool.
const sessions = new Map();      // sid -> { email, name }
const pendingStates = new Set(); // CSRF states awaiting callback

// ---- pure helpers ----
const slugify = s => String(s).toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
const isRemote = s => /^(https?:\/\/|git@)/i.test(String(s).trim());
// Embed a token into an https URL for private-repo clones. x-access-token works for classic + fine-grained PATs and GitHub App tokens.
const authUrl = (source, token) => token ? String(source).replace(/^https:\/\//i, `https://x-access-token:${token}@`) : source;
// Never hang on a hidden credential prompt — fail fast instead. (When a token is supplied it's in the URL, so this never triggers.)
const gitEnv = () => ({ ...process.env, GIT_TERMINAL_PROMPT: '0' });

function findFreePort(start, used) {
  return new Promise(resolve => {
    if (used && used.has(start)) return resolve(findFreePort(start + 1, used));
    const srv = net.createServer();
    srv.once('error', () => resolve(findFreePort(start + 1, used)));
    srv.listen(start, () => srv.close(() => resolve(start)));
  });
}

function killTree(pid) {
  if (!pid) return;
  try {
    if (IS_WIN) spawn('taskkill', ['/pid', String(pid), '/T', '/F']);
    else process.kill(pid, 'SIGTERM');
  } catch (_) {}
}

// ---- state ----
let apps = [];
try { apps = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch (_) {}
const procs = new Map();    // name -> child process
const logbuf = new Map();   // name -> string[]
const clients = new Map();  // name -> Set<res> (SSE)
const restartHist = new Map();       // name -> number[] recent auto-restart timestamps (crash-loop guard)
const healthFails = new Map();       // name -> consecutive failed health probes
const lastHealthRestart = new Map(); // name -> ts of last health-triggered restart (throttle)
const metricHistory = [];            // ring buffer of { ts, mem, disk } host samples
const lastAlert = {};                // resource -> ts of last threshold email (throttle)

const REQ_CAP = 300;                 // recent proxied requests kept per app (Application Insights)
const reqLog = new Map();            // name -> [{ ts, method, path, status, ms }]
const lastReq = new Map();           // name -> ts of the last proxied request (drives idle sleep)
const waking = new Map();            // name -> in-flight wake Promise (dedupes a burst of requests)
const jobRunning = new Set();        // "app:index" of scheduled jobs still running (no overlapping runs)

const logFile = name => path.join(LOG_DIR, slugify(name) + '.log');
// Mirror a log chunk to disk so logs survive restarts and can be downloaded. Self-trims when it grows past the cap.
function appendLogFile(name, text) {
  try {
    const f = logFile(name);
    fs.appendFileSync(f, text.endsWith('\n') ? text : text + '\n');
    if (fs.statSync(f).size > LOG_FILE_CAP) fs.writeFileSync(f, fs.readFileSync(f).slice(-LOG_FILE_CAP / 2));
  } catch (_) {}
}

// Severity of a stored log line, so Insights can filter to just the errors. Keyword match — apps
// log in every format under the sun, so this is deliberately loose rather than a parser.
const ERR_RE = /(\berrors?\b|[a-z]*Error\b|\bexception\b|\bfail(ed|ure|s)?\b|\bfatal\b|\bunhandled|traceback|EADDRINUSE|ECONNREFUSED|ENOENT|MODULE_NOT_FOUND)/i;
const WARN_RE = /(\bwarn(ing)?s?\b|\bdeprecat)/i;
const levelOf = line => ERR_RE.test(line) ? 'error' : WARN_RE.test(line) ? 'warn' : 'info';

const find = name => apps.find(a => a.name === name);
const save = () => fs.writeFileSync(STATE_FILE, JSON.stringify(apps, null, 2));

// ---- persistence for sessions / API tokens / metric history (all survive a restart) ----
const appMetrics = new Map();  // name -> [{ ts, rss, cpu }] per-app history
const memViol = new Map();     // name -> consecutive over-plan-cap samples (soft memory ceiling)
let tokens = {};               // API bearer token -> owner email
const loadJSON = (f, fallback) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch (_) { return fallback; } };
const saveSessions = () => { try { fs.writeFileSync(SESS_FILE, JSON.stringify([...sessions])); } catch (_) {} };
const saveTokens = () => { try { fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens)); } catch (_) {} };
const saveMetrics = () => { try { fs.writeFileSync(METRICS_FILE, JSON.stringify({ host: metricHistory, apps: [...appMetrics] })); } catch (_) {} };

// ---- env vars encrypted at rest (AES-256-GCM) ----
// Key: JC_SECRET if set, else a generated key persisted in logs/.secret. Stored blobs are "enc:<iv>:<tag>:<ct>"
// (all base64). decVal passes plaintext through, so legacy unencrypted envs keep working and a bad blob never throws.
let _encKey = null;
function encKey() {
  if (_encKey) return _encKey;
  if (process.env.JC_SECRET) return _encKey = crypto.createHash('sha256').update(process.env.JC_SECRET).digest();
  try { const k = fs.readFileSync(SECRET_FILE); if (k.length === 32) return _encKey = k; } catch (_) {}
  _encKey = crypto.randomBytes(32);
  try { fs.mkdirSync(LOG_DIR, { recursive: true }); fs.writeFileSync(SECRET_FILE, _encKey, { mode: 0o600 }); } catch (_) {}
  return _encKey;
}
const encVal = v => {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', encKey(), iv);
  const ct = Buffer.concat([c.update(String(v), 'utf8'), c.final()]);
  return `enc:${iv.toString('base64')}:${c.getAuthTag().toString('base64')}:${ct.toString('base64')}`;
};
const decVal = v => {
  const s = String(v);
  if (!s.startsWith('enc:')) return v; // plaintext (legacy) -> pass through
  try {
    const [, iv, tag, ct] = s.split(':');
    const d = crypto.createDecipheriv('aes-256-gcm', encKey(), Buffer.from(iv, 'base64'));
    d.setAuthTag(Buffer.from(tag, 'base64'));
    return d.update(Buffer.from(ct, 'base64'), undefined, 'utf8') + d.final('utf8');
  } catch (_) { return v; } // never crash on a bad/foreign blob
};
const encEnv = e => Object.fromEntries(Object.entries(e || {}).map(([k, v]) => [k, encVal(v)]));
const decEnv = e => Object.fromEntries(Object.entries(e || {}).map(([k, v]) => [k, decVal(v)]));
// App object for API responses: env decrypted for display, the access password replaced by a boolean
// (it protects the app itself — the portal never needs the value back), everything else untouched.
const publicApp = a => ({ ...a, env: decEnv(a.env), accessPassword: undefined, hasPassword: !!a.accessPassword });
// ---- subscription roles (Azure's three built-ins, same split of powers) ----
// Scope is the whole subscription — this Jerrick Cloud instance — which is what makes them different
// from an app's own owner/collaborators (that's resource-level access, and it still applies).
//   owner        full control over every app, and hands out roles
//   contributor  full control over every app, cannot touch role assignments
//   useradmin    hands out roles, read-only over apps (Azure's User Access Administrator)
const ROLES = { owner: 'Owner', contributor: 'Contributor', useradmin: 'User Access Administrator' };
let roles = {};                  // email -> role id, persisted in roles.json
const saveRoles = () => { try { fs.writeFileSync(ROLES_FILE, JSON.stringify(roles, null, 2)); } catch (_) {} };
const roleOf = user => (user && roles[String(user.email || '').toLowerCase()]) || null;
const canAssign = user => ['owner', 'useradmin'].includes(roleOf(user));   // may change role assignments
const subManage = user => ['owner', 'contributor'].includes(roleOf(user)); // may change any app in the subscription
const subOwner = () => Object.keys(roles).find(e => roles[e] === 'owner') || null;
// The org a role can be handed out within: ORG_DOMAIN, else the owner's own mail domain.
const orgDomain = () => String(process.env.ORG_DOMAIN || (subOwner() || '').split('@')[1] || '').toLowerCase();
// True when `email` is the only Owner left — demoting or removing them would lock everyone out of role management.
const lastOwner = email => Object.entries(roles).filter(([, r]) => r === 'owner').every(([e]) => e === email);
// Someone has to be Owner, and on a fresh install that's whoever sets it up. SUBSCRIPTION_OWNER pins it instead.
function claimOwner(email) {
  if (!email || subOwner()) return;
  roles[String(email).toLowerCase()] = 'owner'; saveRoles();
}

// Who may see an app: with sign-in off, everyone; otherwise any subscription role, its owner, its
// collaborators, and legacy apps that predate owners. Single rule for the apps API and the assistant's tools alike.
const canSee = (a, user) => !AUTH_ON || !a.owner || !!roleOf(user) ||
  !!(user && (a.owner === user.email || (a.collaborators || []).includes(user.email)));
// Who may change an app: the same list minus User Access Administrators — they manage access, not resources.
const canWrite = (a, user) => !AUTH_ON || !a.owner || subManage(user) ||
  !!(user && (a.owner === user.email || (a.collaborators || []).includes(user.email)));

// ---- activity log ----
// Append-only record of who did what. IAM answers "who may"; this answers "who did", which is the
// question you actually have after something disappears. One JSON object per line, so a write is an
// append with no parse-and-rewrite, and a half-line left by a trim just fails its own JSON.parse.
// ponytail: whole-file read on the GET, byte-capped like the app logs. Fine for a home box — move it
//   to a real store if the file ever gets big enough to notice.
const ACTIVITY_FILE = path.join(LOG_DIR, 'activity.jsonl');
const ACTIVITY_CAP = 1024 * 1024;   // trim to the last half once it passes this, same as logs/<app>.log
function logActivity(user, action, app, detail, denied) {
  try {
    const e = { at: new Date().toISOString(), by: (user && user.email) || 'local', action };
    if (app) e.app = app;
    if (detail) e.detail = String(detail).slice(0, 500);
    if (denied) e.denied = true;
    fs.appendFileSync(ACTIVITY_FILE, JSON.stringify(e) + '\n');
    if (fs.statSync(ACTIVITY_FILE).size > ACTIVITY_CAP)
      fs.writeFileSync(ACTIVITY_FILE, fs.readFileSync(ACTIVITY_FILE).slice(-ACTIVITY_CAP / 2));
  } catch (_) {} // an audit write must never break the action it is auditing
}
// Visible to whoever could have caused it or can see what it touched: the actor, anyone holding a
// subscription role (they read every app anyway), and anyone the named app is shared with. An entry
// about an app that has since been deleted therefore stays with the actor and the role holders.
const canSeeEntry = (e, user) => !AUTH_ON || !!roleOf(user) || e.by === (user && user.email) ||
  (!!e.app && !!find(e.app) && canSee(find(e.app), user));
function activity(user, limit = 200) {
  let lines = [];
  try { lines = fs.readFileSync(ACTIVITY_FILE, 'utf8').split('\n'); } catch (_) {} // nothing recorded yet
  const out = [];
  for (const l of lines) { try { const e = JSON.parse(l); if (canSeeEntry(e, user)) out.push(e); } catch (_) {} }
  return out.slice(-limit).reverse(); // newest first
}

// ---- per-app access restrictions (enforced at the proxy, before anything reaches the app) ----
// Requests per client IP per app, in a fixed 60s window, enforced with the other proxy gates below.
// The README recommends fronting this box with a tunnel, which makes an app reachable by anything on
// the internet — one runaway caller is then enough to keep a home machine busy. 0 / unset = off.
// ponytail: fixed window, so a caller can burst 2x across a boundary, and the counters live in memory
//   (a restart forgives everyone). Enough to stop a loop hammering an app; not a DDoS defence.
const RATE_WINDOW = 60_000;
const rateHits = new Map();   // "<app>|<ip>" -> { n, resetAt }
const clampInt = (v, max) => Math.max(0, Math.min(max, Math.round(Number(v) || 0)));
// 0 = let it through; otherwise the seconds left in this window (used as Retry-After).
function rateExceeded(app, ip) {
  const max = app.rateLimit || 0;
  if (!max) return 0;
  const now = Date.now(), key = app.name + '|' + ip;
  let h = rateHits.get(key);
  if (!h || now >= h.resetAt) { h = { n: 0, resetAt: now + RATE_WINDOW }; rateHits.set(key, h); }
  h.n++;
  if (rateHits.size > 10_000) for (const [k, v] of rateHits) if (v.resetAt <= now) rateHits.delete(k); // drop dead windows
  return h.n > max ? Math.ceil((h.resetAt - now) / 1000) : 0;
}
// The platform listens on every interface, so without this every app is open to the LAN and to any
// tunnel pointed at it. Two independent gates, both optional: an IP allow list and a password.
// ponytail: allow-list entries are an exact IP or a prefix ending in "." / ":" ("192.168.1.") — no CIDR math.
const ipOf = req => String(req.socket.remoteAddress || '').replace(/^::ffff:/, ''); // never trust X-Forwarded-For here
const ipAllowed = (list, ip) => !list || !list.length ||
  list.some(e => (e.endsWith('.') || e.endsWith(':')) ? ip.startsWith(e) : ip === e);
// Constant-time compare over digests, so lengths can differ without leaking via timing.
const sameSecret = (a, b) => {
  const h = s => crypto.createHash('sha256').update(String(s)).digest();
  return crypto.timingSafeEqual(h(a), h(b));
};
// null = let it through; otherwise the response to send instead (401 challenge / 403).
function accessDenied(app, req) {
  const wait = rateExceeded(app, ipOf(req)); // outermost gate: cheapest, and it shields the password compare
  if (wait) return { code: 429, headers: { 'Retry-After': String(wait) }, body: `Too many requests — try again in ${wait}s.` };
  if (!ipAllowed(app.allowIps, ipOf(req)))
    return { code: 403, body: 'Forbidden — your address is not on this app\'s allow list.' };
  const pass = app.accessPassword ? decVal(app.accessPassword) : '';
  if (!pass) return null;
  const m = (req.headers.authorization || '').match(/^Basic\s+(\S+)$/i);
  const supplied = m ? Buffer.from(m[1], 'base64').toString('utf8').split(':').slice(1).join(':') : '';
  if (supplied && sameSecret(supplied, pass)) return null;
  return { code: 401, headers: { 'WWW-Authenticate': `Basic realm="${app.name}"` }, body: 'Authentication required.' };
}

// ---- health probes (used by zero-downtime cutover + the periodic health check) ----
function tcpOk(port, timeout = 2500) {
  return new Promise(r => {
    const s = net.connect(port, '127.0.0.1'); let d = false;
    const done = v => { if (d) return; d = true; try { s.destroy(); } catch (_) {} r(v); };
    s.once('connect', () => done(true)); s.once('error', () => done(false)); s.setTimeout(timeout, () => done(false));
  });
}
function httpOk(port, pathname, timeout = 3000) {
  return new Promise(r => {
    const req = http.request({ host: '127.0.0.1', port, path: pathname || '/', method: 'GET', timeout }, res => { res.resume(); r(res.statusCode < 500); });
    req.on('error', () => r(false)); req.on('timeout', () => { req.destroy(); r(false); }); req.end();
  });
}
// Poll until the app answers on `port` (HTTP path if set, else TCP), or give up. Bails early if the child dies.
async function waitHealthy(port, healthPath, child, ms = HEALTH_TIMEOUT) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (child && child.exitCode !== null) return false;
    if (await (healthPath ? httpOk(port, healthPath) : tcpOk(port))) return true;
    await new Promise(r => setTimeout(r, 500));
  }
  return false;
}

// ---- docker runtime helpers ----
const dockerImage = name => `jc-${slugify(name)}`;
const dockerName = (name, port) => `jc-${slugify(name)}-${port}`;
const dockerRm = container => { if (container) try { spawn('docker', ['rm', '-f', container], { stdio: 'ignore' }); } catch (_) {} };

// A deploy step failed. If an old version is still serving (graceful redeploy), keep it live; else mark failed.
function failDeploy(app) {
  if (procs.get(app.name)) {
    pushLog(app.name, 'Deploy failed — keeping the current version live.');
    app.status = 'running'; broadcast(app.name, 'status', 'running'); save(); // restore label without a "went live" email
    return;
  }
  setStatus(app.name, 'failed');
}

function broadcast(name, event, data) {
  const set = clients.get(name);
  if (!set) return;
  const payload = `event: ${event}\ndata: ${data}\n\n`;
  for (const res of set) { try { res.write(payload); } catch (_) {} }
}
function pushLog(name, chunk) {
  const buf = logbuf.get(name) || [];
  for (const line of String(chunk).split(/\r?\n/)) {
    if (line === '') continue;
    buf.push(line);
    if (buf.length > LOG_CAP) buf.shift();
    broadcast(name, 'message', line);
    appendLogFile(name, line);
  }
  logbuf.set(name, buf);
}
function setStatus(name, status) {
  const a = find(name);
  if (a) a.status = status;
  if (a && status === 'running') a.diagnosis = undefined; // back up → the last crash's root cause is history
  broadcast(name, 'status', status);
  save();
  // Email on terminal deploy outcomes. Fire-and-forget — a mail failure never blocks a deploy.
  if (status === 'running' || status === 'failed') notifyDeploy(a || { name }, status);
  if (status === 'failed') diagnose(a); // async, fire-and-forget: ask Claude why, store the answer
}

// Who gets the email: the app's owner (set once Google login is wired up), else the configured fallback.
const recipientFor = app => app.owner || process.env.NOTIFY_TO || process.env.GMAIL_USER;

function notifyDeploy(app, status) {
  const to = recipientFor(app);
  if (!to) return; // notifications not configured — no-op
  const live = status === 'running';
  const subject = `[Jerrick Cloud] ${app.name} ${live ? 'is live ✅' : 'failed to deploy ❌'}`;
  const body = live
    ? `${app.name} deployed successfully.\n\nLive at: ${app.url || 'n/a'}\nRuntime: ${app.runtime || 'n/a'}`
    : `${app.name} failed to deploy.\n\nOpen the Log stream in Jerrick Cloud for the build output.`;
  sendMail(to, subject, body, app.name);
}

// Minimal SMTP-over-TLS sender for Gmail (smtp.gmail.com:465, implicit TLS). Configure via env:
//   GMAIL_USER      your gmail address (also the "from")
//   GMAIL_APP_PASS  a Google *App Password* (account needs 2FA) — NOT your normal password
//   NOTIFY_TO       optional; who to email (defaults to GMAIL_USER)
// Unset GMAIL_USER/GMAIL_APP_PASS => no-op, so the platform runs fine unconfigured.
// ponytail: naive single-message SMTP, no queue/retry/attachments. Swap in nodemailer if you outgrow it.
function sendMail(to, subject, body, logName) {
  const user = process.env.GMAIL_USER, pass = process.env.GMAIL_APP_PASS;
  if (!user || !pass || !to) return;
  const b64 = s => Buffer.from(String(s)).toString('base64');
  const msg = `From: Jerrick Cloud <${user}>\r\nTo: <${to}>\r\nSubject: ${subject}\r\n` +
              `Content-Type: text/plain; charset=utf-8\r\n\r\n` +
              `${String(body).replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..')}\r\n.`; // dot-stuff so a lone "." can't end DATA early
  const cmds = [
    ['EHLO jerrick.local', 250], ['AUTH LOGIN', 334], [b64(user), 334], [b64(pass), 235],
    [`MAIL FROM:<${user}>`, 250], [`RCPT TO:<${to}>`, 250], ['DATA', 354], [msg, 250], ['QUIT', 221],
  ];
  const sock = tls.connect(465, 'smtp.gmail.com', { servername: 'smtp.gmail.com' });
  sock.setEncoding('utf8');
  let buf = '', i = 0, expect = 220, closed = false; // first reply is the 220 greeting
  const finish = (ok, detail) => {
    if (closed) return; closed = true;
    try { sock.destroy(); } catch (_) {}
    if (logName) pushLog(logName, ok ? `📧 Emailed ${to}` : `email failed: ${detail || 'connection error'}`);
  };
  sock.on('data', d => {
    buf += d;
    if (!/\r?\n$/.test(buf)) return;                     // wait for a complete reply
    const last = buf.split(/\r?\n/).filter(Boolean).pop() || '';
    if (!/^\d{3} /.test(last)) return;                   // multiline reply (250-...) still going
    buf = '';
    if (parseInt(last, 10) !== expect) return finish(false, last);
    if (i >= cmds.length) return finish(true);           // QUIT acknowledged
    const [cmd, exp] = cmds[i++]; expect = exp; sock.write(cmd + '\r\n');
  });
  sock.on('error', e => finish(false, e.message));
  sock.setTimeout(15000, () => finish(false, 'timeout'));
}

// run a command to completion, streaming output; resolve(true) on exit 0
function run(name, cmd, args, cwd, shell, env) {
  return new Promise(resolve => {
    let child;
    try { child = spawn(cmd, args, { cwd, env: env || process.env, shell: !!shell }); }
    catch (e) { pushLog(name, `Error: ${e.message}`); return resolve(false); }
    child.stdout.on('data', d => pushLog(name, d.toString()));
    child.stderr.on('data', d => pushLog(name, d.toString()));
    child.on('error', e => { pushLog(name, `Error: ${e.message}`); resolve(false); });
    child.on('exit', code => { pushLog(name, `(exit ${code})`); resolve(code === 0); });
  });
}

// Read a `<key>:` process line from a Heroku-style Procfile, if present. `web:` is the start-command
// escape hatch for anything we don't auto-detect (Ruby, Go, …); `release:` is a one-off pre-start command.
function procfileEntry(cwd, key) {
  try {
    const m = fs.readFileSync(path.join(cwd, 'Procfile'), 'utf8').match(new RegExp(`^\\s*${key}\\s*:\\s*(.+?)\\s*$`, 'mi'));
    return m ? m[1] : null;
  } catch (_) { return null; }
}

// Detect the app's runtime from marker files → { name, install, start } (shell command strings).
// A Procfile `web:` line always overrides the start command. Returns null if nothing matches.
// ponytail: convention-based, no per-app config, global pip/no venv, `dotnet run` assumes a single
//   runnable project. When those corners bite, drop a Procfile in the repo — that's the upgrade path.
function detectRuntime(cwd) {
  // No code to look at — a deploy that never landed, or a folder deleted underneath us. Nothing matches,
  // so callers take their existing "no runtime" path instead of path.join throwing on an undefined cwd.
  if (!cwd || !fs.existsSync(cwd)) return null;
  const has = f => fs.existsSync(path.join(cwd, f));
  let files = [];
  try { files = fs.readdirSync(cwd); } catch (_) {}
  const hasExt = re => files.some(f => re.test(f));

  let rt = null;
  if (has('Dockerfile'))
    rt = { name: 'Docker', install: null, start: null, docker: true }; // build + run the image; own isolation
  else if (has('package.json'))
    rt = { name: 'Node', install: 'npm install', start: 'npm start' };
  else if (has('requirements.txt') || has('pyproject.toml') || has('app.py') || has('main.py'))
    rt = { name: 'Python',
           install: has('requirements.txt') ? 'pip install -r requirements.txt' : null,
           start: `python ${has('app.py') ? 'app.py' : 'main.py'}` };
  else if (hasExt(/\.(sln|slnx|csproj|fsproj)$/i))
    rt = { name: '.NET', install: 'dotnet restore', start: 'dotnet run' };

  // Last resort: a plain static site — index.html at the root, or a pre-built dist/ committed to the repo.
  // Served by static-server.js on the injected PORT, so proxying/health/metrics work like any other app.
  if (!rt) {
    const dir = STATIC_DIRS.find(d => has(path.join(d, 'index.html')));
    if (dir !== undefined) rt = { name: 'Static', install: null, start: `node ${JSON.stringify(STATIC_SERVER)} ${JSON.stringify(dir || '.')}` };
  }

  const web = procfileEntry(cwd, 'web');
  if (web && !(rt && rt.docker)) rt = { name: rt ? rt.name : 'Procfile', install: rt ? rt.install : null, start: web };
  if (rt) rt.release = procfileEntry(cwd, 'release'); // optional one-off pre-start command (migrations, asset build…)
  return rt;
}

// ---- jerrick.json: the app's own configuration, committed next to its code ----
// Everything in Configuration / Scale up lives only in this host's apps.json, so a fresh Jerrick Cloud
// gets a bare app even from a repo that has been tuned for months. A jerrick.json in the repo root
// carries the plan, health check path, idle sleep and scheduled jobs along with the code, and is
// applied on every deploy — the file owns the fields it names, the way a Procfile already owns the
// start command. Environment variables are the exception: declared ones are defaults that never
// overwrite a value already set here, so a repo file can't clobber a secret typed into Configuration.
// A bad field is logged and skipped; a bad manifest never fails a deploy.
// ponytail: no domains (they collide across apps and want the 409 check the route does) and no
//   build/start (the Procfile owns those). Add them when a repo actually needs them.
function applyManifest(app, cwd) {
  let m;
  try { m = JSON.parse(fs.readFileSync(path.join(cwd, 'jerrick.json'), 'utf8')); }
  catch (e) { if (e.code !== 'ENOENT') pushLog(app.name, `Ignoring jerrick.json — ${e.message}`); return; }
  if (!m || typeof m !== 'object') return;
  const applied = [];

  if ('plan' in m) {
    const plan = String(m.plan).toLowerCase();
    if (PLANS[plan]) { app.size = plan; applied.push(`plan ${plan} (${PLANS[plan]} MB)`); }
    else pushLog(app.name, `jerrick.json: unknown plan "${m.plan}" — keeping ${app.size || 'free'}`);
  }
  if ('healthPath' in m) {
    let p = String(m.healthPath || '').trim();
    if (p && !p.startsWith('/')) p = '/' + p;
    app.healthPath = p || undefined;
    applied.push(`health check ${p || 'off'}`);
  }
  if ('idleMin' in m) {
    const n = clampInt(m.idleMin, 1440);
    app.idleMin = n || undefined;
    applied.push(`idle sleep ${n ? n + ' min' : 'off'}`);
  }
  if ('rateLimit' in m) {
    const n = clampInt(m.rateLimit, 100_000);
    app.rateLimit = n || undefined;
    applied.push(`rate limit ${n ? n + '/min per IP' : 'off'}`);
  }
  if ('jobs' in m) {
    const jobs = (Array.isArray(m.jobs) ? m.jobs : []).slice(0, 20)
      .map(j => ({ schedule: String((j || {}).schedule || '').trim(), cmd: String((j || {}).cmd || '').trim() }))
      .filter(j => j.schedule && j.cmd);
    for (const j of jobs) if (!cronValid(j.schedule)) pushLog(app.name, `jerrick.json: "${j.schedule}" is not a valid cron schedule — that job is skipped`);
    app.jobs = jobs.filter(j => cronValid(j.schedule));
    applied.push(`${app.jobs.length} scheduled job(s)`);
  }
  if (m.env && typeof m.env === 'object') {
    const cur = decEnv(app.env), added = [];
    for (const [k, v] of Object.entries(m.env)) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) { pushLog(app.name, `jerrick.json: "${k}" is not a valid environment variable name — skipped`); continue; }
      if (k in cur) continue; // already set on this host → the repo file defers, so a secret survives
      cur[k] = String(v); added.push(k);
    }
    if (added.length) { app.env = encEnv(cur); applied.push(`env defaults ${added.join(', ')}`); }
  }

  if (applied.length) pushLog(app.name, `Applied jerrick.json — ${applied.join('; ')}`);
  save();
}

async function deploy(app, token, checkout) {
  logbuf.set(app.name, []); // fresh build log
  setStatus(app.name, 'building');
  pushLog(app.name, `=== Deploying ${app.name} ===`);

  let cwd;
  if (app.uploaded) {
    // Zip-uploaded app: code already lives in workspaces/<name>; nothing to clone.
    cwd = path.join(WORKSPACES, app.name);
    if (!fs.existsSync(cwd)) { pushLog(app.name, `Upload missing for ${app.name}`); return failDeploy(app); }
  } else if (app.managed) {
    cwd = path.join(WORKSPACES, app.name);
    if (!fs.existsSync(cwd)) {
      fs.mkdirSync(WORKSPACES, { recursive: true });
      pushLog(app.name, `$ git clone ${app.source}`); // clean URL — never log the token
      if (!await run(app.name, 'git', ['clone', authUrl(app.source, token), cwd], ROOT, false, gitEnv()))
        return failDeploy(app);
    } else {
      pushLog(app.name, `$ git pull`); // token persisted in the clone's .git/config from the first clone
      await run(app.name, 'git', ['pull'], cwd, false, gitEnv());
    }
    if (checkout) { // rollback: pin to a past commit
      pushLog(app.name, `$ git checkout ${checkout}`);
      if (!await run(app.name, 'git', ['checkout', checkout], cwd, false, gitEnv()))
        return failDeploy(app);
    }
    const commit = await gitHead(cwd); // record what we deployed (for history + rollback)
    if (commit) { pushLog(app.name, `Deployed commit ${commit}`); recordDeploy(app, commit); }
  } else {
    cwd = app.source;
    if (!fs.existsSync(cwd)) { pushLog(app.name, `Path not found: ${cwd}`); return failDeploy(app); }
  }
  app.cwd = cwd;
  applyManifest(app, cwd); // repo-declared plan / health path / idle sleep / jobs / env defaults

  // Detect the runtime BEFORE running anything. If this is missing, npm/etc. can walk UP to the
  // platform's own package.json and run server.js (Jerrick Cloud) as the "app" — it kills its own tree.
  const rt = detectRuntime(cwd);
  if (!rt) {
    pushLog(app.name, `Couldn't detect a runtime. Supported: Node (package.json), Python (requirements.txt/app.py), .NET (.sln/.csproj), Docker (Dockerfile), a static site (index.html, or one in dist/ public/ build/), or any repo with a Procfile ("web: <command>").`);
    return failDeploy(app);
  }
  app.runtime = rt.name;
  pushLog(app.name, `Detected ${rt.name} app`);

  if (rt.docker) {
    pushLog(app.name, `$ docker build -t ${dockerImage(app.name)} .`);
    if (!await run(app.name, 'docker', ['build', '-t', dockerImage(app.name), '.'], cwd, false))
      return failDeploy(app);
  } else if (rt.install) {
    pushLog(app.name, `$ ${rt.install}`);
    if (!await run(app.name, rt.install, [], cwd, true)) // shell:true — Windows needs it for npm.cmd etc.
      return failDeploy(app);
  }

  if (rt.release) { // Procfile release: one-off command run after install, before start (migrations, asset build…)
    pushLog(app.name, `$ ${rt.release}`);
    if (!await run(app.name, rt.release, [], cwd, true)) return failDeploy(app);
  }

  startApp(app, { graceful: true });
}

// Start (or, when graceful and already running, hot-swap) the app's process.
// Graceful zero-downtime path: bring the new version up on a fresh port, health-check it, then cut traffic
// over and retire the old process. If the new version never goes healthy, the old one is left serving.
async function startApp(app, { graceful = false } = {}) {
  app.desired = 'running'; // expresses intent to run → drives auto-restart + boot auto-start
  const rt = detectRuntime(app.cwd);
  if (!rt) {
    pushLog(app.name, app.cwd ? `No runtime detected in ${app.cwd} — redeploy needed.` : 'No deployed code yet — redeploy needed.');
    return failDeploy(app);
  }

  const oldChild = procs.get(app.name), oldContainer = app.container;
  // Swap in only when a live old process is actually serving (its status may read "building" mid-redeploy).
  const swap = graceful && oldChild && oldChild.exitCode === null;
  const used = new Set(apps.map(a => a.port).filter(p => p && (swap || p !== app.port)));
  const port = swap ? await findFreePort(PORT_BASE, used) : (app.port || await findFreePort(PORT_BASE, used));
  const cap = planMem(app.size);
  const env = { ...process.env, ...decEnv(app.env), PORT: String(port), WEBSITE_PORT: String(port),
    ASPNETCORE_URLS: `http://localhost:${port}`,
    NODE_OPTIONS: `${process.env.NODE_OPTIONS || ''} --max-old-space-size=${cap}`.trim() }; // Node self-limits to the plan

  let child, container = null;
  if (rt.docker) {
    container = dockerName(app.name, port);
    dockerRm(container); // clear any stale container with this name
    const args = ['run', '--rm', '--name', container, '-e', `PORT=${port}`, `--memory=${cap}m`,
      '-p', `127.0.0.1:${port}:${port}`,
      ...Object.entries(decEnv(app.env)).flatMap(([k, v]) => ['-e', `${k}=${v}`]), dockerImage(app.name)];
    pushLog(app.name, `$ docker run …:${port} ${dockerImage(app.name)}`);
    child = spawn('docker', args, { cwd: app.cwd });
  } else {
    pushLog(app.name, `$ PORT=${port} ${rt.start}`);
    child = spawn(rt.start, { cwd: app.cwd, shell: true, env });
  }
  child.stdout.on('data', d => pushLog(app.name, d.toString()));
  child.stderr.on('data', d => pushLog(app.name, d.toString()));

  if (swap) {
    pushLog(app.name, `Starting new version on :${port} — health-checking before cutover…`);
    if (!await waitHealthy(port, app.healthPath, child)) {
      pushLog(app.name, 'New version failed its health check — keeping the current version live.');
      if (rt.docker) dockerRm(container); else killTree(child.pid);
      return; // old process/container keeps serving; status stays running
    }
    procs.set(app.name, child);
    app.pid = child.pid; app.port = port; app.container = container;
    app.startedAt = new Date().toISOString();
    app.url = `${PROTO}://${app.name}.localhost:${PORT}`;
    child.on('exit', code => onExit(app.name, code));
    setStatus(app.name, 'running');
    if (oldChild) { oldChild.removeAllListeners('exit'); killTree(oldChild.pid); } // retire old now traffic points away
    if (oldContainer && oldContainer !== container) dockerRm(oldContainer);
    pushLog(app.name, '✓ Cutover complete — zero-downtime deploy.');
    return;
  }

  procs.set(app.name, child);
  app.pid = child.pid; app.port = port; app.container = container;
  app.startedAt = new Date().toISOString();
  app.url = `${PROTO}://${app.name}.localhost:${PORT}`; // pretty URL via the reverse proxy below
  child.on('exit', code => onExit(app.name, code));
  setStatus(app.name, 'running');
}

// Process died. If the user didn't stop it, auto-restart with exponential backoff — unless it's crash-looping.
function onExit(name, code) {
  procs.delete(name);
  const a = find(name);
  if (!a) return;
  a.pid = null;
  if (a.desired !== 'running') { if (a.status === 'running') setStatus(name, 'stopped'); return; }
  const hist = (restartHist.get(name) || []).filter(t => Date.now() - t < RESTART_WINDOW);
  if (hist.length >= RESTART_MAX) {
    restartHist.set(name, hist);
    pushLog(name, `Crashed ${hist.length}× in ${RESTART_WINDOW / 1000}s — giving up. Fix the app, then hit Start.`);
    return setStatus(name, 'failed');
  }
  hist.push(Date.now()); restartHist.set(name, hist);
  a.restarts = (a.restarts || 0) + 1;
  const delay = Math.min(30_000, 1000 * 2 ** (hist.length - 1));
  pushLog(name, `Process exited (code ${code}) — auto-restart #${a.restarts} in ${Math.round(delay / 1000)}s`);
  setStatus(name, 'stopped');
  setTimeout(() => { const app = find(name); if (app && app.desired === 'running') startApp(app); }, delay);
}

function stopApp(app) {
  app.desired = 'stopped'; // explicit stop → don't auto-restart, don't auto-start on boot
  restartHist.delete(app.name);
  killProc(app);
  app.sleeping = false;
  setStatus(app.name, 'stopped');
}

// Kill an app's process/container without touching `desired` — shared by stop and idle-sleep.
function killProc(app) {
  const child = procs.get(app.name);
  if (child) child.removeAllListeners('exit'); // don't let the death we're about to cause trigger auto-restart
  killTree(app.pid);
  if (app.container) dockerRm(app.container); // stop the container too (docker run --rm leaves it otherwise)
  procs.delete(app.name);
  app.pid = null; app.container = null;
}

// ---- idle sleep / wake on request ----
// An app with idleMin set is stopped after that long without a proxied request and marked "sleeping":
// `desired` stays 'running', so the next request through the proxy starts it again (see wakeApp).
function sleepApp(app) {
  killProc(app);
  app.sleeping = true;
  pushLog(app.name, `Idle for ${app.idleMin} min — sleeping to free memory. The next request wakes it.`);
  setStatus(app.name, 'sleeping');
}
// Wake and wait until it actually serves. Concurrent requests share one wake, so a burst starts one process.
function wakeApp(app) {
  if (waking.has(app.name)) return waking.get(app.name);
  const p = (async () => {
    pushLog(app.name, 'Request received — waking from idle sleep…');
    app.sleeping = false;
    await bootApp(app); // start in place, or redeploy if the code is gone
    if (app.port) await waitHealthy(app.port, app.healthPath, procs.get(app.name));
  })().finally(() => waking.delete(app.name));
  waking.set(app.name, p);
  return p;
}

// Bring an app back after a server boot: start in place if we already have its code, else (re)deploy to fetch it.
function bootApp(app) {
  return (app.cwd && fs.existsSync(app.cwd)) ? startApp(app) : deploy(app);
}

// Probe every running app (HTTP health path if configured, else TCP). Repeated failures = hung app → restart (throttled to once/min).
function healthCheck() {
  for (const a of apps) {
    if (a.status !== 'running' || !a.port) { healthFails.delete(a.name); continue; }
    (a.healthPath ? httpOk(a.port, a.healthPath) : tcpOk(a.port, 3000)).then(good => {
      if (good) { a.health = 'healthy'; healthFails.set(a.name, 0); return; }
      const n = (healthFails.get(a.name) || 0) + 1; healthFails.set(a.name, n);
      a.health = 'unhealthy';
      if (n >= 3 && a.desired === 'running' && Date.now() - (lastHealthRestart.get(a.name) || 0) > 60_000) {
        lastHealthRestart.set(a.name, Date.now()); healthFails.set(a.name, 0);
        pushLog(a.name, `Health check failed ${n}× — restarting unresponsive app`);
        stopApp(a); setTimeout(() => startApp(a), 800);
      }
    });
  }
}

// Sample host + per-app metrics into ring buffers, enforce plan memory caps, fire threshold alerts, persist. At boot.
function startMetricSampler() {
  const sample = async () => {
    const m = metrics();
    metricHistory.push({ ts: m.ts, mem: m.mem.pct, disk: m.disk ? m.disk.pct : null });
    while (metricHistory.length > METRIC_HISTORY) metricHistory.shift();
    checkAlert('memory', m.mem.pct);
    if (m.disk) checkAlert('disk', m.disk.pct);
    await sampleApps();
    await sampleDisk();   // one app per tick — see DISK_INTERVAL
    saveMetrics();
  };
  sample();
  setInterval(sample, METRIC_INTERVAL).unref();
}
// ---- per-app disk usage ----
// Plans cap memory, nothing caps disk, and the host disk alert can say "85%" without saying which app
// got there. This measures what each app occupies — its working directory plus its stored log — so the
// alert can name the culprit and the Metrics tab can show it.
// ponytail: a recursive walk with a stat per file, so it is measured for ONE app per sampler tick and
//   at most once every DISK_INTERVAL. Symlinks are skipped (isFile() is false for them), which also
//   keeps a link loop from hanging the walk. Measure-and-report only — no quota, no enforcement.
const DISK_INTERVAL = 10 * 60_000;   // how stale a per-app disk figure may get before it is re-walked
const DISK_FILE_CAP = 50_000;        // stop walking past this many files; the figure is then a floor
const appDisk = new Map();           // name -> { bytes, at, capped }

async function dirSize(dir, budget) {
  let entries;
  try { entries = await fs.promises.readdir(dir, { withFileTypes: true }); } catch (_) { return 0; } // gone or unreadable
  let total = 0;
  for (const e of entries) {
    if (budget.files <= 0) break;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) total += await dirSize(p, budget);
    else if (e.isFile()) { budget.files--; try { total += (await fs.promises.stat(p)).size; } catch (_) {} }
  }
  return total;
}

// One app per call: the stalest one that is due. With N apps every app is refreshed every
// max(DISK_INTERVAL, N * METRIC_INTERVAL), and a tick never walks more than one tree.
async function sampleDisk() {
  const now = Date.now();
  const due = apps.find(a => { const p = appDisk.get(a.name); return !p || now - p.at > DISK_INTERVAL; });
  if (!due) return;
  const budget = { files: DISK_FILE_CAP };
  let bytes = due.cwd ? await dirSize(due.cwd, budget) : 0;
  try { bytes += fs.statSync(logFile(due.name)).size; } catch (_) {} // stored logs count against the box too
  appDisk.set(due.name, { bytes, at: Date.now(), capped: budget.files <= 0 });
}
const diskOf = name => (appDisk.get(name) || {}).bytes ?? null;

// Per-app RSS/CPU history + plan memory-cap enforcement (restart an app that overruns its plan for 3 samples).
async function sampleApps() {
  for (const a of apps) {
    if (a.status !== 'running' || !a.pid) continue;
    // Idle sleep: no proxied request for idleMin minutes → stop the process, keep it wakeable.
    if (a.idleMin > 0 && a.desired === 'running' && !waking.has(a.name)) {
      const since = lastReq.get(a.name) || Date.parse(a.startedAt) || Date.now();
      if (Date.now() - since > a.idleMin * 60_000) { sleepApp(a); continue; }
    }
    const st = await pidStat(a.pid);
    const cpu = pidCpuPct(a.name, a.pid, st.cpuMs);
    const hist = appMetrics.get(a.name) || [];
    hist.push({ ts: Date.now(), rss: st.rss, cpu });
    while (hist.length > APP_METRIC_HISTORY) hist.shift();
    appMetrics.set(a.name, hist);
    const capBytes = planMem(a.size) * 1024 * 1024;
    if (st.rss && st.rss > capBytes) {
      const n = (memViol.get(a.name) || 0) + 1; memViol.set(a.name, n);
      if (n >= 3 && a.desired === 'running') {
        memViol.set(a.name, 0);
        pushLog(a.name, `Memory ${(st.rss / 1048576 | 0)} MB exceeded the ${planMem(a.size)} MB ${a.size || 'free'} plan — restarting`);
        stopApp(a); setTimeout(() => startApp(a), 800);
      }
    } else memViol.set(a.name, 0);
  }
}
// ---- scheduled jobs (per-app cron) ----
// Standard 5-field cron: minute hour day-of-month month day-of-week, with *, */step, a-b ranges and
// comma lists. Local time, minute resolution, Sunday = 0. Anything unparseable matches nothing.
function cronField(spec, min, max) {
  const out = new Set();
  for (const part of String(spec).split(',')) {
    const m = part.trim().match(/^(\*|\d+)(?:-(\d+))?(?:\/(\d+))?$/);
    if (!m) return new Set(); // one bad field → the whole expression never fires
    const step = Math.max(1, +(m[3] || 1));
    const lo = m[1] === '*' ? min : +m[1];
    const hi = m[2] != null ? +m[2] : (m[1] === '*' || m[3] ? max : lo); // "5" = just 5; "5/10" = 5,15,25…
    for (let v = Math.max(lo, min); v <= Math.min(hi, max); v += step) out.add(v);
  }
  return out;
}
const CRON_RANGES = [[0, 59], [0, 23], [1, 31], [1, 12], [0, 6]];
function cronMatch(expr, d) {
  const f = String(expr).trim().split(/\s+/);
  if (f.length !== 5) return false;
  const vals = [d.getMinutes(), d.getHours(), d.getDate(), d.getMonth() + 1, d.getDay()];
  return vals.every((v, i) => cronField(f[i], CRON_RANGES[i][0], CRON_RANGES[i][1]).has(v));
}
const cronValid = expr => String(expr).trim().split(/\s+/).length === 5 &&
  String(expr).trim().split(/\s+/).every((p, i) => cronField(p, CRON_RANGES[i][0], CRON_RANGES[i][1]).size > 0);

// Tick every minute; run each app's due jobs in its working dir with its env (Docker apps: inside the
// container). A job still running when it comes due again is skipped rather than stacked up.
let lastCronMinute = null;
function runJobs(now = new Date()) {
  const minute = Math.floor(now.getTime() / 60_000);
  if (minute === lastCronMinute) return; // an interval that drifts must not fire twice in one minute
  lastCronMinute = minute;
  for (const app of apps) {
    for (const [i, job] of (app.jobs || []).entries()) {
      if (!job.cmd || !cronMatch(job.schedule, now)) continue;
      const key = `${app.name}:${i}`;
      if (jobRunning.has(key)) { pushLog(app.name, `⏱ Job "${job.cmd}" is still running — skipping this run.`); continue; }
      if (!app.cwd || !fs.existsSync(app.cwd)) { pushLog(app.name, `⏱ Job skipped — no deployed code yet.`); continue; }
      if (app.container && !procs.get(app.name)) { pushLog(app.name, `⏱ Job skipped — container is not running.`); continue; }
      jobRunning.add(key);
      pushLog(app.name, `⏱ Scheduled job (${job.schedule}): ${job.cmd}`);
      const p = app.container
        ? run(app.name, 'docker', ['exec', app.container, 'sh', '-c', job.cmd], app.cwd, false)
        : run(app.name, job.cmd, [], app.cwd, true, { ...process.env, ...decEnv(app.env), PORT: String(app.port || '') });
      p.finally(() => jobRunning.delete(key));
    }
  }
}

// ---- backup / restore of platform state ----
// One JSON file: app definitions (env still encrypted), the caller's API tokens, and — when the key
// lives in logs/.secret rather than JC_SECRET — that key, since without it the env vars won't decrypt.
function backup(visible) {
  const mine = apps.filter(visible);
  const owners = new Set(mine.map(a => a.owner).filter(Boolean));
  let secret = null;
  if (!process.env.JC_SECRET) try { secret = fs.readFileSync(SECRET_FILE).toString('base64'); } catch (_) {}
  return {
    v: 1, ts: new Date().toISOString(), apps: mine, secret,
    tokens: Object.fromEntries(Object.entries(tokens).filter(([, email]) => owners.has(email))),
  };
}
// Additive by design: an app whose name already exists is skipped, never overwritten, and restored apps
// land stopped so nothing launches behind your back. The existing encryption key is never replaced.
function restore(data) {
  const notes = [];
  if (data.secret && !process.env.JC_SECRET) {
    if (fs.existsSync(SECRET_FILE)) notes.push('Kept the existing encryption key — env vars from another host may not decrypt.');
    else { try { fs.writeFileSync(SECRET_FILE, Buffer.from(data.secret, 'base64'), { mode: 0o600 }); _encKey = null; } catch (_) {} }
  }
  const added = [], skipped = [];
  for (const a of Array.isArray(data.apps) ? data.apps : []) {
    if (!a || !a.name) continue;
    if (find(a.name)) { skipped.push(a.name); continue; }
    apps.push({ ...a, pid: null, container: null, sleeping: false, status: 'stopped', desired: 'stopped', health: 'unknown' });
    added.push(a.name);
  }
  if (data.tokens && typeof data.tokens === 'object') { Object.assign(tokens, data.tokens); saveTokens(); }
  save();
  return { added, skipped, notes };
}

function checkAlert(resource, pct) {
  if (pct < ALERT_PCT || Date.now() - (lastAlert[resource] || 0) < ALERT_EVERY) return;
  lastAlert[resource] = Date.now();
  const to = process.env.NOTIFY_TO || process.env.GMAIL_USER;
  if (!to) return;
  // Name the biggest apps on a disk alert — "85% full" is not actionable on its own.
  const top = resource === 'disk'
    ? [...appDisk].filter(([, d]) => d.bytes).sort((a, b) => b[1].bytes - a[1].bytes).slice(0, 3)
    : [];
  const largest = top.length ? '\n\nLargest apps on disk:\n' + top.map(([n, d]) => `  ${n} — ${(d.bytes / 1048576).toFixed(0)} MB`).join('\n') : '';
  sendMail(to, `[Jerrick Cloud] ${resource} at ${pct}%`,
    `Host ${resource} usage is ${pct}% (alert threshold ${ALERT_PCT}%).\nFree up ${resource} on your Jerrick Cloud server.${largest}`, null);
}

// "[D-]H:MM:SS" (win tasklist) / "[DD-]HH:MM:SS" (unix ps) cumulative CPU time -> ms, or null.
function parseCpuTime(s) {
  const m = String(s).trim().match(/^(?:(\d+)-)?(\d+):(\d+)(?::(\d+))?/); // optional days, then A:B[:C]
  if (!m) return null;
  const d = +m[1] || 0, g = [m[2], m[3], m[4]].filter(x => x != null).map(Number);
  const [h, mi, se] = g.length === 3 ? g : [0, g[0], g[1]]; // 3 parts = H:M:S, 2 = M:S
  return (((d * 24 + h) * 60 + mi) * 60 + se) * 1000;
}
// Per-pid resident memory + cumulative CPU time in one OS query (Node exposes neither for children).
// ponytail: per-pid only (no child-tree sum); CPU time has 1s resolution -> % is coarse for near-idle apps.
//   Enough for a home-server gauge; poll tighter or read perf counters if you need precision.
function pidStat(pid) {
  return new Promise(resolve => {
    if (!pid) return resolve({ rss: null, cpuMs: null });
    const [cmd, args, parse] = IS_WIN
      ? ['tasklist', ['/v', '/FI', `PID eq ${pid}`, '/NH', '/FO', 'CSV'], o => {
          const f = (o.match(/"([^"]*)"/g) || []).map(s => s.slice(1, -1)); // /v CSV: mem @4 ("12,345 K"), CPU time @7
          return { rss: f[4] ? parseInt(f[4].replace(/\D/g, ''), 10) * 1024 : null, cpuMs: parseCpuTime(f[7]) };
        }]
      : ['ps', ['-o', 'rss=,cputime=', '-p', String(pid)], o => {
          const [r, t] = o.trim().split(/\s+/); const rss = parseInt(r, 10);
          return { rss: isNaN(rss) ? null : rss * 1024, cpuMs: parseCpuTime(t) };
        }];
    let out = '';
    const p = spawn(cmd, args);
    p.stdout.on('data', d => out += d);
    p.on('error', () => resolve({ rss: null, cpuMs: null }));
    p.on('close', () => { try { resolve(parse(out)); } catch (_) { resolve({ rss: null, cpuMs: null }); } });
  });
}
// Instantaneous CPU% from the growth in cumulative CPU time between two polls, normalised by core count.
// Keyed by app name and reset when the pid changes (restart), so the map stays bounded by app count.
const cpuHist = new Map(); // name -> { pid, cpuMs, ts }
function pidCpuPct(name, pid, cpuMs) {
  if (cpuMs == null || !pid) { cpuHist.delete(name); return null; }
  const now = Date.now(), prev = cpuHist.get(name);
  cpuHist.set(name, { pid, cpuMs, ts: now });
  if (!prev || prev.pid !== pid || now <= prev.ts) return null; // need two samples of the same process
  return Math.max(0, Math.min(100, Math.round((cpuMs - prev.cpuMs) / (now - prev.ts) / os.cpus().length * 100)));
}

// Current HEAD (short sha) of a git working copy, or null. Used for deploy history / rollback.
function gitHead(cwd) {
  return new Promise(resolve => {
    let out = '';
    const p = spawn('git', ['rev-parse', '--short', 'HEAD'], { cwd });
    p.stdout.on('data', d => out += d);
    p.on('error', () => resolve(null));
    p.on('close', () => resolve(out.trim() || null));
  });
}
function recordDeploy(app, commit) {
  app.deploys = [{ ts: new Date().toISOString(), commit }, ...(app.deploys || [])].slice(0, 20);
  save();
}

// Extract a .zip into dir with no unzip dependency, using what the OS ships. Resolves true on success.
// Windows: PowerShell Expand-Archive is the reliable native unzip (a bare `tar` may resolve to Git's GNU
// tar, which can't read zips and rejects C:\ paths). Unix: unzip, then bsdtar as a fallback.
function extractZip(zipPath, dir) {
  const runTo = (cmd, args) => new Promise(r => { const p = spawn(cmd, args); p.on('error', () => r(false)); p.on('close', c => r(c === 0)); });
  const bsdtar = () => runTo('tar', ['-xf', zipPath, '-C', dir]);
  return IS_WIN
    ? runTo('powershell', ['-NoProfile', '-Command', `Expand-Archive -LiteralPath '${zipPath}' -DestinationPath '${dir}' -Force`]).then(ok => ok || bsdtar())
    : runTo('unzip', ['-o', zipPath, '-d', dir]).then(ok => ok || bsdtar());
}

// ---- google oauth (zero-dep; Authorization Code flow) ----
function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('='); if (i < 0) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
const currentUser = req => sessions.get(parseCookies(req).jc_session);

// The login landing page: a single "Continue with Google" button. The button hits /auth/google,
// which fires the real OAuth redirect below. Inline (no file) — it's one self-contained screen.
function loginPage() {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in · Jerrick Cloud</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  :root{color-scheme:dark}
  body{font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;
       background:#0a0d14;background-image:radial-gradient(900px 480px at 50% -8%,rgba(91,140,255,.20),transparent 62%);
       color:#e7ebf3;min-height:100vh;display:grid;place-items:center;padding:24px;-webkit-font-smoothing:antialiased}
  .card{background:#111621;border:1px solid #232c3d;width:400px;max-width:100%;border-radius:18px;padding:40px 36px;
        box-shadow:0 28px 64px -22px rgba(0,0,0,.75);text-align:center}
  .mark{width:56px;height:56px;border-radius:16px;margin:0 auto 20px;display:grid;place-items:center;
        background:linear-gradient(135deg,#38bdf8,#5b8cff 45%,#7c5cff);color:#fff;font-weight:800;font-size:26px;
        box-shadow:0 12px 30px -10px rgba(91,140,255,.75)}
  .title{font-size:22px;font-weight:700;letter-spacing:-.01em}
  .sub{color:#98a2b3;font-size:13.5px;margin:8px 0 28px}
  .gbtn{display:flex;align-items:center;justify-content:center;gap:11px;width:100%;height:46px;
        border:1px solid #dadce0;border-radius:10px;background:#fff;color:#3c4043;font-size:14px;font-weight:600;
        text-decoration:none;cursor:pointer;transition:background .15s,box-shadow .15s}
  .gbtn:hover{background:#f7f8f8;box-shadow:0 3px 10px rgba(0,0,0,.3)}
  .foot{color:#5b6472;font-size:11.5px;margin-top:24px}
</style></head><body>
  <div class="card">
    <div class="mark">J</div>
    <div class="title">Jerrick Cloud</div>
    <div class="sub">Sign in to deploy and manage your web apps</div>
    <a class="gbtn" href="/auth/google">
      <svg width="18" height="18" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
      Continue with Google
    </a>
    <div class="foot">Jerrick Cloud · localhost</div>
  </div>
</body></html>`;
}

function startLogin(res) {
  const state = crypto.randomBytes(16).toString('hex');
  pendingStates.add(state);
  const q = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID, redirect_uri: REDIRECT_URI,
    response_type: 'code', scope: 'openid email profile', state, prompt: 'select_account',
  });
  res.writeHead(302, { Location: `https://accounts.google.com/o/oauth2/v2/auth?${q}` });
  res.end();
}

// Trade the auth code for tokens, then read email/name from the id_token. The id_token comes straight from
// Google's token endpoint over TLS, so it's safe to decode the payload without JWK signature verification.
function exchangeCode(code) {
  return new Promise((resolve, reject) => {
    const form = new URLSearchParams({
      code, client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: REDIRECT_URI, grant_type: 'authorization_code',
    }).toString();
    const r = https.request('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(form) },
    }, resp => {
      let b = ''; resp.on('data', c => b += c);
      resp.on('end', () => {
        try {
          const tok = JSON.parse(b);
          if (!tok.id_token) return reject(new Error(tok.error_description || tok.error || 'no id_token'));
          const p = JSON.parse(Buffer.from(tok.id_token.split('.')[1], 'base64url').toString());
          resolve({ email: p.email, name: p.name || p.email });
        } catch (e) { reject(e); }
      });
    });
    r.on('error', reject); r.write(form); r.end();
  });
}

async function handleCallback(req, res, u) {
  const code = u.searchParams.get('code'), state = u.searchParams.get('state');
  if (!code || !state || !pendingStates.delete(state)) { res.writeHead(400); return res.end('Bad OAuth state'); }
  try {
    const user = await exchangeCode(code);
    const sid = crypto.randomBytes(16).toString('hex');
    sessions.set(sid, user); saveSessions(); // persist so a server restart doesn't sign everyone out
    await recordUser(user); // first-time users -> MongoDB; failures never block sign-in
    logActivity(user, 'sign-in');
    res.writeHead(302, { 'Set-Cookie': `jc_session=${sid}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800`, Location: '/' });
    res.end();
  } catch (e) { res.writeHead(500); res.end('Sign-in failed: ' + e.message); }
}

// ---- first-time user persistence: MongoDB ----
// On login, upsert the user by email. $setOnInsert => the first login captures name+createdAt;
// returning logins match the same _id and change nothing (upsert is idempotent, so no existence gate
// is needed). No-op unless MONGODB_URI is set, so the platform still runs open on localhost.
// Configure via one env var:
//   MONGODB_URI   e.g. mongodb+srv://user:pass@cluster.mongodb.net/jerrickcloud
// The db name comes from the connection string; override with MONGODB_DB / MONGODB_COLLECTION (default "users").
// ponytail: one shared client, lazy-connected, no pool tuning beyond the driver's own defaults. Enough for a single-tenant tool.
let mongoUsersPromise = null;
function mongoUsers() {
  if (!mongoUsersPromise) {
    const { MongoClient } = require('mongodb'); // required only when configured -> server runs dep-free unless MONGODB_URI is set
    mongoUsersPromise = new MongoClient(process.env.MONGODB_URI).connect()
      .then(c => c.db(process.env.MONGODB_DB).collection(process.env.MONGODB_COLLECTION || 'users'))
      .catch(e => { mongoUsersPromise = null; throw e; }); // reset on failure so the next login retries
  }
  return mongoUsersPromise;
}

// The login hook: first-timers get recorded; returning logins are idempotent no-ops. Never blocks sign-in.
async function recordUser(user) {
  if (!user || !user.email || !process.env.MONGODB_URI) return;
  const email = String(user.email).toLowerCase();
  try {
    const users = await mongoUsers();
    await users.updateOne(
      { _id: email },
      { $setOnInsert: { _id: email, email, name: user.name || '', createdAt: new Date() } },
      { upsert: true },
    );
  } catch (e) { console.error('recordUser:', e.message); }
}

// ---- host metrics (memory + disk) ----
// Host-level only: total/used memory (os) and disk usage of the drive holding Jerrick Cloud (fs.statfs).
// ponytail: host-level only — per-app memory/CPU live in pidStat, queried per app on demand, not sampled here.
function metrics() {
  const total = os.totalmem(), free = os.freemem(), used = total - free;
  const mem = { total, free, used, pct: Math.round(used / total * 100) };
  let disk = null;
  try { // statfs: Node 18.15+/19.6+. Missing on older Node -> disk stays null, UI shows "unavailable".
    const s = fs.statfsSync(ROOT);
    const dtotal = s.blocks * s.bsize, dfree = s.bavail * s.bsize, dused = dtotal - dfree;
    disk = { total: dtotal, free: dfree, used: dused, pct: Math.round(dused / dtotal * 100) };
  } catch (_) {}
  return { mem, disk, ts: Date.now() };
}

// ---- http + api ----
function json(res, obj, code = 200) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); }
function readBody(req) {
  return new Promise(r => { let b = ''; req.on('data', c => b += c); req.on('end', () => { try { r(JSON.parse(b || '{}')); } catch (_) { r({}); } }); });
}

// Reverse proxy: requests to <app>.localhost:PORT (or a mapped custom domain) are forwarded to that app's internal port.
// *.localhost resolves to 127.0.0.1 in modern browsers with no DNS/hosts setup.
async function proxyToApp(name, req, res) {
  const app = find(name);
  // Every request through the proxy is telemetry: status + latency, for the Insights blade.
  // ponytail: in-memory ring, lost on server restart (the log file isn't) — persist it if post-mortems need it.
  const t0 = Date.now();
  const track = status => {
    const h = reqLog.get(name) || [];
    h.push({ ts: Date.now(), method: req.method, path: req.url.split('?')[0].slice(0, 200), status, ms: Date.now() - t0 });
    while (h.length > REQ_CAP) h.shift();
    reqLog.set(name, h);
  };
  lastReq.set(name, Date.now()); // idle clock — set before any gate, a blocked request is still traffic

  if (app) {
    const denied = accessDenied(app, req); // password / IP gate: refuse before the app is even woken
    if (denied) {
      track(denied.code);
      res.writeHead(denied.code, { 'Content-Type': 'text/html; charset=utf-8', ...(denied.headers || {}) });
      return res.end(`<h2>${denied.code} &middot; ${name}</h2><p>${denied.body}</p>`);
    }
    if (app.sleeping && !procs.get(name)) await wakeApp(app); // wake on request, then serve it
  }

  if (!app || !app.port || !procs.get(name)) { // gate on a live process, not the status label → zero-downtime rebuilds keep serving
    if (app) track(502);
    res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<h2>502 &middot; ${name}</h2><p>This app is not running on Jerrick Cloud.</p>`);
  }
  const headers = { ...req.headers, 'x-forwarded-host': req.headers.host, 'x-forwarded-proto': PROTO, 'x-forwarded-for': req.socket.remoteAddress };
  const up = http.request({ host: '127.0.0.1', port: app.port, method: req.method, path: req.url, headers }, upRes => {
    track(upRes.statusCode);
    res.writeHead(upRes.statusCode, upRes.headers);
    upRes.pipe(res);
  });
  up.on('error', e => { track(502); if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' }); res.end('502 Bad Gateway: ' + e.message); });
  req.pipe(up);
}

// ---- Application Insights ----
// Query the logs already stored on disk by appendLogFile (nothing new is stored) plus the values you
// look up when an app misbehaves: error/warning counts, the last error, request volume + failure rate +
// latency from the proxy, and memory/CPU peaks from the metric sampler.
// ponytail: full-file scan + substring match per query, no index. The log file is capped at 2 MB — fine.
function insights(app, { q = '', level = 'all', limit = 200 } = {}) {
  let lines = [];
  try { lines = fs.readFileSync(logFile(app.name), 'utf8').split(/\r?\n/).filter(Boolean); } catch (_) {} // no log file yet
  const counts = { error: 0, warn: 0, info: 0 };
  const needle = q.toLowerCase();
  const hits = [];
  let lastError = null;
  for (const text of lines) {
    const lvl = levelOf(text);
    counts[lvl]++;
    if (lvl === 'error') lastError = text;
    if (level !== 'all' && lvl !== level) continue;
    if (needle && !text.toLowerCase().includes(needle)) continue;
    hits.push({ level: lvl, text });
  }
  const reqs = reqLog.get(app.name) || [];
  const times = reqs.map(r => r.ms).sort((a, b) => a - b);
  const hist = appMetrics.get(app.name) || [];
  const peak = k => hist.length ? Math.max(...hist.map(h => h[k] || 0)) : null;
  return {
    status: app.status, health: app.health || 'unknown', restarts: app.restarts || 0,
    lines: lines.length, counts, lastError,
    requests: {
      total: reqs.length,
      failed: reqs.filter(r => r.status >= 500).length,
      clientErrors: reqs.filter(r => r.status >= 400 && r.status < 500).length,
      avgMs: times.length ? Math.round(times.reduce((s, v) => s + v, 0) / times.length) : null,
      p95Ms: times.length ? times[Math.min(times.length - 1, Math.floor(times.length * 0.95))] : null,
      failures: reqs.filter(r => r.status >= 400).slice(-25).reverse(), // newest first
    },
    peakRss: peak('rss'), peakCpu: peak('cpu'),
    diagnosis: app.diagnosis || null,
    matched: hits.length, results: hits.slice(-limit).reverse(), // newest first
  };
}

// ---- AI assistant ----
// Claude answers questions about the platform by calling the read-only tools below over the same
// data the dashboard shows. Two env vars, both read by the SDK itself — no other config:
//   ANTHROPIC_API_KEY   your key. Unset => the assistant is off and everything else still runs.
//   ANTHROPIC_BASE_URL  optional; point it at a gateway/proxy instead of api.anthropic.com.
// Env var VALUES are never sent — only their names — so secrets stay on this machine.
// ponytail: read-only tools, no streaming. It diagnoses and tells you what to click; it doesn't
//   restart or scale anything. Add a write tool behind a confirm step if you want it to act.
const ASSISTANT_MODEL = process.env.ANTHROPIC_MODEL || 'claude-opus-5';
let _llm = null;
const llm = () => _llm || (_llm = new Anthropic()); // reads ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL

const ASSISTANT_SYSTEM = `You are the Jerrick Cloud assistant, built into a self-hosted web app platform (an Azure App Service for one machine). Apps are deployed from a Git URL, a local folder, or a zip; Jerrick Cloud installs dependencies, injects PORT, starts the app, and serves it through a reverse proxy at http://<app>.localhost:8080.

Answer questions about the user's own deployed apps: why one is failing, what its logs say, how much memory and CPU it is using, whether it is over its plan's memory cap, what its recent deploys and failed requests look like, and how the host machine is doing.

Always call the tools for real data before answering — never guess a status, a number, or a log line. When an app is broken, name the most likely cause, quote the log line that shows it, and give the concrete fix (an env var to set, a Procfile web: line, a health check path, a bigger plan, a rollback to a named commit).

Be brief and specific: a couple of sentences plus the evidence, not an essay. Environment variable values are deliberately hidden from you; you only ever see their names.

You can propose exactly two actions — restart and redeploy — with request_restart and request_redeploy. Those tools never run anything: they put a Confirm button in front of the user, who decides. Propose one only when your diagnosis says it will actually help, say in one line what it will do and why, and never claim it has happened. Everything else (environment variables, plans, health check paths, custom domains, rollbacks) the user changes themselves — name the tab to do it in.`;

// The assistant's tool surface: everything the dashboard can show, scoped to the apps this user may see.
const assistantTools = visible => [
  betaTool({
    name: 'list_apps',
    description: "List every app this user can see, with status, health, plan, URL, source and restart count. Call this first whenever the question isn't already about one named app.",
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    run: async () => JSON.stringify(visible().map(a => ({
      name: a.name, status: a.status, health: a.health || 'unknown', plan: a.size || 'free',
      url: a.url, source: a.source, port: a.port, restarts: a.restarts || 0,
      startedAt: a.startedAt || null, createdAt: a.createdAt, domains: a.domains || [],
    }))),
  }),
  betaTool({
    name: 'app_diagnostics',
    description: 'Everything known about one app: memory and CPU from the metric sampler, stored log counts, the last error, matching log lines, request volume / failure rate / latency through the proxy, recent failed requests, deploy history, and configuration (environment variable NAMES only). Use q and level to search the stored logs.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'App name, exactly as returned by list_apps' },
        q: { type: 'string', description: 'Optional substring to search the stored logs for, e.g. ECONNREFUSED or TypeError' },
        level: { type: 'string', enum: ['all', 'error', 'warn', 'info'], description: 'Which log lines to return (default error)' },
      },
      required: ['name'],
      additionalProperties: false,
    },
    run: async ({ name, q, level }) => {
      const app = visible().find(a => a.name === name);
      if (!app) return `No app named "${name}" — call list_apps for the names you can see.`;
      const hist = appMetrics.get(app.name) || [];
      const last = hist[hist.length - 1] || {}; // last sample, not a fresh probe: no interference with the CPU% baseline
      return JSON.stringify({
        ...insights(app, { q: q || '', level: level || 'error', limit: 40 }),
        plan: app.size || 'free', planMemMb: planMem(app.size),
        rss: last.rss ?? null, cpu: last.cpu ?? null, sampledAt: last.ts ?? null, diskBytes: diskOf(app.name),
        uptimeSec: app.startedAt && app.status === 'running' ? Math.round((Date.now() - new Date(app.startedAt)) / 1000) : 0,
        source: app.source, url: app.url, port: app.port, runtime: app.runtime || null,
        healthPath: app.healthPath || null, desired: app.desired,
        envKeys: Object.keys(app.env || {}), // names only — values never leave this machine
        deploys: (app.deploys || []).slice(-5), domains: app.domains || [],
      });
    },
  }),
  betaTool({
    name: 'host_metrics',
    description: 'Memory and disk usage of the machine hosting Jerrick Cloud, plus recent samples. Use for "is the server out of memory / disk" questions, or when several apps are unhealthy at once.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    run: async () => JSON.stringify({ ...metrics(), recent: metricHistory.slice(-20), alertPct: ALERT_PCT }),
  }),
];

// The two actions the assistant may propose. Both are graceful — the running version keeps serving
// until the new one is healthy — which is why they're safe to offer behind a single confirm click.
const ACTIONS = {
  restart: 'Restart the app process in place. Use for a hung, wedged, or memory-leaking app, or to pick up environment variables that were changed after it started.',
  redeploy: 'Re-pull the source, reinstall dependencies, and start the new version. Use when the fix is in the code or in the dependencies rather than in the running process.',
};
// Write tools that write nothing: they record a proposal, the dashboard shows the user a Confirm
// button, and confirming calls the same POST /api/apps/<name>/<action> route the toolbar already uses.
// ponytail: one code path performs restarts and it's the one that already existed — this only asks.
const actionTools = (visible, pending) => Object.entries(ACTIONS).map(([action, what]) => betaTool({
  name: `request_${action}`,
  description: `${what} This does NOT perform the ${action} — it puts a "Confirm ${action}" button in front of the user, who decides. Call it once you have diagnosed a problem this would fix.`,
  inputSchema: {
    type: 'object',
    properties: {
      name: { type: 'string', description: 'App name, exactly as returned by list_apps' },
      reason: { type: 'string', description: 'One short line shown to the user next to the button, e.g. "wedged after 5 crash-loops"' },
    },
    required: ['name', 'reason'],
    additionalProperties: false,
  },
  run: async ({ name, reason }) => {
    const app = visible().find(a => a.name === name);
    if (!app) return `No app named "${name}" — call list_apps for the names you can see.`;
    if (!pending.some(p => p.name === name && p.action === action)) pending.push({ action, name, reason: String(reason).slice(0, 200) });
    return `A "Confirm ${action}" button for "${name}" is now in front of the user. Nothing has run. Tell them in one line what it will do and why, and that it is their call. Do not request this again for this app.`;
  },
}));

// Run one assistant turn: chat history in, answer + any actions awaiting confirmation out.
// Tools resolve against `visible()` only, so the assistant can never reach someone else's app.
async function askAssistant(messages, visible) {
  const pending = [];
  const reply = await llm().beta.messages.toolRunner({
    model: ASSISTANT_MODEL,
    max_tokens: 16000,
    system: ASSISTANT_SYSTEM,
    tools: [...assistantTools(visible), ...actionTools(visible, pending)],
    messages,
    max_iterations: 8, // bound the loop — this is a metered API
  });
  return { reply: reply.content.filter(b => b.type === 'text').map(b => b.text).join('\n').trim(), pending };
}

// ---- automatic crash diagnosis ----
// An app just hit `failed`: it is down and nothing is going to bring it back on its own. That is the
// moment the assistant is most useful and least likely to be watched, so run it unprompted, scoped to
// that one app, and leave the root cause in Application Insights for whenever the user looks. Off
// without ANTHROPIC_API_KEY, exactly like the Assistant tab, and it never touches the app.
// ponytail: one API call per failure with an in-flight guard. Add a cooldown if a redeploy loop that
//   fails over and over gets expensive.
const diagnosing = new Set();
async function diagnose(app) {
  if (!process.env.ANTHROPIC_API_KEY || !app || diagnosing.has(app.name)) return;
  diagnosing.add(app.name);
  try {
    const { reply } = await askAssistant([{
      role: 'user',
      content: `The app "${app.name}" just entered the failed state on this host — it is down and will not restart itself. `
        + `Call app_diagnostics for it (and host_metrics if the evidence points at the machine), then report the root cause: `
        + `what broke, the exact log line that shows it, and the concrete fix. Four sentences at most. `
        + `Nobody is reading this live, so ask no questions, and do not call request_restart or request_redeploy — `
        + `there is no user here to click a button.`,
    }], () => [app]); // tools resolve against this list only — it sees the broken app and nothing else
    const a = find(app.name);
    if (!reply || !a || a.status !== 'failed') return; // recovered while we were thinking — a stale diagnosis is worse than none
    a.diagnosis = { text: reply.slice(0, 4000), at: new Date().toISOString() };
    save();
    // A pointer, not the text: the diagnosis quotes error lines, and the log file is what insights() counts.
    pushLog(a.name, '↳ Auto-diagnosis ready — open Application Insights for the root cause.');
  } catch (e) {
    pushLog(app.name, `(auto-diagnosis unavailable: ${e.message})`);
  } finally {
    diagnosing.delete(app.name);
  }
}

// Map an incoming Host header to an app name: an <app>.localhost subdomain, or a mapped custom domain.
function hostToApp(hostname) {
  if (hostname.endsWith('.localhost') && hostname.length > '.localhost'.length) return hostname.slice(0, -('.localhost'.length));
  const a = apps.find(a => (a.domains || []).includes(hostname));
  return a ? a.name : null;
}

const handler = async (req, res) => {
  // App subdomain / custom domain -> reverse proxy to the running app.
  const hostname = (req.headers.host || '').split(':')[0];
  const proxied = hostToApp(hostname);
  if (proxied) return proxyToApp(proxied, req, res);

  const u = new URL(req.url, 'http://localhost');
  const parts = u.pathname.split('/').filter(Boolean);

  // ---- git-push webhook (PRE-auth: GitHub has no session cookie; authenticated by the per-app hook key) ----
  if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'apps' && parts[3] === 'hook') {
    const app = find(parts[2]);
    if (!app || !app.hookKey || u.searchParams.get('key') !== app.hookKey) return json(res, { error: 'Bad hook key' }, 403);
    pushLog(app.name, '🔔 Webhook received — redeploying');
    deploy(app); // graceful: old version keeps serving until the new one is healthy
    return json(res, { ok: true });
  }

  // ---- auth gate (enforced only when Google OAuth is configured) ----
  if (AUTH_ON) {
    if (u.pathname === '/auth/login') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(loginPage()); }
    if (u.pathname === '/auth/google') return startLogin(res);
    if (u.pathname === '/auth/callback') return handleCallback(req, res, u);
    if (u.pathname === '/auth/logout') {
      const sid = parseCookies(req).jc_session;
      if (sid) { logActivity(sessions.get(sid), 'sign-out'); sessions.delete(sid); saveSessions(); }
      res.writeHead(302, { 'Set-Cookie': 'jc_session=; HttpOnly; Path=/; Max-Age=0', Location: '/auth/login' });
      return res.end();
    }
    // API bearer token (for CLI / CI) authenticates too; otherwise the session cookie.
    const bearer = (req.headers.authorization || '').match(/^Bearer\s+(\S+)$/i);
    req.user = (bearer && tokens[bearer[1]]) ? { email: tokens[bearer[1]] } : currentUser(req);
    if (!req.user) {
      if (parts[0] === 'api') return json(res, { error: 'Not authenticated' }, 401);
      res.writeHead(302, { Location: '/auth/login' }); return res.end(); // send the dashboard to Google
    }
    // No Owner yet -> whoever is here first claims the subscription. Sits on the request rather than on
    // the OAuth callback so an install that was already signed in before roles existed still gets one.
    claimOwner(req.user.email);
  }

  if (req.method === 'GET' && u.pathname === '/api/activity')
    return json(res, activity(req.user, Math.min(500, Number(u.searchParams.get('limit')) || 200)));
  if (req.method === 'GET' && u.pathname === '/api/metrics') return json(res, metrics());
  if (req.method === 'GET' && u.pathname === '/api/metrics/history') return json(res, metricHistory);

  // Assistant: chat history in, one answer out. Its tools only ever see apps this user may see.
  if (req.method === 'POST' && u.pathname === '/api/assistant') {
    if (!process.env.ANTHROPIC_API_KEY) return json(res, { error: 'Set ANTHROPIC_API_KEY in .env to turn the assistant on (ANTHROPIC_BASE_URL is optional).' }, 400);
    const body = await readBody(req);
    const messages = (Array.isArray(body.messages) ? body.messages : []).slice(-20)
      .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string' && m.content.trim())
      .map(m => ({ role: m.role, content: m.content.slice(0, 20_000) }));
    if (!messages.length) return json(res, { error: 'A question is required' }, 400);
    try {
      // { reply, pending } — pending actions are proposals; the user confirms them in the UI.
      return json(res, await askAssistant(messages, () => apps.filter(a => canSee(a, req.user))));
    } catch (e) {
      return json(res, { error: `Assistant request failed: ${e.message}` }, 502);
    }
  }

  if (req.method === 'GET' && u.pathname === '/api/me') {
    return json(res, {
      ...(AUTH_ON ? { auth: true, email: (req.user || {}).email, name: (req.user || {}).name } : { auth: false }),
      role: roleOf(req.user), roleName: ROLES[roleOf(req.user)] || null, canAssign: canAssign(req.user),
      assistant: !!process.env.ANTHROPIC_API_KEY,
    });
  }

  // ---- subscription access control (IAM): who holds which role across this whole Jerrick Cloud ----
  if (parts[0] === 'api' && parts[1] === 'roles') {
    if (!AUTH_ON) return json(res, { error: 'Enable Google sign-in (GOOGLE_CLIENT_ID/SECRET) to assign roles' }, 400);

    if (req.method === 'GET' && parts.length === 2) {
      return json(res, {
        org: orgDomain(), owner: subOwner(), roles: ROLES,
        myRole: roleOf(req.user), canAssign: canAssign(req.user),
        assignments: Object.entries(roles).map(([email, role]) => ({ email, role, name: ROLES[role] || role })),
      });
    }

    if (req.method === 'PUT' && parts.length === 2) {
      if (!canAssign(req.user)) return json(res, { error: 'Only an Owner or User Access Administrator can assign roles' }, 403);
      const body = await readBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      const role = String(body.role || '').trim().toLowerCase();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json(res, { error: 'Enter a valid email' }, 400);
      if (!ROLES[role]) return json(res, { error: 'Unknown role' }, 400);
      const org = orgDomain();
      if (org && email.split('@')[1] !== org) return json(res, { error: `${email} is outside your organisation (@${org})` }, 400);
      // Only an Owner hands out Owner — otherwise a User Access Administrator could just promote itself.
      if (role === 'owner' && roleOf(req.user) !== 'owner') return json(res, { error: 'Only an Owner can grant the Owner role' }, 403);
      if (roles[email] === 'owner' && role !== 'owner' && lastOwner(email))
        return json(res, { error: 'The subscription must keep at least one Owner' }, 400);
      roles[email] = role; saveRoles();
      logActivity(req.user, 'grant', null, `${email} → ${ROLES[role]}`);
      return json(res, { ok: true, email, role });
    }

    if (req.method === 'DELETE' && parts.length === 3) {
      if (!canAssign(req.user)) return json(res, { error: 'Only an Owner or User Access Administrator can remove roles' }, 403);
      const email = decodeURIComponent(parts[2]).toLowerCase();
      if (roles[email] === 'owner' && roleOf(req.user) !== 'owner') return json(res, { error: 'Only an Owner can remove an Owner' }, 403);
      if (roles[email] === 'owner' && lastOwner(email)) return json(res, { error: 'The subscription must keep at least one Owner' }, 400);
      const was = roles[email]; delete roles[email]; saveRoles();
      logActivity(req.user, 'revoke', null, `${email} (was ${ROLES[was] || was})`);
      return json(res, { ok: true });
    }
  }

  // API bearer token: issue (POST, revokes any prior) / check (GET). Needs Google sign-in to have a stable owner.
  if (u.pathname === '/api/token') {
    if (!AUTH_ON) return json(res, { error: 'Enable Google sign-in (GOOGLE_CLIENT_ID/SECRET) to use API tokens' }, 400);
    if (req.method === 'POST') {
      for (const [t, e] of Object.entries(tokens)) if (e === req.user.email) delete tokens[t]; // one token per user
      const t = crypto.randomBytes(24).toString('hex'); tokens[t] = req.user.email; saveTokens();
      return json(res, { token: t });
    }
    if (req.method === 'GET') return json(res, { hasToken: Object.values(tokens).includes(req.user.email) });
  }

  // Backup: download every app you can see (env still encrypted) + the key that decrypts it. Restore is additive.
  if (req.method === 'GET' && u.pathname === '/api/backup') {
    const stamp = new Date().toISOString().slice(0, 10);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="jerrick-backup-${stamp}.json"` });
    return res.end(JSON.stringify(backup(a => canSee(a, req.user)), null, 2));
  }
  if (req.method === 'POST' && u.pathname === '/api/restore') {
    if (roleOf(req.user) === 'useradmin') return json(res, { error: 'A User Access Administrator cannot restore apps' }, 403);
    const body = await readBody(req);
    if (!body || !Array.isArray(body.apps)) return json(res, { error: 'That is not a Jerrick Cloud backup file' }, 400);
    const restored = restore(body);
    logActivity(req.user, 'restore', null, `added ${restored.added.length}, skipped ${restored.skipped.length}`);
    return json(res, restored);
  }

  if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/index.html')) {
    return fs.readFile(path.join(ROOT, 'index.html'), (e, data) => {
      if (e) { res.writeHead(404); return res.end('index.html not found'); }
      res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(data);
    });
  }

  if (parts[0] === 'api' && parts[1] === 'apps') {
    // When auth is on, a user sees/controls their own apps, apps shared with them, and legacy apps with no owner.
    const mine = a => canSee(a, req.user);
    if (req.method === 'GET' && parts.length === 2) return json(res, apps.filter(mine).map(publicApp));

    if (req.method === 'POST' && parts.length === 2) {
      // A User Access Administrator manages access, not resources. Anyone else signed in still creates their own apps.
      if (roleOf(req.user) === 'useradmin') return json(res, { error: 'A User Access Administrator cannot create apps' }, 403);
      const body = await readBody(req);
      const name = slugify(body.name);
      const source = String(body.source || '').trim();
      const token = String(body.token || '').trim(); // optional; used for the clone, never stored
      const size = String(body.size || 'free').toLowerCase().slice(0, 20); // chosen plan; cosmetic (all apps run locally)
      const zipB64 = String(body.zip || ''); // optional: base64 zip upload instead of a source
      if (!name) return json(res, { error: 'A valid name is required' }, 400);
      if (find(name)) return json(res, { error: `App "${name}" already exists` }, 409);

      // Fields shared by every new app. hookKey authenticates the git-push webhook; desired drives auto-restart/boot.
      const base = { name, size, port: null, pid: null, status: 'queued', url: null, env: {}, desired: 'running',
        hookKey: crypto.randomBytes(12).toString('hex'), domains: [], deploys: [], collaborators: [],
        owner: req.user ? req.user.email : undefined, createdAt: new Date().toISOString() };

      if (zipB64) { // zip upload → extract into workspaces/, deploy in place
        const buf = Buffer.from(zipB64, 'base64');
        if (!buf.length) return json(res, { error: 'Empty or invalid zip' }, 400);
        if (buf.length > 50 * 1024 * 1024) return json(res, { error: 'Zip too large (max 50 MB)' }, 400);
        const dir = path.join(WORKSPACES, name);
        fs.mkdirSync(dir, { recursive: true });
        const zipPath = path.join(dir, '_upload.zip');
        fs.writeFileSync(zipPath, buf);
        const app = { ...base, source: `zip:${name}`, managed: false, uploaded: true, cwd: dir };
        apps.push(app); save();
        setStatus(name, 'building'); pushLog(name, `Extracting ${(buf.length / 1024).toFixed(0)} KB upload…`);
        extractZip(zipPath, dir).then(ok => {
          try { fs.unlinkSync(zipPath); } catch (_) {}
          if (!ok) { pushLog(name, 'Failed to extract zip (no tar/unzip on this host?)'); return setStatus(name, 'failed'); }
          deploy(app);
        });
        logActivity(req.user, 'create', name, `zip upload, ${(buf.length / 1024).toFixed(0)} KB`);
        return json(res, app, 201);
      }

      if (!source) return json(res, { error: 'A Git URL, local folder path, or zip upload is required' }, 400);
      const app = { ...base, source, managed: isRemote(source) };
      apps.push(app); save();
      logActivity(req.user, 'create', name, source);
      deploy(app, token); // fire and forget; progress streams over SSE
      return json(res, app, 201);
    }

    const app = find(parts[2]);
    if (!app || !mine(app)) return json(res, { error: 'Not found' }, 404); // owned by someone else → 404, not 403
    // One gate for every mutating route below (GETs are already covered by canSee above), so a read-only
    // role can't slip through a route someone adds later. Access management is the exception: that's
    // exactly what a User Access Administrator is for.
    // Every mutation is recorded here, taken or refused — one place, so a route added later is audited
    // for free. exec records itself instead: its command only exists once the body has been read.
    if (req.method !== 'GET') {
      const act = parts[3] || 'delete';
      if (!canWrite(app, req.user) && !(canAssign(req.user) && parts[3] === 'collaborators')) {
        logActivity(req.user, act, app.name, null, true);
        return json(res, { error: `Your subscription role (${ROLES[roleOf(req.user)]}) is read-only for apps` }, 403);
      }
      if (act !== 'exec') logActivity(req.user, act, app.name, parts[4] && decodeURIComponent(parts[4]));
    }

    if (req.method === 'GET' && parts.length === 3) return json(res, publicApp(app));

    if (req.method === 'GET' && parts[3] === 'stats' && parts.length === 4) {
      const st = await pidStat(app.pid);
      const cpu = pidCpuPct(app.name, app.pid, st.cpuMs);
      const uptimeSec = app.startedAt && app.status === 'running' ? Math.round((Date.now() - new Date(app.startedAt)) / 1000) : 0;
      return json(res, { status: app.status, health: app.health || 'unknown', rss: st.rss, cpu, uptimeSec, restarts: app.restarts || 0, memMb: planMem(app.size), disk: diskOf(app.name) });
    }

    if (req.method === 'PUT' && parts[3] === 'env' && parts.length === 4) {
      const body = await readBody(req);
      const env = {}; // keep only valid shell identifiers; stringify values
      for (const [k, v] of Object.entries(body.env || {})) if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) env[k] = String(v);
      app.env = encEnv(env); save(); // encrypted at rest
      return json(res, { ok: true, env }); // takes effect on next start/restart (plaintext back for display)
    }

    if (req.method === 'POST' && parts[3] === 'scale' && parts.length === 4) {
      const body = await readBody(req);
      const size = String(body.size || '').toLowerCase();
      if (!PLANS[size]) return json(res, { error: 'Unknown plan' }, 400);
      app.size = size; save();
      return json(res, { ok: true, size, memMb: planMem(size) }); // applies on next start/restart
    }

    // Access restrictions, idle sleep, and scheduled jobs — one route, each field optional.
    if (req.method === 'PUT' && parts[3] === 'settings' && parts.length === 4) {
      const body = await readBody(req);
      if ('password' in body) { // '' clears it
        const p = String(body.password || '');
        app.accessPassword = p ? encVal(p) : undefined;
      }
      if ('allowIps' in body) {
        const list = (Array.isArray(body.allowIps) ? body.allowIps : String(body.allowIps || '').split(/[\s,]+/))
          .map(s => String(s).trim()).filter(Boolean);
        const bad = list.find(e => !/^[0-9a-f.:]+$/i.test(e));
        if (bad) return json(res, { error: `"${bad}" is not an IP address or prefix` }, 400);
        app.allowIps = list;
      }
      if ('rateLimit' in body) app.rateLimit = clampInt(body.rateLimit, 100_000) || undefined;
      if ('idleMin' in body) {
        const n = clampInt(body.idleMin, 1440);
        app.idleMin = n || undefined;
        if (!n && app.sleeping) { app.sleeping = false; startApp(app); } // idle sleep off → bring it back up
      }
      if ('jobs' in body) {
        const jobs = (Array.isArray(body.jobs) ? body.jobs : []).slice(0, 20)
          .map(j => ({ schedule: String(j.schedule || '').trim(), cmd: String(j.cmd || '').trim() }))
          .filter(j => j.schedule && j.cmd);
        const bad = jobs.find(j => !cronValid(j.schedule));
        if (bad) return json(res, { error: `"${bad.schedule}" is not a valid cron schedule (5 fields, e.g. "0 3 * * *")` }, 400);
        app.jobs = jobs;
      }
      save();
      return json(res, publicApp(app));
    }

    if (req.method === 'PUT' && parts[3] === 'health' && parts.length === 4) {
      const body = await readBody(req);
      let p = String(body.path || '').trim();
      if (p && !p.startsWith('/')) p = '/' + p;
      app.healthPath = p || undefined; save();
      return json(res, { ok: true, healthPath: app.healthPath || '' });
    }

    // Sharing an app is access management, so it takes the app's own owner or a role that grants access
    // across the subscription — a Contributor can run the app but not widen who reaches it (as in Azure).
    const canShare = () => !AUTH_ON || !app.owner || req.user.email === app.owner || canAssign(req.user);

    if (req.method === 'POST' && parts[3] === 'collaborators' && parts.length === 4) {
      if (!canShare()) return json(res, { error: 'Only the owner can share this app' }, 403);
      const body = await readBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json(res, { error: 'Enter a valid email' }, 400);
      app.collaborators = [...new Set([...(app.collaborators || []), email])]; save();
      return json(res, publicApp(app));
    }
    if (req.method === 'DELETE' && parts[3] === 'collaborators' && parts.length === 5) {
      if (!canShare()) return json(res, { error: 'Only the owner can share this app' }, 403);
      app.collaborators = (app.collaborators || []).filter(e => e !== decodeURIComponent(parts[4]).toLowerCase()); save();
      return json(res, publicApp(app));
    }

    if (req.method === 'POST' && parts[3] === 'domains' && parts.length === 4) {
      const body = await readBody(req);
      const d = String(body.domain || '').trim().toLowerCase();
      if (!/^[a-z0-9.-]+\.[a-z0-9.-]+$/.test(d)) return json(res, { error: 'Enter a valid hostname, e.g. app.example.com' }, 400);
      if (apps.some(a => a !== app && (a.domains || []).includes(d))) return json(res, { error: 'Domain already mapped to another app' }, 409);
      app.domains = [...new Set([...(app.domains || []), d])]; save();
      return json(res, publicApp(app));
    }
    if (req.method === 'DELETE' && parts[3] === 'domains' && parts.length === 5) {
      app.domains = (app.domains || []).filter(d => d !== decodeURIComponent(parts[4])); save();
      return json(res, publicApp(app));
    }

    // Application Insights: searchable stored logs + diagnostic values. ?q= substring, ?level=error|warn|info|all
    if (req.method === 'GET' && parts[3] === 'insights' && parts.length === 4) {
      return json(res, insights(app, {
        q: u.searchParams.get('q') || '',
        level: u.searchParams.get('level') || 'all',
        limit: Math.min(1000, Number(u.searchParams.get('limit')) || 200),
      }));
    }

    if (req.method === 'GET' && parts[3] === 'logs' && parts[4] === 'download') {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Disposition': `attachment; filename="${slugify(app.name)}.log"` });
      return fs.createReadStream(logFile(app.name)).on('error', () => res.end('(no logs yet)')).pipe(res);
    }

    if (req.method === 'GET' && parts[3] === 'logs') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
      res.write('\n');
      for (const l of (logbuf.get(app.name) || [])) res.write(`event: message\ndata: ${l}\n\n`);
      res.write(`event: status\ndata: ${app.status}\n\n`);
      let set = clients.get(app.name);
      if (!set) { set = new Set(); clients.set(app.name, set); }
      set.add(res);
      req.on('close', () => set.delete(res));
      return;
    }

    // Console: run one command in the app's working dir (docker apps: inside the container), stream nothing — return output.
    // ponytail: stateless one-shot shell — no PTY, `cd` doesn't persist between commands, 15s cap. Enough for a console.
    if (req.method === 'POST' && parts[3] === 'exec' && parts.length === 4) {
      const cmd = String((await readBody(req)).cmd || '').trim();
      if (!cmd) return json(res, { error: 'A command is required' }, 400);
      if (!app.cwd || !fs.existsSync(app.cwd)) return json(res, { error: 'No deployed code to run against yet' }, 400);
      logActivity(req.user, 'exec', app.name, cmd);
      const [c, a, shell] = app.container
        ? ['docker', ['exec', app.container, 'sh', '-c', cmd], false]
        : [cmd, [], true]; // host shell, in app.cwd, with the app's env
      let out = '', done = false;
      const finish = (extra, code) => { if (done) return; done = true; clearTimeout(timer); json(res, { out: out + (extra || ''), code }); };
      const child = spawn(c, a, { cwd: app.cwd, shell, env: { ...process.env, ...decEnv(app.env) } });
      const cap = d => { out += d; if (out.length > 100_000) out = out.slice(-100_000); }; // bound the reply
      const timer = setTimeout(() => { killTree(child.pid); finish('\n(timed out after 15s)', 124); }, 15_000);
      child.stdout.on('data', cap); child.stderr.on('data', cap);
      child.on('error', e => finish('\n' + e.message, 127));
      child.on('close', code => finish('', code));
      return;
    }

    if (req.method === 'POST' && parts[3]) {
      const action = parts[3];
      // restart/redeploy/rollback are graceful: the running version keeps serving until the new one is healthy.
      if (action === 'stop') stopApp(app);
      else if (action === 'start') startApp(app);
      else if (action === 'restart') startApp(app, { graceful: true });
      else if (action === 'redeploy') deploy(app);
      else if (action === 'rollback') {
        if (!app.managed) return json(res, { error: 'Rollback is available for Git apps only' }, 400);
        const body = await readBody(req);
        const commit = String(body.commit || '').trim();
        if (!/^[0-9a-f]{7,40}$/i.test(commit)) return json(res, { error: 'A commit hash is required' }, 400);
        deploy(app, null, commit);
      }
      else return json(res, { error: 'Unknown action' }, 400);
      return json(res, publicApp(app));
    }

    if (req.method === 'DELETE' && parts.length === 3) {
      stopApp(app);
      // Only delete files we created (git clones / zip uploads under workspaces/). Never touch a user's local folder.
      if ((app.managed || app.uploaded) && app.cwd && app.cwd.startsWith(WORKSPACES)) {
        try { fs.rmSync(app.cwd, { recursive: true, force: true }); } catch (_) {}
      }
      try { fs.rmSync(logFile(app.name), { force: true }); } catch (_) {}
      apps = apps.filter(a => a.name !== app.name); save();
      logbuf.delete(app.name); clients.delete(app.name); appMetrics.delete(app.name); memViol.delete(app.name);
      return json(res, { ok: true });
    }
  }

  json(res, { error: 'Not found' }, 404);
};

const server = SSL ? https.createServer(SSL, handler) : http.createServer(handler);

// WebSocket upgrades: raw-pipe the client socket to the target app's port (subdomain or custom domain).
server.on('upgrade', async (req, socket, head) => {
  const name = hostToApp((req.headers.host || '').split(':')[0]);
  const app = name && find(name);
  if (!app) return socket.destroy();
  if (accessDenied(app, req)) return socket.destroy(); // same password / IP gate as plain HTTP
  lastReq.set(name, Date.now());
  if (app.sleeping && !procs.get(name)) await wakeApp(app);
  if (!app.port || !procs.get(name)) return socket.destroy();
  const up = net.connect(app.port, '127.0.0.1', () => {
    up.write(`${req.method} ${req.url} HTTP/1.1\r\n` +
      Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') + '\r\n\r\n');
    if (head && head.length) up.write(head);
    socket.pipe(up); up.pipe(socket);
  });
  up.on('error', () => socket.destroy());
  socket.on('error', () => up.destroy());
});

// ---- startup / self-check ----
if (process.argv.includes('--check')) {
  const assert = require('assert');
  assert.equal(slugify('My Cool App!'), 'my-cool-app');
  assert.equal(slugify('  a  b  '), 'a-b');
  assert.ok(isRemote('https://github.com/x/y'));
  assert.ok(isRemote('git@github.com:x/y.git'));
  assert.ok(!isRemote('C:\\Users\\me\\app'));
  // .env parsing: KEY=VALUE, strip quotes, ignore comments/blanks.
  assert.deepEqual(parseEnvLine('GOOGLE_CLIENT_ID=abc.apps.googleusercontent.com'), ['GOOGLE_CLIENT_ID', 'abc.apps.googleusercontent.com']);
  assert.deepEqual(parseEnvLine('K = "q u" '), ['K', 'q u']);
  assert.equal(parseEnvLine('# a comment'), null);
  assert.equal(parseEnvLine(''), null);
  // SMTP reply parsing: only a final line "NNN <space>" ends a reply; "NNN-" is a continuation.
  assert.ok(/^\d{3} /.test('250 OK'));
  assert.ok(!/^\d{3} /.test('250-smtp.gmail.com at your service'));
  // Notifications must be a safe no-op when unconfigured (no GMAIL_USER/PASS) — never throws.
  delete process.env.GMAIL_USER; delete process.env.GMAIL_APP_PASS;
  assert.doesNotThrow(() => notifyDeploy({ name: 'x', url: 'u' }, 'running'));
  // Cookie parsing: split on the first '=' so hex session ids survive intact.
  assert.equal(parseCookies({ headers: { cookie: 'a=1; jc_session=deadbeef' } }).jc_session, 'deadbeef');
  // Persistence is a safe no-op when unconfigured (no MONGODB_URI) — never throws, never loads the driver.
  delete process.env.MONGODB_URI;
  assert.doesNotThrow(() => recordUser({ email: 'x@y.com', name: 'X' }));
  // Metrics: memory always present with a sane 0–100 percentage; disk is null-or-valid.
  const mtr = metrics();
  assert.ok(mtr.mem.total > 0 && mtr.mem.pct >= 0 && mtr.mem.pct <= 100);
  assert.ok(mtr.disk === null || (mtr.disk.total > 0 && mtr.disk.pct >= 0 && mtr.disk.pct <= 100));
  // tasklist memory parse: "12,345 K" -> bytes (thousands separators stripped).
  const winMem = '"node.exe","1234","Console","1","12,345 K"'.match(/"([\d.,]+) K"\s*$/m);
  assert.equal(parseInt(winMem[1].replace(/[.,]/g, ''), 10) * 1024, 12345 * 1024);
  // CPU-time parse: "H:MM:SS" / "[D-]H:MM:SS" / "MM:SS" -> ms; junk -> null.
  assert.equal(parseCpuTime('0:00:12'), 12_000);
  assert.equal(parseCpuTime('1-02:03:04'), 93_784_000);
  assert.equal(parseCpuTime('05:30'), 330_000);
  assert.equal(parseCpuTime('N/A'), null);
  // Custom-domain validation: accept an FQDN, reject a bare word.
  assert.ok(/^[a-z0-9.-]+\.[a-z0-9.-]+$/.test('app.example.com'));
  assert.ok(!/^[a-z0-9.-]+\.[a-z0-9.-]+$/.test('localhost'));
  // Rollback commit guard: hex 7–40, nothing else.
  assert.ok(/^[0-9a-f]{7,40}$/i.test('a1b2c3d') && !/^[0-9a-f]{7,40}$/i.test('nope'));
  // Auto-restart backoff: exponential, capped at 30s.
  const backoff = n => Math.min(30_000, 1000 * 2 ** (n - 1));
  assert.equal(backoff(1), 1000); assert.equal(backoff(3), 4000); assert.equal(backoff(10), 30_000);
  // env var key filter: keep valid shell identifiers only.
  assert.ok(/^[A-Za-z_][A-Za-z0-9_]*$/.test('MY_KEY') && !/^[A-Za-z_][A-Za-z0-9_]*$/.test('1BAD'));
  // Plan -> memory cap (MB); unknown/blank falls back to free.
  assert.equal(planMem('premium'), 4096); assert.equal(planMem('nope'), PLANS.free); assert.equal(planMem(), PLANS.free);
  // Env-at-rest: encrypt roundtrips, plaintext (legacy) passes through, a bad blob never throws.
  const _blob = encVal('s3cr3t!'); assert.ok(_blob.startsWith('enc:')); assert.equal(decVal(_blob), 's3cr3t!');
  assert.equal(decVal('plain'), 'plain'); assert.doesNotThrow(() => decVal('enc:not:real:blob'));
  assert.deepEqual(decEnv(encEnv({ A: '1', B: 'two words' })), { A: '1', B: 'two words' });
  // publicApp decrypts env for display and leaves other fields intact.
  const _pa = publicApp({ name: 'x', size: 'basic', env: encEnv({ K: 'v' }) });
  assert.equal(_pa.env.K, 'v'); assert.equal(_pa.size, 'basic');
  // Docker image/container naming: slug-safe and stable.
  assert.equal(dockerImage('My App'), 'jc-my-app'); assert.equal(dockerName('My App', 3005), 'jc-my-app-3005');
  // Insights log levels: errors and warnings are picked out of free-form app output; anything else is info.
  assert.equal(levelOf('Error: connect ECONNREFUSED 127.0.0.1:5432'), 'error');
  assert.equal(levelOf('Health check failed 3× — restarting unresponsive app'), 'error');
  assert.equal(levelOf("TypeError: Cannot read properties of undefined (reading 'id')"), 'error');
  assert.equal(levelOf('npm WARN deprecated request@2.88.2'), 'warn');
  assert.equal(levelOf('Listening on port 3001'), 'info');
  // Insights on an app with no log file / no traffic: zeroed, never throws.
  const _ins = insights({ name: '__no_such_app__', status: 'stopped' });
  assert.equal(_ins.lines, 0); assert.equal(_ins.counts.error, 0); assert.equal(_ins.lastError, null);
  assert.equal(_ins.requests.total, 0); assert.equal(_ins.requests.avgMs, null); assert.deepEqual(_ins.results, []);
  // jerrick.json: the repo file owns the fields it names, env vars are defaults only, a bad field is
  // skipped rather than failing the deploy, and a missing file changes nothing.
  const _mdir = fs.mkdtempSync(path.join(os.tmpdir(), 'jc-mf-'));
  const _mapp = { name: '__manifest_test__', size: 'free', env: encEnv({ SECRET: 'mine' }) };
  applyManifest(_mapp, _mdir);
  assert.equal(_mapp.size, 'free');                              // no jerrick.json -> untouched
  fs.writeFileSync(path.join(_mdir, 'jerrick.json'), JSON.stringify({
    plan: 'standard', healthPath: 'healthz', idleMin: 5000, env: { SECRET: 'from-repo', NODE_ENV: 'production' },
    jobs: [{ schedule: '0 3 * * *', cmd: 'npm run cleanup' }, { schedule: 'nope', cmd: 'x' }],
  }));
  applyManifest(_mapp, _mdir);
  assert.equal(_mapp.size, 'standard');
  assert.equal(_mapp.healthPath, '/healthz');                    // leading slash added, as in the UI
  assert.equal(_mapp.idleMin, 1440);                             // clamped to a day
  assert.deepEqual(_mapp.jobs, [{ schedule: '0 3 * * *', cmd: 'npm run cleanup' }]); // bad cron dropped
  assert.equal(decEnv(_mapp.env).SECRET, 'mine');                // never overwrites a value set on this host
  assert.equal(decEnv(_mapp.env).NODE_ENV, 'production');        // new keys land as defaults
  fs.writeFileSync(path.join(_mdir, 'jerrick.json'), '{ not json');
  assert.doesNotThrow(() => applyManifest(_mapp, _mdir));        // a broken manifest never fails a deploy
  assert.equal(_mapp.size, 'standard');
  fs.rmSync(_mdir, { recursive: true, force: true });
  fs.rmSync(logFile('__manifest_test__'), { force: true });
  // Static-site detection: index.html (root or a built subdir) is the last-resort runtime, and it must
  // never win over a real stack — a Vite repo has both package.json and index.html and is a Node app.
  const _tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'jc-rt-'));
  assert.equal(detectRuntime(_tmp), null);                                     // empty dir → nothing to run
  fs.writeFileSync(path.join(_tmp, 'index.html'), '<h1>hi</h1>');
  assert.equal(detectRuntime(_tmp).name, 'Static');
  assert.ok(detectRuntime(_tmp).start.includes('static-server.js'));
  assert.equal(detectRuntime(_tmp).install, null);                             // never npm-install a static site
  fs.writeFileSync(path.join(_tmp, 'package.json'), '{}');
  assert.equal(detectRuntime(_tmp).name, 'Node');                              // real stack wins
  fs.rmSync(_tmp, { recursive: true, force: true });
  // A built site in dist/ is found too, and both paths stay quoted — this repo lives under "App service".
  const _tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'jc rt-')); // note the space in the temp dir name
  fs.mkdirSync(path.join(_tmp2, 'dist'));
  fs.writeFileSync(path.join(_tmp2, 'dist', 'index.html'), '<h1>built</h1>');
  assert.match(detectRuntime(_tmp2).start, /^node "[^"]*static-server\.js" "dist"$/);
  fs.rmSync(_tmp2, { recursive: true, force: true });
  // IP allow list: empty = open, exact match, prefix match, and everything else refused.
  assert.ok(ipAllowed([], '10.0.0.9') && ipAllowed(null, '10.0.0.9'));
  assert.ok(ipAllowed(['127.0.0.1'], '127.0.0.1') && !ipAllowed(['127.0.0.1'], '127.0.0.2'));
  assert.ok(ipAllowed(['192.168.1.'], '192.168.1.55') && !ipAllowed(['192.168.1.'], '192.168.2.55'));
  assert.equal(ipOf({ socket: { remoteAddress: '::ffff:192.168.1.7' } }), '192.168.1.7');
  // Access gate: open by default; password → 401 challenge until the right one arrives; wrong IP → 403.
  const _basic = p => ({ headers: { authorization: 'Basic ' + Buffer.from('x:' + p).toString('base64') }, socket: { remoteAddress: '127.0.0.1' } });
  const _open = { name: 'a' }, _locked = { name: 'a', accessPassword: encVal('hunter2') };
  assert.equal(accessDenied(_open, _basic('')), null);
  assert.equal(accessDenied(_locked, { headers: {}, socket: { remoteAddress: '127.0.0.1' } }).code, 401);
  assert.equal(accessDenied(_locked, _basic('wrong')).code, 401);
  assert.equal(accessDenied(_locked, _basic('hunter2')), null);
  assert.equal(accessDenied({ name: 'a', allowIps: ['10.0.0.1'] }, _basic('')).code, 403);
  // Proxy rate limit: off unless set, budgeted per client IP, and refused only past the ceiling.
  assert.equal(rateExceeded({ name: '__rate_off__' }, '1.2.3.4'), 0);          // unset -> never limits
  const _rl = { name: '__rate_test__', rateLimit: 3 };
  assert.deepEqual([1, 2, 3].map(() => rateExceeded(_rl, '1.2.3.4')), [0, 0, 0]);
  assert.ok(rateExceeded(_rl, '1.2.3.4') > 0);                                 // the 4th in the window waits
  assert.equal(rateExceeded(_rl, '5.6.7.8'), 0);                               // another caller has its own budget
  // ...and it is the first gate accessDenied applies, so the WebSocket path is covered by the same call.
  assert.equal(accessDenied(_rl, { headers: {}, socket: { remoteAddress: '1.2.3.4' } }).code, 429);
  assert.equal(clampInt('7', 100), 7); assert.equal(clampInt(-5, 100), 0); assert.equal(clampInt(1e9, 100), 100);
  // Cron: field expansion, then whole-expression matching against a real Date.
  assert.deepEqual([...cronField('*/15', 0, 59)], [0, 15, 30, 45]);
  assert.deepEqual([...cronField('5', 0, 59)], [5]);
  assert.deepEqual([...cronField('1-3,9', 0, 59)], [1, 2, 3, 9]);
  assert.equal(cronField('bad', 0, 59).size, 0);
  assert.equal(cronField('99', 0, 59).size, 0);                                // out of range → never fires
  const _at = (h, mi, day = 4) => new Date(2026, 7, 13 + (day - 4), h, mi);    // 2026-08-13 is a Thursday
  assert.ok(cronMatch('0 3 * * *', _at(3, 0)) && !cronMatch('0 3 * * *', _at(3, 1)));
  assert.ok(cronMatch('*/15 * * * *', _at(9, 30)) && !cronMatch('*/15 * * * *', _at(9, 31)));
  assert.ok(cronMatch('0 9 * * 1', _at(9, 0, 1)) && !cronMatch('0 9 * * 1', _at(9, 0, 4))); // Mondays only
  assert.ok(!cronMatch('* * * *', _at(0, 0)) && !cronMatch('', _at(0, 0)));    // wrong field count
  assert.ok(cronValid('0 3 * * *') && !cronValid('0 3 * *') && !cronValid('99 3 * * *'));
  // runJobs is minute-deduped: the same minute twice is a no-op (an interval that drifts can't double-fire).
  lastCronMinute = null; assert.doesNotThrow(() => { runJobs(); runJobs(); });
  // Backup keeps only apps you can see; restore is additive and never overwrites an existing app.
  const _bk = backup(a => a.name === '__no_such_app__');
  assert.deepEqual(_bk.apps, []); assert.equal(_bk.v, 1);
  const _r = restore({ apps: [{ name: '__restore_test__', source: 'x', status: 'running', desired: 'running', pid: 999 }] });
  assert.deepEqual(_r.added, ['__restore_test__']);
  assert.equal(find('__restore_test__').status, 'stopped');                    // restored apps never auto-launch
  assert.equal(find('__restore_test__').pid, null);
  assert.deepEqual(restore({ apps: [{ name: '__restore_test__' }] }), { added: [], skipped: ['__restore_test__'], notes: [] });
  apps = apps.filter(a => a.name !== '__restore_test__'); save();
  // Auto-diagnosis: a no-op without an API key, and a recovered app drops its stale diagnosis.
  delete process.env.ANTHROPIC_API_KEY;
  assert.doesNotThrow(() => diagnose({ name: '__no_such_app__' }));
  apps.push({ name: '__diag_test__', status: 'failed', diagnosis: { text: 'stale', at: 'then' } });
  setStatus('__diag_test__', 'running');
  assert.equal(find('__diag_test__').diagnosis, undefined);
  apps = apps.filter(a => a.name !== '__diag_test__'); save();
  // publicApp never hands the access password back to the browser — just whether one is set.
  const _pw = publicApp({ name: 'x', env: {}, accessPassword: encVal('s3cret') });
  assert.equal(_pw.accessPassword, undefined); assert.equal(_pw.hasPassword, true);
  assert.equal(publicApp({ name: 'x', env: {} }).hasPassword, false);
  // Collaborator email guard: accept a real address, reject junk.
  const emailOk = e => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);
  assert.ok(emailOk('a@b.com') && !emailOk('nope'));
  // App visibility: with sign-in off everyone sees everything; the rule the assistant's tools share.
  assert.ok(canSee({ name: 'x' }, null));
  assert.ok(canSee({ owner: 'a@b.com' }, { email: 'a@b.com' }));
  // Subscription roles: who can manage apps, who can hand out roles, who is read-only.
  const _realRoles = loadJSON(ROLES_FILE, null); // claimOwner persists — put the real assignments back after
  roles = { 'boss@acme.com': 'owner', 'dev@acme.com': 'contributor', 'iam@acme.com': 'useradmin' };
  const _as = e => ({ email: e });
  assert.deepEqual([subOwner(), orgDomain()], ['boss@acme.com', 'acme.com']);
  assert.deepEqual(['boss', 'dev', 'iam', 'nobody'].map(u => subManage(_as(u + '@acme.com'))), [true, true, false, false]);
  assert.deepEqual(['boss', 'dev', 'iam', 'nobody'].map(u => canAssign(_as(u + '@acme.com'))), [true, false, true, false]);
  // Someone else's app: an Owner/Contributor can change it, a User Access Administrator only reads it.
  const _theirs = { owner: 'someone@acme.com', collaborators: [] };
  assert.ok(canSee(_theirs, _as('iam@acme.com')) && canSee(_theirs, _as('dev@acme.com')));
  assert.ok(canWrite(_theirs, _as('dev@acme.com')));
  if (AUTH_ON) assert.ok(!canWrite(_theirs, _as('iam@acme.com')));
  // Activity log visibility: your own actions, everything if you hold a role, nothing else.
  assert.ok(canSeeEntry({ by: 'nobody@acme.com', action: 'sign-in' }, _as('nobody@acme.com')));
  assert.ok(canSeeEntry({ by: 'someone@acme.com', action: 'delete', app: '__gone__' }, _as('iam@acme.com')));
  if (AUTH_ON) {
    assert.ok(!canSeeEntry({ by: 'someone@acme.com', action: 'delete', app: '__gone__' }, _as('nobody@acme.com')));
    assert.ok(!canSeeEntry({ by: 'someone@acme.com', action: 'sign-in' }, _as('nobody@acme.com')));
  }
  // Lock-out guard: the sole Owner can't be demoted or removed; a second Owner frees the first.
  assert.ok(lastOwner('boss@acme.com'));
  roles['boss2@acme.com'] = 'owner';
  assert.ok(!lastOwner('boss@acme.com'));
  roles = {};
  claimOwner('First@Acme.com');                       // fresh install -> first sign-in claims it, lower-cased
  assert.equal(subOwner(), 'first@acme.com');
  claimOwner('second@acme.com');                      // an Owner already exists -> no silent takeover
  assert.equal(Object.keys(roles).length, 1);
  roles = _realRoles || {};
  if (_realRoles) saveRoles(); else { try { fs.rmSync(ROLES_FILE, { force: true }); } catch (_) {} }
  // Assistant tool surface: three read-only tools, and env var VALUES never leave this machine.
  const _visible = () => [{ name: 'demo', status: 'stopped', size: 'basic', env: encEnv({ SECRET_KEY: 'hunter2' }), deploys: [], domains: [] }];
  const _tools = assistantTools(_visible);
  assert.deepEqual(_tools.map(t => t.name), ['list_apps', 'app_diagnostics', 'host_metrics']);
  // Action tools only ever propose: they record a pending action, dedupe it, and run nothing.
  const _pending = [];
  const _acts = actionTools(_visible, _pending);
  assert.deepEqual(_acts.map(t => t.name), ['request_restart', 'request_redeploy']);
  findFreePort(PORT_BASE, new Set()).then(async p => {
    assert.ok(p >= PORT_BASE);
    const diag = await _tools[1].run({ name: 'demo' });
    assert.ok(!diag.includes('hunter2'), 'env values must never be sent to the model');
    assert.deepEqual(JSON.parse(diag).envKeys, ['SECRET_KEY']);
    assert.equal(JSON.parse(diag).planMemMb, 1024);
    assert.ok((await _tools[1].run({ name: 'nope' })).startsWith('No app named'));
    assert.ok(JSON.parse(await _tools[0].run({}))[0].name === 'demo');
    await _acts[0].run({ name: 'demo', reason: 'wedged' });
    await _acts[0].run({ name: 'demo', reason: 'wedged again' });          // same action+app -> no duplicate button
    assert.ok((await _acts[0].run({ name: 'nope', reason: 'x' })).startsWith('No app named'));
    assert.deepEqual(_pending, [{ action: 'restart', name: 'demo', reason: 'wedged' }]);
    // Per-app disk: a recursive walk that adds up real files at every depth, survives an unreadable
    // path, and stops at the file budget rather than walking a pathological tree forever.
    const _ddir = fs.mkdtempSync(path.join(os.tmpdir(), 'jc-du-'));
    fs.mkdirSync(path.join(_ddir, 'sub', 'deep'), { recursive: true });
    fs.writeFileSync(path.join(_ddir, 'a.txt'), 'x'.repeat(100));
    fs.writeFileSync(path.join(_ddir, 'sub', 'b.txt'), 'y'.repeat(250));
    fs.writeFileSync(path.join(_ddir, 'sub', 'deep', 'c.txt'), 'z'.repeat(650));
    assert.equal(await dirSize(_ddir, { files: 50 }), 1000);
    assert.equal(await dirSize(path.join(_ddir, '__nope__'), { files: 50 }), 0);   // missing dir -> 0, no throw
    const _capped = await dirSize(_ddir, { files: 1 });
    assert.ok(_capped > 0 && _capped < 1000);                                      // budget stops the walk early
    fs.rmSync(_ddir, { recursive: true, force: true });
    assert.equal(diskOf('__no_such_app__'), null);                                 // never measured -> null, not 0
    console.log('self-check OK'); process.exit(0);
  });
} else {
  fs.mkdirSync(LOG_DIR, { recursive: true });
  // Restore persisted logins, API tokens, and metric history so a restart is seamless.
  for (const [sid, u] of loadJSON(SESS_FILE, [])) sessions.set(sid, u);
  tokens = loadJSON(TOKENS_FILE, {});
  roles = loadJSON(ROLES_FILE, {});
  // SUBSCRIPTION_OWNER pins the Owner; without it the first person to sign in claims the subscription.
  if (process.env.SUBSCRIPTION_OWNER) { roles[process.env.SUBSCRIPTION_OWNER.toLowerCase()] = 'owner'; saveRoles(); }
  const savedMetrics = loadJSON(METRICS_FILE, null);
  if (savedMetrics) {
    if (Array.isArray(savedMetrics.host)) metricHistory.push(...savedMetrics.host.slice(-METRIC_HISTORY));
    for (const [k, v] of savedMetrics.apps || []) appMetrics.set(k, v);
  }
  // Clean up orphaned children from a previous run; migrate old records; mark desired-running apps for boot.
  for (const a of apps) {
    if (a.pid) killTree(a.pid);
    if (a.container) dockerRm(a.container); // stop a container left running by a previous process
    a.pid = null; a.container = null;
    a.health = 'unknown';
    if (a.desired === undefined) a.desired = a.status === 'running' ? 'running' : 'stopped'; // migrate pre-desired records
    if (!a.hookKey) a.hookKey = crypto.randomBytes(12).toString('hex'); // backfill webhooks/env/domains onto legacy apps
    if (!a.env) a.env = {};
    if (!a.domains) a.domains = [];
    if (!a.deploys) a.deploys = [];
    if (!a.collaborators) a.collaborators = [];
    if (!a.jobs) a.jobs = [];
    // A sleeping app stays asleep across a restart — that's the point of it — and wakes on its next request.
    a.status = a.sleeping ? 'sleeping' : a.desired === 'running' ? 'queued' : 'stopped';
  }
  save();
  server.listen(PORT, () => console.log(`Jerrick Cloud running -> ${PROTO}://localhost:${PORT}`));
  // Bring back everything that was running before the reboot (staggered so ports settle), then watch health + metrics.
  apps.filter(a => a.desired === 'running' && !a.sleeping).forEach((a, i) => setTimeout(() => bootApp(a), 800 + i * 500));
  setInterval(healthCheck, HEALTH_INTERVAL).unref();
  setInterval(runJobs, CRON_INTERVAL).unref();
  startMetricSampler();
}
