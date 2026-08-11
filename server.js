// Jerrick Cloud — minimal real deploy engine (zero dependencies).
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
const METRICS_FILE = path.join(LOG_DIR, 'metrics.json'); // persisted host + per-app metric history
const SECRET_FILE = path.join(LOG_DIR, '.secret');       // 32-byte key for env-var-at-rest encryption
const APP_METRIC_HISTORY = 240;                          // per-app samples kept (~1h at 15s)
const HEALTH_TIMEOUT = 30_000;                           // zero-downtime: max wait for a new version to go healthy
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

const logFile = name => path.join(LOG_DIR, slugify(name) + '.log');
// Mirror a log chunk to disk so logs survive restarts and can be downloaded. Self-trims when it grows past the cap.
function appendLogFile(name, text) {
  try {
    const f = logFile(name);
    fs.appendFileSync(f, text.endsWith('\n') ? text : text + '\n');
    if (fs.statSync(f).size > LOG_FILE_CAP) fs.writeFileSync(f, fs.readFileSync(f).slice(-LOG_FILE_CAP / 2));
  } catch (_) {}
}

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
// App object for API responses: env decrypted for display, everything else untouched.
const publicApp = a => ({ ...a, env: decEnv(a.env) });

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
  broadcast(name, 'status', status);
  save();
  // Email on terminal deploy outcomes. Fire-and-forget — a mail failure never blocks a deploy.
  if (status === 'running' || status === 'failed') notifyDeploy(a || { name }, status);
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

  const web = procfileEntry(cwd, 'web');
  if (web && !(rt && rt.docker)) rt = { name: rt ? rt.name : 'Procfile', install: rt ? rt.install : null, start: web };
  if (rt) rt.release = procfileEntry(cwd, 'release'); // optional one-off pre-start command (migrations, asset build…)
  return rt;
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

  // Detect the runtime BEFORE running anything. If this is missing, npm/etc. can walk UP to the
  // platform's own package.json and run server.js (Jerrick Cloud) as the "app" — it kills its own tree.
  const rt = detectRuntime(cwd);
  if (!rt) {
    pushLog(app.name, `Couldn't detect a runtime. Supported: Node (package.json), Python (requirements.txt/app.py), .NET (.sln/.csproj), or any repo with a Procfile ("web: <command>").`);
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
  if (!rt) { pushLog(app.name, `No runtime detected in ${app.cwd} — redeploy needed.`); return failDeploy(app); }

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
  const child = procs.get(app.name);
  if (child) child.removeAllListeners('exit'); // don't let the death we're about to cause trigger auto-restart
  killTree(app.pid);
  if (app.container) dockerRm(app.container); // stop the container too (docker run --rm leaves it otherwise)
  procs.delete(app.name);
  app.pid = null; app.container = null;
  setStatus(app.name, 'stopped');
}

// Bring an app back after a server boot: start in place if we already have its code, else (re)deploy to fetch it.
function bootApp(app) {
  if (app.cwd && fs.existsSync(app.cwd)) startApp(app);
  else deploy(app);
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
    saveMetrics();
  };
  sample();
  setInterval(sample, METRIC_INTERVAL).unref();
}
// Per-app RSS/CPU history + plan memory-cap enforcement (restart an app that overruns its plan for 3 samples).
async function sampleApps() {
  for (const a of apps) {
    if (a.status !== 'running' || !a.pid) continue;
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
function checkAlert(resource, pct) {
  if (pct < ALERT_PCT || Date.now() - (lastAlert[resource] || 0) < ALERT_EVERY) return;
  lastAlert[resource] = Date.now();
  const to = process.env.NOTIFY_TO || process.env.GMAIL_USER;
  if (to) sendMail(to, `[Jerrick Cloud] ${resource} at ${pct}%`,
    `Host ${resource} usage is ${pct}% (alert threshold ${ALERT_PCT}%).\nFree up ${resource} on your Jerrick Cloud server.`, null);
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
    await recordUser(user); // first-time users -> Cosmos + R2; failures never block sign-in
    res.writeHead(302, { 'Set-Cookie': `jc_session=${sid}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800`, Location: '/' });
    res.end();
  } catch (e) { res.writeHead(500); res.end('Sign-in failed: ' + e.message); }
}

// ---- first-time user persistence: R2 (existence gate) + Cosmos DB (record) ----
// On login: HEAD the gmail in R2 -> exists ? returning user, go home.
//                                -> missing ? upsert full details to Cosmos, then mark the gmail in R2.
// R2 is the cheap existence check; Cosmos holds the record. Both no-op unless configured, so the
// platform still runs open on localhost. Configure via env (unset -> whole feature is a no-op):
//   R2_ACCOUNT_ID / R2_ACCESS_KEY_ID / R2_SECRET_ACCESS_KEY / R2_BUCKET     (Cloudflare R2, S3 API)
//   COSMOS_CONN (AccountEndpoint=...;AccountKey=...;) / COSMOS_DB / COSMOS_CONTAINER   (Azure Cosmos, SQL API)
//   The Cosmos container must be partitioned on /email.
// ponytail: naive one-object-per-user marker, HEAD-based existence, no retry/pagination. Enough for a
//   single-tenant tool; a Cosmos point-read could replace R2 if you'd rather run one store.
const sha256hex = s => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
const hmac = (key, msg) => crypto.createHmac('sha256', key).update(msg, 'utf8').digest();
// AccountEndpoint=https://x.documents.azure.com:443/;AccountKey=BASE64==; -> { endpoint, key }
const parseCosmosConn = cs => ({
  endpoint: (String(cs).match(/AccountEndpoint=([^;]+)/) || [])[1] || '',
  key: (String(cs).match(/AccountKey=([^;]+)/) || [])[1] || '',
});
const COSMOS = parseCosmosConn(process.env.COSMOS_CONN || '');
const R2_ON = !!(process.env.R2_ACCOUNT_ID && process.env.R2_ACCESS_KEY_ID && process.env.R2_SECRET_ACCESS_KEY && process.env.R2_BUCKET);
const COSMOS_ON = !!(COSMOS.endpoint && (COSMOS.key || process.env.COSMOS_KEY) && process.env.COSMOS_DB && process.env.COSMOS_CONTAINER);

// One S3-compatible (SigV4) request to R2. Object key is a sha256 hex of the email -> always URL-safe.
function r2Request(method, key, body = '') {
  return new Promise((resolve, reject) => {
    const host = `${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
    const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''); // YYYYMMDDTHHMMSSZ
    const dateStamp = amzDate.slice(0, 8);
    const payloadHash = sha256hex(body);
    const uri = `/${process.env.R2_BUCKET}/${key}`;
    const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
    const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
    const canonicalReq = [method, uri, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');
    const scope = `${dateStamp}/auto/s3/aws4_request`; // R2 region is always "auto"
    const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalReq)].join('\n');
    let k = hmac('AWS4' + process.env.R2_SECRET_ACCESS_KEY, dateStamp);
    k = hmac(k, 'auto'); k = hmac(k, 's3'); k = hmac(k, 'aws4_request');
    const signature = crypto.createHmac('sha256', k).update(toSign, 'utf8').digest('hex');
    const headers = {
      Authorization: `AWS4-HMAC-SHA256 Credential=${process.env.R2_ACCESS_KEY_ID}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
      'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate,
    };
    if (body) headers['Content-Length'] = Buffer.byteLength(body);
    const req = https.request({ host, method, path: uri, headers }, resp => {
      let b = ''; resp.on('data', c => b += c); resp.on('end', () => resolve({ status: resp.statusCode, body: b }));
    });
    req.on('error', reject); if (body) req.write(body); req.end();
  });
}
const r2Key = email => `users/${sha256hex(String(email).toLowerCase())}`;
async function r2Exists(email) { return (await r2Request('HEAD', r2Key(email))).status === 200; }
async function r2Mark(email) {
  const r = await r2Request('PUT', r2Key(email), String(email).toLowerCase());
  if (r.status >= 300) throw new Error(`R2 PUT ${r.status}: ${r.body}`);
}

// Upsert the user record into Cosmos (SQL/Core API). Container must be partitioned on /email.
function cosmosUpsertUser(user) {
  return new Promise((resolve, reject) => {
    const key = COSMOS.key || process.env.COSMOS_KEY;
    const resId = `dbs/${process.env.COSMOS_DB}/colls/${process.env.COSMOS_CONTAINER}`;
    const date = new Date().toUTCString();
    const text = `post\ndocs\n${resId}\n${date.toLowerCase()}\n\n`;
    const sig = crypto.createHmac('sha256', Buffer.from(key, 'base64')).update(text, 'utf8').digest('base64');
    const auth = encodeURIComponent(`type=master&ver=1.0&sig=${sig}`);
    const email = String(user.email).toLowerCase();
    const body = JSON.stringify({ id: email, email, name: user.name || '', createdAt: new Date().toISOString() });
    const url = new URL(`${COSMOS.endpoint.replace(/\/+$/, '')}/${resId}/docs`);
    const req = https.request({ host: url.hostname, port: url.port || 443, path: url.pathname, method: 'POST', headers: {
      Authorization: auth, 'x-ms-date': date, 'x-ms-version': '2018-12-31',
      'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
      'x-ms-documentdb-is-upsert': 'true', 'x-ms-documentdb-partitionkey': JSON.stringify([email]),
    } }, resp => { let b = ''; resp.on('data', c => b += c); resp.on('end', () => resp.statusCode < 300 ? resolve() : reject(new Error(`Cosmos ${resp.statusCode}: ${b}`))); });
    req.on('error', reject); req.write(body); req.end();
  });
}

// The login hook: first-timers get persisted; returning users (already in R2) short-circuit. Never blocks sign-in.
async function recordUser(user) {
  if (!user || !user.email || !(R2_ON && COSMOS_ON)) return;
  try {
    if (await r2Exists(user.email)) return;   // returning user -> nothing to do
    await cosmosUpsertUser(user);             // first login -> save details to Cosmos
    await r2Mark(user.email);                 // then mark the gmail in R2 for next time
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
function proxyToApp(name, req, res) {
  const app = find(name);
  if (!app || !app.port || !procs.get(name)) { // gate on a live process, not the status label → zero-downtime rebuilds keep serving
    res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<h2>502 &middot; ${name}</h2><p>This app is not running on Jerrick Cloud.</p>`);
  }
  const headers = { ...req.headers, 'x-forwarded-host': req.headers.host, 'x-forwarded-proto': PROTO, 'x-forwarded-for': req.socket.remoteAddress };
  const up = http.request({ host: '127.0.0.1', port: app.port, method: req.method, path: req.url, headers }, upRes => {
    res.writeHead(upRes.statusCode, upRes.headers);
    upRes.pipe(res);
  });
  up.on('error', e => { if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' }); res.end('502 Bad Gateway: ' + e.message); });
  req.pipe(up);
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
      const sid = parseCookies(req).jc_session; if (sid) { sessions.delete(sid); saveSessions(); }
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
  }

  if (req.method === 'GET' && u.pathname === '/api/metrics') return json(res, metrics());
  if (req.method === 'GET' && u.pathname === '/api/metrics/history') return json(res, metricHistory);

  if (req.method === 'GET' && u.pathname === '/api/me') {
    return json(res, AUTH_ON ? { auth: true, email: (req.user || {}).email, name: (req.user || {}).name } : { auth: false });
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

  if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/index.html')) {
    return fs.readFile(path.join(ROOT, 'index.html'), (e, data) => {
      if (e) { res.writeHead(404); return res.end('index.html not found'); }
      res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(data);
    });
  }

  if (parts[0] === 'api' && parts[1] === 'apps') {
    // When auth is on, a user sees/controls their own apps, apps shared with them, and legacy apps with no owner.
    const mine = a => !AUTH_ON || !a.owner || (req.user && (a.owner === req.user.email || (a.collaborators || []).includes(req.user.email)));
    if (req.method === 'GET' && parts.length === 2) return json(res, apps.filter(mine).map(publicApp));

    if (req.method === 'POST' && parts.length === 2) {
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
        return json(res, app, 201);
      }

      if (!source) return json(res, { error: 'A Git URL, local folder path, or zip upload is required' }, 400);
      const app = { ...base, source, managed: isRemote(source) };
      apps.push(app); save();
      deploy(app, token); // fire and forget; progress streams over SSE
      return json(res, app, 201);
    }

    const app = find(parts[2]);
    if (!app || !mine(app)) return json(res, { error: 'Not found' }, 404); // owned by someone else → 404, not 403

    if (req.method === 'GET' && parts.length === 3) return json(res, publicApp(app));

    if (req.method === 'GET' && parts[3] === 'stats' && parts.length === 4) {
      const st = await pidStat(app.pid);
      const cpu = pidCpuPct(app.name, app.pid, st.cpuMs);
      const uptimeSec = app.startedAt && app.status === 'running' ? Math.round((Date.now() - new Date(app.startedAt)) / 1000) : 0;
      return json(res, { status: app.status, health: app.health || 'unknown', rss: st.rss, cpu, uptimeSec, restarts: app.restarts || 0, memMb: planMem(app.size) });
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

    if (req.method === 'PUT' && parts[3] === 'health' && parts.length === 4) {
      const body = await readBody(req);
      let p = String(body.path || '').trim();
      if (p && !p.startsWith('/')) p = '/' + p;
      app.healthPath = p || undefined; save();
      return json(res, { ok: true, healthPath: app.healthPath || '' });
    }

    if (req.method === 'POST' && parts[3] === 'collaborators' && parts.length === 4) {
      if (AUTH_ON && app.owner && req.user.email !== app.owner) return json(res, { error: 'Only the owner can share this app' }, 403);
      const body = await readBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json(res, { error: 'Enter a valid email' }, 400);
      app.collaborators = [...new Set([...(app.collaborators || []), email])]; save();
      return json(res, publicApp(app));
    }
    if (req.method === 'DELETE' && parts[3] === 'collaborators' && parts.length === 5) {
      if (AUTH_ON && app.owner && req.user.email !== app.owner) return json(res, { error: 'Only the owner can share this app' }, 403);
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
server.on('upgrade', (req, socket, head) => {
  const name = hostToApp((req.headers.host || '').split(':')[0]);
  const app = name && find(name);
  if (!app || !app.port || !procs.get(name)) return socket.destroy();
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
  // Cosmos conn-string parsing: pull endpoint + key out of the connection string.
  const cc = parseCosmosConn('AccountEndpoint=https://x.documents.azure.com:443/;AccountKey=YWJj;');
  assert.equal(cc.endpoint, 'https://x.documents.azure.com:443/');
  assert.equal(cc.key, 'YWJj');
  // R2 object key: url-safe sha256 hex of the lowercased email (stable + case-insensitive).
  assert.match(r2Key('User@Gmail.com'), /^users\/[0-9a-f]{64}$/);
  assert.equal(r2Key('User@Gmail.com'), r2Key('user@gmail.com'));
  // SigV4 amz-date: ISO -> YYYYMMDDTHHMMSSZ.
  assert.equal(new Date('2026-08-10T12:34:56.789Z').toISOString().replace(/[:-]|\.\d{3}/g, ''), '20260810T123456Z');
  // Persistence is a safe no-op when unconfigured (no R2/Cosmos env) — never throws.
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
  // Collaborator email guard: accept a real address, reject junk.
  const emailOk = e => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);
  assert.ok(emailOk('a@b.com') && !emailOk('nope'));
  findFreePort(PORT_BASE, new Set()).then(p => { assert.ok(p >= PORT_BASE); console.log('self-check OK'); process.exit(0); });
} else {
  fs.mkdirSync(LOG_DIR, { recursive: true });
  // Restore persisted logins, API tokens, and metric history so a restart is seamless.
  for (const [sid, u] of loadJSON(SESS_FILE, [])) sessions.set(sid, u);
  tokens = loadJSON(TOKENS_FILE, {});
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
    a.status = a.desired === 'running' ? 'queued' : 'stopped';
  }
  save();
  server.listen(PORT, () => console.log(`Jerrick Cloud running -> ${PROTO}://localhost:${PORT}`));
  // Bring back everything that was running before the reboot (staggered so ports settle), then watch health + metrics.
  apps.filter(a => a.desired === 'running').forEach((a, i) => setTimeout(() => bootApp(a), 800 + i * 500));
  setInterval(healthCheck, HEALTH_INTERVAL).unref();
  startMetricSampler();
}
