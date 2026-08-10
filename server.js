// Jerrick Cloud — minimal real deploy engine (zero dependencies).
// Give it a Git URL or a local folder; it runs `npm install` then `npm start`
// on a free port (PORT injected) and the app is live at http://localhost:<port>.
// Scope: Node web apps, single-user local tool. It runs your code by design.
// ponytail: no sandboxing / multi-tenant isolation — that's the "big cloud" version.

const http = require('http');
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

const find = name => apps.find(a => a.name === name);
const save = () => fs.writeFileSync(STATE_FILE, JSON.stringify(apps, null, 2));

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

// Read the `web:` process from a Heroku-style Procfile, if present. The escape hatch for
// anything we don't auto-detect (Ruby, Go, custom start commands): `web: <shell command>`.
function procfileWeb(cwd) {
  try {
    const m = fs.readFileSync(path.join(cwd, 'Procfile'), 'utf8').match(/^\s*web\s*:\s*(.+?)\s*$/mi);
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
  if (has('package.json'))
    rt = { name: 'Node', install: 'npm install', start: 'npm start' };
  else if (has('requirements.txt') || has('pyproject.toml') || has('app.py') || has('main.py'))
    rt = { name: 'Python',
           install: has('requirements.txt') ? 'pip install -r requirements.txt' : null,
           start: `python ${has('app.py') ? 'app.py' : 'main.py'}` };
  else if (hasExt(/\.(sln|slnx|csproj|fsproj)$/i))
    rt = { name: '.NET', install: 'dotnet restore', start: 'dotnet run' };

  const web = procfileWeb(cwd);
  if (web) rt = { name: rt ? rt.name : 'Procfile', install: rt ? rt.install : null, start: web };
  return rt;
}

async function deploy(app, token) {
  logbuf.set(app.name, []); // fresh build log
  setStatus(app.name, 'building');
  pushLog(app.name, `=== Deploying ${app.name} ===`);

  let cwd;
  if (app.managed) {
    cwd = path.join(WORKSPACES, app.name);
    if (!fs.existsSync(cwd)) {
      fs.mkdirSync(WORKSPACES, { recursive: true });
      pushLog(app.name, `$ git clone ${app.source}`); // clean URL — never log the token
      if (!await run(app.name, 'git', ['clone', authUrl(app.source, token), cwd], ROOT, false, gitEnv()))
        return setStatus(app.name, 'failed');
    } else {
      pushLog(app.name, `$ git pull`); // token persisted in the clone's .git/config from the first clone
      await run(app.name, 'git', ['pull'], cwd, false, gitEnv());
    }
  } else {
    cwd = app.source;
    if (!fs.existsSync(cwd)) { pushLog(app.name, `Path not found: ${cwd}`); return setStatus(app.name, 'failed'); }
  }
  app.cwd = cwd;

  // Detect the runtime BEFORE running anything. If this is missing, npm/etc. can walk UP to the
  // platform's own package.json and run server.js (Jerrick Cloud) as the "app" — it kills its own tree.
  const rt = detectRuntime(cwd);
  if (!rt) {
    pushLog(app.name, `Couldn't detect a runtime. Supported: Node (package.json), Python (requirements.txt/app.py), .NET (.sln/.csproj), or any repo with a Procfile ("web: <command>").`);
    return setStatus(app.name, 'failed');
  }
  app.runtime = rt.name;
  pushLog(app.name, `Detected ${rt.name} app`);

  if (rt.install) {
    pushLog(app.name, `$ ${rt.install}`);
    if (!await run(app.name, rt.install, [], cwd, true)) // shell:true — Windows needs it for npm.cmd etc.
      return setStatus(app.name, 'failed');
  }

  startApp(app);
}

async function startApp(app) {
  const rt = detectRuntime(app.cwd);
  if (!rt) { pushLog(app.name, `No runtime detected in ${app.cwd} — redeploy needed.`); return setStatus(app.name, 'failed'); }
  const used = new Set(apps.map(a => a.port).filter(p => p && p !== app.port));
  const port = app.port || await findFreePort(PORT_BASE, used);
  pushLog(app.name, `$ PORT=${port} ${rt.start}`);
  const child = spawn(rt.start, {
    cwd: app.cwd, shell: true,
    // PORT is the cross-runtime convention; ASPNETCORE_URLS makes Kestrel (.NET) bind it too. Harmless elsewhere.
    env: { ...process.env, PORT: String(port), WEBSITE_PORT: String(port), ASPNETCORE_URLS: `http://localhost:${port}` }
  });
  procs.set(app.name, child);
  app.pid = child.pid;
  app.port = port;
  app.url = `http://${app.name}.localhost:${PORT}`; // pretty URL via the reverse proxy below
  setStatus(app.name, 'running');
  child.stdout.on('data', d => pushLog(app.name, d.toString()));
  child.stderr.on('data', d => pushLog(app.name, d.toString()));
  child.on('exit', code => {
    procs.delete(app.name);
    const a = find(app.name);
    if (a && a.status === 'running') { pushLog(app.name, `Process exited (code ${code})`); setStatus(app.name, 'stopped'); }
  });
}

function stopApp(app) {
  killTree(app.pid);
  procs.delete(app.name);
  app.pid = null;
  setStatus(app.name, 'stopped');
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
    sessions.set(sid, user);
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

// ---- http + api ----
function json(res, obj, code = 200) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); }
function readBody(req) {
  return new Promise(r => { let b = ''; req.on('data', c => b += c); req.on('end', () => { try { r(JSON.parse(b || '{}')); } catch (_) { r({}); } }); });
}

// Reverse proxy: requests to <app>.localhost:PORT are forwarded to that app's internal port.
// *.localhost resolves to 127.0.0.1 in modern browsers with no DNS/hosts setup.
function proxyToApp(name, req, res) {
  const app = find(name);
  if (!app || app.status !== 'running' || !app.port) {
    res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<h2>502 &middot; ${name}</h2><p>This app is not running on Jerrick Cloud.</p>`);
  }
  const headers = { ...req.headers, 'x-forwarded-host': req.headers.host, 'x-forwarded-proto': 'http', 'x-forwarded-for': req.socket.remoteAddress };
  const up = http.request({ host: '127.0.0.1', port: app.port, method: req.method, path: req.url, headers }, upRes => {
    res.writeHead(upRes.statusCode, upRes.headers);
    upRes.pipe(res);
  });
  up.on('error', e => { if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' }); res.end('502 Bad Gateway: ' + e.message); });
  req.pipe(up);
}
// ponytail: HTTP only — WebSocket upgrades aren't proxied. Add server.on('upgrade') socket piping if a deployed app needs WS.

const server = http.createServer(async (req, res) => {
  // App subdomain -> reverse proxy to the running app.
  const hostname = (req.headers.host || '').split(':')[0];
  if (hostname.endsWith('.localhost') && hostname.length > '.localhost'.length) {
    return proxyToApp(hostname.slice(0, -('.localhost'.length)), req, res);
  }

  const u = new URL(req.url, 'http://localhost');
  const parts = u.pathname.split('/').filter(Boolean);

  // ---- auth gate (enforced only when Google OAuth is configured) ----
  if (AUTH_ON) {
    if (u.pathname === '/auth/login') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(loginPage()); }
    if (u.pathname === '/auth/google') return startLogin(res);
    if (u.pathname === '/auth/callback') return handleCallback(req, res, u);
    if (u.pathname === '/auth/logout') {
      const sid = parseCookies(req).jc_session; if (sid) sessions.delete(sid);
      res.writeHead(302, { 'Set-Cookie': 'jc_session=; HttpOnly; Path=/; Max-Age=0', Location: '/auth/login' });
      return res.end();
    }
    req.user = currentUser(req);
    if (!req.user) {
      if (parts[0] === 'api') return json(res, { error: 'Not authenticated' }, 401);
      res.writeHead(302, { Location: '/auth/login' }); return res.end(); // send the dashboard to Google
    }
  }

  if (req.method === 'GET' && u.pathname === '/api/me') {
    return json(res, AUTH_ON ? { auth: true, email: (req.user || {}).email, name: (req.user || {}).name } : { auth: false });
  }

  if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/index.html')) {
    return fs.readFile(path.join(ROOT, 'index.html'), (e, data) => {
      if (e) { res.writeHead(404); return res.end('index.html not found'); }
      res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(data);
    });
  }

  if (parts[0] === 'api' && parts[1] === 'apps') {
    if (req.method === 'GET' && parts.length === 2) return json(res, apps);

    if (req.method === 'POST' && parts.length === 2) {
      const body = await readBody(req);
      const name = slugify(body.name);
      const source = String(body.source || '').trim();
      const token = String(body.token || '').trim(); // optional; used for the clone, never stored
      if (!name) return json(res, { error: 'A valid name is required' }, 400);
      if (find(name)) return json(res, { error: `App "${name}" already exists` }, 409);
      if (!source) return json(res, { error: 'A Git URL or local folder path is required' }, 400);
      const app = { name, source, managed: isRemote(source), port: null, pid: null, status: 'queued', url: null, owner: req.user ? req.user.email : undefined, createdAt: new Date().toISOString() };
      apps.push(app); save();
      deploy(app, token); // fire and forget; progress streams over SSE
      return json(res, app, 201);
    }

    const app = find(parts[2]);
    if (!app) return json(res, { error: 'Not found' }, 404);

    if (req.method === 'GET' && parts.length === 3) return json(res, app);

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
      if (action === 'stop') stopApp(app);
      else if (action === 'start') startApp(app);
      else if (action === 'restart') { stopApp(app); setTimeout(() => startApp(app), 800); }
      else if (action === 'redeploy') { stopApp(app); setTimeout(() => deploy(app), 800); }
      else return json(res, { error: 'Unknown action' }, 400);
      return json(res, app);
    }

    if (req.method === 'DELETE' && parts.length === 3) {
      stopApp(app);
      // Only delete files we created (git clones under workspaces/). Never touch a user's local folder.
      if (app.managed && app.cwd && app.cwd.startsWith(WORKSPACES)) {
        try { fs.rmSync(app.cwd, { recursive: true, force: true }); } catch (_) {}
      }
      apps = apps.filter(a => a.name !== app.name); save();
      logbuf.delete(app.name); clients.delete(app.name);
      return json(res, { ok: true });
    }
  }

  json(res, { error: 'Not found' }, 404);
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
  findFreePort(PORT_BASE, new Set()).then(p => { assert.ok(p >= PORT_BASE); console.log('self-check OK'); process.exit(0); });
} else {
  // Clean up any orphaned child processes from a previous run, then start fresh.
  for (const a of apps) { if (a.pid) killTree(a.pid); a.pid = null; a.status = 'stopped'; }
  save();
  server.listen(PORT, () => console.log(`Jerrick Cloud running -> http://localhost:${PORT}`));
}
