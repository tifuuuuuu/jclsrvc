#!/usr/bin/env node
// jc — Jerrick Cloud CLI. Zero-dep client over the existing REST API (server.js).
// Auth: JC_TOKEN env or `jc login <token>` (token from the dashboard / POST /api/token).
// Server: JC_URL env or `--url` on login (default http://localhost:8080).
const http = require('http'), https = require('https');
const fs = require('fs'), os = require('os'), path = require('path');

const CFG = path.join(os.homedir(), '.jc.json');
const cfg = () => { try { return JSON.parse(fs.readFileSync(CFG, 'utf8')); } catch (_) { return {}; } };
const saveCfg = c => fs.writeFileSync(CFG, JSON.stringify(c, null, 2), { mode: 0o600 });
const base = () => process.env.JC_URL || cfg().url || 'http://localhost:8080';
const token = () => process.env.JC_TOKEN || cfg().token;
const die = m => { console.error('error:', m.message || m); process.exit(1); };

// Split "--flag val" / "--flag=val" out of argv → [positionals, flags].
function parseArgs(argv) {
  const pos = [], flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > -1) flags[a.slice(2, eq)] = a.slice(eq + 1);
      else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) flags[a.slice(2)] = argv[++i];
      else flags[a.slice(2)] = true;
    } else pos.push(a);
  }
  return [pos, flags];
}

function api(method, apiPath, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(apiPath, base());
    const lib = u.protocol === 'https:' ? https : http;
    const data = body ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json' };
    if (token()) headers.Authorization = `Bearer ${token()}`;
    if (data) headers['Content-Length'] = Buffer.byteLength(data);
    const req = lib.request(u, { method, headers }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => {
        let j; try { j = JSON.parse(b || '{}'); } catch (_) { j = b; }
        if (res.statusCode >= 400) return reject(new Error((j && j.error) || b || `HTTP ${res.statusCode}`));
        resolve(j);
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// Stream an app's SSE log. follow=false exits once the initial backlog + status line arrive.
function streamLogs(name, follow) {
  const u = new URL(`/api/apps/${name}/logs`, base());
  const lib = u.protocol === 'https:' ? https : http;
  const headers = { Accept: 'text/event-stream' };
  if (token()) headers.Authorization = `Bearer ${token()}`;
  const req = lib.request(u, { headers }, res => {
    if (res.statusCode >= 400) { res.resume(); return die(`HTTP ${res.statusCode} — is the app name right?`); }
    let buf = '';
    res.on('data', d => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\n\n')) > -1) {
        const evt = buf.slice(0, i); buf = buf.slice(i + 2);
        const ev = (evt.match(/^event: (.*)$/m) || [])[1];
        const data = (evt.match(/^data: (.*)$/m) || [])[1];
        if (ev === 'message' && data != null) console.log(data);
        else if (ev === 'status') { if (!follow) { res.destroy(); process.exit(0); } else console.log(`── status: ${data} ──`); }
      }
    });
    res.on('end', () => process.exit(0));
  });
  req.on('error', die); req.end();
}

const pad = (s, n) => String(s == null ? '' : s).padEnd(n);
function printApps(apps) {
  if (!apps.length) return console.log('No apps yet. Deploy one:  jc deploy <git-url|path> --name my-app');
  console.log(pad('NAME', 22) + pad('STATUS', 12) + pad('RUNTIME', 10) + 'URL');
  for (const a of apps) console.log(pad(a.name, 22) + pad(a.status, 12) + pad(a.runtime || '-', 10) + (a.url || '-'));
}

const HELP = `jc — Jerrick Cloud CLI

  jc login <token> [--url http://host:8080]   save credentials (~/.jc.json)
  jc list                                     list your apps
  jc deploy <git-url|path> [--name n] [--size free|basic|standard|premium] [--token gitPAT]
  jc logs <name> [-f|--follow]                view / stream logs
  jc exec <name> <command>                    run a command in the app's dir
  jc start|stop|restart|redeploy <name>       lifecycle actions
  jc rollback <name> <commit>                 redeploy a past commit (Git apps)
  jc env <name>                               show env vars
  jc env <name> KEY=val [KEY=val ...]         set env vars (merged)
  jc scale <name> <plan>                      change plan (memory cap)
  jc stats <name>                             cpu / memory / uptime
  jc open <name>                              print the app URL
  jc delete <name>                            remove the app

Env: JC_URL, JC_TOKEN override the saved config.`;

async function main() {
  const [pos, flags] = parseArgs(process.argv.slice(2));
  const [cmd, ...rest] = pos;

  if (flags.check) return selfCheck();
  if (!cmd || cmd === 'help' || flags.help) return console.log(HELP);

  switch (cmd) {
    case 'login': {
      if (!rest[0]) return die('usage: jc login <token> [--url URL]');
      const c = cfg(); c.token = rest[0]; if (flags.url) c.url = flags.url; saveCfg(c);
      return console.log(`Saved. Server: ${base()}`);
    }
    case 'list': case 'ls':
      return printApps(await api('GET', '/api/apps'));
    case 'deploy': {
      const source = rest[0];
      if (!source) return die('usage: jc deploy <git-url|local-path> [--name n] [--size s]');
      const name = flags.name || path.basename(String(source).replace(/\.git$/, '').replace(/[\/\\]+$/, ''));
      const app = await api('POST', '/api/apps', { name, source, size: flags.size || 'free', token: flags.token || '' });
      console.log(`Deploying ${app.name} … streaming build log (Ctrl-C to detach):\n`);
      return streamLogs(app.name, true);
    }
    case 'logs':
      if (!rest[0]) return die('usage: jc logs <name> [-f]');
      return streamLogs(rest[0], flags.follow || flags.f || rest.includes('-f'));
    case 'start': case 'stop': case 'restart': case 'redeploy': {
      if (!rest[0]) return die(`usage: jc ${cmd} <name>`);
      await api('POST', `/api/apps/${rest[0]}/${cmd}`);
      return console.log(`${cmd} → ${rest[0]}`);
    }
    case 'rollback': {
      if (!rest[1]) return die('usage: jc rollback <name> <commit>');
      await api('POST', `/api/apps/${rest[0]}/rollback`, { commit: rest[1] });
      return console.log(`Rolling back ${rest[0]} to ${rest[1]}`);
    }
    case 'env': {
      if (!rest[0]) return die('usage: jc env <name> [KEY=val ...]');
      if (rest.length === 1) {
        const a = await api('GET', `/api/apps/${rest[0]}`);
        const e = a.env || {};
        return Object.keys(e).length ? Object.entries(e).forEach(([k, v]) => console.log(`${k}=${v}`)) : console.log('(no env vars)');
      }
      const cur = (await api('GET', `/api/apps/${rest[0]}`)).env || {};
      for (const kv of rest.slice(1)) { const i = kv.indexOf('='); if (i > 0) cur[kv.slice(0, i)] = kv.slice(i + 1); }
      await api('PUT', `/api/apps/${rest[0]}/env`, { env: cur });
      return console.log('Saved. Takes effect on next start/restart.');
    }
    case 'scale': {
      if (!rest[1]) return die('usage: jc scale <name> <free|basic|standard|premium>');
      const r = await api('POST', `/api/apps/${rest[0]}/scale`, { size: rest[1] });
      return console.log(`${rest[0]} → ${r.size} (${r.memMb} MB)`);
    }
    case 'exec': case 'run': {
      const c = rest.slice(1).join(' ');
      if (!rest[0] || !c) return die('usage: jc exec <name> <command>');
      const r = await api('POST', `/api/apps/${rest[0]}/exec`, { cmd: c });
      if (r.out) process.stdout.write(r.out.endsWith('\n') ? r.out : r.out + '\n');
      return process.exit(r.code || 0);
    }
    case 'stats': {
      if (!rest[0]) return die('usage: jc stats <name>');
      const s = await api('GET', `/api/apps/${rest[0]}/stats`);
      const mb = b => b ? (b / 1048576).toFixed(0) + ' MB' : '-';
      return console.log(`status=${s.status} health=${s.health} cpu=${s.cpu ?? '-'}% mem=${mb(s.rss)}/${s.memMb}MB uptime=${s.uptimeSec}s restarts=${s.restarts}`);
    }
    case 'open': {
      if (!rest[0]) return die('usage: jc open <name>');
      const a = await api('GET', `/api/apps/${rest[0]}`);
      return console.log(a.url || '(not running)');
    }
    case 'delete': case 'rm':
      if (!rest[0]) return die('usage: jc delete <name>');
      await api('DELETE', `/api/apps/${rest[0]}`);
      return console.log(`Deleted ${rest[0]}`);
    default:
      return die(`unknown command "${cmd}" — run  jc help`);
  }
}

function selfCheck() {
  const assert = require('assert');
  assert.deepEqual(parseArgs(['deploy', 'x', '--name', 'app', '--size=basic']), [['deploy', 'x'], { name: 'app', size: 'basic' }]);
  assert.deepEqual(parseArgs(['logs', 'a', '-f']), [['logs', 'a', '-f'], {}]);
  assert.deepEqual(parseArgs(['x', '--follow']), [['x'], { follow: true }]);
  // deploy name is derived from the source basename when --name is absent.
  const base = s => path.basename(String(s).replace(/\.git$/, '').replace(/[\/\\]+$/, ''));
  assert.equal(base('https://github.com/me/cool-app.git'), 'cool-app');
  assert.equal(base('C:/Users/me/my-app/'), 'my-app');
  console.log('self-check OK'); process.exit(0);
}

main().catch(die);
