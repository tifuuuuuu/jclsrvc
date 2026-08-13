// Static-site runtime for Jerrick Cloud. The platform starts this for any app that has an
// index.html and no other detected runtime (a plain HTML site, or a built dist/ from Vite/CRA).
//   node static-server.js [dir]     dir is relative to cwd, default "."
// Serves on $PORT like every other app, so the proxy/health/metrics path is unchanged.
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(process.argv[2] && process.argv[2] !== '--check' ? process.argv[2] : '.');
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.map': 'application/json',
  '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp', '.avif': 'image/avif',
  '.ico': 'image/x-icon', '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.otf': 'font/otf',
  '.mp4': 'video/mp4', '.webm': 'video/webm', '.mp3': 'audio/mpeg', '.pdf': 'application/pdf', '.wasm': 'application/wasm',
};

// URL path -> absolute file inside root, or null if it escapes root / doesn't resolve to a file.
// The escape check is the trust boundary here: "/../../.env" must never resolve outside root.
function resolveFile(urlPath, root = ROOT) {
  let rel;
  try { rel = decodeURIComponent(String(urlPath).split('?')[0]); } catch (_) { return null; } // bad %-escape
  if (rel.includes('\0')) return null;
  const f = path.resolve(root, '.' + (rel.startsWith('/') ? rel : '/' + rel));
  if (f !== root && !f.startsWith(root + path.sep)) return null;
  let st = null;
  try { st = fs.statSync(f); } catch (_) {}
  if (st && st.isDirectory()) {
    const idx = path.join(f, 'index.html');
    return fs.existsSync(idx) ? idx : null;
  }
  if (st) return f;
  // Unknown path with no file extension -> SPA fallback (React Router & friends own the route).
  if (!path.extname(f)) {
    const idx = path.join(root, 'index.html');
    if (fs.existsSync(idx)) return idx;
  }
  return null;
}

if (process.argv.includes('--check')) {
  const assert = require('assert');
  const root = fs.mkdtempSync(path.join(require('os').tmpdir(), 'jc-static-'));
  fs.writeFileSync(path.join(root, 'index.html'), 'hi');
  fs.mkdirSync(path.join(root, 'assets'));
  fs.writeFileSync(path.join(root, 'assets', 'app.js'), '1');
  assert.equal(resolveFile('/', root), path.join(root, 'index.html'));
  assert.equal(resolveFile('/assets/app.js', root), path.join(root, 'assets', 'app.js'));
  assert.equal(resolveFile('/dashboard/settings', root), path.join(root, 'index.html')); // SPA route
  assert.equal(resolveFile('/missing.png', root), null);                                 // real 404, no fallback
  // Path traversal, in every spelling — must never resolve outside root.
  assert.equal(resolveFile('/../../.env', root), null);
  assert.equal(resolveFile('/..%2f..%2fapps.json', root), null);
  assert.equal(resolveFile('/%2e%2e/%2e%2e/apps.json', root), null);
  assert.equal(resolveFile('/assets/../../../apps.json', root), null);
  assert.equal(resolveFile('/%ZZ', root), null);                                          // bad escape
  fs.rmSync(root, { recursive: true, force: true });
  console.log('static-server self-check OK');
  process.exit(0);
}

http.createServer((req, res) => {
  const f = resolveFile(req.url);
  if (!f) { res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end('<h2>404 · Not found</h2>'); }
  res.writeHead(200, { 'Content-Type': TYPES[path.extname(f).toLowerCase()] || 'application/octet-stream' });
  fs.createReadStream(f).on('error', () => res.end()).pipe(res);
}).listen(process.env.PORT || 3000, () => console.log(`Serving ${ROOT} on :${process.env.PORT || 3000}`));
