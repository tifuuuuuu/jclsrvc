# Jerrick Cloud

A tiny deploy platform for your own machine — an Azure App Service / Heroku you host at home. Give it a Git URL, a local folder, or a `.zip`; it detects the runtime (Node / Python / .NET / Docker / any `Procfile`), installs deps, and runs the app on a free port behind a reverse proxy at `http://<app>.localhost:8080`.

```bash
node server.js            # http://localhost:8080
node server.js --check    # run the self-checks
```

## Features

**Reliability**
- **Auto-restart** — crashed apps come back with exponential backoff; a crash-loop (5× in 60s) stops and is flagged instead of thrashing.
- **Survives reboot** — apps that were running are automatically restored when the server starts. Run the server itself on boot with [`install-service.ps1`](install-service.ps1). Logins, API tokens, and metric history are persisted too, so a restart is seamless.
- **Health checks** — each app is TCP-probed (or HTTP-probed against a configurable path in the Configuration tab); a hung app is restarted, throttled to once/min.

**Deploy**
- **Git / local folder / zip / Docker** — three sources in the create dialog; a repo with a `Dockerfile` is built and run as a container (its own isolation).
- **Zero-downtime deploys** — redeploy / restart / rollback bring the new version up on a fresh port, health-check it, then cut traffic over and retire the old process. A failed build leaves the current version live.
- **Auto-deploy on push** — each app has a webhook URL (Deployment Center → *Auto-deploy on git push*). Add it as a GitHub webhook and every push redeploys.
- **History + rollback** — recent deploys are listed with their commit; roll a Git app back to any of them.
- **Release command** — a Procfile `release:` line runs once after install, before start (migrations, asset builds).
- **Editable env vars** — Configuration tab, **encrypted at rest** in `apps.json`. Applied on the next start/restart. `PORT` is always injected.

**Scale & access**
- **Plans with real memory caps** — Scale up tab. Each plan (Free 512 MB → Premium 4 GB) sets a ceiling: an app that overruns is restarted, Node gets a matching `--max-old-space-size`, Docker a `--memory` limit.
- **Sharing** — add collaborators by Google email (owner only); they see and control the app.
- **API tokens** — issue a Bearer token (Configuration tab) and drive the API from a CLI / CI with `Authorization: Bearer <token>`.

**Monitoring**
- **Assistant tab** — ask Claude about your apps in plain language (*why did protein-left stop?*, *which app is using the most memory?*). It calls read-only tools over your live status, per-app memory/CPU, deploy history, host metrics, and stored logs before answering, so it quotes the actual error line and names the fix. Scoped to the apps you can see; environment variable **names** are visible to it, values never are. It can **propose** a restart or redeploy when its diagnosis calls for one — that only puts a Confirm button in the chat, which runs the same action the toolbar does; nothing happens until you click it. Everything else it explains and points you at the right tab. Set `ANTHROPIC_API_KEY` to turn it on.
- **Application Insights tab** — everything the app has logged is stored on disk (`logs/<app>.log`, survives restarts) and searchable here: substring search, filter by error / warning / info, and the values to check when something breaks — errors and warnings logged, last error, restarts, requests seen, failed requests, avg + p95 response time, peak memory / CPU, and a table of recent 4xx/5xx requests through the proxy. Full log downloadable.
- **Metrics tab** — this app's process memory / CPU / uptime / restarts / health, plus live host memory & disk with sparklines and a sample log. Per-app history is sampled and persisted.
- **Threshold alerts** — emails when host memory or disk crosses 85% (set `ALERT_PCT` to change). Reuses the SMTP config below.

**Networking**
- **Custom domains** — map a hostname to an app (Custom domains tab); point its DNS here and the proxy routes it.
- **WebSocket proxying** — upgrades are piped through to the app.
- **Optional HTTPS** — set `SSL_CERT` and `SSL_KEY` to serve over TLS.

## Configuration (all optional — `.env` or real env vars)

| Var | Purpose |
|-----|---------|
| `PORT` | Platform port (default 8080). |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Enable Google sign-in. When set, users only see their own apps. |
| `GMAIL_USER` / `GMAIL_APP_PASS` / `NOTIFY_TO` | SMTP for deploy + threshold-alert emails. |
| `ALERT_PCT` | Memory/disk alert threshold percent (default 85). |
| `SSL_CERT` / `SSL_KEY` | Paths to a cert/key pair → serve over HTTPS. |
| `JC_SECRET` | Key for env-var-at-rest encryption. Unset → a random key is generated and stored in `logs/.secret`. |
| `MONGODB_URI` | First-login user persistence (MongoDB — a connection string; db name optional in the URI). |
| `ANTHROPIC_API_KEY` | Turns the Assistant tab on. Unset → the assistant is off, everything else runs. |
| `ANTHROPIC_BASE_URL` | Optional endpoint override — point it at a gateway/proxy instead of `api.anthropic.com`. |
| `ANTHROPIC_MODEL` | Optional model override (default `claude-opus-5`). |

## Reaching it from other devices

The server listens on all interfaces, so other machines on your LAN can hit `http://<this-pc-ip>:8080`. The pretty `*.localhost` app URLs only resolve on the host, though — from other devices use a **custom domain** (map it in the app, point DNS at the PC), or the direct `http://<ip>:<app-port>`.

To reach it from the public internet without exposing your home IP, run a tunnel (e.g. **Cloudflare Tunnel**: `cloudflared tunnel --url http://localhost:8080`) and point your domain at it. That terminates HTTPS for you, so you can skip `SSL_CERT`/`SSL_KEY`.

## Deliberately out of scope

These are whole subsystems (real infra or a lot of protocol code), not single features — still deferred by design:

- **Managed databases / add-ons (Postgres, Redis) and persistent volumes** — a provisioning subsystem; apps bring their own for now.
- **Automatic Let's Encrypt (ACME)** — ~300 lines of JWS/challenge protocol to do zero-dep; use `SSL_CERT`/`SSL_KEY` or a tunnel that terminates TLS.
- **Usage quotas / billing** — a metering + payments subsystem; no real money on a home box.
- **Deploy slots (staging + swap)** — a bigger data-model feature; zero-downtime deploys cover the main pain.
- **Full OS sandboxing** — native apps run as child processes with your privileges. Use the **Docker** source for a repo you want isolated.
