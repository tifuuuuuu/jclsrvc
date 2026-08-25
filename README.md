# Jerrick Cloud

A tiny deploy platform for your own machine — an Azure App Service / Heroku you host at home. Give it a Git URL, a local folder, or a `.zip`; it detects the runtime (Node / Python / .NET / Docker / static site / any `Procfile`), installs deps, and runs the app on a free port behind a reverse proxy at `http://<app>.localhost:8080`.

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
- **Static sites** — a folder with an `index.html` (or a built `dist/`, `public/`, `build/`, `out/`, `www/`) needs no runtime: it's served by [`static-server.js`](static-server.js) on the injected `PORT`, with an SPA fallback so client-side routes work. Detected last, so a real stack always wins — a Vite repo is a Node app, not a static one.
- **Zero-downtime deploys** — redeploy / restart / rollback bring the new version up on a fresh port, health-check it, then cut traffic over and retire the old process. A failed build leaves the current version live.
- **Auto-deploy on push** — each app has a webhook URL (Deployment Center → *Auto-deploy on git push*). Add it as a GitHub webhook and every push redeploys.
- **History + rollback** — recent deploys are listed with their commit; roll a Git app back to any of them.
- **Release command** — a Procfile `release:` line runs once after install, before start (migrations, asset builds).
- **`jerrick.json` — config that ships with the code** — drop one in the repo root and the plan, health check path, idle sleep, rate limit and scheduled jobs travel with the app instead of living only in this host's `apps.json`. Applied on every deploy, so the file owns the fields it names (the way a `Procfile` already owns the start command) — change one in the portal and the next deploy puts it back. Declared environment variables are *defaults only*: a key already set in Configuration is never overwritten, so a repo file can't clobber a secret. Unknown plans, bad cron lines and invalid variable names are logged in the build output and skipped; a broken manifest never fails a deploy.

  ```json
  {
    "plan": "standard",
    "healthPath": "/healthz",
    "idleMin": 30,
    "rateLimit": 600,
    "env": { "NODE_ENV": "production" },
    "jobs": [{ "schedule": "0 3 * * *", "cmd": "npm run cleanup" }]
  }
  ```

- **Editable env vars** — Configuration tab, **encrypted at rest** in `apps.json`. Applied on the next start/restart. `PORT` is always injected. Non-secret defaults can ship in `jerrick.json` instead (above).

**Scale & access**
- **Plans with real memory caps** — Scale up tab. Each plan (Free 512 MB → Premium 4 GB) sets a ceiling: an app that overruns is restarted, Node gets a matching `--max-old-space-size`, Docker a `--memory` limit.
- **Idle sleep** — set a minutes-idle value (Configuration tab) and the app is stopped after that long without traffic, then started again on the next request through the proxy. Frees memory on a box running more apps than it uses; the first request after sleeping waits for the cold start (~0.5s for a small app). Sleeping apps stay asleep across a platform restart.
- **Access restrictions** — password-protect an app (HTTP Basic, any username), limit it to an IP allow list, and/or cap requests per minute per visitor IP, all enforced at the proxy before anything reaches the app. Over the rate limit gets a `429` with `Retry-After` until the minute rolls, and the 4xx shows up in Application Insights like any other failed request. Covers the `*.localhost` subdomain, custom domains, and WebSocket upgrades alike. Worth setting on anything you expose through a tunnel — the platform listens on every interface, so an app is otherwise reachable by everything on your LAN.
- **Sharing** — add collaborators by Google email; they see and control that one app. Grantable by the app's owner or by anyone holding a role that manages access (below).
- **Subscription roles (Access control / IAM)** — Azure's three built-ins, scoped to the whole subscription rather than one app, on the dashboard under *Access control (IAM)*. **Owner** controls every app and hands out roles; **Contributor** controls every app but cannot change who has access; **User Access Administrator** hands out roles and reads apps but changes none. Roles can only be granted to addresses in your organisation — the owner's own mail domain, or `ORG_DOMAIN`. The first person to sign in claims Owner (or pin it with `SUBSCRIPTION_OWNER`), and the last Owner can't be demoted or removed, so nobody can lock the subscription. Stored in `logs/roles.json`.
- **Activity log** — who did what, on the dashboard under *Activity log*. Every create, deploy, restart, scale, config edit, console command, domain change, role grant, restore and sign-in is appended to `logs/activity.jsonl`, along with the ones a role refused — recorded at the same gate every mutating route already passes through, so a route added later is audited without being wired up. You see entries for the apps you can see; a subscription role sees all of them.
- **API tokens** — issue a Bearer token (Configuration tab) and drive the API from a CLI / CI with `Authorization: Bearer <token>`.
- **Scheduled jobs** — cron lines per app (`0 3 * * *`, `*/15 * * * *`, …) run a command in the app's folder with its env vars; Docker apps run theirs inside the container. Output lands in the log stream. A run that's still going when the job comes due again is skipped, never stacked.

**Backup**
- **Backup / restore** — ⬇ Backup on the dashboard downloads one JSON file: every app you can see, your API tokens, and the key that decrypts your env vars (so keep it somewhere safe — it's the whole platform). ⬆ Restore adds apps you don't already have, stopped, and never overwrites an existing app or replaces the encryption key already on this host.

**Monitoring**
- **Assistant tab** — ask Claude about your apps in plain language (*why did protein-left stop?*, *which app is using the most memory?*). It calls read-only tools over your live status, per-app memory/CPU, deploy history, host metrics, and stored logs before answering, so it quotes the actual error line and names the fix. Scoped to the apps you can see; environment variable **names** are visible to it, values never are. It can **propose** a restart or redeploy when its diagnosis calls for one — that only puts a Confirm button in the chat, which runs the same action the toolbar does; nothing happens until you click it. Everything else it explains and points you at the right tab. Set `ANTHROPIC_API_KEY` to turn it on.
- **Auto-diagnosis on failure** — when an app gives up (a crash-loop, or a deploy that dies with nothing left serving), the assistant runs itself: it reads that app's logs, metrics, deploy history and the host's memory/disk, then writes the root cause — what broke, the log line that proves it, the fix — into **Application Insights → Why it failed**. The log stream gets a one-line pointer; the diagnosis is stored, survives a restart, and clears the moment the app runs again. Nobody has to be watching, and it never touches the app. Same `ANTHROPIC_API_KEY` as the Assistant tab; unset → the app just fails quietly like before.
- **Application Insights tab** — everything the app has logged is stored on disk (`logs/<app>.log`, survives restarts) and searchable here: substring search, filter by error / warning / info, and the values to check when something breaks — errors and warnings logged, last error, restarts, requests seen, failed requests, avg + p95 response time, peak memory / CPU, and a table of recent 4xx/5xx requests through the proxy. Full log downloadable.
- **Metrics tab** — this app's process memory / CPU / uptime / restarts / health, what it occupies on disk (its working directory plus its stored log), plus live host memory & disk with sparklines and a sample log. Per-app history is sampled and persisted.
- **Threshold alerts** — emails when host memory or disk crosses 85% (set `ALERT_PCT` to change). A disk alert names the three largest apps, so the message says which one to go look at. Reuses the SMTP config below.
- **Webhook notifications** — set `NOTIFY_WEBHOOK` and every deploy result and threshold alert is also POSTed there as JSON. The body carries both `text` and `content`, so the same URL works for Slack or Discord without configuring which; `subject`, `body` and `source` are there for anything custom. Independent of email — either, both, or neither can be configured.

**Networking**
- **Custom domains** — map a hostname to an app (Custom domains tab); point its DNS here and the proxy routes it.
- **WebSocket proxying** — upgrades are piped through to the app.
- **Optional HTTPS** — set `SSL_CERT` and `SSL_KEY` to serve over TLS.

## Configuration (all optional — `.env` or real env vars)

| Var | Purpose |
|-----|---------|
| `PORT` | Platform port (default 8080). |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Enable Google sign-in. When set, users only see their own apps (plus whatever their subscription role grants). |
| `SUBSCRIPTION_OWNER` | Email that holds the Owner role. Unset → the first person to sign in claims it. |
| `ORG_DOMAIN` | Mail domain roles may be granted within. Unset → the owner's own domain. |
| `GMAIL_USER` / `GMAIL_APP_PASS` / `NOTIFY_TO` | SMTP for deploy + threshold-alert emails. |
| `NOTIFY_WEBHOOK` | URL to POST the same notifications to as JSON (Slack / Discord / anything). |
| `ALERT_PCT` | Memory/disk alert threshold percent (default 85). |
| `SSL_CERT` / `SSL_KEY` | Paths to a cert/key pair → serve over HTTPS. |
| `JC_SECRET` | Key for env-var-at-rest encryption. Unset → a random key is generated and stored in `logs/.secret`. |
| `MONGODB_URI` | First-login user persistence (MongoDB — a connection string; db name optional in the URI). |
| `ANTHROPIC_API_KEY` | Turns the Assistant tab and auto-diagnosis on. Unset → both off, everything else runs. |
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
