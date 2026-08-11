# Jerrick Cloud

A tiny, zero-dependency deploy platform for your own machine — an Azure App Service / Heroku you host at home. Give it a Git URL, a local folder, or a `.zip`; it detects the runtime (Node / Python / .NET / any `Procfile`), installs deps, and runs the app on a free port behind a reverse proxy at `http://<app>.localhost:8080`.

```bash
node server.js            # http://localhost:8080
node server.js --check    # run the self-checks
```

## Features

**Reliability**
- **Auto-restart** — crashed apps come back with exponential backoff; a crash-loop (5× in 60s) stops and is flagged instead of thrashing.
- **Survives reboot** — apps that were running are automatically restored when the server starts. Run the server itself on boot with [`install-service.ps1`](install-service.ps1).
- **Health checks** — each app is TCP-probed; a hung app (alive but not accepting connections) is restarted, throttled to once/min.

**Deploy**
- **Git / local folder / zip upload** — three sources in the create dialog.
- **Auto-deploy on push** — each app has a webhook URL (Deployment Center → *Auto-deploy on git push*). Add it as a GitHub webhook and every push redeploys.
- **History + rollback** — recent deploys are listed with their commit; roll a Git app back to any of them.
- **Editable env vars** — Configuration tab. Applied on the next start/restart. `PORT` is always injected.

**Monitoring**
- **Metrics tab** — this app's process memory / uptime / restarts / health, plus live host memory & disk with sparklines and a sample log.
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
| `R2_*` / `COSMOS_*` | First-login user persistence (Cloudflare R2 + Azure Cosmos). |

## Reaching it from other devices

The server listens on all interfaces, so other machines on your LAN can hit `http://<this-pc-ip>:8080`. The pretty `*.localhost` app URLs only resolve on the host, though — from other devices use a **custom domain** (map it in the app, point DNS at the PC), or the direct `http://<ip>:<app-port>`.

To reach it from the public internet without exposing your home IP, run a tunnel (e.g. **Cloudflare Tunnel**: `cloudflared tunnel --url http://localhost:8080`) and point your domain at it. That terminates HTTPS for you, so you can skip `SSL_CERT`/`SSL_KEY`.

## Deliberately out of scope

- **Managed databases / add-ons (Postgres, Redis) and persistent volumes** — a whole provisioning subsystem; apps bring their own for now.
- **Automatic Let's Encrypt (ACME)** — not built zero-dep; use the `SSL_CERT`/`SSL_KEY` env or a tunnel that terminates TLS.
- **Sandboxing / multi-tenant isolation** — apps run as child processes with your privileges. Fine for your own code on your own box.
