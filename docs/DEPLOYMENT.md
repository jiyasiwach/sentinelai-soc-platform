# Deployment

SentinelAI ships as one Docker image (see `Dockerfile`): a Node 20 stage builds the React UI, and a
Python 3.12-slim stage installs the backend, copies the built UI to `/app/static` (`STATIC_DIR`), runs as a
non-root user (uid 10001), listens on `$PORT` (default 8000) and has a `HEALTHCHECK` on `/api/health`. The UI
and the API are served from the same origin, so no CORS configuration is needed in production (the CORS
middleware is only enabled when `APP_ENV` is not `production`).

## Configuration reference

All settings come from environment variables (`backend/app/config.py`). An empty value is treated as
unset for the variables that have a default.

| Variable | Default | Notes |
|---|---|---|
| `APP_ENV` | `development` | `production` enables the start-up checks below and disables CORS |
| `DATABASE_URL` | `sqlite:///./sentinel.db` (Docker image: `sqlite:////app/data/sentinel.db`) | `postgres://` and `postgresql://` are rewritten to `postgresql+psycopg://` |
| `JWT_SECRET` | dev-only placeholder | **required in production**: at least 32 characters |
| `JWT_EXPIRE_MINUTES` | `480` | token lifetime |
| `AI_PROVIDER` | `offline` | `offline`, `anthropic` or `openai`; anything else stops start-up |
| `ANTHROPIC_API_KEY` | - | |
| `ANTHROPIC_MODEL` | `claude-opus-5-5` | |
| `ANTHROPIC_BASE_URL` | `https://api.anthropic.com` | |
| `ANTHROPIC_FALLBACKS` | `true` | server-side refusal fallbacks for current Claude models |
| `OPENAI_API_KEY` | - | optional (local servers such as Ollama need none) |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | any OpenAI-compatible `/chat/completions` endpoint |
| `OPENAI_MODEL` | `gpt-4o-mini` | |
| `AI_TIMEOUT_SECONDS` | `90` | per LLM call |
| `CORRELATION_WINDOW_MINUTES` | `60` | |
| `LOGIN_MAX_FAILURES` | `5` | failed logins per username within the window before it is locked |
| `LOGIN_IP_MAX_FAILURES` | `20` | failed logins per client IP (any username) within the window before it is locked |
| `LOGIN_LOCKOUT_MINUTES` | `15` | sliding window length; a lock lifts as old failures age out |
| `SEED_DEMO_DATA` | `true` | seeds users and demo data when the database has no users |
| `ADMIN_PASSWORD` / `ANALYST_PASSWORD` / `VIEWER_PASSWORD` | `Admin@12345` / `Analyst@12345` / `Viewer@12345` | used only when seeding |
| `CORS_ORIGINS` | `http://localhost:5173` | comma-separated; ignored in production |
| `STATIC_DIR` | empty (Docker image: `/app/static`) | directory with the built UI; falls back to `../frontend/dist` |
| `PORT` | `8000` | read by the Docker `CMD`, not by the Python code |

Generate a secret with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

## Pre-deploy checklist

- [ ] `APP_ENV=production`.
- [ ] `JWT_SECRET` set to a random value of **at least 32 characters**. With `APP_ENV=production` the app
      refuses to start if the secret is missing (the built-in placeholder), shorter than 32 characters, or
      one of `secret`, `changeme`, `change-me`, `password`.
- [ ] `DATABASE_URL` points at PostgreSQL (managed database or the compose `db` service). SQLite in a
      container is lost when the container is replaced unless `/app/data` is on a volume.
- [ ] Demo accounts: either set strong `ADMIN_PASSWORD`, `ANALYST_PASSWORD`, `VIEWER_PASSWORD` **before the
      first start**, or set `SEED_DEMO_DATA=false` and create the first admin yourself (below). In production
      the app logs a start-up warning when `SEED_DEMO_DATA` is on and `ADMIN_PASSWORD` is the default.
- [ ] AI keys (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY`) only in the host's environment or secret store,
      never in Git. `.env` is for local use.
- [ ] HTTPS in front of the app (all the platforms below terminate TLS for you; on a VPS use Caddy).
- [ ] Health check path `/api/health`.

### Important: how users are created

- Seeding runs only when the `users` table is empty. Changing `ADMIN_PASSWORD` etc. later does **not**
  change existing passwords.
- With `SEED_DEMO_DATA=false` on an empty database **no user exists**, and the API has no sign-up. Create
  the first admin with a one-off command inside the app container (or from `backend/` locally with the
  same `DATABASE_URL`):

```bash
python -c "
from app.database import init_db, SessionLocal
from app.models import User
from app.security import hash_password
init_db()
with SessionLocal() as db:
    db.add(User(username='admin', full_name='Administrator', role='admin',
                password_hash=hash_password('CHANGE-ME-to-a-long-passphrase')))
    db.commit()
"
```

  With Docker Compose: `docker compose exec app python -c "..."`. Further users can then be created on the
  *Admin* page (`POST /api/auth/users`).
- There is no password-change endpoint. To reset a password, run the same kind of command:

```bash
python -c "
from app.database import SessionLocal
from app.models import User
from app.security import hash_password
with SessionLocal() as db:
    u = db.query(User).filter_by(username='admin').one()
    u.password_hash = hash_password('NEW-long-passphrase')
    db.commit()
"
```

## Option 1: Render (blueprint)

`render.yaml` defines one Docker web service (`sentinelai`, health check `/api/health`) and a managed
PostgreSQL database (`sentinelai-db`). It sets `APP_ENV=production`, generates `JWT_SECRET`
(`generateValue: true`), wires `DATABASE_URL` from the database's connection string and sets
`AI_PROVIDER=offline`. `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and the three demo passwords are declared with
`sync: false`, so Render asks you for them.

1. Push the repository to GitHub/GitLab.
2. Render dashboard -> **New** -> **Blueprint** -> select the repository.
3. Enter strong values for `ADMIN_PASSWORD`, `ANALYST_PASSWORD`, `VIEWER_PASSWORD` (leave the AI keys empty
   for offline mode). If you leave a password empty, the default demo password is used.
4. Apply. Render builds the image and provides an `https://<name>.onrender.com` URL. Render supplies `PORT`,
   which the image honours.
5. To use an LLM later, set `AI_PROVIDER` and the key in the service's *Environment* tab; Render redeploys.

The blueprint uses the `free` plan for both resources. Free web services sleep when idle, and free databases
have limits on lifetime and backups; check Render's current plan terms before relying on it.

## Option 2: Railway

1. **New Project** -> **Deploy from GitHub repo**. Railway detects the `Dockerfile` at the repository root.
2. **New** -> **Database** -> **PostgreSQL** in the same project.
3. In the app service's **Variables** add:
   - `DATABASE_URL` = `${{Postgres.DATABASE_URL}}` (a reference to the database service's variable; the
     `postgresql://` URL is accepted as is)
   - `APP_ENV` = `production`
   - `JWT_SECRET` = output of the `secrets.token_urlsafe(48)` command
   - `ADMIN_PASSWORD`, `ANALYST_PASSWORD`, `VIEWER_PASSWORD` (or `SEED_DEMO_DATA=false`)
   - optionally `AI_PROVIDER` and the key
4. **Settings** -> **Networking** -> **Generate Domain**. Railway injects `PORT`; the image listens on it.
5. Set the health-check path to `/api/health` under **Settings** -> **Deploy**.

## Option 3: VPS with Docker Compose and Caddy

Suitable for any Linux server with Docker Engine and the Compose plugin, and a DNS name pointing at it.

1. Copy the repository to the server and create `.env` next to `docker-compose.yml`:

   ```bash
   APP_ENV=production
   JWT_SECRET=<48+ random characters>
   POSTGRES_PASSWORD=<random database password>
   ADMIN_PASSWORD=<strong>
   ANALYST_PASSWORD=<strong>
   VIEWER_PASSWORD=<strong>
   AI_PROVIDER=offline
   ```

   Compose uses `APP_ENV`, `AI_PROVIDER` and `POSTGRES_PASSWORD` from this file for variable substitution,
   passes the file to the app container (`env_file`), and builds `DATABASE_URL` for the `db` service
   itself, so any `DATABASE_URL` line in `.env` is overridden.

2. Publish the app only on the loopback interface so that it is reachable through Caddy alone. In
   `docker-compose.yml` on the server change the app's port mapping to:

   ```yaml
       ports:
         - "127.0.0.1:8000:8000"
   ```

3. Start it: `docker compose up -d --build`, then `docker compose ps` until `app` is healthy.

4. Install Caddy (it obtains and renews Let's Encrypt certificates automatically) and use this
   `/etc/caddy/Caddyfile`:

   ```caddyfile
   soc.example.com {
       encode gzip
       request_body {
           max_size 25MB
       }
       header {
           Strict-Transport-Security "max-age=31536000; includeSubDomains"
           -Server
       }
       reverse_proxy 127.0.0.1:8000
   }
   ```

   `max_size` is slightly above the app's own 20 MB upload limit. Reload with `sudo systemctl reload caddy`.
   The container runs uvicorn with `--proxy-headers --forwarded-allow-ips='*'`, so client IPs and the
   scheme from Caddy are honoured; this is safe only because the port is bound to `127.0.0.1`.

5. Open ports 80 and 443 in the firewall; keep 8000 and 5432 closed.

The application throttles logins itself (per username and per client IP, `429` with `Retry-After`, see
`LOGIN_*` above). The counters live in process memory, which fits the single container shipped here; if you
run several replicas, also rate-limit `POST /api/auth/login` at the proxy or move the counters to a shared
store such as Redis. Because the per-IP limit uses the client address, keep `--proxy-headers` behind a
trusted proxy only (as configured), otherwise every user would share the proxy's IP.

## Option 4: Vercel (frontend) + another host (backend)

Vercel can host the static React build, but **not this backend**: SentinelAI is a long-running FastAPI
process with a persistent database connection, start-up seeding, 20 MB uploads and LLM calls that may take
up to `AI_TIMEOUT_SECONDS` (90 s). Run the backend on Render, Railway, Fly.io or a VPS (any option in this
document), then put the UI on Vercel and proxy `/api` to it.

1. Deploy the backend first and note its URL, e.g. `https://sentinel-api.onrender.com`. Check
   `https://sentinel-api.onrender.com/api/health`.
2. In Vercel: **Add New Project** -> import the repository -> **Root Directory** `frontend`, framework
   preset **Vite**, build command `npm run build`, output directory `dist`.
3. Add `frontend/vercel.json` (not included in the repository) so that `/api/*` is rewritten to the backend
   and every other path falls back to the SPA:

   ```json
   {
     "rewrites": [
       { "source": "/api/:path*", "destination": "https://sentinel-api.onrender.com/api/:path*" },
       { "source": "/(.*)", "destination": "/index.html" }
     ]
   }
   ```

4. Deploy. The browser only talks to the Vercel domain, so requests are same-origin and the backend needs
   no CORS settings (it disables CORS in production anyway). The UI calls relative `/api/...` paths, so
   no build-time API URL is needed.

Caveats: Vercel's proxy applies its own request-size and timeout limits to rewritten requests, which can be
lower than the backend's (large alert uploads, slow LLM investigations). Check Vercel's current limits; if
they get in the way, serve everything from the backend host instead, which already serves the UI.

## Option 5: Fly.io

1. Install `flyctl` and log in. From the repository root run `fly launch --no-deploy`; it detects the
   `Dockerfile` and writes `fly.toml`. Make sure it contains:

   ```toml
   [http_service]
     internal_port = 8000
     force_https = true

   [[http_service.checks]]
     grace_period = "20s"
     interval = "30s"
     method = "GET"
     path = "/api/health"
     timeout = "5s"
   ```

2. Create a Postgres database with Fly (`fly postgres create` then `fly postgres attach <db-app>`, which
   sets the `DATABASE_URL` secret) or use any external Postgres and set `DATABASE_URL` yourself.
3. Set the secrets:

   ```bash
   fly secrets set APP_ENV=production JWT_SECRET=<48+ random characters> \
       ADMIN_PASSWORD=<strong> ANALYST_PASSWORD=<strong> VIEWER_PASSWORD=<strong>
   ```

4. `fly deploy`.

## Operations

### Logs

The app logs to stdout: uvicorn access logs, `sentinel` (start-up line with environment and AI provider,
unhandled errors with stack traces) and `sentinel.ai` (a warning each time an LLM call fails and the offline
analyst is used).

- Compose: `docker compose logs -f app`
- Render / Railway / Fly: the platform's log view, or `fly logs`.

Security-relevant events (logins, failed logins, imports, AI calls, response actions, changes) are in the
application audit log (*Admin* page or `GET /api/auth/audit`), stored in the `audit_logs` table.

### Backups

- PostgreSQL in Compose:

  ```bash
  docker compose exec -T db pg_dump -U sentinel -d sentinel --format=custom > sentinel-$(date +%F).dump
  # restore into an empty database:
  docker compose exec -T db pg_restore -U sentinel -d sentinel --clean < sentinel-2026-11-20.dump
  ```

- Managed Postgres (Render, Railway, Fly): use the provider's backup feature where your plan has one, and
  also take periodic `pg_dump` exports with the connection string.
- SQLite: stop the app and copy the database file, or use `sqlite3 sentinel.db ".backup backup.db"`.

Back up before every upgrade.

### Upgrades

1. Back up the database.
2. Pull the new code and rebuild: `docker compose up -d --build` (or push to the branch the platform
   deploys from).
3. Check `/api/health` and the start-up log line.

Tables are created with SQLAlchemy `create_all` at start-up. That adds **new tables** but does not alter
existing ones; if a release changes columns, apply the change manually (or export, recreate and re-import).
There is no migration tool yet.

### Rotating secrets

- **`JWT_SECRET`**: set a new value and restart. All existing tokens become invalid and every user has to
  sign in again. Rotate immediately if the secret may have leaked.
- **AI keys**: create a new key with the provider, update the environment variable, restart, then revoke
  the old key. A bad key does not break the app; investigations fall back to the offline analyst with an
  `engine_note`, and `sentinel.ai` logs a warning.
- **User passwords**: see "How users are created" above. Deactivating a user (`is_active = false` in the
  database) blocks their existing tokens at once because the user is re-checked on every request.
- **Database password**: change it in the database, update `DATABASE_URL` (or `POSTGRES_PASSWORD` for
  Compose; note the official Postgres image only applies `POSTGRES_PASSWORD` when it initialises an empty
  data volume), and restart the app.
