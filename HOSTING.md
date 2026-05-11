# Hosting INDEXTECH Enterprise Suite (central database)

The app is served by **Node.js**. All business data lives in **SQLite** on the server (`data/suite.db` by default), so every employee who signs in sees the **same** CRM, inventory, invoices, and documents.

## Quick start (Windows / Mac / Linux)

```bash
cd /path/to/indextech-suite
npm install
npm start
```

Open **http://localhost:8080** — default login: **admin** / **admin123** (set `ADMIN_PASSWORD` before exposing to the internet).

## Environment variables

| Variable         | Purpose |
|------------------|---------|
| `PORT`           | HTTP port (default `8080`) |
| `DATA_DIR`       | Folder for `suite.db` (default `./data`) |
| `JWT_SECRET`     | **Required in production** — signing key for sessions |
| `ADMIN_PASSWORD` | Password for the seeded `admin` user (first run only) |
| `NODE_ENV`       | `production` recommended when deployed |

## Docker

```bash
docker compose up -d --build
```

- Database persists in the **`suite-data`** Docker volume (under `/app/data` in the container).
- Override secrets: create a `.env` next to `docker-compose.yml` with `JWT_SECRET` and `ADMIN_PASSWORD`.

## Security notes

- Use **HTTPS** in production (reverse proxy: Caddy, nginx, Traefik, Cloudflare).
- Change **admin** password and `JWT_SECRET` before going live.
- The API does **not** implement per-field RBAC on every write; roles still control the UI. Treat network access as trusted or add VPN/IP allowlists for sensitive deployments.

## Migrating old browser-only data

If you previously used the app with **localStorage** only, use **Reports → Export full backup** in the old browser, then (optional) we can add an admin import endpoint — or manually merge JSON into the SQLite blobs via a one-off script. Ask if you need an import tool.

## Optional: `API_BASE` for split hosting

If the HTML is served from a different origin than the API, set before the app scripts in `index.html`:

```html
<script>window.API_BASE = 'https://api.yourcompany.com';</script>
```

Same-origin deployment (default) does not need this.
