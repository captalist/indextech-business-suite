# Hosting INDEXTECH Enterprise Suite (central database)

The app is served by **Node.js**. All business data lives in a **separate PostgreSQL database** so application updates do not overwrite your data.

## Quick start (Windows / Mac / Linux)

1. Install and start **PostgreSQL 14+**, then create the database:

```sql
CREATE USER suite WITH PASSWORD 'suite';
CREATE DATABASE indextech_suite OWNER suite;
```

2. Run the app:

```bash
cd /path/to/indextech-suite
npm install
set DATABASE_URL=postgresql://suite:suite@localhost:5432/indextech_suite
npm start
```

On Linux/macOS use `export DATABASE_URL=...` instead of `set`.

Open **http://localhost:8080** and sign in with your administrator account.

## Environment variables

| Variable         | Purpose |
|------------------|---------|
| `DATABASE_URL`   | PostgreSQL connection string (required) |
| `PORT`           | HTTP port (default `8080`) |
| `JWT_SECRET`     | **Required in production** — signing key for sessions |
| `ADMIN_PASSWORD` | Password for the seeded `admin` user (first run only) |
| `NODE_ENV`       | `production` recommended when deployed |

Default `DATABASE_URL` if unset: `postgresql://suite:suite@localhost:5432/indextech_suite`

## Docker (recommended)

```bash
docker compose up -d --build
```

- **PostgreSQL** runs in its own container with the **`postgres-data`** volume — survives app image rebuilds and updates.
- The app container connects via `DATABASE_URL`.
- Copy `.env.example` to `.env` and set `POSTGRES_PASSWORD`, `JWT_SECRET`, and `ADMIN_PASSWORD`.

## Security notes

- Use **HTTPS** in production (reverse proxy: Caddy, nginx, Traefik, Cloudflare).
- Change the **admin** password and `JWT_SECRET` before going live.
- The API does **not** implement per-field RBAC on every write; roles still control the UI. Treat network access as trusted or add VPN/IP allowlists for sensitive deployments.

## Migrating from SQLite

If you previously used `data/suite.db`, export a full backup from the old app (**Reports → Export full backup**), then contact your administrator for a one-time import into PostgreSQL blobs, or run a custom migration script against both databases.

## Optional: `API_BASE` for split hosting

If the HTML is served from a different origin than the API, set before the app scripts in `index.html`:

```html
<script>window.API_BASE = 'https://api.yourcompany.com';</script>
```

Same-origin deployment (default) does not need this.
