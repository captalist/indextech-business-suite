/**
 * INDEXTECH Enterprise Suite — centralized API + PostgreSQL + static UI
 */
'use strict';

const path = require('path');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const ROOT = __dirname;

const DATABASE_URL =
  process.env.DATABASE_URL || 'postgresql://postgres:KODI1kodi2@localhost:5432/indextech_suite';

const pool = new Pool({ connectionString: DATABASE_URL });

const CO_DEFAULT = {
  name: 'IndexTech Digital Company',
  addr: 'Nkrumah Street, Kumalija Building',
  pobox: 'P.O Box 1652, Mwanza',
  tin: '137-651-750',
  phone: '+255 758 179 958 / +255 712 179 958',
  email: 'info@indextech.co.tz',
  web: 'www.indextech.co.tz',
  banks: [{ n: 'NMB', a: '32910019849' }, { n: 'CRDB', a: '015C493674500' }],
};

const DEFAULT_SEQ = { ic: 1, wc: 1, ac: 1, won: 1, qc: 1, tkn: 1, pon: 1 };

const BLOB_KEYS = new Set([
  'company',
  'seq',
  'crm',
  'sales',
  'products',
  'wo',
  'cal',
  'quotes',
  'tickets',
  'projects',
  'assets',
  'expenses',
  'vendors',
  'po',
  'employees',
  'docs',
]);

const ROLE_DEFS = {
  admin: { permissions: ['*'] },
  manager: {
    permissions: [
      'dashboard', 'calendar', 'crm', 'sales', 'quotes', 'invoice', 'inventory', 'warranty', 'service',
      'tickets', 'projects', 'assets', 'finance', 'procurement', 'hr', 'agreement', 'history', 'reports',
      'settings_company', 'data_export', 'docs_delete',
    ],
  },
  sales: {
    permissions: ['dashboard', 'calendar', 'crm', 'sales', 'quotes', 'invoice', 'agreement', 'history', 'projects', 'tickets', 'data_export'],
  },
  technician: {
    permissions: ['dashboard', 'calendar', 'service', 'warranty', 'inventory', 'history', 'tickets', 'projects'],
  },
  accountant: {
    permissions: ['dashboard', 'calendar', 'invoice', 'finance', 'procurement', 'assets', 'reports', 'history', 'agreement', 'data_export'],
  },
  viewer: { permissions: ['dashboard', 'calendar', 'reports', 'history'] },
};

const ALL_PERMISSION_KEYS = [
  'dashboard', 'calendar', 'crm', 'sales', 'quotes', 'invoice', 'inventory', 'warranty', 'service',
  'tickets', 'projects', 'assets', 'finance', 'procurement', 'hr', 'agreement', 'history', 'reports',
  'settings_company', 'data_export', 'docs_delete', 'users_manage',
];

function roleDefaultPermissions(role) {
  const def = ROLE_DEFS[role];
  if (!def) return [];
  if (def.permissions.includes('*')) return ALL_PERMISSION_KEYS.slice();
  return def.permissions.slice();
}

function resolveUserPermissions(role, permissionsJson) {
  if (permissionsJson != null && String(permissionsJson).trim() !== '') {
    try {
      const parsed = JSON.parse(permissionsJson);
      if (Array.isArray(parsed) && parsed.length > 0) {
        return parsed.filter((k) => ALL_PERMISSION_KEYS.includes(k) || k === '*');
      }
    } catch {
      /* fall through to role */
    }
  }
  return roleDefaultPermissions(role);
}

function sanitizePermissionsInput(perms) {
  if (perms === undefined || perms === null) return null;
  if (!Array.isArray(perms)) return null;
  const out = [...new Set(perms.filter((k) => typeof k === 'string' && (k === '*' || ALL_PERMISSION_KEYS.includes(k))))];
  return out.length ? out : null;
}

function userHasPerm(auth, key) {
  const perms = auth.permissions || roleDefaultPermissions(auth.role);
  if (perms.includes('*')) return true;
  return perms.includes(key);
}

async function attachAuthPermissions(req, _res, next) {
  try {
    const { rows } = await pool.query('SELECT role, permissions FROM users WHERE id = $1', [req.auth.userId]);
    const u = rows[0];
    if (!u) return next();
    req.auth.permissions = resolveUserPermissions(u.role, u.permissions);
    next();
  } catch (e) {
    next(e);
  }
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS blobs (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT,
      role TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TEXT,
      permissions TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx ON users (LOWER(username));
  `);
}

async function ensureBlobDefaults() {
  await pool.query(
    `INSERT INTO blobs (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`,
    ['company', JSON.stringify(CO_DEFAULT)]
  );
  await pool.query(
    `INSERT INTO blobs (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`,
    ['seq', JSON.stringify(DEFAULT_SEQ)]
  );
  for (const k of ['crm', 'sales', 'products', 'wo', 'cal', 'quotes', 'tickets', 'projects', 'assets', 'expenses', 'vendors', 'po', 'employees', 'docs']) {
    await pool.query(`INSERT INTO blobs (key, value) VALUES ($1, '[]') ON CONFLICT (key) DO NOTHING`, [k]);
  }
}

async function seedAdmin() {
  const { rows } = await pool.query('SELECT COUNT(*)::int AS c FROM users');
  if (rows[0].c > 0) return;
  const pwd = process.env.ADMIN_PASSWORD || 'admin123';
  const hash = bcrypt.hashSync(pwd, 10);
  await pool.query(
    `INSERT INTO users (id, username, display_name, role, password_hash, active, created_at)
     VALUES ($1, $2, $3, $4, $5, TRUE, $6)`,
    ['u_admin', 'admin', 'Administrator', 'admin', hash, new Date().toISOString()]
  );
  console.log('[suite] Seeded admin user (username: admin). Set ADMIN_PASSWORD on first deploy.');
}

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
if (JWT_SECRET === 'dev-secret-change-me' && process.env.NODE_ENV === 'production') {
  console.warn('[suite] WARNING: Set JWT_SECRET in production.');
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.auth = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requirePerm(key) {
  return (req, res, next) => {
    if (!userHasPerm(req.auth, key)) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

async function parseBlob(key) {
  const { rows } = await pool.query('SELECT value FROM blobs WHERE key = $1', [key]);
  if (!rows.length) return [];
  try {
    const v = JSON.parse(rows[0].value);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

function mapUserRow(r) {
  let permissions = null;
  let customPermissions = false;
  if (r.permissions != null && String(r.permissions).trim() !== '') {
    customPermissions = true;
    permissions = resolveUserPermissions(r.role, r.permissions);
  }
  return {
    id: r.id,
    username: r.username,
    displayName: r.display_name,
    role: r.role,
    active: r.active !== false,
    createdAt: r.created_at,
    permissions,
    customPermissions,
  };
}

const app = express();
app.use(express.json({ limit: '50mb' }));

const API_PUBLIC = new Set(['/health', '/auth/login']);
app.use('/api', (req, res, next) => {
  if (API_PUBLIC.has(req.path)) return next();
  authMiddleware(req, res, () => attachAuthPermissions(req, res, next));
});

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, db: 'postgresql' });
  } catch {
    res.status(503).json({ ok: false, error: 'Database unavailable' });
  }
});

app.get('/api/permissions', (_req, res) => {
  res.json({ keys: ALL_PERMISSION_KEYS, roles: ROLE_DEFS });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const { rows } = await pool.query('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [
      String(username).trim(),
    ]);
    const u = rows[0];
    if (!u || !u.active) return res.status(401).json({ error: 'Invalid username or account disabled' });
    if (!bcrypt.compareSync(password, u.password_hash)) return res.status(401).json({ error: 'Invalid password' });
    const permissions = resolveUserPermissions(u.role, u.permissions);
    const token = jwt.sign(
      { userId: u.id, username: u.username, role: u.role, displayName: u.display_name || u.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({
      token,
      user: {
        id: u.id,
        username: u.username,
        displayName: u.display_name || u.username,
        role: u.role,
        permissions,
        customPermissions: u.permissions != null && String(u.permissions).trim() !== '',
      },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/notify-snapshot', async (_req, res) => {
  try {
    const wo = (await parseBlob('wo')).map((w) => ({
      id: w.id,
      num: w.num,
      tech: w.tech,
      customer: w.customer,
      status: w.status,
      updated: w.updated,
    }));
    const cal = (await parseBlob('cal')).map((e) => ({
      id: e.id,
      title: e.title,
      date: e.date,
      time: e.time,
      cat: e.cat,
    }));
    const sales = (await parseBlob('sales')).map((s) => ({
      id: s.id,
      title: s.title,
      custName: s.custName,
      updated: s.updated,
    }));
    const quotes = (await parseBlob('quotes')).map((q) => ({
      id: q.id,
      number: q.number,
      title: q.title,
      customer: q.customer,
      updated: q.updated,
    }));
    res.json({ wo, cal, sales, quotes });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Snapshot failed' });
  }
});

app.get('/api/state', async (req, res) => {
  try {
    const get = async (key) => {
      const { rows } = await pool.query('SELECT value FROM blobs WHERE key = $1', [key]);
      if (!rows.length) return null;
      try {
        return JSON.parse(rows[0].value);
      } catch {
        return null;
      }
    };
    const company = await get('company');
    const seq = await get('seq');
    res.json({
      company: company || CO_DEFAULT,
      seq: seq || DEFAULT_SEQ,
      crm: (await get('crm')) || [],
      sales: (await get('sales')) || [],
      products: (await get('products')) || [],
      workOrders: (await get('wo')) || [],
      cal: (await get('cal')) || [],
      quotes: (await get('quotes')) || [],
      tickets: (await get('tickets')) || [],
      projects: (await get('projects')) || [],
      assets: (await get('assets')) || [],
      expenses: (await get('expenses')) || [],
      vendors: (await get('vendors')) || [],
      po: (await get('po')) || [],
      employees: (await get('employees')) || [],
      docs: (await get('docs')) || [],
      me: {
        permissions: req.auth.permissions,
        role: req.auth.role,
      },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Load failed' });
  }
});

app.put('/api/blobs', async (req, res) => {
  const client = await pool.connect();
  try {
    const body = req.body || {};
    await client.query('BEGIN');
    for (const [k, v] of Object.entries(body)) {
      if (!BLOB_KEYS.has(k)) continue;
      await client.query(
        `INSERT INTO blobs (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
        [k, JSON.stringify(v)]
      );
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Save failed' });
  } finally {
    client.release();
  }
});

app.get('/api/users', requirePerm('users_manage'), async (_req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users ORDER BY username');
    res.json(rows.map(mapUserRow));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Load failed' });
  }
});

app.post('/api/users', requirePerm('users_manage'), async (req, res) => {
  try {
    const { username, displayName, role, password, active, permissions, useRoleDefaults } = req.body || {};
    const uname = String(username || '')
      .toLowerCase()
      .trim();
    if (!uname) return res.status(400).json({ error: 'Username required' });
    if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (!ROLE_DEFS[role]) return res.status(400).json({ error: 'Invalid role' });
    const permJson = useRoleDefaults
      ? null
      : JSON.stringify(sanitizePermissionsInput(permissions) || roleDefaultPermissions(role));
    const hash = bcrypt.hashSync(password, 10);
    const id = 'u' + Date.now();
    await pool.query(
      `INSERT INTO users (id, username, display_name, role, password_hash, active, created_at, permissions)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [id, uname, displayName || uname, role, hash, active === false ? false : true, new Date().toISOString(), permJson]
    );
    res.json({ ok: true, id });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Username already exists' });
    console.error(e);
    res.status(500).json({ error: 'Create failed' });
  }
});

app.patch('/api/users/:id', requirePerm('users_manage'), async (req, res) => {
  try {
    const { id } = req.params;
    const { displayName, role, active, password, permissions, useRoleDefaults } = req.body || {};
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    const u = rows[0];
    if (!u) return res.status(404).json({ error: 'Not found' });
    const nextRole = role !== undefined ? role : u.role;
    if (!ROLE_DEFS[nextRole]) return res.status(400).json({ error: 'Invalid role' });
    const nextActive = active !== undefined ? active : u.active;
    const nextDisp = displayName !== undefined ? displayName : u.display_name;

    const wasAdminActive = u.role === 'admin' && u.active;
    const willBeAdminActive = nextRole === 'admin' && nextActive;
    if (wasAdminActive && !willBeAdminActive) {
      const { rows: ac } = await pool.query(
        `SELECT COUNT(*)::int AS c FROM users WHERE role = 'admin' AND active = TRUE AND id != $1`,
        [id]
      );
      if (ac[0].c === 0) return res.status(400).json({ error: 'Cannot remove the last administrator' });
    }

    let hash = u.password_hash;
    if (password && String(password).length > 0) {
      if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
      hash = bcrypt.hashSync(password, 10);
    }

    let nextPerms = u.permissions;
    if (useRoleDefaults === true) nextPerms = null;
    else if (permissions !== undefined) {
      const sanitized = sanitizePermissionsInput(permissions);
      nextPerms = sanitized ? JSON.stringify(sanitized) : null;
    }

    await pool.query(
      `UPDATE users SET display_name = $1, role = $2, active = $3, password_hash = $4, permissions = $5 WHERE id = $6`,
      [nextDisp, nextRole, nextActive, hash, nextPerms, id]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Update failed' });
  }
});

app.delete('/api/users/:id', requirePerm('users_manage'), async (req, res) => {
  try {
    const { id } = req.params;
    if (req.auth.userId === id) return res.status(400).json({ error: 'You cannot delete your own account' });
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    const u = rows[0];
    if (!u) return res.status(404).json({ error: 'Not found' });
    const { rows: ac } = await pool.query(`SELECT COUNT(*)::int AS c FROM users WHERE role = 'admin' AND active = TRUE`);
    if (u.role === 'admin' && u.active && ac[0].c <= 1) {
      return res.status(400).json({ error: 'Cannot delete the last administrator' });
    }
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Delete failed' });
  }
});

app.use(express.static(ROOT, { index: false }));

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  res.sendFile(path.join(ROOT, 'index.html'));
});

const PORT = parseInt(process.env.PORT || '8080', 10);

async function start() {
  await initDb();
  await ensureBlobDefaults();
  await seedAdmin();
  app.listen(PORT, () => {
    console.log(`INDEXTECH suite → http://localhost:${PORT}  (PostgreSQL)`);
  });
}

start().catch((err) => {
  console.error('[suite] Failed to start:', err.message);
  process.exit(1);
});
