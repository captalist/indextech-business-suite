/**
 * INDEXTECH Enterprise Suite — centralized API + SQLite + static UI
 */
'use strict';

const path = require('path');
const fs = require('fs');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'suite.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS blobs (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  display_name TEXT,
  role TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT,
  permissions TEXT
);
`);

try {
  db.exec('ALTER TABLE users ADD COLUMN permissions TEXT');
} catch {
  /* column already exists */
}

const CO_DEFAULT = {
  name: 'IndexTech Digital Company',
  addr: 'Nkrumah Street, Kumalija Building',
  pobox: 'P.O Box 1652, Mwanza',
  tin: '137-651-750',
  phone: '+255 758 179 958 / +255 712 179 958',
  email: 'info@indextech.co.tz',
  web: 'www.indextech.co.tz',
  banks: [{ n: 'NMB', a: '329100191849' }, { n: 'CRDB', a: '015C493674500' }],
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

/** All grantable permissions (modules + admin actions). */
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

function attachAuthPermissions(req, _res, next) {
  const u = db.prepare('SELECT role, permissions FROM users WHERE id = ?').get(req.auth.userId);
  if (!u) return next();
  req.auth.permissions = resolveUserPermissions(u.role, u.permissions);
  next();
}

function ensureBlobDefaults() {
  const ins = db.prepare('INSERT OR IGNORE INTO blobs (key, value) VALUES (?, ?)');
  ins.run('company', JSON.stringify(CO_DEFAULT));
  ins.run('seq', JSON.stringify(DEFAULT_SEQ));
  for (const k of ['crm', 'sales', 'products', 'wo', 'cal', 'quotes', 'tickets', 'projects', 'assets', 'expenses', 'vendors', 'po', 'employees', 'docs']) {
    ins.run(k, '[]');
  }
}

function seedAdmin() {
  const row = db.prepare('SELECT COUNT(*) AS c FROM users').get();
  if (row.c > 0) return;
  const pwd = process.env.ADMIN_PASSWORD || 'admin123';
  const hash = bcrypt.hashSync(pwd, 10);
  db.prepare(
    `INSERT INTO users (id, username, display_name, role, password_hash, active, created_at)
     VALUES (?, ?, ?, ?, ?, 1, ?)`
  ).run('u_admin', 'admin', 'Administrator', 'admin', hash, new Date().toISOString());
  console.log('[suite] Seeded admin user (username: admin). Change ADMIN_PASSWORD on first deploy.');
}

ensureBlobDefaults();
seedAdmin();

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

const app = express();
app.use(express.json({ limit: '50mb' }));

const API_PUBLIC = new Set(['/health', '/auth/login']);
app.use('/api', (req, res, next) => {
  if (API_PUBLIC.has(req.path)) return next();
  authMiddleware(req, res, () => attachAuthPermissions(req, res, next));
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

app.get('/api/permissions', (_req, res) => {
  res.json({ keys: ALL_PERMISSION_KEYS, roles: ROLE_DEFS });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const u = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(String(username).trim());
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
});

function parseBlob(key) {
  const row = db.prepare('SELECT value FROM blobs WHERE key = ?').get(key);
  if (!row) return [];
  try {
    const v = JSON.parse(row.value);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

app.get('/api/notify-snapshot', (req, res) => {
  const wo = parseBlob('wo').map((w) => ({
    id: w.id,
    num: w.num,
    tech: w.tech,
    customer: w.customer,
    updated: w.updated,
  }));
  const cal = parseBlob('cal').map((e) => ({
    id: e.id,
    title: e.title,
    date: e.date,
    time: e.time,
    cat: e.cat,
  }));
  const sales = parseBlob('sales').map((s) => ({
    id: s.id,
    title: s.title,
    custName: s.custName,
    updated: s.updated,
  }));
  res.json({ wo, cal, sales });
});

app.get('/api/state', (req, res) => {
  const get = (key) => {
    const row = db.prepare('SELECT value FROM blobs WHERE key = ?').get(key);
    if (!row) return null;
    try {
      return JSON.parse(row.value);
    } catch {
      return null;
    }
  };
  const company = get('company');
  const seq = get('seq');
  res.json({
    company: company || CO_DEFAULT,
    seq: seq || DEFAULT_SEQ,
    crm: get('crm') || [],
    sales: get('sales') || [],
    products: get('products') || [],
    workOrders: get('wo') || [],
    cal: get('cal') || [],
    quotes: get('quotes') || [],
    tickets: get('tickets') || [],
    projects: get('projects') || [],
    assets: get('assets') || [],
    expenses: get('expenses') || [],
    vendors: get('vendors') || [],
    po: get('po') || [],
    employees: get('employees') || [],
    docs: get('docs') || [],
    me: {
      permissions: req.auth.permissions,
      role: req.auth.role,
    },
  });
});

const upsertBlob = db.prepare('INSERT INTO blobs (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');

app.put('/api/blobs', (req, res) => {
  const body = req.body || {};
  const tx = db.transaction(() => {
    for (const [k, v] of Object.entries(body)) {
      if (!BLOB_KEYS.has(k)) continue;
      upsertBlob.run(k, JSON.stringify(v));
    }
  });
  try {
    tx();
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Save failed' });
  }
});

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
    active: r.active !== 0,
    createdAt: r.created_at,
    permissions,
    customPermissions,
  };
}

app.get('/api/users', requirePerm('users_manage'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM users ORDER BY username').all();
  res.json(rows.map(mapUserRow));
});

app.post('/api/users', requirePerm('users_manage'), (req, res) => {
  const { username, displayName, role, password, active, permissions, useRoleDefaults } = req.body || {};
  const uname = String(username || '')
    .toLowerCase()
    .trim();
  if (!uname) return res.status(400).json({ error: 'Username required' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!ROLE_DEFS[role]) return res.status(400).json({ error: 'Invalid role' });
  const permJson = useRoleDefaults ? null : JSON.stringify(sanitizePermissionsInput(permissions) || roleDefaultPermissions(role));
  try {
    const hash = bcrypt.hashSync(password, 10);
    const id = 'u' + Date.now();
    db.prepare(
      `INSERT INTO users (id, username, display_name, role, password_hash, active, created_at, permissions)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(id, uname, displayName || uname, role, hash, active === false ? 0 : 1, new Date().toISOString(), permJson);
    res.json({ ok: true, id });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(400).json({ error: 'Username already exists' });
    throw e;
  }
});

app.patch('/api/users/:id', requirePerm('users_manage'), (req, res) => {
  const { id } = req.params;
  const { displayName, role, active, password, permissions, useRoleDefaults } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  const nextRole = role !== undefined ? role : u.role;
  if (!ROLE_DEFS[nextRole]) return res.status(400).json({ error: 'Invalid role' });
  const nextActive = active !== undefined ? (active ? 1 : 0) : u.active;
  const nextDisp = displayName !== undefined ? displayName : u.display_name;

  const wasAdminActive = u.role === 'admin' && u.active === 1;
  const willBeAdminActive = nextRole === 'admin' && nextActive === 1;
  if (wasAdminActive && !willBeAdminActive) {
    const otherAdmins = db.prepare(`SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND active = 1 AND id != ?`).get(id).c;
    if (otherAdmins === 0) return res.status(400).json({ error: 'Cannot remove the last administrator' });
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

  db.prepare(`UPDATE users SET display_name = ?, role = ?, active = ?, password_hash = ?, permissions = ? WHERE id = ?`).run(
    nextDisp,
    nextRole,
    nextActive,
    hash,
    nextPerms,
    id
  );
  res.json({ ok: true });
});

app.delete('/api/users/:id', requirePerm('users_manage'), (req, res) => {
  const { id } = req.params;
  if (req.auth.userId === id) return res.status(400).json({ error: 'You cannot delete your own account' });
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  const admins = db.prepare(`SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND active = 1`).get().c;
  if (u.role === 'admin' && u.active === 1 && admins <= 1) {
    return res.status(400).json({ error: 'Cannot delete the last administrator' });
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.use(express.static(ROOT, { index: false }));

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  res.sendFile(path.join(ROOT, 'index.html'));
});

const PORT = parseInt(process.env.PORT || '8080', 10);
app.listen(PORT, () => {
  console.log(`INDEXTECH suite → http://localhost:${PORT}  (data: ${DATA_DIR})`);
});
