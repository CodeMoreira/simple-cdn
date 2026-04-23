const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs-extra');
const multer = require('multer');
const AdmZip = require('adm-zip');
const { verifyPassword, generateSessionToken } = require('./src/crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Directory constants
const CDN_DIR = path.join(__dirname, 'cdn');
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

const db = require('./src/db');

// Ensure directories exist
[CDN_DIR, PUBLIC_DIR, UPLOAD_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) {
    console.log(`📁 Creating directory: ${path.basename(dir)}`);
    fs.ensureDirSync(dir);
  }
});

app.use(cors());
app.use(express.json());
app.use('/cdn', express.static(CDN_DIR));
app.use(express.static(PUBLIC_DIR));

const upload = multer({ 
  dest: UPLOAD_DIR,
  limits: { fileSize: 1024 * 1024 * 1024 } // 1GB max file size for giant bundles
});

/**
 * Role hierarchy: higher rank satisfies lower-rank requirements.
 * admin(3) > deployer(2) > viewer(1)
 */
const ROLE_RANK = { admin: 3, deployer: 2, viewer: 1 };

const hasPermission = (userRole, requiredRole) => {
  if (!requiredRole) return true;
  return (ROLE_RANK[userRole] ?? 0) >= (ROLE_RANK[requiredRole] ?? 99);
};

/**
 * authenticate(requiredRole)
 * Dual-path: accepts either a web session token OR an API token (Bearer).
 * API tokens are limited to deploy actions — they cannot perform promotions
 * or user-management operations (enforced at the route level via `sessionOnly`).
 */
const authenticate = (requiredRole) => (req, res, next) => {
  const sessionToken = req.headers['x-session-token'] || req.headers['authorization']?.split(' ')[1];

  if (!sessionToken) {
    return res.status(401).json({ error: 'Unauthorized: Missing credentials' });
  }

  // 1. Try session lookup (web login)
  const session = db.prepare(
    'SELECT s.token as session_token, u.* FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ?'
  ).get(sessionToken);

  if (session) {
    if (!hasPermission(session.role, requiredRole)) {
      return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
    }
    req.user = session;
    req.authMethod = 'session';
    return next();
  }

  // 2. Try API token lookup (automated environments — deploy only)
  const user = db.prepare('SELECT * FROM users WHERE token = ?').get(sessionToken);
  if (user) {
    if (!hasPermission(user.role, requiredRole)) {
      return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
    }
    req.user = user;
    req.authMethod = 'token';
    return next();
  }

  return res.status(401).json({ error: 'Unauthorized: Invalid credentials' });
};

/**
 * sessionOnly middleware — blocks API token access for sensitive operations.
 * Use this on promotion, user management, and password endpoints.
 */
const sessionOnly = (req, res, next) => {
  if (req.authMethod === 'token') {
    return res.status(403).json({
      error: 'Forbidden: This operation requires web session authentication. API tokens are restricted to deploy actions only.'
    });
  }
  next();
};

// ─── Auth Routes ──────────────────────────────────────────────────────────────

/**
 * POST /auth/login
 * Authenticates with username + password. Returns a session token.
 */
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  const token = generateSessionToken();
  db.prepare('INSERT INTO sessions (user_id, token) VALUES (?, ?)').run(user.id, token);

  db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .run(user.id, 'LOGIN', `Web login from ${req.ip}`);

  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role }
  });
});

/**
 * POST /auth/logout
 * Invalidates the current session token.
 */
app.post('/auth/logout', authenticate(), (req, res) => {
  if (req.authMethod === 'session') {
    const token = req.headers['authorization']?.split(' ')[1] ||
                  req.headers['x-session-token'];
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  }
  res.json({ message: 'Signed out successfully.' });
});

/**
 * GET /auth/me
 * Returns the authenticated user's profile.
 */
app.get('/auth/me', authenticate(), (req, res) => {
  const { password_hash, token, ...safeUser } = req.user;
  res.json({ ...safeUser, authMethod: req.authMethod });
});

/** 
 * CONSUMER API: Get Active Modules
 * Requires valid AuthToken.
 */
app.get('/modules', authenticate(), (req, res) => {
  const host = `${req.protocol}://${req.get('host')}`;
  const modules = db.prepare('SELECT * FROM modules').all();
  
  const result = modules.map(m => {
    return {
      id: m.id,
      name: m.name,
      // Logic for selecting the environment based on user role or header
      // For now, we return all or respect the promotion level
      active_version: m.production_version || m.staging_version || m.dev_version,
      urls: {
        dev: m.dev_version ? `${host}/cdn/${m.id}/${m.dev_version}/index.bundle` : null,
        staging: m.staging_version ? `${host}/cdn/${m.id}/${m.staging_version}/index.bundle` : null,
        production: m.production_version ? `${host}/cdn/${m.id}/${m.production_version}/index.bundle` : null
      }
    };
  });
  
  res.json(result);
});

app.get('/api/admin/modules', authenticate('viewer'), (req, res) => {
  const host = `${req.protocol}://${req.get('host')}`;
  const modules = db.prepare('SELECT * FROM modules').all();
  
  const result = modules.map(m => {
    const devPath = path.join(CDN_DIR, m.id, 'dev', 'index.bundle');
    const hasDev = fs.existsSync(devPath);
    const versionsCount = db.prepare('SELECT count(*) as count FROM versions WHERE module_id = ?').get(m.id).count;
    
    return {
      ...m,
      has_dev_bundle: hasDev,
      dev_url: hasDev ? `${host}/cdn/${m.id}/dev/index.bundle` : null,
      versions_count: versionsCount,
    };
  });
  res.json(result);
});

/**
 * ADMIN API: Create Module
 */
app.post('/api/admin/modules', authenticate('admin'), (req, res) => {
  const { id, name, description } = req.body;
  
  try {
    const stmt = db.prepare('INSERT INTO modules (id, name, description) VALUES (?, ?, ?)');
    stmt.run(id, name, description);
    
    db.prepare('INSERT INTO audit_logs (user_id, action, module_id, details) VALUES (?, ?, ?, ?)')
      .run(req.user.id, 'CREATE_MODULE', id, `Created module ${name}`);

    res.status(201).json({ id, name, description });
  } catch (err) {
    res.status(400).json({ error: 'Module creation failed: ' + err.message });
  }
});

/**
 * ADMIN API: Update Module Info
 */
app.put('/api/admin/modules/:id', authenticate('admin'), (req, res) => {
  const { id } = req.params;
  const { name, description } = req.body;

  try {
    db.prepare('UPDATE modules SET name = COALESCE(?, name), description = COALESCE(?, description) WHERE id = ?')
      .run(name, description, id);
    
    res.json({ id, name, description });
  } catch (err) {
    res.status(400).json({ error: 'Update failed: ' + err.message });
  }
});

/**
 * ADMIN API: Delete Module
 */
app.delete('/api/admin/modules/:id', authenticate('admin'), (req, res) => {
  const { id } = req.params;
  
  try {
    db.prepare('DELETE FROM versions WHERE module_id = ?').run(id);
    db.prepare('DELETE FROM modules WHERE id = ?').run(id);
    
    // Cleanup files
    const assetDir = path.join(CDN_DIR, id);
    if (fs.existsSync(assetDir)) fs.removeSync(assetDir);

    res.status(204).end();
  } catch (err) {
    res.status(500).json({ error: 'Delete failed: ' + err.message });
  }
});

/**
 * ADMIN API: Get Module Versions History
 */
app.get('/api/admin/modules/:id/versions', authenticate('viewer'), (req, res) => {
  try {
    const versions = db.prepare('SELECT * FROM versions WHERE module_id = ? ORDER BY created_at DESC').all(req.params.id);
    res.json(versions);
  } catch(err) {
    res.status(500).json({ error: 'Failed to fetch versions' });
  }
});

/**
 * ADMIN API: Promote Dev to Staging
 * Copies the dev folder to staging.
 */
app.post('/api/admin/modules/:id/promote/staging', authenticate('admin'), (req, res) => {
  const { id } = req.params;
  const devPath = path.join(CDN_DIR, id, 'dev');
  const stagingPath = path.join(CDN_DIR, id, 'staging');
  
  if (!fs.existsSync(devPath)) return res.status(400).json({ error: 'No development bundle exists to promote' });
  
  try {
    if (fs.existsSync(stagingPath)) fs.removeSync(stagingPath);
    fs.copySync(devPath, stagingPath);
    
    db.prepare('UPDATE modules SET staging_version = ? WHERE id = ?').run('staging', id);
    
    db.prepare('INSERT INTO audit_logs (user_id, action, module_id, details) VALUES (?, ?, ?, ?)')
      .run(req.user.id, 'PROMOTE_STAGING', id, 'Promoted dev bundle to staging');

    res.json({ message: 'Successfully promoted to staging', id });
  } catch(err) {
    res.status(500).json({ error: 'Promotion failed: ' + err.message });
  }
});

/**
 * ADMIN API: Promote Staging to Production
 * Creates an immutable version from the staging folder.
 */
app.post('/api/admin/modules/:id/promote/production', authenticate('admin'), (req, res) => {
  const { id } = req.params;
  const { version, name } = req.body;
  const stagingPath = path.join(CDN_DIR, id, 'staging');
  
  if (!fs.existsSync(stagingPath)) return res.status(400).json({ error: 'No staging bundle exists to promote' });
  if (!version || !name) return res.status(400).json({ error: 'Version and Name are required' });
  
  const extractPath = path.join(CDN_DIR, id, version);
  
  try {
    fs.ensureDirSync(extractPath);
    fs.emptyDirSync(extractPath);
    fs.copySync(stagingPath, extractPath);
    
    db.prepare('INSERT OR REPLACE INTO versions (module_id, version_number, name) VALUES (?, ?, ?)')
      .run(id, version, name);
      
    db.prepare('UPDATE modules SET production_version = ? WHERE id = ?').run(version, id);
    
    db.prepare('INSERT INTO audit_logs (user_id, action, module_id, details) VALUES (?, ?, ?, ?)')
      .run(req.user.id, 'PROMOTE_PRODUCTION', id, `Promoted staging to production version ${version}`);

    res.json({ message: `Successfully promoted to production ${version}`, id, version });
  } catch(err) {
    res.status(500).json({ error: 'Promotion failed: ' + err.message });
  }
});

/**
 * ADMIN API: Activate / Rollback Version
 */
app.post('/api/admin/modules/:id/activate', authenticate('admin'), (req, res) => {
  const { id } = req.params;
  const { version } = req.body;
  
  if (!version) return res.status(400).json({ error: 'Version is required' });
  
  try {
    const v = db.prepare('SELECT * FROM versions WHERE module_id = ? AND version_number = ?').get(id, version);
    if (!v) return res.status(404).json({ error: 'Version not found in history' });
    
    db.prepare('UPDATE modules SET production_version = ? WHERE id = ?').run(version, id);
    
    db.prepare('INSERT INTO audit_logs (user_id, action, module_id, details) VALUES (?, ?, ?, ?)')
      .run(req.user.id, 'ROLLBACK_PRODUCTION', id, `Activated historical version ${version}`);

    res.json({ message: `Successfully activated ${version}`, id, version });
  } catch(err) {
    res.status(500).json({ error: 'Activation failed: ' + err.message });
  }
});

/**
 * ADMIN API: Upload Development Bundle (Cloud-Dev Sync)
 */
app.post('/api/admin/modules/:id/dev', authenticate('deployer'), upload.single('bundle'), (req, res) => {
  const { id } = req.params;
  
  if (!req.file) return res.status(400).json({ error: 'Missing bundle file' });

  try {
    const m = db.prepare('SELECT * FROM modules WHERE id = ?').get(id);
    if (!m) return res.status(404).json({ error: 'Module not found' });

    const devPath = path.join(CDN_DIR, id, 'dev');
    if (fs.existsSync(devPath)) fs.removeSync(devPath);
    fs.ensureDirSync(devPath);
    
    const zip = new AdmZip(req.file.path);
    zip.extractAllTo(devPath, true);
    fs.unlinkSync(req.file.path);
    
    // Update module record to reflect that there is a dev version
    db.prepare('UPDATE modules SET dev_version = ? WHERE id = ?').run('dev', id);

    res.json({ message: 'Dev bundle updated', id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process dev bundle: ' + err.message });
  }
});

/**
 * ADMIN API: Upload Bundle Version (Deploy)
 */
app.post('/api/admin/modules/:id/versions', authenticate('deployer'), upload.single('bundle'), (req, res) => {
  const { id } = req.params;
  const { version } = req.body;
  
  if (!req.file || !version) return res.status(400).json({ error: 'Missing bundle file or version' });

  try {
    const m = db.prepare('SELECT * FROM modules WHERE id = ?').get(id);
    if (!m) return res.status(404).json({ error: 'Module not found' });

    const extractPath = path.join(CDN_DIR, id, version);
    fs.ensureDirSync(extractPath);
    
    const zip = new AdmZip(req.file.path);
    zip.extractAllTo(extractPath, true);
    fs.unlinkSync(req.file.path);
    
    // Register version in DB
    db.prepare('INSERT OR IGNORE INTO versions (module_id, version_number) VALUES (?, ?)')
      .run(id, version);
    
    // Automatically set dev_version to the latest upload
    db.prepare('UPDATE modules SET dev_version = ? WHERE id = ?').run(version, id);

    db.prepare('INSERT INTO audit_logs (user_id, action, module_id, details) VALUES (?, ?, ?, ?)')
      .run(req.user.id, 'UPLOAD_VERSION', id, `Uploaded version ${version}`);

    res.json({ id, version, status: 'uploaded' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process bundle: ' + err.message });
  }
});

// ─── Profile API (all authenticated users) ───────────────────────────────────

/**
 * PUT /api/profile/password
 * Changes the current user's password. Requires current password confirmation.
 * Session-only (tokens cannot change passwords).
 */
app.put('/api/profile/password', authenticate(), sessionOnly, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'currentPassword and newPassword are required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!verifyPassword(currentPassword, user.password_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect.' });
  }

  // Password strength validation
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,}$/;
  if (!passwordRegex.test(newPassword)) {
    return res.status(400).json({
      error: 'Password must be at least 8 characters and include uppercase, lowercase, number, and symbol.'
    });
  }

  const { hashPassword } = require('./src/crypto');
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), user.id);

  db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .run(user.id, 'PASSWORD_CHANGE', 'User changed their own password');

  res.json({ message: 'Password updated successfully.' });
});

/**
 * POST /api/profile/token/regenerate
 * Generates a new API token for the current user.
 * Session-only.
 */
app.post('/api/profile/token/regenerate', authenticate(), sessionOnly, (req, res) => {
  const newToken = generateSessionToken();
  db.prepare('UPDATE users SET token = ? WHERE id = ?').run(newToken, req.user.id);

  db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .run(req.user.id, 'TOKEN_REGENERATED', 'User regenerated their API token');

  res.json({ token: newToken });
});

/**
 * GET /api/profile/token
 * Returns the current user's API token. Session-only.
 */
app.get('/api/profile/token', authenticate(), sessionOnly, (req, res) => {
  const user = db.prepare('SELECT token FROM users WHERE id = ?').get(req.user.id);
  res.json({ token: user.token });
});

// ─── Admin API (admin only) ───────────────────────────────────────────────────

/**
 * GET /api/admin/users
 * Lists all users with optional filtering.
 */
app.get('/api/admin/users', authenticate('admin'), sessionOnly, (req, res) => {
  const { search, role } = req.query;
  let query = 'SELECT id, username, role, created_at FROM users WHERE 1=1';
  const params = [];

  if (role) {
    query += ' AND role = ?';
    params.push(role);
  }
  if (search) {
    query += ' AND username LIKE ?';
    params.push(`%${search}%`);
  }

  query += ' ORDER BY created_at DESC';

  const users = db.prepare(query).all(...params);
  res.json(users);
});

/**
 * POST /api/admin/users
 * Creates a new user. Returns the generated password.
 */
app.post('/api/admin/users', authenticate('admin'), sessionOnly, (req, res) => {
  const { username, role } = req.body;
  if (!username || !role) return res.status(400).json({ error: 'username and role are required.' });
  if (!ROLE_RANK[role]) return res.status(400).json({ error: `Invalid role. Valid: admin, deployer, viewer` });

  const { hashPassword } = require('./src/crypto');
  // Generate a random initial password
  const tempPassword = require('crypto').randomBytes(8).toString('hex') + 'A1!';
  const apiToken = generateSessionToken();

  try {
    db.prepare('INSERT INTO users (username, password_hash, role, token) VALUES (?, ?, ?, ?)')
      .run(username, hashPassword(tempPassword), role, apiToken);

    db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
      .run(req.user.id, 'CREATE_USER', `Created user: ${username} (${role})`);

    res.status(201).json({ username, role, tempPassword });
  } catch (err) {
    res.status(400).json({ error: 'User creation failed: ' + err.message });
  }
});

/**
 * POST /api/admin/users/:id/reset-password
 * Resets a user's password. Returns the new generated password.
 */
app.post('/api/admin/users/:id/reset-password', authenticate('admin'), sessionOnly, (req, res) => {
  const { id } = req.params;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  const { hashPassword } = require('./src/crypto');
  const newPassword = require('crypto').randomBytes(8).toString('hex') + 'A1!';

  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), id);

  db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .run(req.user.id, 'PASSWORD_RESET', `Admin reset password for user: ${user.username}`);

  res.json({ newPassword });
});

/**
 * DELETE /api/admin/users/:id
 * Deletes a user.
 */
app.delete('/api/admin/users/:id', authenticate('admin'), sessionOnly, (req, res) => {
  const { id } = req.params;
  if (Number(id) === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account.' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id);

  db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .run(req.user.id, 'DELETE_USER', `Deleted user: ${user.username}`);

  res.status(204).end();
});

/**
 * PUT /api/admin/users/:id/role
 * Changes a user's role.
 */
app.put('/api/admin/users/:id/role', authenticate('admin'), sessionOnly, (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  if (!ROLE_RANK[role]) return res.status(400).json({ error: 'Invalid role.' });

  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);

  db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .run(req.user.id, 'CHANGE_ROLE', `Changed role of user ${id} to ${role}`);

  res.json({ message: 'Role updated.' });
});

/**
 * GET /api/admin/audit
 * Returns the audit log (paginated, with filtering).
 */
app.get('/api/admin/audit', authenticate('admin'), sessionOnly, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  const { action, startDate, endDate, username } = req.query;

  let query = `
    SELECT a.*, u.username
    FROM audit_logs a
    LEFT JOIN users u ON a.user_id = u.id
    WHERE 1=1
  `;
  const params = [];

  if (username) {
    query += ' AND u.username LIKE ?';
    params.push(`%${username}%`);
  }
  if (action) {
    query += ' AND a.action = ?';
    params.push(action);
  }
  if (startDate) {
    query += ' AND date(a.timestamp) >= date(?)';
    params.push(startDate);
  }
  if (endDate) {
    query += ' AND date(a.timestamp) <= date(?)';
    params.push(endDate);
  }

  query += ' ORDER BY a.timestamp DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const logs = db.prepare(query).all(...params);
  res.json(logs);
});

/**
 * GET /api/admin/errors
 * Returns system error logs.
 */
app.get('/api/admin/errors', authenticate('admin'), sessionOnly, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const logs = db.prepare('SELECT * FROM error_logs ORDER BY timestamp DESC LIMIT ?').all(limit);
  res.json(logs);
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[System Error]', err);
  try {
    db.prepare('INSERT INTO error_logs (message, stack, route) VALUES (?, ?, ?)')
      .run(err.message, err.stack, req.originalUrl);
  } catch (e) {
    console.error('Failed to write to error_logs', e);
  }
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(PORT, () => {
  console.log(`🚀 Simple CDN V2 running on http://localhost:${PORT}`);
});

