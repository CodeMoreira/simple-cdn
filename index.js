const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs-extra');
const multer = require('multer');
const extract = require('extract-zip');
const { verifyPassword, generateSessionToken } = require('./src/crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Directory constants
const CDN_DIR = path.join(__dirname, 'cdn');
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

const db = require('./src/db');

// In-memory security threat tracking cache
const securityStats = {
  failedLogins: [], // Array of timestamps
  rateLimitBlocks: 0
};

// Clean expired sessions (> 24 hours old) on server startup
try {
  const deleted = db.prepare("DELETE FROM sessions WHERE created_at < datetime('now', '-1 day')").run().changes;
  if (deleted > 0) {
    console.log(`🧹 Cleaned up ${deleted} expired sessions on startup`);
  }
} catch (e) {
  console.error('Failed to clean expired sessions on startup:', e);
}


// Ensure directories exist
[CDN_DIR, PUBLIC_DIR, UPLOAD_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) {
    console.log(`📁 Creating directory: ${path.basename(dir)}`);
    fs.ensureDirSync(dir);
  }
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.tailwindcss.com", "https://unpkg.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"]
    }
  }
}));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));

const globalLimiter = rateLimit({ 
  windowMs: 15 * 60 * 1000, 
  max: 500, 
  message: { error: 'Too many requests' },
  handler: (req, res, next, options) => {
    securityStats.rateLimitBlocks++;
    res.status(options.statusCode).json(options.message);
  }
});
const authLimiter = rateLimit({ 
  windowMs: 15 * 60 * 1000, 
  max: 15, 
  skipSuccessfulRequests: true,
  handler: (req, res, next, options) => {
    securityStats.rateLimitBlocks++;
    res.status(options.statusCode).json({ error: 'Too many login attempts. Please try again later.' });
  }
});

app.use('/api', globalLimiter);
app.use('/auth', globalLimiter);
app.use(express.json());
app.use('/cdn', express.static(CDN_DIR));
app.use(express.static(PUBLIC_DIR));

const upload = multer({ 
  dest: UPLOAD_DIR,
  limits: { fileSize: 1024 * 1024 * 1024 } // 1GB max file size for giant bundles
});

/**
 * Role hierarchy: higher rank satisfies lower-rank requirements.
 * owner(7) > master(6) > manager(5) > release_manager(4) > moderator(3) > dev(2) > user(1)
 */
const ROLE_RANK = { owner: 7, master: 6, manager: 5, release_manager: 4, moderator: 3, dev: 2, user: 1 };

/**
 * Checks if a user role satisfies a minimum required role based on the hierarchy.
 * @param {string} userRole The role of the acting user.
 * @param {string} requiredRole The minimum role required for the operation.
 * @returns {boolean} True if permitted.
 */
const hasPermission = (userRole, requiredRole) => {
  if (!requiredRole) return true;
  return (ROLE_RANK[userRole] ?? 0) >= (ROLE_RANK[requiredRole] ?? 99);
};

/** Returns an array of group names for a given user ID. */
const getUserGroups = (userId) => {
  return db.prepare(
    'SELECT g.name FROM groups g JOIN user_groups ug ON g.id = ug.group_id WHERE ug.user_id = ?'
  ).all(userId).map(r => r.name);
};

/** Returns an array of group names required by a module. */
const getModuleGroups = (moduleId) => {
  return db.prepare(
    'SELECT g.name FROM groups g JOIN module_groups mg ON g.id = mg.group_id WHERE mg.module_id = ?'
  ).all(moduleId).map(r => r.name);
};

/** Checks if the acting user can manage (edit/delete/promote) the target user based on hierarchy. */
const canManageUser = (actorRole, targetRole) => {
  const actorRank = ROLE_RANK[actorRole] ?? 0;
  const targetRank = ROLE_RANK[targetRole] ?? 99;
  // Nobody can manage someone of equal or higher rank
  return actorRank > targetRank;
};

/** Returns the max role a given actor can assign to other users. */
const getMaxAssignableRole = (actorRole) => {
  const limits = {
    owner: 'master',
    master: 'manager',
    manager: 'moderator',
  };
  return limits[actorRole] || null;
};

/**
 * authenticate(requiredRole)
 * Dual-path: accepts either a web session token OR an API token (Bearer).
 */
const authenticate = (requiredRole) => (req, res, next) => {
  const sessionToken = req.cookies?.esad_cdn_session || req.headers['x-session-token'] || req.headers['authorization']?.split(' ')[1];

  if (!sessionToken) {
    return res.status(401).json({ error: 'Unauthorized: Missing credentials' });
  }

  // 1. Try session lookup (web login)
  const session = db.prepare(`
    SELECT s.token as session_token, u.* 
    FROM sessions s 
    JOIN users u ON s.user_id = u.id 
    WHERE s.token = ? AND s.created_at > datetime('now', '-1 day')
  `).get(sessionToken);

  if (session) {
    if (!hasPermission(session.role, requiredRole)) {
      return res.status(404).json({ error: 'Not found' });
    }
    session.groups = getUserGroups(session.id);
    req.user = session;
    req.authMethod = 'session';
    return next();
  }

  // 2. Try API token lookup (automated environments — deploy only)
  const user = db.prepare('SELECT * FROM users WHERE token = ?').get(sessionToken);
  if (user) {
    if (!hasPermission(user.role, requiredRole)) {
      return res.status(404).json({ error: 'Not found' });
    }
    user.groups = getUserGroups(user.id);
    req.user = user;
    req.authMethod = 'token';
    return next();
  }

  return res.status(401).json({ error: 'Unauthorized: Invalid credentials' });
};

/**
 * sessionOnly middleware — blocks API token access for sensitive operations.
 */
const sessionOnly = (req, res, next) => {
  if (req.authMethod === 'token') {
    return res.status(403).json({
      error: 'Forbidden: This operation requires web session authentication.'
    });
  }
  next();
};

/**
 * canUserSeeModule — checks if the user has group access to a module.
 * master/owner bypass group checks entirely.
 */
/**
 * Evaluates if a user has access to see/consume a module.
 * Master/Owner have absolute access. Public modules are visible to all.
 * Private modules require group membership.
 * @param {object} user User object with role and groups.
 * @param {object} moduleRow Module database row.
 * @returns {boolean}
 */
const canUserSeeModule = (user, moduleRow) => {
  if (['master', 'owner'].includes(user.role)) return true;
  if (moduleRow.visibility === 'public') return true;
  
  const moduleGroups = getModuleGroups(moduleRow.id);
  // If private and no groups assigned, it's effectively restricted to admins
  if (moduleGroups.length === 0) return false; 
  
  return user.groups.some(g => moduleGroups.includes(g));
};

/**
 * getEnvironmentUrl — returns the correct bundle URL based on user's target_environment.
 */
const getEnvironmentUrl = (host, module, userEnv) => {
  const envPriority = { production: ['production'], staging: ['staging', 'production'], dev: ['dev', 'staging', 'production'] };
  const allowed = envPriority[userEnv] || ['production'];
  for (const env of allowed) {
    const version = module[`${env}_version`];
    if (version) return `${host}/cdn/${module.id}/${version}/index.bundle`;
  }
  return null;
};

// ─── Auth Routes ──────────────────────────────────────────────────────────────

/**
 * POST /auth/login
 * Authenticates with username + password. Returns a session token.
 */
app.post('/auth/login', authLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !verifyPassword(password, user.password_hash)) {
    securityStats.failedLogins.push(Date.now());
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  const token = generateSessionToken();
  db.prepare('INSERT INTO sessions (user_id, token) VALUES (?, ?)').run(user.id, token);

  db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .run(user.id, 'LOGIN', `Web login from ${req.ip}`);

  res.cookie('esad_cdn_session', token, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  });

  const groups = getUserGroups(user.id);

  res.json({
    user: { id: user.id, username: user.username, role: user.role, target_environment: user.target_environment, groups },
    token
  });
});

/**
 * POST /auth/logout
 * Invalidates the current session token.
 */
app.post('/auth/logout', authenticate(), (req, res) => {
  if (req.authMethod === 'session') {
    const token = req.cookies?.esad_cdn_session || req.headers['authorization']?.split(' ')[1] || req.headers['x-session-token'];
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    res.clearCookie('esad_cdn_session');
  }
  res.json({ message: 'Signed out successfully.' });
});

/**
 * GET /auth/me
 * Returns the authenticated user's profile.
 */
app.get('/auth/me', authenticate(), (req, res) => {
  const { password_hash, token, session_token, ...safeUser } = req.user;
  res.json({ ...safeUser, authMethod: req.authMethod });
});

/** 
 * CONSUMER API: Get Active Modules
 * Requires valid AuthToken.
 */
app.get('/modules', authenticate(), (req, res) => {
  const host = `${req.protocol}://${req.get('host')}`;
  const modules = db.prepare('SELECT * FROM modules').all();
  const userEnv = req.user.target_environment || 'production';

  const result = [];
  for (const m of modules) {
    if (!canUserSeeModule(req.user, m)) continue;
    const url = getEnvironmentUrl(host, m, userEnv);
    if (!url) continue;
    result.push({ id: m.id, name: m.name, url });
  }

  res.json(result);
});

/** Admin: List all modules (with environment masking based on role) */
app.get('/api/admin/modules', authenticate('dev'), (req, res) => {
  const host = `${req.protocol}://${req.get('host')}`;
  const modules = db.prepare('SELECT * FROM modules').all();
  
  const result = [];
  for (const m of modules) {
    if (!canUserSeeModule(req.user, m)) continue;
    const devPath = path.join(CDN_DIR, m.id, 'dev', 'index.bundle');
    const hasDev = fs.existsSync(devPath);
    const versionsCount = db.prepare('SELECT count(*) as count FROM versions WHERE module_id = ?').get(m.id).count;
    const moduleGroups = getModuleGroups(m.id);

    // Environment masking: hide environments the user's role cannot see
    const userRank = ROLE_RANK[req.user.role] ?? 0;
    const masked = { ...m };
    if (userRank < ROLE_RANK['moderator']) { masked.staging_version = null; }
    if (userRank < ROLE_RANK['release_manager']) { masked.production_version = null; }

    result.push({
      ...masked,
      visibility: m.visibility,
      allowed_groups: moduleGroups,
      has_dev_bundle: hasDev,
      dev_url: hasDev ? `${host}/cdn/${m.id}/dev/index.bundle` : null,
      versions_count: versionsCount,
    });
  }
  res.json(result);
});

/**
 * ADMIN API: Create Module
 */
app.post('/api/admin/modules', authenticate('manager'), (req, res) => {
  const { id, name, description, visibility } = req.body;
  
  try {
    const stmt = db.prepare('INSERT INTO modules (id, name, description, visibility) VALUES (?, ?, ?, ?)');
    stmt.run(id, name, description, visibility || 'public');
    
    db.prepare('INSERT INTO audit_logs (user_id, action, module_id, details) VALUES (?, ?, ?, ?)')
      .run(req.user.id, 'CREATE_MODULE', id, `Created module ${name}`);

    res.status(201).json({ id, name, description, visibility: visibility || 'public' });
  } catch (err) {
    res.status(400).json({ error: 'Module creation failed: ' + err.message });
  }
});

/**
 * ADMIN API: Update Module Info
 */
app.put('/api/admin/modules/:id', authenticate('manager'), (req, res) => {
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
app.delete('/api/admin/modules/:id', authenticate('manager'), (req, res) => {
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
app.get('/api/admin/modules/:id/versions', authenticate('dev'), (req, res) => {
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
app.post('/api/admin/modules/:id/promote/staging', authenticate('moderator'), (req, res) => {
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
app.post('/api/admin/modules/:id/promote/production', authenticate('release_manager'), (req, res) => {
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
app.post('/api/admin/modules/:id/activate', authenticate('release_manager'), (req, res) => {
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
app.post('/api/admin/modules/:id/dev', authenticate('dev'), upload.single('bundle'), async (req, res) => {
  const { id } = req.params;
  
  if (!req.file) return res.status(400).json({ error: 'Missing bundle file' });

  try {
    const m = db.prepare('SELECT * FROM modules WHERE id = ?').get(id);
    if (!m) return res.status(404).json({ error: 'Module not found' });

    const devPath = path.join(CDN_DIR, id, 'dev');
    if (fs.existsSync(devPath)) fs.removeSync(devPath);
    fs.ensureDirSync(devPath);
    
    await extract(req.file.path, { dir: devPath });
    
    // Update module record to reflect that there is a dev version
    db.prepare('UPDATE modules SET dev_version = ? WHERE id = ?').run('dev', id);

    res.json({ message: 'Dev bundle updated', id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process dev bundle: ' + err.message });
  } finally {
    if (req.file && fs.existsSync(req.file.path)) {
      try { fs.unlinkSync(req.file.path); } catch(e) {}
    }
  }
});

/**
 * ADMIN API: Upload Bundle Version (Deploy)
 */
app.post('/api/admin/modules/:id/versions', authenticate('dev'), upload.single('bundle'), async (req, res) => {
  const { id } = req.params;
  const { version } = req.body;
  
  if (!req.file || !version) return res.status(400).json({ error: 'Missing bundle file or version' });

  try {
    const m = db.prepare('SELECT * FROM modules WHERE id = ?').get(id);
    if (!m) return res.status(404).json({ error: 'Module not found' });

    const extractPath = path.join(CDN_DIR, id, version);
    fs.ensureDirSync(extractPath);
    
    await extract(req.file.path, { dir: extractPath });
    
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
  } finally {
    if (req.file && fs.existsSync(req.file.path)) {
      try { fs.unlinkSync(req.file.path); } catch(e) {}
    }
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
 * manager+ can see users, but only those they can manage.
 */
app.get('/api/admin/users', authenticate('manager'), sessionOnly, (req, res) => {
  const { search, role } = req.query;
  let query = 'SELECT id, username, role, target_environment, created_at FROM users WHERE 1=1';
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

  let users = db.prepare(query).all(...params);

  // Attach groups to each user
  users = users.map(u => ({
    ...u,
    groups: getUserGroups(u.id)
  }));

  res.json(users);
});

/**
 * POST /api/admin/users
 * Creates a new user. Hierarchy enforced.
 */
app.post('/api/admin/users', authenticate('manager'), sessionOnly, (req, res) => {
  const { username, role, target_environment, group_ids } = req.body;
  if (!username || !role) return res.status(400).json({ error: 'username and role are required.' });
  if (!ROLE_RANK[role]) return res.status(400).json({ error: 'Invalid role.' });
  if (role === 'owner') return res.status(404).json({ error: 'Not found' });

  // Hierarchy: can only assign up to the limit
  const maxRole = getMaxAssignableRole(req.user.role);
  if (!maxRole || (ROLE_RANK[role] > ROLE_RANK[maxRole])) {
    return res.status(404).json({ error: 'Not found' });
  }

  const { hashPassword } = require('./src/crypto');
  const tempPassword = require('crypto').randomBytes(8).toString('hex') + 'A1!';
  const apiToken = generateSessionToken();

  try {
    const result = db.prepare('INSERT INTO users (username, password_hash, role, target_environment, token) VALUES (?, ?, ?, ?, ?)')
      .run(username, hashPassword(tempPassword), role, target_environment || 'production', apiToken);

    // Assign groups if provided
    if (group_ids && Array.isArray(group_ids)) {
      const insertGroup = db.prepare('INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)');
      for (const gid of group_ids) {
        insertGroup.run(result.lastInsertRowid, gid);
      }
    }

    db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
      .run(req.user.id, 'CREATE_USER', `Created user: ${username} (${role})`);

    res.status(201).json({ username, role, tempPassword });
  } catch (err) {
    res.status(400).json({ error: 'User creation failed: ' + err.message });
  }
});

/**
 * POST /api/admin/users/:id/reset-password
 * Resets a user's password. Hierarchy enforced.
 */
app.post('/api/admin/users/:id/reset-password', authenticate('manager'), sessionOnly, (req, res) => {
  const { id } = req.params;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  if (!canManageUser(req.user.role, user.role)) return res.status(404).json({ error: 'Not found' });

  const { hashPassword } = require('./src/crypto');
  const newPassword = require('crypto').randomBytes(8).toString('hex') + 'A1!';

  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), id);

  db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .run(req.user.id, 'PASSWORD_RESET', `Reset password for user: ${user.username}`);

  res.json({ newPassword });
});

/**
 * DELETE /api/admin/users/:id
 * Deletes a user. Hierarchy enforced.
 */
app.delete('/api/admin/users/:id', authenticate('manager'), sessionOnly, (req, res) => {
  const { id } = req.params;
  if (Number(id) === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account.' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  if (user.role === 'owner') return res.status(404).json({ error: 'Not found' });
  if (!canManageUser(req.user.role, user.role)) return res.status(404).json({ error: 'Not found' });

  db.prepare('DELETE FROM users WHERE id = ?').run(id);

  db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .run(req.user.id, 'DELETE_USER', `Deleted user: ${user.username}`);

  res.status(204).end();
});

/**
 * PUT /api/admin/users/:id/role
 * Changes a user's role. Hierarchy enforced.
 */
app.put('/api/admin/users/:id/role', authenticate('manager'), sessionOnly, (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  if (!ROLE_RANK[role]) return res.status(400).json({ error: 'Invalid role.' });
  if (role === 'owner') return res.status(404).json({ error: 'Not found' });

  const targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!targetUser) return res.status(404).json({ error: 'Not found' });
  if (!canManageUser(req.user.role, targetUser.role)) return res.status(404).json({ error: 'Not found' });

  // Can only assign up to the allowed limit
  const maxRole = getMaxAssignableRole(req.user.role);
  if (!maxRole || (ROLE_RANK[role] > ROLE_RANK[maxRole])) {
    return res.status(404).json({ error: 'Not found' });
  }

  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);

  db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .run(req.user.id, 'CHANGE_ROLE', `Changed role of user ${targetUser.username} to ${role}`);

  res.json({ message: 'Role updated.' });
});

/**
 * PUT /api/admin/users/:id/environment
 * Changes a user's target environment.
 */
app.put('/api/admin/users/:id/environment', authenticate('manager'), sessionOnly, (req, res) => {
  const { id } = req.params;
  const { target_environment } = req.body;
  if (!['dev', 'staging', 'production'].includes(target_environment)) {
    return res.status(400).json({ error: 'Invalid environment.' });
  }

  const targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!targetUser) return res.status(404).json({ error: 'Not found' });
  if (!canManageUser(req.user.role, targetUser.role)) return res.status(404).json({ error: 'Not found' });

  db.prepare('UPDATE users SET target_environment = ? WHERE id = ?').run(target_environment, id);

  db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .run(req.user.id, 'CHANGE_ENVIRONMENT', `Changed environment of user ${targetUser.username} to ${target_environment}`);

  res.json({ message: 'Environment updated.' });
});

/**
 * PUT /api/admin/users/:id/groups
 * Replaces all groups for a user. Master/Owner cannot have groups assigned.
 */
app.put('/api/admin/users/:id/groups', authenticate('manager'), sessionOnly, (req, res) => {
  const { id } = req.params;
  const { group_ids } = req.body;
  if (!Array.isArray(group_ids)) return res.status(400).json({ error: 'group_ids must be an array.' });

  const targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!targetUser) return res.status(404).json({ error: 'Not found' });
  if (!canManageUser(req.user.role, targetUser.role)) return res.status(404).json({ error: 'Not found' });
  if (['master', 'owner'].includes(targetUser.role)) {
    return res.status(400).json({ error: 'Master and Owner users cannot be assigned to groups.' });
  }

  // Replace all group assignments
  db.prepare('DELETE FROM user_groups WHERE user_id = ?').run(id);
  const insert = db.prepare('INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)');
  for (const gid of group_ids) {
    insert.run(id, gid);
  }

  db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .run(req.user.id, 'CHANGE_GROUPS', `Updated groups for user ${targetUser.username}`);

  res.json({ message: 'Groups updated.', groups: getUserGroups(Number(id)) });
});

/**
 * GET /api/admin/health
 * Returns CDN system telemetry (database status, user count, active sessions, disk space).
 */
app.get('/api/admin/health', authenticate('manager'), sessionOnly, (req, res) => {
  try {
    const userCount = db.prepare('SELECT count(*) as count FROM users').get().count;
    
    // Only count unique users with active sessions in the last 24 hours
    const activeUsers = db.prepare(`
      SELECT count(DISTINCT user_id) as count 
      FROM sessions 
      WHERE created_at > datetime('now', '-1 day')
    `).get().count;
    
    // Count critical security actions in the last 24 hours
    const criticalOps = db.prepare(`
      SELECT count(*) as count 
      FROM audit_logs 
      WHERE action IN ('CREATE_USER', 'DELETE_USER', 'CHANGE_ROLE', 'CHANGE_GROUPS', 'PASSWORD_RESET', 'TOKEN_REGENERATED') 
        AND timestamp > datetime('now', '-1 day')
    `).get().count;

    // Filter out failed logins older than 24 hours
    const now = Date.now();
    securityStats.failedLogins = securityStats.failedLogins.filter(t => now - t < 24 * 60 * 60 * 1000);
    const failedLogins24h = securityStats.failedLogins.length;

    let cdnSize = 0;
    const walkDir = (dir) => {
      if (!fs.existsSync(dir)) return;
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const filePath = path.join(dir, file);
        const stat = fs.statSync(filePath);
        if (stat.isDirectory()) {
          walkDir(filePath);
        } else {
          cdnSize += stat.size;
        }
      }
    };
    walkDir(CDN_DIR);

    // Get real V8 memory metrics
    const v8 = require('v8');
    const mem = process.memoryUsage();
    const heapLimit = v8.getHeapStatistics().heap_size_limit;

    res.json({
      dbStatus: 'online',
      activeUsers,
      cdnSize,
      userCount,
      uptime: process.uptime(),
      memory: {
        heapUsed: mem.heapUsed,
        heapTotal: mem.heapTotal,
        heapLimit
      },
      securityMetrics: {
        failedLogins24h,
        rateLimitBlocks24h: securityStats.rateLimitBlocks,
        criticalOps24h: criticalOps
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch health status: ' + err.message });
  }
});

/**
 * GET /api/admin/audit
 * Returns the audit log (paginated, with filtering).
 */
app.get('/api/admin/audit', authenticate('manager'), sessionOnly, (req, res) => {
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
app.get('/api/admin/errors', authenticate('master'), sessionOnly, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const logs = db.prepare('SELECT * FROM error_logs ORDER BY timestamp DESC LIMIT ?').all(limit);
  res.json(logs);
});

// ─── Group Management API ─────────────────────────────────────────────────────

/** GET /api/admin/groups — List all groups */
app.get('/api/admin/groups', authenticate('manager'), sessionOnly, (req, res) => {
  const groups = db.prepare('SELECT * FROM groups ORDER BY name ASC').all();
  res.json(groups);
});

/** POST /api/admin/groups — Create a new group */
app.post('/api/admin/groups', authenticate('manager'), sessionOnly, (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Group name is required.' });

  try {
    db.prepare('INSERT INTO groups (name, description) VALUES (?, ?)').run(name, description || null);
    db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
      .run(req.user.id, 'CREATE_GROUP', `Created group: ${name}`);
    res.status(201).json({ name, description });
  } catch (err) {
    res.status(400).json({ error: 'Group creation failed: ' + err.message });
  }
});

/** DELETE /api/admin/groups/:id — Delete a group (CASCADE cleans junctions) */
app.delete('/api/admin/groups/:id', authenticate('manager'), sessionOnly, (req, res) => {
  const { id } = req.params;
  const group = db.prepare('SELECT * FROM groups WHERE id = ?').get(id);
  if (!group) return res.status(404).json({ error: 'Not found' });

  db.prepare('DELETE FROM groups WHERE id = ?').run(id);
  db.prepare('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)')
    .run(req.user.id, 'DELETE_GROUP', `Deleted group: ${group.name}`);
  res.status(204).end();
});

// ─── Module-Group Assignment API ──────────────────────────────────────────────

/** PUT /api/admin/modules/:id/groups — Set allowed groups for a private module */
app.put('/api/admin/modules/:id/groups', authenticate('manager'), sessionOnly, (req, res) => {
  const { id } = req.params;
  const { group_ids } = req.body;
  if (!Array.isArray(group_ids)) return res.status(400).json({ error: 'group_ids must be an array.' });

  const module = db.prepare('SELECT * FROM modules WHERE id = ?').get(id);
  if (!module) return res.status(404).json({ error: 'Not found' });

  db.prepare('DELETE FROM module_groups WHERE module_id = ?').run(id);
  const insert = db.prepare('INSERT INTO module_groups (module_id, group_id) VALUES (?, ?)');
  for (const gid of group_ids) {
    insert.run(id, gid);
  }

  db.prepare('INSERT INTO audit_logs (user_id, action, module_id, details) VALUES (?, ?, ?, ?)')
    .run(req.user.id, 'UPDATE_MODULE_GROUPS', id, `Updated allowed groups for module ${id}`);

  res.json({ message: 'Module groups updated.', groups: getModuleGroups(id) });
});

/** PUT /api/admin/modules/:id/visibility — Toggle module visibility */
app.put('/api/admin/modules/:id/visibility', authenticate('manager'), sessionOnly, (req, res) => {
  const { id } = req.params;
  const { visibility } = req.body;
  if (!['public', 'private'].includes(visibility)) return res.status(400).json({ error: 'Invalid visibility.' });

  const module = db.prepare('SELECT * FROM modules WHERE id = ?').get(id);
  if (!module) return res.status(404).json({ error: 'Not found' });

  db.prepare('UPDATE modules SET visibility = ? WHERE id = ?').run(visibility, id);
  db.prepare('INSERT INTO audit_logs (user_id, action, module_id, details) VALUES (?, ?, ?, ?)')
    .run(req.user.id, 'CHANGE_VISIBILITY', id, `Changed visibility of module ${id} to ${visibility}`);

  res.json({ message: 'Visibility updated.' });
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

