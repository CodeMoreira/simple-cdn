const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs-extra');

const DB_PATH = path.join(__dirname, 'registry.db');
const db = new Database(DB_PATH);

// Enable foreign key enforcement (SQLite has it OFF by default)
db.pragma('foreign_keys = ON');

// Initialize schema
db.exec(`
  -- ─── Users ──────────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT CHECK(role IN ('user', 'dev', 'moderator', 'release_manager', 'manager', 'master', 'owner')) NOT NULL DEFAULT 'user',
    target_environment TEXT CHECK(target_environment IN ('dev', 'staging', 'production')) NOT NULL DEFAULT 'production',
    token TEXT UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- ─── Groups ─────────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- ─── User <-> Group (N-to-N Junction) ───────────────────────────────────────
  CREATE TABLE IF NOT EXISTS user_groups (
    user_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
  );

  -- ─── Modules ────────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS modules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    visibility TEXT CHECK(visibility IN ('public', 'private')) NOT NULL DEFAULT 'public',
    dev_version TEXT,
    staging_version TEXT,
    production_version TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- ─── Module <-> Group (N-to-N Junction) ─────────────────────────────────────
  CREATE TABLE IF NOT EXISTS module_groups (
    module_id TEXT NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY (module_id, group_id),
    FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
  );

  -- ─── Versions ───────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_id TEXT NOT NULL,
    version_number TEXT NOT NULL,
    name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(module_id) REFERENCES modules(id) ON DELETE CASCADE,
    UNIQUE(module_id, version_number)
  );

  -- ─── Sessions ───────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- ─── Audit Logs ─────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    module_id TEXT,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
  );

  -- ─── Error Logs ─────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS error_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT NOT NULL,
    stack TEXT,
    route TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ─── Schema Migration (safe patches for existing databases) ─────────────────
// These try/catch blocks allow the schema to evolve without breaking existing installs.
try { db.exec('ALTER TABLE users ADD COLUMN target_environment TEXT DEFAULT \'production\''); } catch(e) {}
try { db.exec('ALTER TABLE modules ADD COLUMN visibility TEXT DEFAULT \'public\''); } catch(e) {}

// Normalize roles from older versions (V1) if necessary
try {
  db.prepare("UPDATE users SET role = 'master' WHERE role = 'admin'").run();
  db.prepare("UPDATE users SET role = 'release_manager' WHERE role = 'deployer'").run();
  db.prepare("UPDATE users SET role = 'user' WHERE role = 'viewer'").run();
} catch (e) {
  // Column or table might not exist yet, which is fine for a fresh install
}

module.exports = db;
