const crypto = require('crypto');
const db = require('./src/db');
const { hashPassword, generateSessionToken } = require('./src/crypto');

// Clear in FK-safe order: junction tables first, then children, then parents
db.prepare('DELETE FROM error_logs').run();
db.prepare('DELETE FROM audit_logs').run();
db.prepare('DELETE FROM sessions').run();
db.prepare('DELETE FROM module_groups').run();
db.prepare('DELETE FROM user_groups').run();
db.prepare('DELETE FROM versions').run();
db.prepare('DELETE FROM modules').run();
db.prepare('DELETE FROM groups').run();
db.prepare('DELETE FROM users').run();

// ─── Users ────────────────────────────────────────────────────────────────────
const ownerPass = 'Owner@12345!';
const masterPass = 'Master@12345!';
const managerPass = 'Manager@12345!';
const releasePass = 'Release@12345!';
const modPass = 'Moderator@12345!';
const devPass = 'Dev@12345!';
const userPass = 'User@12345!';

const ownerToken = generateSessionToken();
const masterToken = generateSessionToken();
const managerToken = generateSessionToken();
const releaseToken = generateSessionToken();
const modToken = generateSessionToken();
const devToken = generateSessionToken();
const userToken = generateSessionToken();

// Owner (ID: 1) — unique, cannot be promoted to or demoted from
db.prepare('INSERT INTO users (username, password_hash, role, target_environment, token) VALUES (?, ?, ?, ?, ?)')
  .run('owner', hashPassword(ownerPass), 'owner', 'production', ownerToken);

// Master — can do everything except modify owner/other masters
db.prepare('INSERT INTO users (username, password_hash, role, target_environment, token) VALUES (?, ?, ?, ?, ?)')
  .run('master_user', hashPassword(masterPass), 'master', 'production', masterToken);

// Manager — manages users and groups, promotes up to moderator
db.prepare('INSERT INTO users (username, password_hash, role, target_environment, token) VALUES (?, ?, ?, ?, ?)')
  .run('manager_user', hashPassword(managerPass), 'manager', 'production', managerToken);

// Release Manager — can promote to production and change active version
db.prepare('INSERT INTO users (username, password_hash, role, target_environment, token) VALUES (?, ?, ?, ?, ?)')
  .run('release_user', hashPassword(releasePass), 'release_manager', 'production', releaseToken);

// Moderator — can promote to staging but not production
db.prepare('INSERT INTO users (username, password_hash, role, target_environment, token) VALUES (?, ?, ?, ?, ?)')
  .run('mod_user', hashPassword(modPass), 'moderator', 'staging', modToken);

// Dev — can deploy to dev only
db.prepare('INSERT INTO users (username, password_hash, role, target_environment, token) VALUES (?, ?, ?, ?, ?)')
  .run('dev_user', hashPassword(devPass), 'dev', 'dev', devToken);

// User — read-only consumer
db.prepare('INSERT INTO users (username, password_hash, role, target_environment, token) VALUES (?, ?, ?, ?, ?)')
  .run('app_user', hashPassword(userPass), 'user', 'production', userToken);

// ─── Groups ───────────────────────────────────────────────────────────────────
db.prepare('INSERT INTO groups (name, description) VALUES (?, ?)').run('finance', 'Financial modules and dashboards');
db.prepare('INSERT INTO groups (name, description) VALUES (?, ?)').run('hr', 'Human Resources modules');
db.prepare('INSERT INTO groups (name, description) VALUES (?, ?)').run('logistics', 'Logistics and delivery tracking');

// ─── User <-> Group Assignments ───────────────────────────────────────────────
// Manager, Release Manager, Moderator, Dev and User get assigned to groups
// Master and Owner do NOT get groups (they see everything)
const managerUserId = db.prepare('SELECT id FROM users WHERE username = ?').get('manager_user').id;
const releaseUserId = db.prepare('SELECT id FROM users WHERE username = ?').get('release_user').id;
const modUserId = db.prepare('SELECT id FROM users WHERE username = ?').get('mod_user').id;
const devUserId = db.prepare('SELECT id FROM users WHERE username = ?').get('dev_user').id;
const appUserId = db.prepare('SELECT id FROM users WHERE username = ?').get('app_user').id;

const financeGroupId = db.prepare('SELECT id FROM groups WHERE name = ?').get('finance').id;
const hrGroupId = db.prepare('SELECT id FROM groups WHERE name = ?').get('hr').id;
const logisticsGroupId = db.prepare('SELECT id FROM groups WHERE name = ?').get('logistics').id;

// Manager sees finance and hr
db.prepare('INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)').run(managerUserId, financeGroupId);
db.prepare('INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)').run(managerUserId, hrGroupId);

// Release Manager sees finance
db.prepare('INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)').run(releaseUserId, financeGroupId);

// Moderator sees logistics
db.prepare('INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)').run(modUserId, logisticsGroupId);

// Dev sees logistics
db.prepare('INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)').run(devUserId, logisticsGroupId);

// App user sees finance
db.prepare('INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)').run(appUserId, financeGroupId);

console.log('✅ Database seeded!');
console.log('\n👤 Web Login Credentials:');
console.log('   Owner            — username: owner          | password:', ownerPass);
console.log('   Master           — username: master_user    | password:', masterPass);
console.log('   Manager          — username: manager_user   | password:', managerPass);
console.log('   Release Manager  — username: release_user   | password:', releasePass);
console.log('   Moderator        — username: mod_user       | password:', modPass);
console.log('   Dev              — username: dev_user       | password:', devPass);
console.log('   User             — username: app_user       | password:', userPass);
console.log('\n🤖 API Tokens (automated environments / CLI only):');
console.log('   Owner Token          :', ownerToken);
console.log('   Master Token         :', masterToken);
console.log('   Manager Token        :', managerToken);
console.log('   Release Manager Token:', releaseToken);
console.log('   Moderator Token      :', modToken);
console.log('   Dev Token            :', devToken);
console.log('   User Token           :', userToken);
console.log('\n⚠️  Change default passwords after first login!');
