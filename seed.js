const crypto = require('crypto');
const db = require('./src/db');
const { hashPassword, generateSessionToken } = require('./src/crypto');

// Clear in FK-safe order: children first, then parent
db.prepare('DELETE FROM error_logs').run();
db.prepare('DELETE FROM audit_logs').run();
db.prepare('DELETE FROM sessions').run();
db.prepare('DELETE FROM users').run();

// Passwords are hashed with scrypt (see src/crypto.js)
const adminPass = 'Admin@12345!';
const deployerPass = 'Deploy@12345!';

// API tokens for automated environments (CI/CD, CLI) — deploy-only by design
const adminToken = generateSessionToken();
const deployerToken = generateSessionToken();

db.prepare('INSERT INTO users (username, password_hash, role, token) VALUES (?, ?, ?, ?)')
  .run('admin', hashPassword(adminPass), 'admin', adminToken);

db.prepare('INSERT INTO users (username, password_hash, role, token) VALUES (?, ?, ?, ?)')
  .run('dev_user', hashPassword(deployerPass), 'deployer', deployerToken);

console.log('✅ Database seeded!');
console.log('\n👤 Web Login Credentials:');
console.log('   Admin    — username: admin     | password:', adminPass);
console.log('   Deployer — username: dev_user  | password:', deployerPass);
console.log('\n🤖 API Tokens (automated environments / CLI only):');
console.log('   Admin Token   :', adminToken);
console.log('   Deployer Token:', deployerToken);
console.log('\n⚠️  Change default passwords after first login!');
