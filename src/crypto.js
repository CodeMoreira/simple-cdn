const crypto = require('crypto');

const SALT_LENGTH = 16;
const KEY_LENGTH = 64;
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

/**
 * Hashes a plain-text password using scrypt.
 * Returns a string in the format: salt:hash (both hex-encoded)
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(SALT_LENGTH).toString('hex');
  const hash = crypto
    .scryptSync(password, salt, KEY_LENGTH, SCRYPT_PARAMS)
    .toString('hex');
  return `${salt}:${hash}`;
}

/**
 * Verifies a plain-text password against a stored hash string.
 */
function verifyPassword(password, stored) {
  const [salt, expectedHash] = stored.split(':');
  if (!salt || !expectedHash) return false;
  const hash = crypto
    .scryptSync(password, salt, KEY_LENGTH, SCRYPT_PARAMS)
    .toString('hex');
  // Constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(hash, 'hex'),
    Buffer.from(expectedHash, 'hex')
  );
}

/**
 * Generates a cryptographically secure random session token.
 */
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = { hashPassword, verifyPassword, generateSessionToken };
