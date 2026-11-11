import bcrypt from 'bcrypt';
import crypto from 'node:crypto';
import { env } from '../../config/env.js';

/**
 * Hardened Cryptographic Utilities
 */

/**
 * Hash a plain-text password using bcrypt with a high work factor (>= 12)
 * Resilient against brute-force, dictionary, and rainbow table attacks.
 */
export async function hashPassword(plainPassword) {
  return bcrypt.hash(plainPassword, env.BCRYPT_SALT_ROUNDS);
}

/**
 * Verify a plain-text password against a stored bcrypt hash
 */
export async function comparePassword(plainPassword, hashedPassword) {
  if (!plainPassword || !hashedPassword) {
    return false;
  }
  return bcrypt.compare(plainPassword, hashedPassword);
}

/**
 * Cryptographic SHA-256 Hash for Refresh Tokens and API Keys
 * We NEVER store raw refresh tokens in the database.
 * If the database is compromised, an attacker cannot replay hashed tokens.
 */
export function hashToken(token) {
  if (!token) return '';
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Timing-Safe String Comparison to prevent Side-Channel Timing Attacks
 * Essential for comparing API keys, secret hashes, and HMACs.
 */
export function timingSafeStringEqual(strA, strB) {
  if (typeof strA !== 'string' || typeof strB !== 'string') {
    return false;
  }

  const bufA = Buffer.from(strA, 'utf8');
  const bufB = Buffer.from(strB, 'utf8');

  // Prevent timing leak on buffer length mismatch by performing constant-time comparison
  if (bufA.length !== bufB.length) {
    // Perform dummy comparison to keep constant execution time
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }

  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Cryptographically secure pseudo-random string generator
 */
export function generateSecureRandomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}
