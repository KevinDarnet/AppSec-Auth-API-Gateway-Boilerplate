import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, comparePassword, timingSafeStringEqual, hashToken } from '../src/core/utils/crypto.js';
import { signAccessToken, verifyAccessToken } from '../src/core/utils/jwt.js';
import { sanitizeNoSqlPayload } from '../src/middlewares/sanitize.middleware.js';
import { registerSchema, loginSchema } from '../src/modules/auth/auth.validation.js';
import { createApp } from '../src/app.js';

describe('AppSec Core Security Test Suite', () => {
  describe('1. Cryptographic Password Hashing & Timing-Safe Helpers', () => {
    it('should hash passwords using bcrypt with at least 12 salt rounds', async () => {
      const password = 'SuperSecureP@ssw0rd123!';
      const hash = await hashPassword(password);

      // Verify bcrypt hash format: $2a$ or $2b$ followed by cost factor (12)
      assert.match(hash, /^\$2[ab]\$12\$/);

      const isValid = await comparePassword(password, hash);
      assert.strictEqual(isValid, true);

      const isInvalid = await comparePassword('WrongPassword!', hash);
      assert.strictEqual(isInvalid, false);
    });

    it('should compare strings in constant time without throwing on mismatching lengths', () => {
      const secret = 'ultra_secret_api_key_1234567890';
      const identical = 'ultra_secret_api_key_1234567890';
      const different = 'ultra_secret_api_key_1234567899';
      const short = 'short';

      assert.strictEqual(timingSafeStringEqual(secret, identical), true);
      assert.strictEqual(timingSafeStringEqual(secret, different), false);
      assert.strictEqual(timingSafeStringEqual(secret, short), false);
    });

    it('should generate consistent SHA-256 hashes for refresh token lookup', () => {
      const token = 'sample_raw_jwt_refresh_token_string';
      const hash1 = hashToken(token);
      const hash2 = hashToken(token);

      assert.strictEqual(hash1.length, 64);
      assert.strictEqual(hash1, hash2);
    });
  });

  describe('2. JWT Access Token Signing & Verification', () => {
    it('should sign and verify valid JWT access tokens with correct claims', () => {
      const payload = { userId: '507f1f77bcf86cd799439011', role: 'user' };
      const token = signAccessToken(payload);

      assert.ok(typeof token === 'string');

      const decoded = verifyAccessToken(token);
      assert.strictEqual(decoded.sub, payload.userId);
      assert.strictEqual(decoded.role, payload.role);
      assert.strictEqual(decoded.tokenType, 'access');
      assert.strictEqual(decoded.iss, 'appsec-gateway');
      assert.strictEqual(decoded.aud, 'appsec-api');
    });

    it('should reject tampered JWT access tokens', () => {
      const payload = { userId: '507f1f77bcf86cd799439011', role: 'user' };
      const token = signAccessToken(payload);
      const tamperedToken = token.slice(0, -5) + 'xxxxx';

      assert.throws(
        () => verifyAccessToken(tamperedToken),
        (err) => err.statusCode === 401 && err.errorCode === 'AUTH_TOKEN_INVALID'
      );
    });
  });

  describe('3. Deep NoSQL Injection Sanitization', () => {
    it('should neutralize malicious MongoDB query operators ($gt, $ne, $where) recursively', () => {
      const maliciousPayload = {
        username: 'admin',
        password: { $ne: null },
        filter: {
          $gt: '',
          nested: {
            $regex: '.*',
            safeValue: 'ok',
          },
        },
        'user.profile.isAdmin': true,
      };

      const clean = sanitizeNoSqlPayload(maliciousPayload);

      assert.deepStrictEqual(clean, {
        username: 'admin',
        password: {},
        filter: {
          nested: {
            safeValue: 'ok',
          },
        },
      });
      assert.strictEqual(clean.password.$ne, undefined);
      assert.strictEqual(clean['user.profile.isAdmin'], undefined);
    });
  });

  describe('4. Input Validation & Defense against Mass Assignment', () => {
    it('should enforce strict password complexity rules', () => {
      // Valid registration
      const valid = registerSchema.safeParse({
        email: 'dev@company.com',
        password: 'ValidP@ssword123!',
        fullName: 'Jane Doe',
      });
      assert.strictEqual(valid.success, true);

      // Weak password: missing special character
      const weak = registerSchema.safeParse({
        email: 'dev@company.com',
        password: 'Password123',
        fullName: 'Jane Doe',
      });
      assert.strictEqual(weak.success, false);

      // Mass assignment attempt (extra unrecognized field: role='admin')
      const massAssignment = registerSchema.safeParse({
        email: 'hacker@company.com',
        password: 'ValidP@ssword123!',
        fullName: 'Attacker',
        role: 'admin',
      });
      assert.strictEqual(massAssignment.success, false);
    });
  });

  describe('5. HTTP Security Headers (Defense in Depth via Helmet)', () => {
    it('should set strict security headers on all responses', async () => {
      const app = createApp();
      const server = app.listen(0);
      const port = server.address().port;

      try {
        const res = await fetch(`http://127.0.0.1:${port}/health/live`);
        assert.strictEqual(res.status, 200);

        // Security Header Assertions
        assert.strictEqual(res.headers.get('x-frame-options'), 'DENY');
        assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
        assert.strictEqual(res.headers.get('x-dns-prefetch-control'), 'off');
        assert.ok(res.headers.get('strict-transport-security')?.includes('max-age=31536000'));
        assert.strictEqual(res.headers.get('referrer-policy'), 'no-referrer');
        assert.strictEqual(res.headers.get('x-powered-by'), null); // Server signature suppressed
        assert.ok(res.headers.get('x-request-id') !== null); // Correlation ID present
      } finally {
        server.close();
      }
    });

    it('should reject unauthorized CORS origin with 403', async () => {
      const app = createApp();
      const server = app.listen(0);
      const port = server.address().port;

      try {
        const res = await fetch(`http://127.0.0.1:${port}/health/live`, {
          headers: {
            Origin: 'http://malicious-attacker-site.com',
          },
        });
        assert.strictEqual(res.status, 403);
      } finally {
        server.close();
      }
    });
  });
});
