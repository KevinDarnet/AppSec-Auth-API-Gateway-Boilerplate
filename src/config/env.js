import dotenv from 'dotenv';

dotenv.config();

/**
 * Strict Environment Variable Schema and Configuration
 * Enforces Fail-Fast: Process terminates immediately if critical security variables are missing.
 */
class EnvironmentConfig {
  constructor() {
    this.NODE_ENV = process.env.NODE_ENV || 'development';
    this.PORT = parseInt(process.env.PORT || '4000', 10);
    this.HOST = process.env.HOST || '0.0.0.0';

    // Database
    this.MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/appsec_gateway_db';

    // Cryptography & Secrets
    this.BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);
    this.JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || '';
    this.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || '';
    this.JWT_ACCESS_EXPIRATION = process.env.JWT_ACCESS_EXPIRATION || '15m';
    this.JWT_REFRESH_EXPIRATION_DAYS = parseInt(process.env.JWT_REFRESH_EXPIRATION_DAYS || '7', 10);
    this.COOKIE_SECRET = process.env.COOKIE_SECRET || '';

    // API Gateway & Security
    this.GATEWAY_API_KEY = process.env.GATEWAY_API_KEY || '';
    this.CORS_ALLOWED_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost:5173')
      .split(',')
      .map((origin) => origin.trim())
      .filter(Boolean);

    // Rate Limiting
    this.RATE_LIMIT_GLOBAL_WINDOW_MS = parseInt(process.env.RATE_LIMIT_GLOBAL_WINDOW_MS || '900000', 10); // 15 mins
    this.RATE_LIMIT_GLOBAL_MAX = parseInt(process.env.RATE_LIMIT_GLOBAL_MAX || '100', 10);
    this.RATE_LIMIT_AUTH_WINDOW_MS = parseInt(process.env.RATE_LIMIT_AUTH_WINDOW_MS || '900000', 10); // 15 mins
    this.RATE_LIMIT_AUTH_MAX = parseInt(process.env.RATE_LIMIT_AUTH_MAX || '5', 10); // Strict brute-force prevention

    // Body parser limits
    this.BODY_LIMIT = process.env.BODY_LIMIT || '10kb';

    // Logging
    this.LOG_LEVEL = process.env.LOG_LEVEL || (this.NODE_ENV === 'production' ? 'info' : 'debug');

    this.validate();
  }

  validate() {
    const errors = [];

    if (this.BCRYPT_SALT_ROUNDS < 12) {
      errors.push('BCRYPT_SALT_ROUNDS must be >= 12 to ensure sufficient computational work factor.');
    }

    if (this.NODE_ENV === 'production') {
      if (!this.JWT_ACCESS_SECRET || this.JWT_ACCESS_SECRET.length < 32) {
        errors.push('JWT_ACCESS_SECRET is mandatory in production and must have at least 32 characters of high entropy.');
      }
      if (!this.JWT_REFRESH_SECRET || this.JWT_REFRESH_SECRET.length < 32) {
        errors.push('JWT_REFRESH_SECRET is mandatory in production and must have at least 32 characters of high entropy.');
      }
      if (!this.COOKIE_SECRET || this.COOKIE_SECRET.length < 32) {
        errors.push('COOKIE_SECRET is mandatory in production and must have at least 32 characters.');
      }
      if (!this.GATEWAY_API_KEY || this.GATEWAY_API_KEY.length < 32) {
        errors.push('GATEWAY_API_KEY is mandatory in production and must have at least 32 characters.');
      }
    } else {
      // In development/test, provide default fallbacks if missing to allow local testing
      if (!this.JWT_ACCESS_SECRET) {
        this.JWT_ACCESS_SECRET = 'dev_super_secret_jwt_access_key_min_32_chars_long!';
      }
      if (!this.JWT_REFRESH_SECRET) {
        this.JWT_REFRESH_SECRET = 'dev_super_secret_jwt_refresh_key_min_32_chars_long!';
      }
      if (!this.COOKIE_SECRET) {
        this.COOKIE_SECRET = 'dev_super_secret_cookie_signing_key_32_chars!';
      }
      if (!this.GATEWAY_API_KEY) {
        this.GATEWAY_API_KEY = 'dev_gateway_api_key_secure_baseline_token_123456';
      }
    }

    if (errors.length > 0) {
      console.error('\n❌ FATAL: Environment Configuration Security Validation Failed:');
      errors.forEach((err) => console.error(`  - ${err}`));
      console.error('\nServer initialization halted for security reasons.\n');
      process.exit(1);
    }
  }
}

export const env = new EnvironmentConfig();
