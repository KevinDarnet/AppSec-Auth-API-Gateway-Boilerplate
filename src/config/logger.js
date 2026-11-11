import winston from 'winston';
import { env } from './env.js';

// Keys that must always be redacted to prevent sensitive data leakage in logs
const SENSITIVE_KEYS = new Set([
  'password',
  'passwordconfirmation',
  'confirmpassword',
  'oldpassword',
  'newpassword',
  'token',
  'accesstoken',
  'refreshtoken',
  'authorization',
  'cookie',
  'set-cookie',
  'apikey',
  'x-api-key',
  'secret',
  'creditcard',
  'cvv',
  'ssn',
]);

/**
 * Deep in-place redaction function to sanitize log metadata while preserving Winston Symbols
 */
function redactInPlace(obj, depth = 0) {
  if (depth > 6 || obj === null || typeof obj !== 'object') {
    return obj;
  }

  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      if (typeof obj[i] === 'object' && obj[i] !== null) {
        redactInPlace(obj[i], depth + 1);
      }
    }
    return obj;
  }

  for (const key of Object.keys(obj)) {
    const normalizedKey = key.toLowerCase().replace(/[-_]/g, '');
    if (SENSITIVE_KEYS.has(normalizedKey)) {
      obj[key] = '[REDACTED_SENSITIVE]';
    } else if (typeof obj[key] === 'object' && obj[key] !== null) {
      redactInPlace(obj[key], depth + 1);
    }
  }
  return obj;
}

// Winston custom format for scrubbing sensitive data
const scrubSensitiveData = winston.format((info) => {
  redactInPlace(info);
  return info;
});

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
  winston.format.errors({ stack: true }),
  scrubSensitiveData(),
  env.NODE_ENV === 'production'
    ? winston.format.json()
    : winston.format.printf(({ timestamp, level, message, stack, ...meta }) => {
        const metaStr = Object.keys(meta).length ? `\n${JSON.stringify(meta, null, 2)}` : '';
        const stackStr = stack ? `\n${stack}` : '';
        return `[${timestamp}] [${level.toUpperCase()}]: ${message}${metaStr}${stackStr}`;
      })
);

export const logger = winston.createLogger({
  level: env.LOG_LEVEL,
  defaultMeta: { service: 'appsec-auth-gateway' },
  format: logFormat,
  transports: [
    new winston.transports.Console({
      silent: env.NODE_ENV === 'test',
    }),
  ],
});
