import cors from 'cors';
import { env } from './env.js';

/**
 * Strict Cross-Origin Resource Sharing (CORS) Configuration
 *
 * Security Rules:
 * 1. No wildcard `*` with credentials (OWASP A01 / A05 mitigation).
 * 2. Origin validation strictly matching a configurable whitelist.
 * 3. Restricts allowed HTTP methods and request headers.
 * 4. Exposes only safe correlation headers (e.g. X-Request-Id, Retry-After).
 */
export const corsOptions = {
  origin: (origin, callback) => {
    // Allow non-browser requests (e.g. cURL, Postman, internal server-to-server) without Origin header
    if (!origin) {
      return callback(null, true);
    }

    // Verify if origin is explicitly present in the whitelist
    const isAllowed = env.CORS_ALLOWED_ORIGINS.includes(origin);

    if (isAllowed) {
      return callback(null, true);
    }

    // Explicit rejection for unauthorized origins
    const corsError = new Error(`CORS blocked: Origin '${origin}' is not authorized by security policy.`);
    corsError.statusCode = 403;
    corsError.isOperational = true;
    return callback(corsError, false);
  },

  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Request-Id',
    'X-API-Key',
    'Accept',
    'Origin',
  ],
  exposedHeaders: ['X-Request-Id', 'Retry-After'],
  credentials: true, // Allow transmitting HttpOnly cookies & authorization tokens
  maxAge: 86400, // Cache preflight response for 24 hours (reduces browser OPTIONS chatter)
  optionsSuccessStatus: 204,
};

export const corsConfig = cors(corsOptions);
