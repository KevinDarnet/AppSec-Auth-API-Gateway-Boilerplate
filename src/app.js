import express from 'express';
import cookieParser from 'cookie-parser';
import { env } from './config/env.js';
import { helmetConfig } from './config/helmet.js';
import { corsConfig } from './config/cors.js';
import { requestIdMiddleware } from './middlewares/requestId.middleware.js';
import { requestTimeout } from './middlewares/timeout.middleware.js';
import { noSqlSanitizerMiddleware, hppProtection } from './middlewares/sanitize.middleware.js';
import { globalRateLimiter } from './middlewares/rateLimiter.middleware.js';
import { errorHandlerMiddleware, notFoundMiddleware } from './middlewares/error.middleware.js';

// Route Handlers
import { authRoutes } from './modules/auth/auth.routes.js';
import { userRoutes } from './modules/user/user.routes.js';
import { gatewayRoutes } from './modules/gateway/gateway.routes.js';
import { healthRoutes } from './modules/health/health.routes.js';

export function createApp() {
  const app = express();

  // 1. Disable server fingerprinting
  app.disable('x-powered-by');

  // 2. Trust proxy configuration (Essential when behind reverse proxies e.g. Cloudflare, AWS ALB, Nginx)
  app.set('trust proxy', 1);

  // 3. Correlation Tracking Middleware (Assigns/Validates X-Request-Id)
  app.use(requestIdMiddleware);

  // 4. Hardened Security Headers via Helmet
  app.use(helmetConfig);

  // 5. Strict Cross-Origin Resource Sharing (CORS)
  app.use(corsConfig);

  // 6. Request Timeout (Mitigates Slowloris and connection exhaustion attacks)
  app.use(requestTimeout(30000));

  // 7. Controlled Body Parsers (Mitigates Large Payload Memory-Exhaustion DoS)
  app.use(express.json({ limit: env.BODY_LIMIT }));
  app.use(express.urlencoded({ extended: true, limit: env.BODY_LIMIT }));

  // 8. Secure Cookie Parser
  app.use(cookieParser(env.COOKIE_SECRET));

  // 9. Input Sanitization: Deep NoSQL Injection Protection
  app.use(noSqlSanitizerMiddleware);

  // 10. HTTP Parameter Pollution Protection
  app.use(hppProtection);

  // 11. Health & Observability Probes (Bypasses rate limiting for infrastructure monitors)
  app.use('/health', healthRoutes);

  // 12. Global Volumetric Rate Limiter for all API routes
  app.use('/api', globalRateLimiter);

  // 13. API Route Modules
  app.use('/api/v1/auth', authRoutes);
  app.use('/api/v1/users', userRoutes);
  app.use('/api/v1/gateway', gatewayRoutes);

  // 14. 404 Handler for Unmapped Endpoints
  app.use(notFoundMiddleware);

  // 15. Centralized Error Handler (Hardened against Information Disclosure)
  app.use(errorHandlerMiddleware);

  return app;
}
