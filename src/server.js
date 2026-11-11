import { env } from './config/env.js';
import { logger } from './config/logger.js';
import { connectDatabase, disconnectDatabase } from './config/database.js';
import { createApp } from './app.js';

async function bootstrap() {
  logger.info('Initializing AppSec Auth & API Gateway Server...', {
    environment: env.NODE_ENV,
    port: env.PORT,
  });

  // Connect to Database
  try {
    await connectDatabase();
  } catch (error) {
    logger.error('❌ Database bootstrap connection failed. Exiting process (Fail-Fast mode active).', {
      error: error.message,
      uri: env.MONGODB_URI.replace(/\/\/([^:]+):([^@]+)@/, '//$1:[REDACTED]@'),
      hint: 'Ensure MongoDB is running locally (e.g. "systemctl start mongod" or "docker compose up mongodb") or update MONGODB_URI in your .env file.',
    });
    // Allow stdout/stderr buffers to flush before process exit
    setTimeout(() => process.exit(1), 100);
    return;
  }

  const app = createApp();

  const server = app.listen(env.PORT, env.HOST, () => {
    logger.info(`🚀 Security Hardened Server running securely at http://${env.HOST}:${env.PORT}`);
  });

  // Keep-alive timeout hardening (prevents keep-alive race conditions with load balancers)
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 66000;

  // Graceful Shutdown Handler
  let isShuttingDown = false;

  async function handleGracefulShutdown(signal) {
    if (isShuttingDown) return;
    isShuttingDown = true;

    logger.info(`Received ${signal}. Initiating graceful shutdown...`);

    // Force terminate after 15 seconds if graceful close takes too long
    const forceExitTimeout = setTimeout(() => {
      logger.error('Graceful shutdown timed out. Forcing process termination.');
      process.exit(1);
    }, 15000);
    forceExitTimeout.unref();

    server.close(async () => {
      logger.info('HTTP server closed. In-flight requests completed.');
      try {
        await disconnectDatabase();
        logger.info('Database connection closed cleanly. Goodbye!');
        process.exit(0);
      } catch (err) {
        logger.error('Error during database disconnection', { error: err.message });
        process.exit(1);
      }
    });
  }

  process.on('SIGTERM', () => handleGracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => handleGracefulShutdown('SIGINT'));

  // Defensive Process-Level Exception Handling
  process.on('uncaughtException', (error) => {
    logger.error('FATAL: Uncaught Exception detected in Node runtime', {
      error: error.message,
      stack: error.stack,
    });
    // Exit immediately to avoid running in an undetermined/corrupted state
    process.exit(1);
  });

  process.on('unhandledRejection', (reason) => {
    logger.error('FATAL: Unhandled Promise Rejection detected', {
      reason: reason instanceof Error ? reason.message : reason,
      stack: reason instanceof Error ? reason.stack : undefined,
    });
    process.exit(1);
  });
}

bootstrap();
