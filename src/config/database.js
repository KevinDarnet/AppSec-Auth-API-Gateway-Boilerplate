import mongoose from 'mongoose';
import { env } from './env.js';
import { logger } from './logger.js';

/**
 * Hardened MongoDB Connection Setup using Mongoose
 * - Strict query enforcement prevents unintended query casting
 * - Connection pooling optimized for high-throughput and resilience
 * - Auto-indexing controlled per environment
 */
export async function connectDatabase() {
  mongoose.set('strictQuery', true);

  const mongooseOptions = {
    maxPoolSize: 50,
    minPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    autoIndex: env.NODE_ENV !== 'production', // Prevent index building overhead/locks in production
  };

  try {
    const conn = await mongoose.connect(env.MONGODB_URI, mongooseOptions);
    logger.info(`MongoDB connected successfully to host: ${conn.connection.host}`);
  } catch (error) {
    logger.error('Failed to establish initial MongoDB connection', { error: error.message });
    throw error;
  }

  mongoose.connection.on('error', (err) => {
    logger.error('MongoDB runtime connection error', { error: err.message });
  });

  mongoose.connection.on('disconnected', () => {
    logger.warn('MongoDB disconnected from database host');
  });

  mongoose.connection.on('reconnected', () => {
    logger.info('MongoDB reconnected to database host');
  });
}

export async function disconnectDatabase() {
  try {
    await mongoose.connection.close(false);
    logger.info('MongoDB connection closed cleanly');
  } catch (error) {
    logger.error('Error during MongoDB disconnect', { error: error.message });
  }
}
