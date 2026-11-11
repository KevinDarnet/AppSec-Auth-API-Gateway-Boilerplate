import mongoose from 'mongoose';
import { ApiResponse } from '../../core/utils/response.js';

export class HealthController {
  /**
   * Liveness Probe
   * Indicates if the server container process is alive.
   */
  static live(req, res) {
    return ApiResponse.success(res, { status: 'alive' }, 'Service is alive', 200);
  }

  /**
   * Readiness Probe
   * Indicates if the server is ready to accept production traffic (e.g., DB connected).
   */
  static ready(req, res) {
    const isDbConnected = mongoose.connection.readyState === 1;

    const healthStatus = {
      status: isDbConnected ? 'ready' : 'unhealthy',
      database: isDbConnected ? 'connected' : 'disconnected',
      uptimeSeconds: Math.floor(process.uptime()),
      memoryUsageMb: Math.round(process.memoryUsage().rss / 1024 / 1024),
    };

    if (!isDbConnected) {
      return ApiResponse.error(res, 'Database dependency unavailable', 503, 'SERVICE_UNAVAILABLE', healthStatus);
    }

    return ApiResponse.success(res, healthStatus, 'Service is ready to handle traffic', 200);
  }
}
