import { ApiResponse } from '../../core/utils/response.js';

export class GatewayController {
  /**
   * Gateway Info & Registered Upstream Services Status
   * GET /api/v1/gateway/status
   */
  static getStatus(req, res) {
    const upstreamServices = [
      { id: 'auth-service', name: 'Identity & Authentication', status: 'healthy', routePrefix: '/api/v1/auth' },
      { id: 'user-service', name: 'User Management & RBAC', status: 'healthy', routePrefix: '/api/v1/users' },
      { id: 'payment-service', name: 'PCI-DSS Payment Enclave', status: 'isolated', routePrefix: '/api/v1/gateway/payments' },
    ];

    return ApiResponse.success(res, {
      gateway: 'AppSec Hardened API Gateway',
      environment: process.env.NODE_ENV,
      authenticated: !!req.isGatewayAuthenticated,
      upstreamServices,
    }, 'Gateway status and upstream route registry');
  }

  /**
   * Mock Downstream Protected Endpoint
   * Used to verify API Key enforcement and gateway forwarding
   */
  static mockSecureProxy(req, res) {
    return ApiResponse.success(res, {
      routedService: 'Mock Downstream Protected Service',
      forwardedHeaders: {
        requestId: req.id,
        authenticatedVia: req.isGatewayAuthenticated ? 'API_KEY' : 'JWT',
      },
      payloadReceived: req.body || null,
    }, 'Gateway proxy request processed successfully');
  }
}
