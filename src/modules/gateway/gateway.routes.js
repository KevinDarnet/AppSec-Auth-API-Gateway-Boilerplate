import { Router } from 'express';
import { GatewayController } from './gateway.controller.js';
import { validateApiKey } from '../../middlewares/apiKey.middleware.js';
import { authenticate } from '../../middlewares/auth.middleware.js';
import { requireRole } from '../../middlewares/rbac.middleware.js';
import { Roles } from '../../core/constants/roles.js';

const router = Router();

// Gateway Status: Accessible by Admin JWT or valid API Key
router.get('/status', validateApiKey, GatewayController.getStatus);

// Protected Service Route: Requires Valid API Key (Service-to-Service gateway communication)
router.all('/proxy/service-mock', validateApiKey, GatewayController.mockSecureProxy);

// Administrative Gateway Management: Admin JWT required
router.get('/admin/registry', authenticate, requireRole(Roles.ADMIN), GatewayController.getStatus);

export const gatewayRoutes = router;
