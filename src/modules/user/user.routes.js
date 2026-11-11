import { Router } from 'express';
import { UserController } from './user.controller.js';
import { authenticate } from '../../middlewares/auth.middleware.js';
import { requireRole } from '../../middlewares/rbac.middleware.js';
import { validate } from '../../middlewares/validate.middleware.js';
import { updateProfileSchema, changePasswordSchema, updateUserRoleSchema } from './user.validation.js';
import { sensitiveActionLimiter } from '../../middlewares/rateLimiter.middleware.js';
import { Roles } from '../../core/constants/roles.js';

const router = Router();

// Profile operations (Authenticated users)
router.get('/me', authenticate, UserController.getMe);
router.patch('/me', authenticate, validate(updateProfileSchema), UserController.updateMe);
router.post('/me/change-password', authenticate, sensitiveActionLimiter, validate(changePasswordSchema), UserController.changePassword);

// Administrative operations (Strict Admin RBAC)
router.get('/', authenticate, requireRole(Roles.ADMIN), UserController.listAllUsers);
router.patch('/:id', authenticate, requireRole(Roles.ADMIN), validate(updateUserRoleSchema), UserController.updateUserStatus);

export const userRoutes = router;
