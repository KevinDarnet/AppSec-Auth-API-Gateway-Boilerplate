import { Router } from 'express';
import { AuthController } from './auth.controller.js';
import { validate } from '../../middlewares/validate.middleware.js';
import { registerSchema, loginSchema, refreshTokenSchema } from './auth.validation.js';
import { authRateLimiter, sensitiveActionLimiter } from '../../middlewares/rateLimiter.middleware.js';
import { authenticate } from '../../middlewares/auth.middleware.js';

const router = Router();

// Registration: protected against automated abuse by authRateLimiter and strict validation
router.post('/register', authRateLimiter, validate(registerSchema), AuthController.register);

// Login: hardened against brute-force and credential stuffing
router.post('/login', authRateLimiter, validate(loginSchema), AuthController.login);

// Token Refresh: protected against replay attacks with sensitive rate limiting
router.post('/refresh', sensitiveActionLimiter, validate(refreshTokenSchema), AuthController.refresh);

// Logout: invalidates current refresh token session
router.post('/logout', AuthController.logout);

// Global Session Revocation: requires authenticated session
router.post('/revoke-all', authenticate, AuthController.revokeAll);

export const authRoutes = router;
