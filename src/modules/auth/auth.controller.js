import { AuthService } from './auth.service.js';
import { ApiResponse } from '../../core/utils/response.js';
import { env } from '../../config/env.js';

/**
 * Cookie configuration helper
 */
function getRefreshTokenCookieOptions() {
  return {
    httpOnly: true, // Prevents access from client-side JavaScript (mitigates XSS token theft)
    secure: env.NODE_ENV === 'production', // Transmit only over HTTPS in production
    sameSite: 'strict', // Mitigates Cross-Site Request Forgery (CSRF)
    path: '/api/v1/auth', // Scope cookie to auth routes only
    maxAge: env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000,
  };
}

export class AuthController {
  /**
   * Register a new user
   * POST /api/v1/auth/register
   */
  static async register(req, res, next) {
    try {
      const user = await AuthService.registerUser(req.body);
      return ApiResponse.success(res, { user }, 'User registration completed successfully', 201);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Log in user
   * POST /api/v1/auth/login
   */
  static async login(req, res, next) {
    try {
      const { email, password } = req.body;
      const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
      const userAgent = req.headers['user-agent'] || 'unknown';

      const result = await AuthService.loginUser({ email, password, ipAddress, userAgent });

      // Set Refresh Token in secure HttpOnly cookie
      res.cookie('refreshToken', result.refreshToken, getRefreshTokenCookieOptions());

      return ApiResponse.success(
        res,
        {
          user: result.user,
          accessToken: result.accessToken,
          refreshToken: result.refreshToken, // Also returned in body for non-browser clients (e.g. mobile/CLI)
        },
        'Authentication successful',
        200
      );
    } catch (error) {
      next(error);
    }
  }

  /**
   * Refresh token
   * POST /api/v1/auth/refresh
   */
  static async refresh(req, res, next) {
    try {
      const rawRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
      const ipAddress = req.ip || 'unknown';
      const userAgent = req.headers['user-agent'] || 'unknown';

      const tokens = await AuthService.refreshAccessToken({ rawRefreshToken, ipAddress, userAgent });

      // Set new rotated refresh token in secure cookie
      res.cookie('refreshToken', tokens.refreshToken, getRefreshTokenCookieOptions());

      return ApiResponse.success(
        res,
        {
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
        },
        'Token pair refreshed and rotated successfully',
        200
      );
    } catch (error) {
      next(error);
    }
  }

  /**
   * Log out
   * POST /api/v1/auth/logout
   */
  static async logout(req, res, next) {
    try {
      const rawRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
      await AuthService.logout({ rawRefreshToken });

      // Clear cookie
      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/api/v1/auth',
      });

      return ApiResponse.success(res, null, 'Logged out successfully', 200);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Log out from all sessions (Revoke all active refresh tokens)
   * POST /api/v1/auth/revoke-all
   */
  static async revokeAll(req, res, next) {
    try {
      await AuthService.revokeAllUserSessions(req.user.id);

      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/api/v1/auth',
      });

      return ApiResponse.success(res, null, 'All active sessions have been revoked', 200);
    } catch (error) {
      next(error);
    }
  }
}
