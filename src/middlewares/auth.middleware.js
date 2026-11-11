import { verifyAccessToken } from '../core/utils/jwt.js';
import { AppError } from '../core/errors/AppError.js';
import { ErrorCodes } from '../core/errors/errorCodes.js';
import { UserModel } from '../modules/user/user.model.js';

/**
 * Authentication Middleware
 * Validates JWT Access Token and verifies user account status in database.
 */
export async function authenticate(req, res, next) {
  try {
    let token = null;

    // 1. Check Authorization Header (Bearer token)
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7).trim();
    }

    // 2. Fallback to HttpOnly cookie if header is absent
    if (!token && req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      throw AppError.unauthorized('Authentication token missing. Please log in.', ErrorCodes.AUTH_TOKEN_MISSING);
    }

    // 3. Cryptographically verify signature and token claims
    const decoded = verifyAccessToken(token);

    // 4. Verify user exists in database and has not been deactivated or locked
    const user = await UserModel.findById(decoded.sub).select('+isActive +isLocked +passwordChangedAt');

    if (!user) {
      throw AppError.unauthorized('User associated with this token no longer exists', ErrorCodes.AUTH_ACCOUNT_DISABLED);
    }

    if (!user.isActive) {
      throw AppError.forbidden('This user account has been deactivated', ErrorCodes.AUTH_ACCOUNT_DISABLED);
    }

    if (user.isLocked) {
      throw AppError.forbidden('This user account is currently locked due to security policy', ErrorCodes.AUTH_ACCOUNT_LOCKED);
    }

    // 5. Check if password was changed after token issuance
    if (user.passwordChangedAt && decoded.iat) {
      const changedTimestamp = parseInt(user.passwordChangedAt.getTime() / 1000, 10);
      if (decoded.iat < changedTimestamp) {
        throw AppError.unauthorized('User password was recently changed. Please log in again.', ErrorCodes.AUTH_TOKEN_INVALID);
      }
    }

    // 6. Attach sanitized user identity to request context
    req.user = {
      id: user._id.toString(),
      email: user.email,
      role: user.role,
      fullName: user.fullName,
    };

    next();
  } catch (error) {
    next(error);
  }
}
