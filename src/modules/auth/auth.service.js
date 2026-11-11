import { UserModel } from '../user/user.model.js';
import { RefreshTokenModel } from '../session/refreshToken.model.js';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '../../core/utils/jwt.js';
import { hashToken } from '../../core/utils/crypto.js';
import { AppError } from '../../core/errors/AppError.js';
import { ErrorCodes } from '../../core/errors/errorCodes.js';
import { env } from '../../config/env.js';
import { logger } from '../../config/logger.js';

export class AuthService {
  /**
   * Register a new user
   */
  static async registerUser({ email, password, fullName }) {
    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      throw AppError.conflict('An account with this email address already exists.', ErrorCodes.RESOURCE_CONFLICT);
    }

    const user = await UserModel.create({
      email,
      password,
      fullName,
    });

    return user.toJSON();
  }

  /**
   * Authenticate user credentials and issue token pair
   */
  static async loginUser({ email, password, ipAddress, userAgent }) {
    // Explicitly select password and lockout fields which are excluded by default
    const user = await UserModel.findOne({ email }).select('+password +failedLoginAttempts +lockUntil +isActive');

    // Generic error message to prevent user enumeration attacks (OWASP A07)
    const invalidCredentialsError = AppError.unauthorized(
      'Invalid email address or password provided.',
      ErrorCodes.AUTH_INVALID_CREDENTIALS
    );

    if (!user) {
      // Perform dummy verification work to mitigate timing side-channel attacks against non-existent users
      await user?.verifyPassword?.(password);
      throw invalidCredentialsError;
    }

    if (!user.isActive) {
      throw AppError.forbidden('This account has been deactivated.', ErrorCodes.AUTH_ACCOUNT_DISABLED);
    }

    // Check account lockout
    if (user.isAccountLocked()) {
      const remainingMinutes = Math.ceil((user.lockUntil.getTime() - Date.now()) / (60 * 1000));
      throw AppError.forbidden(
        `Account temporarily locked due to excessive failed attempts. Please retry in ${remainingMinutes} minutes.`,
        ErrorCodes.AUTH_ACCOUNT_LOCKED
      );
    }

    const isMatch = await user.verifyPassword(password);
    if (!isMatch) {
      await user.recordFailedLogin();
      throw invalidCredentialsError;
    }

    // Reset failed counter upon successful authentication
    await user.recordSuccessfulLogin();

    // Issue token pair
    const accessToken = signAccessToken({ userId: user._id.toString(), role: user.role });
    const { token: refreshToken, jti, familyId } = signRefreshToken({ userId: user._id.toString() });

    // Store hashed refresh token in database (never store raw tokens!)
    const hashedToken = hashToken(refreshToken);
    const expiresAt = new Date(Date.now() + env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000);

    await RefreshTokenModel.create({
      userId: user._id,
      tokenHash: hashedToken,
      familyId,
      jti,
      ipAddress,
      userAgent,
      expiresAt,
    });

    return {
      user: user.toJSON(),
      accessToken,
      refreshToken,
    };
  }

  /**
   * Refresh Access Token with Token Rotation and Automatic Reuse Detection
   * Conforms to OAuth 2.0 Security Best Current Practice & OWASP ASVS
   */
  static async refreshAccessToken({ rawRefreshToken, ipAddress, userAgent }) {
    if (!rawRefreshToken) {
      throw AppError.unauthorized('Refresh token is required', ErrorCodes.AUTH_TOKEN_MISSING);
    }

    // 1. Verify cryptographic validity and expiration of the JWT refresh token
    const decoded = verifyRefreshToken(rawRefreshToken);
    const tokenHash = hashToken(rawRefreshToken);

    // 2. Query database for this token session
    const session = await RefreshTokenModel.findOne({ tokenHash });

    // 3. REUSE DETECTION (Breach Response):
    // If token does not exist or was already revoked, someone is replaying a spent token!
    if (!session || session.isRevoked) {
      logger.error('CRITICAL SECURITY ALERT: Refresh token reuse detected!', {
        userId: decoded.sub,
        familyId: decoded.familyId,
        ip: ipAddress,
      });

      // Revoke all sessions belonging to this token family to neutralize compromised credentials
      await RefreshTokenModel.updateMany(
        { familyId: decoded.familyId },
        { isRevoked: true }
      );

      throw AppError.unauthorized(
        'Security violation detected: Compromised token reuse. All associated sessions have been invalidated.',
        ErrorCodes.AUTH_TOKEN_REUSE_DETECTED
      );
    }

    // 4. Verify user status
    const user = await UserModel.findById(session.userId);
    if (!user || !user.isActive) {
      throw AppError.forbidden('User account is invalid or deactivated', ErrorCodes.AUTH_ACCOUNT_DISABLED);
    }

    // 5. Rotate token: Revoke current refresh token and generate a new pair
    const { token: newRefreshToken, jti: newJti, familyId } = signRefreshToken(
      { userId: user._id.toString() },
      session.familyId
    );

    const newHashedToken = hashToken(newRefreshToken);
    const newExpiresAt = new Date(Date.now() + env.JWT_REFRESH_EXPIRATION_DAYS * 24 * 60 * 60 * 1000);

    // Invalidate old token session
    session.isRevoked = true;
    session.replacedByTokenHash = newHashedToken;
    await session.save();

    // Persist new rotated session
    await RefreshTokenModel.create({
      userId: user._id,
      tokenHash: newHashedToken,
      familyId,
      jti: newJti,
      ipAddress,
      userAgent,
      expiresAt: newExpiresAt,
    });

    // Generate fresh short-lived access token
    const newAccessToken = signAccessToken({ userId: user._id.toString(), role: user.role });

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }

  /**
   * Invalidate a single refresh token session (Logout)
   */
  static async logout({ rawRefreshToken }) {
    if (!rawRefreshToken) return;

    try {
      const tokenHash = hashToken(rawRefreshToken);
      await RefreshTokenModel.updateOne({ tokenHash }, { isRevoked: true });
    } catch (error) {
      logger.warn('Failed to invalidate refresh token during logout', { error: error.message });
    }
  }

  /**
   * Revoke all active sessions for a user (Global Logout / Account Security)
   */
  static async revokeAllUserSessions(userId) {
    await RefreshTokenModel.updateMany({ userId }, { isRevoked: true });
  }
}
