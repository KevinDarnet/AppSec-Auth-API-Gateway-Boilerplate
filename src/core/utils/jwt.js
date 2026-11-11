import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import { env } from '../../config/env.js';
import { AppError } from '../errors/AppError.js';
import { ErrorCodes } from '../errors/errorCodes.js';

const JWT_ISSUER = 'appsec-gateway';
const JWT_AUDIENCE = 'appsec-api';

/**
 * Generate a short-lived Access Token
 */
export function signAccessToken(payload) {
  return jwt.sign(
    {
      sub: payload.userId,
      role: payload.role,
      tokenType: 'access',
    },
    env.JWT_ACCESS_SECRET,
    {
      expiresIn: env.JWT_ACCESS_EXPIRATION,
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      algorithm: 'HS256',
    }
  );
}

/**
 * Generate a long-lived Refresh Token with unique JTI and Family ID
 */
export function signRefreshToken(payload, familyId = null) {
  const jti = crypto.randomUUID();
  const tokenFamily = familyId || crypto.randomUUID();

  const token = jwt.sign(
    {
      sub: payload.userId,
      jti,
      familyId: tokenFamily,
      tokenType: 'refresh',
    },
    env.JWT_REFRESH_SECRET,
    {
      expiresIn: `${env.JWT_REFRESH_EXPIRATION_DAYS}d`,
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      algorithm: 'HS256',
    }
  );

  return { token, jti, familyId: tokenFamily };
}

/**
 * Verify and decode an Access Token
 */
export function verifyAccessToken(token) {
  try {
    const decoded = jwt.verify(token, env.JWT_ACCESS_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      algorithms: ['HS256'], // Explicitly whitelist allowed algorithms to prevent alg='none' attack
    });

    if (decoded.tokenType !== 'access') {
      throw AppError.unauthorized('Invalid token purpose: Access token expected', ErrorCodes.AUTH_TOKEN_INVALID);
    }

    return decoded;
  } catch (error) {
    if (error instanceof AppError) throw error;
    if (error.name === 'TokenExpiredError') {
      throw AppError.unauthorized('Access token has expired', ErrorCodes.AUTH_TOKEN_EXPIRED);
    }
    throw AppError.unauthorized('Invalid access token signature or payload', ErrorCodes.AUTH_TOKEN_INVALID);
  }
}

/**
 * Verify and decode a Refresh Token
 */
export function verifyRefreshToken(token) {
  try {
    const decoded = jwt.verify(token, env.JWT_REFRESH_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      algorithms: ['HS256'],
    });

    if (decoded.tokenType !== 'refresh') {
      throw AppError.unauthorized('Invalid token purpose: Refresh token expected', ErrorCodes.AUTH_TOKEN_INVALID);
    }

    return decoded;
  } catch (error) {
    if (error instanceof AppError) throw error;
    if (error.name === 'TokenExpiredError') {
      throw AppError.unauthorized('Refresh token has expired, please log in again', ErrorCodes.AUTH_TOKEN_EXPIRED);
    }
    throw AppError.unauthorized('Invalid refresh token signature', ErrorCodes.AUTH_TOKEN_INVALID);
  }
}
