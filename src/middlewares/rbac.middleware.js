import { AppError } from '../core/errors/AppError.js';
import { ErrorCodes } from '../core/errors/errorCodes.js';
import { RolePermissions } from '../core/constants/roles.js';

/**
 * Role-Based Access Control (RBAC) Middleware
 * Restricts access to users holding one of the specified roles.
 *
 * @param {string[]} allowedRoles
 */
export function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return next(AppError.unauthorized('Authentication required before checking roles'));
    }

    if (!allowedRoles.includes(req.user.role)) {
      return next(
        AppError.forbidden(
          `Access denied. Role '${req.user.role}' is not authorized for this resource.`,
          ErrorCodes.FORBIDDEN_INSUFFICIENT_PERMISSIONS
        )
      );
    }

    next();
  };
}

/**
 * Granular Permission-Based Access Control
 * Checks if the user's role is mapped to the required permission(s).
 *
 * @param {string[]} requiredPermissions
 */
export function requirePermission(...requiredPermissions) {
  return (req, res, next) => {
    if (!req.user) {
      return next(AppError.unauthorized('Authentication required before checking permissions'));
    }

    const grantedPermissions = RolePermissions[req.user.role] || [];
    const hasAllPermissions = requiredPermissions.every((perm) => grantedPermissions.includes(perm));

    if (!hasAllPermissions) {
      return next(
        AppError.forbidden(
          'Access denied. Missing required security permissions.',
          ErrorCodes.FORBIDDEN_INSUFFICIENT_PERMISSIONS
        )
      );
    }

    next();
  };
}
