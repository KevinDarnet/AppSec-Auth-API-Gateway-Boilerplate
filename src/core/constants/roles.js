/**
 * Role-Based Access Control (RBAC) Definitions
 * Follows the Principle of Least Privilege (PoLP)
 */
export const Roles = {
  USER: 'user',
  MODERATOR: 'moderator',
  ADMIN: 'admin',
};

export const Permissions = {
  USERS_READ: 'users:read',
  USERS_WRITE: 'users:write',
  USERS_DELETE: 'users:delete',
  GATEWAY_ADMIN: 'gateway:admin',
  AUDIT_READ: 'audit:read',
};

// Map each role to its granted permissions
export const RolePermissions = {
  [Roles.USER]: [
    Permissions.USERS_READ, // Can view public profile
  ],
  [Roles.MODERATOR]: [
    Permissions.USERS_READ,
    Permissions.USERS_WRITE,
  ],
  [Roles.ADMIN]: [
    Permissions.USERS_READ,
    Permissions.USERS_WRITE,
    Permissions.USERS_DELETE,
    Permissions.GATEWAY_ADMIN,
    Permissions.AUDIT_READ,
  ],
};
