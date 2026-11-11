import { z } from 'zod';
import { Roles } from '../../core/constants/roles.js';

export const updateProfileSchema = z.object({
  fullName: z
    .string()
    .min(2, 'Full name must contain at least 2 characters')
    .max(100, 'Full name cannot exceed 100 characters')
    .trim()
    .optional(),
}).strict(); // Prevents unauthorized field injection (e.g. role, isActive)

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z
    .string()
    .min(8, 'Password must contain at least 8 characters')
    .max(72, 'Password cannot exceed 72 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one digit')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
}).strict();

export const updateUserRoleSchema = z.object({
  role: z.nativeEnum(Roles, { errorMap: () => ({ message: 'Invalid role specified' }) }).optional(),
  isActive: z.boolean().optional(),
}).strict();
