import { z } from 'zod';

/**
 * Strong Password Policy (NIST SP 800-63B & OWASP ASVS aligned):
 * - Minimum 8 characters, maximum 72 characters (Bcrypt truncation limit defense)
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - At least one special character
 */
const passwordValidation = z
  .string({ required_error: 'Password is required' })
  .min(8, 'Password must contain at least 8 characters')
  .max(72, 'Password cannot exceed 72 characters (Bcrypt safe boundary)')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one digit')
  .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character');

export const registerSchema = z.object({
  email: z
    .string({ required_error: 'Email address is required' })
    .email('Invalid email address format')
    .toLowerCase()
    .trim(),
  password: passwordValidation,
  fullName: z
    .string({ required_error: 'Full name is required' })
    .min(2, 'Full name must contain at least 2 characters')
    .max(100, 'Full name cannot exceed 100 characters')
    .trim(),
}).strict(); // Disallow unknown properties to prevent mass assignment

export const loginSchema = z.object({
  email: z
    .string({ required_error: 'Email address is required' })
    .email('Invalid email address format')
    .toLowerCase()
    .trim(),
  password: z
    .string({ required_error: 'Password is required' })
    .min(1, 'Password cannot be empty'),
}).strict();

export const refreshTokenSchema = z.object({
  refreshToken: z.string().optional(),
}).strict();
