import { UserModel } from './user.model.js';
import { AppError } from '../../core/errors/AppError.js';
import { ErrorCodes } from '../../core/errors/errorCodes.js';

export class UserService {
  static async getUserProfile(userId) {
    const user = await UserModel.findById(userId);
    if (!user) {
      throw AppError.notFound('User profile not found', ErrorCodes.RESOURCE_NOT_FOUND);
    }
    return user.toJSON();
  }

  static async updateProfile(userId, { fullName }) {
    const user = await UserModel.findById(userId);
    if (!user) {
      throw AppError.notFound('User not found', ErrorCodes.RESOURCE_NOT_FOUND);
    }

    if (fullName) {
      user.fullName = fullName;
    }

    await user.save();
    return user.toJSON();
  }

  static async changePassword(userId, { currentPassword, newPassword }) {
    const user = await UserModel.findById(userId).select('+password');
    if (!user) {
      throw AppError.notFound('User not found', ErrorCodes.RESOURCE_NOT_FOUND);
    }

    const isMatch = await user.verifyPassword(currentPassword);
    if (!isMatch) {
      throw AppError.badRequest('Current password verification failed', ErrorCodes.AUTH_INVALID_CREDENTIALS);
    }

    user.password = newPassword;
    await user.save();
    return true;
  }

  static async listUsers({ page = 1, limit = 20 }) {
    const safeLimit = Math.min(Math.max(1, limit), 100);
    const skip = (Math.max(1, page) - 1) * safeLimit;

    const [users, total] = await Promise.all([
      UserModel.find().skip(skip).limit(safeLimit).sort({ createdAt: -1 }),
      UserModel.countDocuments(),
    ]);

    return {
      users: users.map((u) => u.toJSON()),
      pagination: {
        page: Math.max(1, page),
        limit: safeLimit,
        total,
        totalPages: Math.ceil(total / safeLimit),
      },
    };
  }

  static async updateUserStatus(userId, { role, isActive }) {
    const user = await UserModel.findById(userId);
    if (!user) {
      throw AppError.notFound('User not found', ErrorCodes.RESOURCE_NOT_FOUND);
    }

    if (role !== undefined) user.role = role;
    if (isActive !== undefined) user.isActive = isActive;

    await user.save();
    return user.toJSON();
  }
}
