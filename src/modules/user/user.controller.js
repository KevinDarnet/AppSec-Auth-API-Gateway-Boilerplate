import { UserService } from './user.service.js';
import { ApiResponse } from '../../core/utils/response.js';

export class UserController {
  static async getMe(req, res, next) {
    try {
      const user = await UserService.getUserProfile(req.user.id);
      return ApiResponse.success(res, { user }, 'User profile retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  static async updateMe(req, res, next) {
    try {
      const user = await UserService.updateProfile(req.user.id, req.body);
      return ApiResponse.success(res, { user }, 'Profile updated successfully');
    } catch (error) {
      next(error);
    }
  }

  static async changePassword(req, res, next) {
    try {
      await UserService.changePassword(req.user.id, req.body);
      return ApiResponse.success(res, null, 'Password changed successfully');
    } catch (error) {
      next(error);
    }
  }

  static async listAllUsers(req, res, next) {
    try {
      const page = parseInt(req.query.page || '1', 10);
      const limit = parseInt(req.query.limit || '20', 10);
      const result = await UserService.listUsers({ page, limit });
      return ApiResponse.success(res, result.users, 'Users retrieved successfully', 200, {
        pagination: result.pagination,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateUserStatus(req, res, next) {
    try {
      const user = await UserService.updateUserStatus(req.params.id, req.body);
      return ApiResponse.success(res, { user }, 'User status updated successfully');
    } catch (error) {
      next(error);
    }
  }
}
