import { Response } from 'express';
import { AuthenticatedRequest } from '../types';
import User from '../models/User';
import logger from '../utils/logger';
import AuditLog from '../models/AuditLog';

export class UserController {
  getAllUsers = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const users = await User.find({})
        .select('-password -twoFactorSecret')
        .populate('devices')
        .lean();

      res.json({ users });
    } catch (error: any) {
      logger.error('Get users error:', error);
      res.status(500).json({ error: 'Failed to fetch users' });
    }
  };

  getUserById = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      const user = await User.findById(id)
        .select('-password -twoFactorSecret')
        .populate('devices')
        .lean();

      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      res.json({ user });
    } catch (error: any) {
      logger.error('Get user error:', error);
      res.status(500).json({ error: 'Failed to fetch user' });
    }
  };

  updateUser = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const { email, role, isActive, permissions } = req.body;

      const user = await User.findById(id);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      if (email) user.email = email;
      if (role) user.role = role;
      if (typeof isActive === 'boolean') user.isActive = isActive;
      if (permissions) user.permissions = { ...user.permissions, ...permissions };

      await user.save();

      await AuditLog.create({
        userId: req.user?.userId,
        action: 'update',
        resource: 'user',
        resourceId: id,
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
        success: true,
      });

      const userResponse = user.toObject();
      delete userResponse.password;
      delete userResponse.twoFactorSecret;

      res.json({ user: userResponse });
    } catch (error: any) {
      logger.error('Update user error:', error);
      res.status(500).json({ error: 'Failed to update user' });
    }
  };

  deleteUser = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      const user = await User.findById(id);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      await User.deleteOne({ _id: id });

      await AuditLog.create({
        userId: req.user?.userId,
        action: 'delete',
        resource: 'user',
        resourceId: id,
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
        success: true,
      });

      res.json({ message: 'User deleted successfully' });
    } catch (error: any) {
      logger.error('Delete user error:', error);
      res.status(500).json({ error: 'Failed to delete user' });
    }
  };

  updatePermissions = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const { permissions } = req.body;

      const user = await User.findById(id);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      user.permissions = { ...user.permissions, ...permissions };
      await user.save();

      await AuditLog.create({
        userId: req.user?.userId,
        action: 'update_permissions',
        resource: 'user',
        resourceId: id,
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
        success: true,
      });

      const userResponse = user.toObject();
      delete userResponse.password;
      delete userResponse.twoFactorSecret;

      res.json({ user: userResponse });
    } catch (error: any) {
      logger.error('Update permissions error:', error);
      res.status(500).json({ error: 'Failed to update permissions' });
    }
  };

  getUserDevices = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      const user = await User.findById(id).populate('devices').lean();
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      res.json({ devices: user.devices });
    } catch (error: any) {
      logger.error('Get user devices error:', error);
      res.status(500).json({ error: 'Failed to fetch user devices' });
    }
  };
}

