import { Response } from 'express';
import { AuthenticatedRequest } from '../types';
import { config } from '../config/environment';
import logger from '../utils/logger';
import User from '../models/User';

export class SettingsController {
  getSettings = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const userId = req.user?.userId;

      if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      // Get user to include user-specific settings
      const user = await User.findById(userId).select('-password -twoFactorSecret').lean();

      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      // Public settings (available to all users)
      const publicSettings = {
        maxFileSize: config.file.maxSize,
        allowedFileTypes: config.file.allowedTypes,
        websocket: {
          path: config.websocket.path,
          pingTimeout: config.websocket.pingTimeout,
          pingInterval: config.websocket.pingInterval,
        },
      };

      // User-specific settings
      const userSettings = {
        email: user.email,
        role: user.role,
        permissions: user.permissions,
        twoFactorEnabled: user.twoFactorEnabled,
        isActive: user.isActive,
      };

      // Admin-only settings
      const adminSettings = req.user?.role === 'admin' ? {
        rateLimit: {
          windowMs: config.rateLimit.windowMs,
          maxRequests: config.rateLimit.maxRequests,
        },
        security: {
          bcryptRounds: config.security.bcryptRounds,
        },
      } : {};

      res.json({
        public: publicSettings,
        user: userSettings,
        ...adminSettings,
      });
    } catch (error: any) {
      logger.error('Get settings error:', error);
      res.status(500).json({ error: 'Failed to fetch settings' });
    }
  };

  updateUserSettings = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const userId = req.user?.userId;
      const { email, permissions, twoFactorEnabled } = req.body;

      if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      const user = await User.findById(userId);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      // Users can only update certain settings
      if (email && email !== user.email) {
        // Check if email is already taken
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser && existingUser._id.toString() !== userId) {
          res.status(400).json({ error: 'Email already in use' });
          return;
        }
        user.email = email.toLowerCase();
      }

      if (typeof twoFactorEnabled === 'boolean') {
        user.twoFactorEnabled = twoFactorEnabled;
      }

      // Only admins can update permissions
      if (permissions && req.user?.role === 'admin') {
        user.permissions = { ...user.permissions, ...permissions };
      }

      await user.save();

      const userResponse = user.toObject();
      delete userResponse.password;
      delete userResponse.twoFactorSecret;

      res.json({
        message: 'Settings updated successfully',
        user: userResponse,
      });
    } catch (error: any) {
      logger.error('Update user settings error:', error);
      res.status(500).json({ error: 'Failed to update settings' });
    }
  };

  getSystemSettings = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      // Only admins can access system settings
      if (req.user?.role !== 'admin') {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }

      const systemSettings = {
        environment: config.env,
        port: config.port,
        file: {
          maxSize: config.file.maxSize,
          allowedTypes: config.file.allowedTypes,
          uploadDir: config.file.uploadDir,
        },
        rateLimit: {
          windowMs: config.rateLimit.windowMs,
          maxRequests: config.rateLimit.maxRequests,
        },
        security: {
          bcryptRounds: config.security.bcryptRounds,
        },
        websocket: {
          path: config.websocket.path,
          pingTimeout: config.websocket.pingTimeout,
          pingInterval: config.websocket.pingInterval,
        },
        jwt: {
          expiresIn: config.jwt.expiresIn,
          refreshExpiresIn: config.jwt.refreshExpiresIn,
        },
      };

      res.json({ systemSettings });
    } catch (error: any) {
      logger.error('Get system settings error:', error);
      res.status(500).json({ error: 'Failed to fetch system settings' });
    }
  };
}

