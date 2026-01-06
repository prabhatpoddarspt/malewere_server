import { Response } from 'express';
import { AuthenticatedRequest } from '../types';
import Device from '../models/Device';
import User from '../models/User';
import { SecurityUtils } from '../utils/security';
import logger from '../utils/logger';
import { auditLogAsync } from '../utils/auditLogger';
import mongoose from 'mongoose';

export class DeviceController {
  getAllDevices = async (_req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      // Admin panel is read-only - only view devices created by applications
      // All devices come from applications, so show all devices (including anonymous)
      let query: any = {};
      
      // Show all devices - admin panel can view all devices registered by applications
      // No filtering needed since all devices come from applications

      // Find all devices - all devices come from applications
      const devices = await Device.find(query).populate('userId', 'email').sort({ createdAt: -1 }).lean();

      // Ensure devices array is properly formatted and serialize properly
      // Convert devices to plain objects and handle undefined userId
      const formattedDevices = devices.map(device => {
        // Handle populated userId
        let userIdData = null;
        if (device.userId) {
          if (typeof device.userId === 'object' && 'email' in device.userId) {
            // Populated userId
            userIdData = {
              _id: device.userId._id?.toString() || device.userId._id,
              email: device.userId.email,
            };
          } else if (typeof device.userId === 'string' || device.userId instanceof mongoose.Types.ObjectId) {
            // Just ObjectId
            userIdData = device.userId.toString();
          }
        }
        
        const deviceObj: any = {
          _id: device._id?.toString() || device._id,
          deviceId: device.deviceId,
          deviceName: device.deviceName,
          platform: device.platform,
          isOnline: device.isOnline || false,
          lastSeen: device.lastSeen,
          ipAddress: device.ipAddress || null,
          authorizedPaths: device.authorizedPaths || [],
          connectionToken: device.connectionToken,
          createdAt: device.createdAt,
          updatedAt: device.updatedAt,
          userId: userIdData,
          isAnonymous: !device.userId, // Flag to indicate anonymous device
        };
        
        return deviceObj;
      });

      const response = { 
        success: true,
        devices: formattedDevices,
        count: formattedDevices.length,
        total: formattedDevices.length,
        message: formattedDevices.length === 0 ? 'No devices found. Register a device first using POST /api/devices' : `Found ${formattedDevices.length} device(s)`,
      };
      
      res.status(200).json(response);
    } catch (error: any) {
      logger.error('Get devices error:', error);
      res.status(500).json({ error: 'Failed to fetch devices' });
    }
  };

  getDeviceById = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      const device = await Device.findById(id).populate('userId', 'email').lean();

      if (!device) {
        res.status(404).json({ error: 'Device not found' });
        return;
      }

      // Non-admin users can only see their own devices
      if (req.user?.role !== 'admin' && device.userId && device.userId.toString() !== userId) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }

      res.json({ device });
    } catch (error: any) {
      logger.error('Get device error:', error);
      res.status(500).json({ error: 'Failed to fetch device' });
    }
  };

  // Anonymous device registration (no authentication required)
  registerDeviceAnonymous = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { deviceId, deviceName, platform, ipAddress, authorizedPaths } = req.body;

      if (!deviceId || !deviceName || !platform) {
        res.status(400).json({ error: 'Missing required fields: deviceId, deviceName, platform' });
        return;
      }

      // Public registration - no registration key required

      // Check if device already exists
      const existingDevice = await Device.findOne({ deviceId });
      if (existingDevice) {
        // If device exists, return existing device info (but don't expose full connectionToken)
        logger.info(`Device already registered - Device: ${deviceId}, returning existing device`);
        res.status(200).json({
          device: {
            _id: existingDevice._id,
            deviceId: existingDevice.deviceId,
            deviceName: existingDevice.deviceName,
            platform: existingDevice.platform,
            connectionToken: existingDevice.connectionToken, // Return token for reconnection
            authorizedPaths: existingDevice.authorizedPaths,
            isOnline: existingDevice.isOnline,
          },
          message: 'Device already registered. Use the connectionToken to connect.',
        });
        return;
      }

      // Generate connection token
      const connectionToken = SecurityUtils.generateToken(32);

      // Create device without userId (anonymous device)
      const device = await Device.create({
        userId: undefined, // Anonymous device
        deviceId,
        deviceName,
        platform,
        ipAddress: ipAddress || req.ip || req.socket.remoteAddress || 'unknown',
        authorizedPaths: authorizedPaths || [],
        connectionToken,
        isOnline: false, // Will be set to true when connected via WebSocket
        lastSeen: new Date(),
      });

      auditLogAsync({
        action: 'register',
        resource: 'device',
        resourceId: device._id.toString(),
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
        success: true,
        details: { anonymous: true, deviceId },
      });

      logger.info(`Anonymous device registered - Device: ${device.deviceId}, Name: ${device.deviceName}`);

      res.status(201).json({ 
        device: {
          _id: device._id,
          deviceId: device.deviceId,
          deviceName: device.deviceName,
          platform: device.platform,
          connectionToken: device.connectionToken,
          authorizedPaths: device.authorizedPaths,
          isOnline: device.isOnline,
        },
        message: 'Device registered successfully. Use the connectionToken to connect via WebSocket.',
      });
    } catch (error: any) {
      logger.error('Anonymous device registration error:', error);
      res.status(500).json({ error: 'Failed to register device' });
    }
  };

  registerDevice = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const userId = req.user?.userId;
      const { deviceId, deviceName, platform, ipAddress, authorizedPaths } = req.body;

      if (!deviceId || !deviceName || !platform) {
        res.status(400).json({ error: 'Missing required fields' });
        return;
      }

      // Check if device already exists
      const existingDevice = await Device.findOne({ deviceId });
      if (existingDevice) {
        res.status(400).json({ error: 'Device already registered' });
        return;
      }

      // Generate connection token
      const connectionToken = SecurityUtils.generateToken(32);

      const device = await Device.create({
        userId,
        deviceId,
        deviceName,
        platform,
        ipAddress,
        authorizedPaths: authorizedPaths || [],
        connectionToken,
        isOnline: true,
        lastSeen: new Date(),
      });

      // Add device to user's devices array
      await User.findByIdAndUpdate(userId, {
        $push: { devices: device._id },
      });

      auditLogAsync({
        userId,
        action: 'register',
        resource: 'device',
        resourceId: device._id.toString(),
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
        success: true,
      });

      logger.info(`Device registered - Device: ${device.deviceId}, Name: ${device.deviceName}, User: ${userId}`);

      res.status(201).json({ 
        device,
        message: 'Device registered successfully. Use the connectionToken to connect via WebSocket.',
      });
    } catch (error: any) {
      logger.error('Register device error:', error);
      res.status(500).json({ error: 'Failed to register device' });
    }
  };

  updateDevice = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;
      const { deviceName, authorizedPaths, isOnline } = req.body;

      const device = await Device.findById(id);
      if (!device) {
        res.status(404).json({ error: 'Device not found' });
        return;
      }

      // Non-admin users can only update their own devices
      if (req.user?.role !== 'admin' && device.userId?.toString() !== userId) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }

      if (deviceName) device.deviceName = deviceName;
      if (authorizedPaths) device.authorizedPaths = authorizedPaths;
      if (typeof isOnline === 'boolean') {
        device.isOnline = isOnline;
        device.lastSeen = new Date();
      }

      await device.save();

      auditLogAsync({
        userId,
        action: 'update',
        resource: 'device',
        resourceId: id,
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
        success: true,
      });

      res.json({ device });
    } catch (error: any) {
      logger.error('Update device error:', error);
      res.status(500).json({ error: 'Failed to update device' });
    }
  };

  deleteDevice = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      const device = await Device.findById(id);
      if (!device) {
        res.status(404).json({ error: 'Device not found' });
        return;
      }

      // Non-admin users can only delete their own devices
      if (req.user?.role !== 'admin' && device.userId?.toString() !== userId) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }

      // Remove device from user's devices array if it has a userId
      if (device.userId) {
        await User.findByIdAndUpdate(device.userId, {
          $pull: { devices: device._id },
        });
      }

      await Device.deleteOne({ _id: id });

      auditLogAsync({
        userId,
        action: 'delete',
        resource: 'device',
        resourceId: id,
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
        success: true,
      });

      res.json({ message: 'Device deleted successfully' });
    } catch (error: any) {
      logger.error('Delete device error:', error);
      res.status(500).json({ error: 'Failed to delete device' });
    }
  };

  getDeviceStatus = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      const device = await Device.findById(id).lean();
      if (!device) {
        res.status(404).json({ error: 'Device not found' });
        return;
      }

      // Non-admin users can only see their own devices
      if (req.user?.role !== 'admin' && device.userId?.toString() !== userId) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }

      res.json({
        isOnline: device.isOnline,
        lastSeen: device.lastSeen,
        platform: device.platform,
      });
    } catch (error: any) {
      logger.error('Get device status error:', error);
      res.status(500).json({ error: 'Failed to fetch device status' });
    }
  };

  authorizeDevicePaths = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const { authorizedPaths } = req.body;
      const userId = req.user?.userId;

      if (!Array.isArray(authorizedPaths)) {
        res.status(400).json({ error: 'authorizedPaths must be an array' });
        return;
      }

      const device = await Device.findById(id);
      if (!device) {
        res.status(404).json({ error: 'Device not found' });
        return;
      }

      // Only admin or device owner can authorize paths
      if (req.user?.role !== 'admin' && device.userId?.toString() !== userId) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }

      device.authorizedPaths = authorizedPaths;
      await device.save();

      auditLogAsync({
        userId,
        action: 'authorize_paths',
        resource: 'device',
        resourceId: id,
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
        success: true,
        details: { authorizedPaths },
      });

      res.json({ device });
    } catch (error: any) {
      logger.error('Authorize device paths error:', error);
      res.status(500).json({ error: 'Failed to authorize device paths' });
    }
  };
}
