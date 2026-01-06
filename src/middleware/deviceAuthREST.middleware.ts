import { Response, NextFunction } from 'express';
import Device from '../models/Device';
import { AuthenticatedRequest } from '../types';
import logger from '../utils/logger';

export const authenticateDeviceREST = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Get connectionToken from header or query
    const connectionToken = req.headers['x-connection-token'] as string ||
                           req.query.connectionToken as string;

    if (connectionToken) {
      const device = await Device.findOne({ connectionToken });
      
      if (!device) {
        res.status(401).json({ error: 'Invalid connection token' });
        return;
      }

      // Set device info in request
      req.device = device;
      // Set user if device has userId, otherwise leave undefined for anonymous device
      if (device.userId) {
        req.user = {
          userId: device.userId.toString(),
          role: 'device',
        };
      }
      
      logger.info(`Device authenticated via REST - Device: ${device.deviceId}, User: ${device.userId || 'anonymous'}`);
      return next();
    }

    // No connectionToken provided, continue to next middleware (JWT auth)
    next();
  } catch (error: any) {
    logger.error('Device REST authentication error:', error);
    res.status(401).json({ error: 'Device authentication failed' });
  }
};

