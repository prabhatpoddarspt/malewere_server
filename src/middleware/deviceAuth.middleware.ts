import { Socket } from 'socket.io';
import Device from '../models/Device';
import logger from '../utils/logger';

export const authenticateDevice = async (socket: Socket, next: Function): Promise<void> => {
  try {
    // Try to get connectionToken from handshake
    const connectionToken = socket.handshake.auth.connectionToken || 
                           socket.handshake.query?.connectionToken as string ||
                           socket.handshake.headers['x-connection-token'] as string;

    if (connectionToken) {
      // Authenticate using device connectionToken
      const device = await Device.findOne({ connectionToken });
      
      if (!device) {
        logger.warn(`Device authentication failed - Invalid connectionToken: ${connectionToken.substring(0, 8)}...`);
        return next(new Error('Device authentication error: Invalid connection token'));
      }

      // Store device info in socket data
      socket.data.deviceId = device._id.toString();
      socket.data.device = device;
      socket.data.userId = device.userId?.toString(); // May be undefined for anonymous devices
      socket.data.isDevice = true;
      socket.data.connectionType = 'Application/Device';
      
      logger.info(`Device authenticated - Device: ${device.deviceId}, Name: ${device.deviceName}`);
      return next();
    }

    // No connectionToken provided - allow JWT authentication to proceed (for admin panel)
    // Don't reject here, let the next middleware handle JWT authentication
    return next();
  } catch (error: any) {
    logger.error('Device authentication error:', error);
    next(new Error('Device authentication error'));
  }
};
