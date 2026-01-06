import { Server as SocketIOServer } from 'socket.io';
import Device from '../models/Device';
import logger from '../utils/logger';

export class WebSocketService {
  private io: SocketIOServer;

  constructor(io: SocketIOServer) {
    this.io = io;
  }

  async notifyDevice(deviceId: string, event: string, data: any): Promise<void> {
    try {
      const device = await Device.findById(deviceId);
      if (!device) {
        logger.warn(`Device not found: ${deviceId}`);
        return;
      }

      // Find all sockets for this device
      const sockets = await this.io.fetchSockets();
      const deviceSockets = sockets.filter(
        (socket) => socket.data.deviceId === deviceId.toString()
      );

      if (deviceSockets.length === 0) {
        logger.warn(`No active sockets for device: ${deviceId}`);
        return;
      }

      deviceSockets.forEach((socket) => {
        socket.emit(event, data);
      });

      logger.info(`Notified device ${deviceId} with event: ${event}`);
    } catch (error: any) {
      logger.error('Error notifying device:', error);
    }
  }

  async broadcastToUser(userId: string, event: string, data: any): Promise<void> {
    try {
      const sockets = await this.io.fetchSockets();
      const userSockets = sockets.filter(
        (socket) => socket.data.userId === userId
      );

      userSockets.forEach((socket) => {
        socket.emit(event, data);
      });

      logger.info(`Broadcasted to user ${userId} with event: ${event}`);
    } catch (error: any) {
      logger.error('Error broadcasting to user:', error);
    }
  }

  getConnectedDevices(): Promise<string[]> {
    return new Promise(async (resolve) => {
      try {
        const sockets = await this.io.fetchSockets();
        const deviceIds = sockets
          .map((socket) => socket.data.deviceId)
          .filter((id) => id !== undefined);
        resolve(deviceIds);
      } catch (error) {
        logger.error('Error getting connected devices:', error);
        resolve([]);
      }
    });
  }
}

