import { Socket, Server } from 'socket.io';
import Device from '../../models/Device';
import logger from '../../utils/logger';

export class ConnectionHandler {
  private socket: Socket;

  constructor(socket: Socket, _io: Server) {
    this.socket = socket;
    // io parameter kept for API consistency but not used
    this.setupEventHandlers();
  }

  private setupEventHandlers(): void {
    this.socket.on('device:connect', async (data: { deviceId: string; connectionToken: string }) => {
      await this.handleDeviceConnect(data);
    });

    this.socket.on('device:disconnect', async () => {
      await this.handleDeviceDisconnect();
    });

    this.socket.on('device:heartbeat', async (data: { deviceId: string }) => {
      await this.handleDeviceHeartbeat(data);
    });

    this.socket.on('disconnect', async () => {
      await this.handleSocketDisconnect();
    });
  }

  private async handleDeviceConnect(data: { deviceId: string; connectionToken: string }): Promise<void> {
    try {
      const { deviceId, connectionToken } = data;
      const userId = this.socket.data.userId;

      // If already authenticated via connectionToken, just verify and update status
      if (this.socket.data.isDevice && this.socket.data.device) {
        const device = this.socket.data.device;
        
        // Verify deviceId matches
        if (device.deviceId !== deviceId) {
          logger.warn(`Device connect failed - DeviceId mismatch: ${device.deviceId} vs ${deviceId}`);
          this.socket.emit('device:connect:error', 'Device ID mismatch');
          return;
        }

        // Update device status
        device.isOnline = true;
        device.lastSeen = new Date();
        device.ipAddress = this.socket.handshake.address;
        await device.save();

        this.socket.emit('device:connect:success', {
          deviceId: device.deviceId,
          authorizedPaths: device.authorizedPaths,
        });

        logger.info(`Device connected - Device: ${device.deviceId}, Name: ${device.deviceName}`);
        return;
      }

      // Legacy: Authenticate using deviceId and connectionToken (for authenticated users)
      const device = await Device.findOne({
        deviceId,
        connectionToken,
        ...(userId ? { userId } : {}), // Only check userId if provided
      });

      if (!device) {
        logger.warn(`Device registration failed - Invalid credentials for DeviceId: ${deviceId}`);
        this.socket.emit('device:connect:error', 'Invalid device credentials');
        return;
      }

      // Update device status
      device.isOnline = true;
      device.lastSeen = new Date();
      device.ipAddress = this.socket.handshake.address;
      await device.save();

      // Store device info in socket data
      this.socket.data.deviceId = device._id.toString();
      this.socket.data.device = device;

      this.socket.emit('device:connect:success', {
        deviceId: device.deviceId,
        authorizedPaths: device.authorizedPaths,
      });

      logger.info(`Device registered - Device: ${device.deviceId}, Name: ${device.deviceName}`);
    } catch (error: any) {
      logger.error(`Device connection failed - DeviceId: ${data.deviceId}, User: ${this.socket.data.userId}:`, error);
      this.socket.emit('device:connect:error', error.message || 'Connection failed');
    }
  }

  private async handleDeviceDisconnect(): Promise<void> {
    try {
      const deviceId = this.socket.data.deviceId;
      if (deviceId) {
        const device = await Device.findById(deviceId);
        if (device) {
          device.isOnline = false;
          device.lastSeen = new Date();
          await device.save();
          logger.info(`Device went offline - Device: ${device.deviceId}, Name: ${device.deviceName}`);
        }
      }
    } catch (error: any) {
      logger.error('Device disconnect error:', error);
    }
  }

  private async handleDeviceHeartbeat(data: { deviceId: string }): Promise<void> {
    try {
      const deviceId = this.socket.data.deviceId || data.deviceId;
      if (deviceId) {
        const device = await Device.findById(deviceId);
        if (device) {
          device.lastSeen = new Date();
          await device.save();
        }
      }
    } catch (error: any) {
      logger.error('Device heartbeat error:', error);
    }
  }

  private async handleSocketDisconnect(): Promise<void> {
    await this.handleDeviceDisconnect();
    // Don't log here - already logged in socket.io.ts
  }
}

