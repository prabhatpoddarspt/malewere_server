import { Server as HTTPServer } from 'http';
import { Server as SocketIOServer, Socket } from 'socket.io';
import { AuthService } from '../services/auth.service';
import { FileStreamHandler } from './handlers/fileStream.handler';
import { ConnectionHandler } from './handlers/connection.handler';
import { DeviceFileBridgeHandler, pendingRequests } from './handlers/deviceFileBridge.handler';
import { authenticateDevice } from '../middleware/deviceAuth.middleware';
import { config } from '../config/environment';
import logger from '../utils/logger';

export class SocketServer {
  private io: SocketIOServer;
  private authService: AuthService;

  constructor(httpServer: HTTPServer) {
    this.io = new SocketIOServer(httpServer, {
      cors: {
        origin: config.cors.origin,
        methods: ['GET', 'POST'],
        credentials: true,
      },
      transports: ['websocket', 'polling'],
      path: config.websocket.path,
      pingTimeout: config.websocket.pingTimeout,
      pingInterval: config.websocket.pingInterval,
    });

    this.authService = new AuthService();
    this.setupMiddleware();
    this.setupHandlers();
  }

  private setupMiddleware(): void {
    // First try device authentication (connectionToken)
    this.io.use(authenticateDevice);
    
    // Then try JWT authentication (for admin panel)
    this.io.use(async (socket, next) => {
      try {
        // Skip if already authenticated as device
        if (socket.data.isDevice) {
          return next();
        }

        const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
        
        if (!token) {
          return next(new Error('Authentication error: No token provided'));
        }

        const decoded = this.authService.verifyToken(token);
        
        if (decoded.type !== 'access') {
          return next(new Error('Authentication error: Invalid token type'));
        }

        socket.data.userId = decoded.userId;
        socket.data.role = decoded.role;
        socket.data.connectionType = 'Admin Panel (Web)';
        
        next();
      } catch (error: any) {
        logger.error('Socket authentication error:', error);
        next(new Error('Authentication error: Invalid or expired token'));
      }
    });
  }

  private setupHandlers(): void {
    this.io.on('connection', (socket) => {
      // Use connection type from authentication
      const connectionType = socket.data.connectionType || 'Unknown';
      
      logger.info(`${connectionType} connected - Socket: ${socket.id}, User: ${socket.data.userId || 'N/A'}`);

      // Initialize handlers
      new ConnectionHandler(socket, this.io);
      new FileStreamHandler(socket, this.io);
      
      // Initialize device file bridge handler for admin panel connections
      if (socket.data.connectionType === 'Admin Panel (Web)') {
        new DeviceFileBridgeHandler(socket, this.io);
      }
      
      // Setup device response forwarding for device connections
      if (socket.data.isDevice) {
        this.setupDeviceResponseForwarding(socket);
      }

      socket.on('disconnect', (reason) => {
        const connectionType = socket.data.connectionType || 'Unknown';
        logger.info(`${connectionType} disconnected - Socket: ${socket.id}, User: ${socket.data.userId || 'N/A'}, Reason: ${reason}`);
      });

      socket.on('error', (error) => {
        logger.error(`Socket error - Socket: ${socket.id}, User: ${socket.data.userId}:`, error);
      });
    });
  }

  private setupDeviceResponseForwarding(deviceSocket: Socket): void {
    logger.info(`[SocketIO] Setting up response forwarding for device socket: ${deviceSocket.id}, deviceId: ${deviceSocket.data.deviceId || 'unknown'}`);
    
    // Forward device responses to waiting admin panel sockets
    const forwardToAdmin = (eventName: string, data: any) => {
      logger.info(`[SocketIO] === DEVICE RESPONSE RECEIVED ===`);
      logger.info(`[SocketIO] Event: ${eventName}, DeviceSocketId: ${deviceSocket.id}, Data: ${JSON.stringify(data)}`);
      
      const requestId = data.requestId;
      if (!requestId) {
        logger.warn(`[SocketIO] Device response missing requestId - event: ${eventName}, data: ${JSON.stringify(data)}`);
        return;
      }

      logger.info(`[SocketIO] Device response received - event: ${eventName}, requestId: ${requestId}, deviceSocketId: ${deviceSocket.id}`);

      const pendingRequest = pendingRequests.get(requestId);
      if (!pendingRequest) {
        logger.warn(`[SocketIO] No pending request found for requestId: ${requestId}, event: ${eventName}`);
        logger.warn(`[SocketIO] Available pending requests: ${Array.from(pendingRequests.keys()).join(', ')}`);
        return; // No matching request found
      }

      logger.info(`[SocketIO] Found pending request - requestId: ${requestId}, adminSocketId: ${pendingRequest.adminSocketId}, deviceId: ${pendingRequest.deviceId}`);

      // Forward to the admin socket that made the request
      const adminSocket = this.io.sockets.sockets.get(pendingRequest.adminSocketId);
      if (adminSocket) {
        logger.info(`[SocketIO] Forwarding response to admin socket - event: ${eventName}, requestId: ${requestId}, adminSocketId: ${pendingRequest.adminSocketId}`);
        logger.info(`[SocketIO] Response data: ${JSON.stringify(data)}`);
        adminSocket.emit(eventName, data);
        logger.info(`[SocketIO] Response forwarded successfully`);

        // Clean up if request is complete
        if (eventName.includes('complete') || eventName.includes('error') || eventName.includes('response')) {
          // Clear timeout if exists
          if (pendingRequest.timeout) {
            clearTimeout(pendingRequest.timeout);
          }
          pendingRequests.delete(requestId);
          logger.info(`[SocketIO] Cleaned up pending request - requestId: ${requestId}`);
        }
      } else {
        // Admin socket disconnected, clean up
        logger.warn(`[SocketIO] Admin socket not found - adminSocketId: ${pendingRequest.adminSocketId}, requestId: ${requestId}`);
        // Clear timeout if exists
        if (pendingRequest.timeout) {
          clearTimeout(pendingRequest.timeout);
        }
        pendingRequests.delete(requestId);
      }
    };

    deviceSocket.on('file:list:response', (data: any) => {
      forwardToAdmin('device:file:list:response', data);
    });

    deviceSocket.on('file:stream:start', (data: any) => {
      forwardToAdmin('device:file:stream:start', data);
    });

    deviceSocket.on('file:stream:chunk', (data: any) => {
      forwardToAdmin('device:file:stream:chunk', data);
    });

    deviceSocket.on('file:stream:complete', (data: any) => {
      forwardToAdmin('device:file:stream:complete', data);
    });

    deviceSocket.on('file:stream:error', (data: any) => {
      forwardToAdmin('device:file:stream:error', data);
    });

    deviceSocket.on('file:metadata:response', (data: any) => {
      forwardToAdmin('device:file:metadata:response', data);
    });

    // Media stream events - forward directly without requestId matching
    deviceSocket.on('camera:stream:started', (data: any) => {
      logger.info(`[SocketIO] Camera stream started from device: ${deviceSocket.id}`);
      // Broadcast to all admin sockets watching this device
      this.io.to('admin').emit('device:camera:stream:started', {
        deviceId: deviceSocket.data.deviceId,
        ...data,
      });
    });

    deviceSocket.on('camera:stream:stopped', (data: any) => {
      logger.info(`[SocketIO] Camera stream stopped from device: ${deviceSocket.id}`);
      this.io.to('admin').emit('device:camera:stream:stopped', {
        deviceId: deviceSocket.data.deviceId,
        ...data,
      });
    });

    deviceSocket.on('camera:stream:frame', (data: any) => {
      // Forward camera frames to all admin sockets
      this.io.to('admin').emit('device:camera:stream:frame', {
        deviceId: deviceSocket.data.deviceId,
        data: data.data,
        timestamp: data.timestamp,
      });
    });

    deviceSocket.on('camera:stream:error', (data: any) => {
      logger.warn(`[SocketIO] Camera stream error from device: ${deviceSocket.id}`);
      this.io.to('admin').emit('device:camera:stream:error', {
        deviceId: deviceSocket.data.deviceId,
        ...data,
      });
    });

    deviceSocket.on('microphone:stream:started', (data: any) => {
      logger.info(`[SocketIO] Microphone stream started from device: ${deviceSocket.id}, deviceId: ${deviceSocket.data.deviceId}`);
      this.io.to('admin').emit('device:microphone:stream:started', {
        deviceId: deviceSocket.data.deviceId,
        ...data,
      });
    });

    deviceSocket.on('microphone:stream:stopped', (data: any) => {
      logger.info(`[SocketIO] Microphone stream stopped from device: ${deviceSocket.id}`);
      this.io.to('admin').emit('device:microphone:stream:stopped', {
        deviceId: deviceSocket.data.deviceId,
        ...data,
      });
    });

    deviceSocket.on('microphone:stream:chunk', (data: any) => {
      // Forward audio chunks to all admin sockets
      logger.debug(`[SocketIO] Forwarding microphone chunk from device: ${deviceSocket.data.deviceId}, data size: ${data.data?.length || 0}`);
      this.io.to('admin').emit('device:microphone:stream:chunk', {
        deviceId: deviceSocket.data.deviceId,
        data: data.data,
        sampleRate: data.sampleRate,
        timestamp: data.timestamp,
        channels: data.channels,
      });
    });

    deviceSocket.on('microphone:stream:error', (data: any) => {
      logger.warn(`[SocketIO] Microphone stream error from device: ${deviceSocket.id}`);
      this.io.to('admin').emit('device:microphone:stream:error', {
        deviceId: deviceSocket.data.deviceId,
        ...data,
      });
    });
  }

  getIO(): SocketIOServer {
    return this.io;
  }
}

