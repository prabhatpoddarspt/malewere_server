import { Socket, Server } from 'socket.io';
import fs from 'fs';
import path from 'path';
import Device from '../../models/Device';
import FileAccess from '../../models/FileAccess';
import { FileUtils } from '../../utils/fileUtils';
import logger from '../../utils/logger';
import { FileStreamRequest } from '../../types';

export class FileStreamHandler {
  private socket: Socket;
  private io: Server;
  private readonly CHUNK_SIZE = 64 * 1024; // 64KB chunks
  private activeStreams: Map<string, fs.ReadStream> = new Map();

  constructor(socket: Socket, io: Server) {
    this.socket = socket;
    this.io = io;
    this.setupEventHandlers();
  }

  private setupEventHandlers(): void {
    this.socket.on('stream:file:request', async (data: FileStreamRequest) => {
      await this.handleFileStreamRequest(data);
    });

    this.socket.on('stream:cancel', (data: { streamId: string }) => {
      this.handleStreamCancel(data.streamId);
    });
  }

  private async handleFileStreamRequest(data: FileStreamRequest): Promise<void> {
    const streamId = `${this.socket.id}-${Date.now()}`;
    
    try {
      const { path: filePath, deviceId } = data;
      const userId = this.socket.data.userId;

      // Verify device access
      const device = await Device.findById(deviceId);
      if (!device) {
        this.socket.emit('stream:error', { streamId, error: 'Device not found' });
        return;
      }

      // Verify user owns the device
      if (device.userId.toString() !== userId) {
        this.socket.emit('stream:error', { streamId, error: 'Unauthorized device access' });
        await this.logFileAccess(userId, deviceId, filePath, 'view', false);
        return;
      }

      // Check if path is authorized
      if (!FileUtils.isPathAuthorized(filePath, device.authorizedPaths)) {
        this.socket.emit('stream:error', { streamId, error: 'Path not authorized' });
        await this.logFileAccess(userId, deviceId, filePath, 'view', false);
        return;
      }

      // Validate and sanitize file path
      const sanitizedPath = FileUtils.sanitizePath(filePath);
      if (!sanitizedPath) {
        this.socket.emit('stream:error', { streamId, error: 'Invalid file path' });
        return;
      }

      // Check if file exists
      const fileStats = await fs.promises.stat(sanitizedPath);
      if (!fileStats.isFile()) {
        this.socket.emit('stream:error', { streamId, error: 'Path is not a file' });
        return;
      }

      // Stream file in chunks
      await this.streamFile(sanitizedPath, fileStats.size, streamId);

      // Log successful access
      await this.logFileAccess(userId, deviceId, filePath, 'view', true);
    } catch (error: any) {
      logger.error('File stream error:', error);
      this.socket.emit('stream:error', { streamId, error: error.message || 'Stream failed' });
    }
  }

  private async streamFile(filePath: string, fileSize: number, streamId: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const fileStream = fs.createReadStream(filePath, { highWaterMark: this.CHUNK_SIZE });
      let bytesRead = 0;

      this.activeStreams.set(streamId, fileStream);

      // Send stream start event
      this.socket.emit('stream:start', {
        streamId,
        totalSize: fileSize,
        fileName: path.basename(filePath),
      });

      fileStream.on('data', (chunk: Buffer) => {
        bytesRead += chunk.length;
        const progress = Math.round((bytesRead / fileSize) * 100);

        this.socket.emit('stream:chunk', {
          streamId,
          chunk: chunk.toString('base64'),
          progress,
          bytesRead,
        });
      });

      fileStream.on('end', () => {
        this.activeStreams.delete(streamId);
        this.socket.emit('stream:complete', {
          streamId,
          totalSize: fileSize,
        });
        resolve();
      });

      fileStream.on('error', (error) => {
        this.activeStreams.delete(streamId);
        this.socket.emit('stream:error', {
          streamId,
          error: error.message,
        });
        reject(error);
      });
    });
  }

  private handleStreamCancel(streamId: string): void {
    const stream = this.activeStreams.get(streamId);
    if (stream) {
      stream.destroy();
      this.activeStreams.delete(streamId);
      this.socket.emit('stream:cancelled', { streamId });
      logger.info(`Stream cancelled: ${streamId}`);
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
      await FileAccess.create({
        userId,
        deviceId,
        filePath,
        action: action as 'view' | 'download' | 'upload' | 'delete',
        success,
        ipAddress: this.socket.handshake.address,
        userAgent: this.socket.handshake.headers['user-agent'],
      });
    } catch (error) {
      logger.error('Failed to log file access:', error);
    }
  }
}

