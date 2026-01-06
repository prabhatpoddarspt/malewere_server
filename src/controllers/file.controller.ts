import { Response } from 'express';
import { AuthenticatedRequest } from '../types';
import { FileService } from '../services/file.service';
import Device from '../models/Device';
import FileAccess from '../models/FileAccess';
import User from '../models/User';
import logger from '../utils/logger';
import { config } from '../config/environment';
import { FileUtils } from '../utils/fileUtils';
import fs from 'fs/promises';
import fsSync from 'fs';
import path from 'path';
import multer from 'multer';
import mongoose from 'mongoose';
// import { Server as SocketIOServer } from 'socket.io'; // Unused import

const fileService = new FileService();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    const uploadDir = config.file.uploadDir;
    FileUtils.ensureDirectoryExists(uploadDir);
    cb(null, uploadDir);
  },
  filename: (_req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({
  storage,
  limits: {
    fileSize: config.file.maxSize,
  },
  fileFilter: (_req, file, cb) => {
    const allowedTypes = config.file.allowedTypes;
    if (FileUtils.isAllowedFileType(file.originalname, allowedTypes)) {
      cb(null, true);
    } else {
      cb(new Error(`File type not allowed. Allowed types: ${allowedTypes.join(', ')}`));
    }
  },
});

export const uploadMiddleware = upload.single('file');

export class FileController {
  listFiles = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    let dirPath: string | undefined;
    try {
      let { path: pathParam, deviceId } = req.query;
      dirPath = pathParam as string;

      logger.info(`[FileController] listFiles request - deviceId: ${deviceId}, path: ${dirPath}, userId: ${req.user?.userId || 'N/A'}`);

      // Check if deviceId is provided
      if (!deviceId || (typeof deviceId === 'string' && deviceId.trim() === '')) {
        logger.warn(`[FileController] List files failed: Missing required parameter - deviceId`);
        res.status(400).json({ 
          error: 'Missing required parameter',
          missing: ['deviceId'],
          required: ['deviceId'],
          hint: 'deviceId is required. Example: /api/files/list?path=/Users/username/Documents&deviceId=your-device-id',
        });
        return;
      }

      // Get device to check status and authorized paths
      logger.info(`[FileController] Looking up device with ID: ${deviceId}`);
      const device = await Device.findById(deviceId as string);
      if (!device) {
        logger.warn(`[FileController] Device not found: ${deviceId}`);
        res.status(404).json({ error: 'Device not found' });
        return;
      }

      logger.info(`[FileController] Device found - deviceId: ${device.deviceId}, deviceName: ${device.deviceName}, isOnline: ${device.isOnline}, authorizedPaths: ${JSON.stringify(device.authorizedPaths)}`);

      // Check if device is online
      if (!device.isOnline) {
        logger.warn(`[FileController] Device is offline - deviceId: ${device.deviceId}, isOnline: ${device.isOnline}`);
        res.status(503).json({ 
          error: 'Device is offline',
          message: 'The device must be online and connected via WebSocket to list files',
          hint: 'Please ensure the device is connected and try again',
          deviceId: device.deviceId,
          deviceName: device.deviceName,
        });
        return;
      }

      // If path is empty or not provided, default to first authorized path
      if (!dirPath || (typeof dirPath === 'string' && dirPath.trim() === '')) {
        logger.info(`[FileController] Path is empty, checking authorized paths`);
        if (!device.authorizedPaths || device.authorizedPaths.length === 0) {
          logger.warn(`[FileController] No authorized paths configured for device: ${device.deviceId}`);
          res.status(400).json({ 
            error: 'No authorized paths configured for this device',
            hint: 'Please configure authorized paths for the device first',
          });
          return;
        }

        // Use the first authorized path as default
        dirPath = device.authorizedPaths[0];
        logger.info(`[FileController] Using default authorized path: ${dirPath}`);
      }

      logger.info(`[FileController] Processing path: ${dirPath}`);

      // Check if this is a device path (Android paths that don't exist on server)
      const devicePathPatterns = [
        /^\/storage\//,
        /^\/sdcard\//,
        /^\/data\//,
        /^\/mnt\//,
        /^\/system\//,
      ];
      
      const isDevicePath = devicePathPatterns.some(pattern => pattern.test(dirPath as string));
      logger.info(`[FileController] Path check - isDevicePath: ${isDevicePath}, path: ${dirPath}`);
      
      if (isDevicePath) {
        logger.warn(`[FileController] Device path detected - cannot access via REST API. Path: ${dirPath}, deviceId: ${device.deviceId}`);
        res.status(503).json({ 
          error: 'Device path cannot be accessed via REST API',
          message: 'Device paths (like /storage/emulated/0) exist only on the device, not on the server',
          hint: 'Please use WebSocket connection to access device files. The admin panel should automatically use WebSocket when the device is online.',
          devicePath: dirPath,
          solution: 'Ensure the device is online and the admin panel is using WebSocket for file operations',
        });
        return;
      }

      logger.info(`[FileController] Attempting to list directory via fileService - path: ${dirPath}, deviceId: ${deviceId}`);
      const files = await fileService.listDirectory(dirPath as string, deviceId as string);
      logger.info(`[FileController] Successfully listed directory - found ${files.length} items`);

      // Log file access (userId may be null for anonymous devices)
      await FileAccess.create({
        userId: req.user?.userId || undefined,
        deviceId: deviceId as string,
        filePath: dirPath as string,
        action: 'view',
        success: true,
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
      });

      res.json({ files });
      logger.info(`[FileController] Successfully returned file list - count: ${files.length}`);
    } catch (error: any) {
      const errorDeviceId = (req.query.deviceId as string) || 'unknown';
      const errorPath = (req.query.path as string) || dirPath || 'unknown';
      logger.error(`[FileController] List files error - deviceId: ${errorDeviceId}, path: ${errorPath}, error:`, error);

      // Log file access failure
      if (req.query.deviceId) {
        FileAccess.create({
          userId: req.user?.userId || req.device?.userId || undefined,
          deviceId: req.query.deviceId as string,
          filePath: (req.query.path as string) || '',
          action: 'view',
          success: false,
          ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
          userAgent: req.get('user-agent'),
        }).catch((logError) => {
          logger.error('Failed to log file access:', logError);
        });
      }

      // Provide better error messages for common issues
      if (error.message?.includes('ENOENT') || error.message?.includes('no such file or directory')) {
        res.status(404).json({ 
          error: 'Path not found on server',
          message: 'The requested path does not exist on the server. Device paths cannot be accessed directly via REST API.',
          hint: 'File operations on device paths should be performed via WebSocket when the device is connected',
          devicePath: dirPath,
          note: 'Device paths (like /storage/emulated/0) exist only on the device, not on the server',
        });
        return;
      }

      // Handle other errors
      if (!res.headersSent) {
        res.status(500).json({ error: error.message || 'Failed to list files' });
      }
    }
  };

  getFileInfo = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { path: filePath, deviceId } = req.query;

      const missing = [];
      if (!filePath || (typeof filePath === 'string' && filePath.trim() === '')) {
        missing.push('path');
      }
      if (!deviceId || (typeof deviceId === 'string' && deviceId.trim() === '')) {
        missing.push('deviceId');
      }

      if (missing.length > 0) {
        logger.warn(`Get file info failed: Missing or empty required parameters - ${missing.join(', ')}`);
        res.status(400).json({ 
          error: 'Missing or empty required parameters',
          missing,
          required: ['path', 'deviceId'],
        });
        return;
      }

      const fileInfo = await fileService.getFileInfo(filePath as string, deviceId as string);

      res.json({ file: fileInfo });
    } catch (error: any) {
      logger.error('Get file info error:', error);
      res.status(500).json({ error: error.message || 'Failed to get file info' });
    }
  };

  downloadFile = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { path: filePath, deviceId } = req.query;

      const missing = [];
      if (!filePath || (typeof filePath === 'string' && filePath.trim() === '')) {
        missing.push('path');
      }
      if (!deviceId || (typeof deviceId === 'string' && deviceId.trim() === '')) {
        missing.push('deviceId');
      }

      if (missing.length > 0) {
        logger.warn(`Download file failed: Missing or empty required parameters - ${missing.join(', ')}`);
        res.status(400).json({ 
          error: 'Missing or empty required parameters',
          missing,
          required: ['path', 'deviceId'],
        });
        return;
      }

      const device = await Device.findById(deviceId);
      if (!device) {
        res.status(404).json({ error: 'Device not found' });
        return;
      }

      // Check permissions (skip for device authentication)
      if (req.device) {
        // Device authenticated, allow download if path is authorized
      } else {
        const user = req.user;
        if (!user) {
          res.status(401).json({ error: 'Unauthorized' });
          return;
        }
        if (user.role !== 'admin') {
          // Check user permissions
          const userDoc = await User.findById(user.userId);
          if (!userDoc?.permissions.canDownload) {
            res.status(403).json({ error: 'Download permission denied' });
            return;
          }
        }
      }

      const sanitizedPath = FileUtils.sanitizePath(filePath as string);
      if (!sanitizedPath || !FileUtils.isPathAuthorized(sanitizedPath, device.authorizedPaths)) {
        res.status(403).json({ error: 'Unauthorized path' });
        return;
      }

      const stats = await fs.stat(sanitizedPath);
      if (stats.isDirectory()) {
        res.status(400).json({ error: 'Path is a directory' });
        return;
      }

      // Log successful download
      await FileAccess.create({
        userId: req.user?.userId || req.device?.userId || undefined,
        deviceId: deviceId as string,
        filePath: sanitizedPath,
        action: 'download',
        success: true,
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
      });

      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${path.basename(sanitizedPath)}"`);
      res.setHeader('Content-Length', stats.size.toString());

      const fileStream = fsSync.createReadStream(sanitizedPath);
      fileStream.pipe(res);
    } catch (error: any) {
      logger.error('Download file error:', error);

      if (req.query.deviceId) {
        await FileAccess.create({
          userId: req.user?.userId || req.device?.userId || undefined,
          deviceId: req.query.deviceId as string,
          filePath: (req.query.path as string) || '',
          action: 'download',
          success: false,
          ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
          userAgent: req.get('user-agent'),
        });
      }

      res.status(500).json({ error: error.message || 'Failed to download file' });
    }
  };

  uploadFile = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { deviceId, targetPath } = req.body;

      if (!deviceId || !req.file) {
        res.status(400).json({ error: 'deviceId and file are required' });
        return;
      }

      const device = await Device.findById(deviceId);
      if (!device) {
        res.status(404).json({ error: 'Device not found' });
        return;
      }

      // Check permissions (skip for device authentication)
      if (req.device) {
        // Device authenticated, allow upload if path is authorized
      } else {
        const user = req.user;
        if (!user) {
          res.status(401).json({ error: 'Unauthorized' });
          return;
        }
        if (user.role !== 'admin') {
          const userDoc = await User.findById(user.userId);
          if (!userDoc?.permissions.canUpload) {
            res.status(403).json({ error: 'Upload permission denied' });
            return;
          }
        }
      }

      const finalPath = targetPath
        ? path.join(targetPath, req.file.filename)
        : path.join(config.file.uploadDir, req.file.filename);

      const sanitizedPath = FileUtils.sanitizePath(finalPath);
      
      // If uploading to default uploads directory, allow it without device path authorization
      // Normalize paths for comparison (handle both relative and absolute)
      const uploadsDirNormalized = path.resolve(config.file.uploadDir);
      const sanitizedPathNormalized = sanitizedPath ? path.resolve(sanitizedPath) : '';
      const isUploadsDir = sanitizedPath && sanitizedPathNormalized.startsWith(uploadsDirNormalized);
      
      if (!sanitizedPath || (!isUploadsDir && !FileUtils.isPathAuthorized(sanitizedPath, device.authorizedPaths))) {
        // Delete uploaded file
        await fs.unlink(req.file.path).catch(() => {});
        res.status(403).json({ 
          error: 'Unauthorized path',
          message: isUploadsDir 
            ? 'Failed to upload to uploads directory' 
            : 'The target path is not authorized for this device',
        });
        return;
      }

      // Move file to target location if specified
      if (targetPath) {
        FileUtils.ensureDirectoryExists(path.dirname(sanitizedPath));
        await fs.rename(req.file.path, sanitizedPath);
      }

      // Log successful upload
      await FileAccess.create({
        userId: req.user?.userId || req.device?.userId || undefined,
        deviceId: deviceId,
        filePath: sanitizedPath,
        action: 'upload',
        success: true,
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
      });

      res.status(201).json({
        message: 'File uploaded successfully',
        file: {
          name: req.file.filename,
          path: sanitizedPath,
          size: req.file.size,
        },
      });
    } catch (error: any) {
      logger.error('Upload file error:', error);
      if (req.file) {
        await fs.unlink(req.file.path).catch(() => {});
      }
      res.status(500).json({ error: error.message || 'Failed to upload file' });
    }
  };

  deleteFile = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { path: filePath, deviceId } = req.query;

      const missing = [];
      if (!filePath || (typeof filePath === 'string' && filePath.trim() === '')) {
        missing.push('path');
      }
      if (!deviceId || (typeof deviceId === 'string' && deviceId.trim() === '')) {
        missing.push('deviceId');
      }

      if (missing.length > 0) {
        logger.warn(`Delete file failed: Missing or empty required parameters - ${missing.join(', ')}`);
        res.status(400).json({ 
          error: 'Missing or empty required parameters',
          missing,
          required: ['path', 'deviceId'],
        });
        return;
      }

      const device = await Device.findById(deviceId);
      if (!device) {
        res.status(404).json({ error: 'Device not found' });
        return;
      }

      // Check permissions (skip for device authentication)
      if (req.device) {
        // Device authenticated, allow delete if path is authorized
      } else {
        const user = req.user;
        if (!user) {
          res.status(401).json({ error: 'Unauthorized' });
          return;
        }
        if (user.role !== 'admin') {
          const userDoc = await User.findById(user.userId);
          if (!userDoc?.permissions.canDelete) {
            res.status(403).json({ error: 'Delete permission denied' });
            return;
          }
        }
      }

      const sanitizedPath = FileUtils.sanitizePath(filePath as string);
      if (!sanitizedPath || !FileUtils.isPathAuthorized(sanitizedPath, device.authorizedPaths)) {
        res.status(403).json({ error: 'Unauthorized path' });
        return;
      }

      await fs.unlink(sanitizedPath);

      // Log successful deletion
      await FileAccess.create({
        userId: req.user?.userId || req.device?.userId || undefined,
        deviceId: deviceId as string,
        filePath: sanitizedPath,
        action: 'delete',
        success: true,
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
      });

      res.json({ message: 'File deleted successfully' });
    } catch (error: any) {
      logger.error('Delete file error:', error);

      if (req.query.deviceId) {
        await FileAccess.create({
          userId: req.user?.userId || req.device?.userId || undefined,
          deviceId: req.query.deviceId as string,
          filePath: (req.query.path as string) || '',
          action: 'delete',
          success: false,
          ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
          userAgent: req.get('user-agent'),
        });
      }

      res.status(500).json({ error: error.message || 'Failed to delete file' });
    }
  };

  searchFiles = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { path: searchPath, term, deviceId } = req.query;

      const missing = [];
      if (!searchPath || (typeof searchPath === 'string' && searchPath.trim() === '')) {
        missing.push('path');
      }
      if (!term || (typeof term === 'string' && term.trim() === '')) {
        missing.push('term');
      }
      if (!deviceId || (typeof deviceId === 'string' && deviceId.trim() === '')) {
        missing.push('deviceId');
      }

      if (missing.length > 0) {
        logger.warn(`Search files failed: Missing or empty required parameters - ${missing.join(', ')}`);
        res.status(400).json({ 
          error: 'Missing or empty required parameters',
          missing,
          required: ['path', 'term', 'deviceId'],
        });
        return;
      }

      const results = await fileService.searchFiles(
        searchPath as string,
        term as string,
        deviceId as string
      );

      res.json({ results });
    } catch (error: any) {
      logger.error('Search files error:', error);
      res.status(500).json({ error: error.message || 'Failed to search files' });
    }
  };

  listUploads = async (_req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      // Public endpoint - no authentication required
      const uploadsDir = config.file.uploadDir;
      
      try {
        const entries = await fs.readdir(uploadsDir, { withFileTypes: true });

        const files = await Promise.all(
          entries.map(async (entry) => {
            try {
              const fullPath = path.join(uploadsDir, entry.name);
              const stats = await fs.stat(fullPath);

              return {
                name: entry.name,
                path: fullPath,
                relativePath: entry.name,
                type: entry.isDirectory() ? 'directory' : 'file',
                size: stats.size,
                modified: stats.mtime,
                created: stats.birthtime,
                permissions: FileUtils.getPermissions(stats),
              };
            } catch (error) {
              logger.error(`Error reading file entry ${entry.name}:`, error);
              return null;
            }
          })
        );

        const validFiles = files.filter((file) => file !== null);

        res.json({ 
          files: validFiles,
          count: validFiles.length,
          directory: uploadsDir,
        });
      } catch (error: any) {
        if (error.code === 'ENOENT') {
          res.status(404).json({ 
            error: 'Uploads directory not found',
            path: uploadsDir,
          });
          return;
        }
        throw error;
      }
    } catch (error: any) {
      logger.error('List uploads error:', error);
      res.status(500).json({ error: error.message || 'Failed to list uploads' });
    }
  };

  logFileAccess = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { filePath, deviceId, action, success } = req.body;

      if (!filePath || !deviceId || !action) {
        res.status(400).json({ 
          error: 'Missing required fields',
          required: ['filePath', 'deviceId', 'action'],
          received: { filePath, deviceId, action, success },
        });
        return;
      }

      // Validate action
      const validActions = ['view', 'download', 'upload', 'delete'];
      if (!validActions.includes(action)) {
        res.status(400).json({ 
          error: 'Invalid action',
          validActions,
          received: action,
        });
        return;
      }

      // Get device to validate it exists
      // deviceId can be either MongoDB _id (ObjectId) or deviceId (string)
      const isObjectId = mongoose.Types.ObjectId.isValid(deviceId);
      const device = isObjectId 
        ? await Device.findById(deviceId)
        : await Device.findOne({ deviceId: deviceId });
      
      if (!device) {
        res.status(404).json({ error: 'Device not found' });
        return;
      }

      // Log file access - use device's MongoDB _id
      await FileAccess.create({
        userId: req.user?.userId || req.device?.userId || undefined,
        deviceId: device._id, // Use MongoDB _id, not the string deviceId
        filePath: filePath,
        action: action,
        success: success !== undefined ? success : true,
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
      });

      res.json({ 
        message: 'File access logged successfully',
        logged: {
          filePath,
          deviceId,
          action,
          success: success !== undefined ? success : true,
        },
      });
    } catch (error: any) {
      logger.error('Log file access error:', error);
      res.status(500).json({ error: error.message || 'Failed to log file access' });
    }
  };
}

