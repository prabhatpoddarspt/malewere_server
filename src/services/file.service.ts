import fs from 'fs/promises';
import path from 'path';
import Device from '../models/Device';
import { FileUtils } from '../utils/fileUtils';
import logger from '../utils/logger';

export class FileService {
  async listDirectory(dirPath: string, deviceId: string): Promise<any[]> {
    // Verify device has access to this path
    const device = await Device.findById(deviceId);
    if (!device) {
      throw new Error('Device not found');
    }

    if (!FileUtils.isPathAuthorized(dirPath, device.authorizedPaths)) {
      throw new Error('Unauthorized path');
    }

    const sanitizedPath = FileUtils.sanitizePath(dirPath);
    if (!sanitizedPath) {
      throw new Error('Invalid path');
    }

    try {
      const entries = await fs.readdir(sanitizedPath, { withFileTypes: true });

      const files = await Promise.all(
        entries.map(async (entry) => {
          try {
            const fullPath = path.join(sanitizedPath, entry.name);
            const stats = await fs.stat(fullPath);

            return {
              name: entry.name,
              path: fullPath,
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

      return files.filter((file) => file !== null);
    } catch (error: any) {
      logger.error('Error listing directory:', error);
      throw new Error(`Failed to list directory: ${error.message}`);
    }
  }

  async getFileInfo(filePath: string, deviceId: string): Promise<any> {
    const device = await Device.findById(deviceId);
    if (!device) {
      throw new Error('Device not found');
    }

    if (!FileUtils.isPathAuthorized(filePath, device.authorizedPaths)) {
      throw new Error('Unauthorized path');
    }

    const sanitizedPath = FileUtils.sanitizePath(filePath);
    if (!sanitizedPath) {
      throw new Error('Invalid path');
    }

    try {
      const stats = await fs.stat(sanitizedPath);

      if (stats.isDirectory()) {
        throw new Error('Path is a directory, not a file');
      }

      return {
        path: sanitizedPath,
        name: path.basename(sanitizedPath),
        size: stats.size,
        type: 'file',
        modified: stats.mtime,
        created: stats.birthtime,
        permissions: FileUtils.getPermissions(stats),
      };
    } catch (error: any) {
      logger.error('Error getting file info:', error);
      throw new Error(`Failed to get file info: ${error.message}`);
    }
  }

  async searchFiles(searchPath: string, searchTerm: string, deviceId: string): Promise<any[]> {
    const device = await Device.findById(deviceId);
    if (!device) {
      throw new Error('Device not found');
    }

    if (!FileUtils.isPathAuthorized(searchPath, device.authorizedPaths)) {
      throw new Error('Unauthorized path');
    }

    const sanitizedPath = FileUtils.sanitizePath(searchPath);
    if (!sanitizedPath) {
      throw new Error('Invalid path');
    }

    const results: any[] = [];

    try {
      await this.searchDirectory(sanitizedPath, searchTerm, device.authorizedPaths, results);
      return results;
    } catch (error: any) {
      logger.error('Error searching files:', error);
      throw new Error(`Failed to search files: ${error.message}`);
    }
  }

  private async searchDirectory(
    dirPath: string,
    searchTerm: string,
    authorizedPaths: string[],
    results: any[],
    maxDepth: number = 10,
    currentDepth: number = 0
  ): Promise<void> {
    if (currentDepth >= maxDepth) {
      return;
    }

    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);

        // Check if path is still authorized
        if (!FileUtils.isPathAuthorized(fullPath, authorizedPaths)) {
          continue;
        }

        // Check if filename matches search term
        if (entry.name.toLowerCase().includes(searchTerm.toLowerCase())) {
          try {
            const stats = await fs.stat(fullPath);
            results.push({
              name: entry.name,
              path: fullPath,
              type: entry.isDirectory() ? 'directory' : 'file',
              size: stats.size,
              modified: stats.mtime,
            });
          } catch (error) {
            // Skip files that can't be accessed
            continue;
          }
        }

        // Recursively search subdirectories
        if (entry.isDirectory()) {
          await this.searchDirectory(fullPath, searchTerm, authorizedPaths, results, maxDepth, currentDepth + 1);
        }
      }
    } catch (error) {
      // Skip directories that can't be accessed
      return;
    }
  }
}

