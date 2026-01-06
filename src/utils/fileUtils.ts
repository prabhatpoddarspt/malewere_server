import path from 'path';
import fs from 'fs';

export class FileUtils {
  static sanitizePath(filePath: string): string | null {
    if (!filePath || typeof filePath !== 'string') {
      return null;
    }
    
    // Prevent path traversal attacks
    const normalized = path.normalize(filePath);
    
    // Check for path traversal attempts
    if (normalized.includes('..')) {
      return null;
    }
    
    // Allow absolute paths (they will be checked against authorized paths)
    return normalized;
  }

  static isPathAuthorized(filePath: string, authorizedPaths: string[]): boolean {
    if (!authorizedPaths || authorizedPaths.length === 0) {
      return false;
    }

    const normalizedFilePath = path.normalize(filePath);
    
    return authorizedPaths.some((authorizedPath) => {
      const normalizedAuthPath = path.normalize(authorizedPath);
      return normalizedFilePath.startsWith(normalizedAuthPath);
    });
  }

  static getFileExtension(filename: string): string {
    return path.extname(filename).toLowerCase().replace('.', '');
  }

  static isAllowedFileType(filename: string, allowedTypes: string[]): boolean {
    const extension = this.getFileExtension(filename);
    return allowedTypes.includes(extension);
  }

  static ensureDirectoryExists(dirPath: string): void {
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
    }
  }

  static getPermissions(stats: fs.Stats): string {
    return (stats.mode & parseInt('777', 8)).toString(8);
  }
}

