import AuditLog from '../models/AuditLog';
import logger from './logger';

interface AuditLogData {
  userId?: string;
  action: string;
  resource: string;
  resourceId?: string;
  details?: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
  success: boolean;
}

/**
 * Safely create an audit log entry without throwing errors.
 * This function is fire-and-forget to prevent audit logging failures
 * from breaking the main application flow.
 */
export const safeAuditLog = async (data: AuditLogData): Promise<void> => {
  try {
    await AuditLog.create({
      userId: data.userId,
      action: data.action,
      resource: data.resource,
      resourceId: data.resourceId,
      details: data.details,
      ipAddress: data.ipAddress || 'unknown',
      userAgent: data.userAgent,
      success: data.success,
    });
  } catch (error: any) {
    // Log the error but don't throw - audit logging failures shouldn't break the app
    logger.error('Failed to create audit log:', {
      action: data.action,
      resource: data.resource,
      error: error.message,
      stack: error.stack,
    });
  }
};

/**
 * Create audit log entry in a non-blocking way (fire-and-forget).
 * Use this when you don't want to wait for audit logging to complete.
 */
export const auditLogAsync = (data: AuditLogData): void => {
  // Don't await - fire and forget
  safeAuditLog(data).catch((error) => {
    // This should never happen since safeAuditLog doesn't throw,
    // but just in case
    logger.error('Unexpected error in auditLogAsync:', error);
  });
};


