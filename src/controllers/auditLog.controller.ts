import { Response } from 'express';
import { AuthenticatedRequest } from '../types';
import AuditLog from '../models/AuditLog';
import logger from '../utils/logger';

export class AuditLogController {
  getAuditLogs = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const pageSize = parseInt(req.query.pageSize as string) || 10;
      const action = req.query.action as string;
      const resource = req.query.resource as string;
      const success = req.query.success as string;
      const userId = req.query.userId as string;
      const startDate = req.query.startDate as string;
      const endDate = req.query.endDate as string;

      const query: any = {};

      // Build query filters
      if (action) {
        query.action = action;
      }

      if (resource) {
        query.resource = resource;
      }

      if (success !== undefined) {
        query.success = success === 'true';
      }

      if (userId) {
        query.userId = userId;
      } else if (req.user?.role !== 'admin') {
        // Non-admin users can only see their own logs
        query.userId = req.user?.userId;
      }

      if (startDate || endDate) {
        query.timestamp = {};
        if (startDate) {
          query.timestamp.$gte = new Date(startDate);
        }
        if (endDate) {
          query.timestamp.$lte = new Date(endDate);
        }
      }

      // Calculate pagination
      const skip = (page - 1) * pageSize;

      // Get total count for pagination
      const total = await AuditLog.countDocuments(query);

      // Get audit logs with pagination
      const auditLogs = await AuditLog.find(query)
        .populate('userId', 'email')
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(pageSize)
        .lean();

      res.json({
        auditLogs,
        pagination: {
          page,
          pageSize,
          total,
          totalPages: Math.ceil(total / pageSize),
        },
      });
    } catch (error: any) {
      logger.error('Get audit logs error:', error);
      res.status(500).json({ error: 'Failed to fetch audit logs' });
    }
  };

  getAuditLogById = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      const auditLog = await AuditLog.findById(id).populate('userId', 'email').lean();

      if (!auditLog) {
        res.status(404).json({ error: 'Audit log not found' });
        return;
      }

      // Non-admin users can only see their own logs
      if (req.user?.role !== 'admin' && auditLog.userId?.toString() !== req.user?.userId) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }

      res.json({ auditLog });
    } catch (error: any) {
      logger.error('Get audit log error:', error);
      res.status(500).json({ error: 'Failed to fetch audit log' });
    }
  };

  getAuditLogStats = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const userId = req.user?.role !== 'admin' ? req.user?.userId : undefined;

      const query: any = {};
      if (userId) {
        query.userId = userId;
      }

      const [
        totalLogs,
        successfulLogs,
        failedLogs,
        logsByAction,
        logsByResource,
      ] = await Promise.all([
        AuditLog.countDocuments(query),
        AuditLog.countDocuments({ ...query, success: true }),
        AuditLog.countDocuments({ ...query, success: false }),
        AuditLog.aggregate([
          { $match: query },
          { $group: { _id: '$action', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
        ]),
        AuditLog.aggregate([
          { $match: query },
          { $group: { _id: '$resource', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
        ]),
      ]);

      res.json({
        stats: {
          total: totalLogs,
          successful: successfulLogs,
          failed: failedLogs,
          successRate: totalLogs > 0 ? ((successfulLogs / totalLogs) * 100).toFixed(2) : 0,
        },
        logsByAction,
        logsByResource,
      });
    } catch (error: any) {
      logger.error('Get audit log stats error:', error);
      res.status(500).json({ error: 'Failed to fetch audit log stats' });
    }
  };
}

