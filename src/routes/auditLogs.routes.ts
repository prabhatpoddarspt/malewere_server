import { Router } from 'express';
import { AuditLogController } from '../controllers/auditLog.controller';
import { authenticate } from '../middleware/auth.middleware';
// import { authorize } from '../middleware/auth.middleware'; // Unused

const router = Router();
const auditLogController = new AuditLogController();

// All routes require authentication
router.use(authenticate);

router.get('/', auditLogController.getAuditLogs);
router.get('/stats', auditLogController.getAuditLogStats);
router.get('/:id', auditLogController.getAuditLogById);

export default router;

