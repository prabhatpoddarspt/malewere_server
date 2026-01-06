import { Router } from 'express';
import { FileController, uploadMiddleware } from '../controllers/file.controller';
import { authenticate } from '../middleware/auth.middleware';
import { authenticateDeviceREST } from '../middleware/deviceAuthREST.middleware';
import { fileStreamLimiter } from '../middleware/rateLimit.middleware';

const router = Router();
const fileController = new FileController();

// Public route - no authentication required
router.get('/uploads', fileController.listUploads);

// Try device authentication first, then JWT authentication
router.use(authenticateDeviceREST);
router.use(authenticate);

router.get('/list', fileStreamLimiter, fileController.listFiles);
router.get('/info', fileController.getFileInfo);
router.get('/download', fileStreamLimiter, fileController.downloadFile);
router.post('/upload', uploadMiddleware, fileController.uploadFile);
router.delete('/delete', fileController.deleteFile);
router.get('/search', fileController.searchFiles);
router.post('/access', fileController.logFileAccess);

export default router;

