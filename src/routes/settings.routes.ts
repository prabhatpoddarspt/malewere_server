import { Router } from 'express';
import { SettingsController } from '../controllers/settings.controller';
import { authenticate, authorize } from '../middleware/auth.middleware';

const router = Router();
const settingsController = new SettingsController();

// All routes require authentication
router.use(authenticate);

router.get('/', settingsController.getSettings);
router.put('/', settingsController.updateUserSettings);
router.get('/system', authorize('admin'), settingsController.getSystemSettings);

export default router;

