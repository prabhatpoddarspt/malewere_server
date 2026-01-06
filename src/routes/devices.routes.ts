import { Router } from 'express';
import { DeviceController } from '../controllers/device.controller';
import { authenticate } from '../middleware/auth.middleware';

const router = Router();
const deviceController = new DeviceController();

// Application device registration (no authentication required)
// Only applications can register devices - admin panel cannot create devices
router.post('/register', deviceController.registerDeviceAnonymous);

// Admin panel routes (read-only - view devices only)
// All routes require authentication
router.use(authenticate);

// View devices (read-only)
router.get('/', deviceController.getAllDevices);
router.get('/:id', deviceController.getDeviceById);
router.get('/:id/status', deviceController.getDeviceStatus);

// Note: Device creation, update, and delete are disabled for admin panel
// Devices can only be created by applications via POST /api/devices/register
// Admin panel is read-only for device management

export default router;
