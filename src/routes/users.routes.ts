import { Router } from 'express';
import { UserController } from '../controllers/user.controller';
import { authenticate, authorize } from '../middleware/auth.middleware';

const router = Router();
const userController = new UserController();

// All routes require authentication
router.use(authenticate);

router.get('/', authorize('admin'), userController.getAllUsers);
router.get('/:id', userController.getUserById);
router.put('/:id', authorize('admin'), userController.updateUser);
router.delete('/:id', authorize('admin'), userController.deleteUser);
router.put('/:id/permissions', authorize('admin'), userController.updatePermissions);
router.get('/:id/devices', userController.getUserDevices);

export default router;

