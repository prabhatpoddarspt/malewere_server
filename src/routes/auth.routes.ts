import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { validateLogin, validateRegister } from '../middleware/validation.middleware';
import { authLimiter } from '../middleware/rateLimit.middleware';

const router = Router();
const authController = new AuthController();

router.post('/register', authLimiter, validateRegister, authController.register);
router.post('/login', authLimiter, validateLogin, authController.login);
router.post('/refresh', authController.refresh);
router.post('/logout', authController.logout);

export default router;

