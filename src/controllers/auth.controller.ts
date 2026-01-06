import { Response } from 'express';
import { AuthenticatedRequest } from '../types';
import { AuthService } from '../services/auth.service';
import logger from '../utils/logger';
import { auditLogAsync } from '../utils/auditLogger';

export class AuthController {
  private authService: AuthService;

  constructor() {
    this.authService = new AuthService();
  }

  register = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { email, password, role } = req.body;

      const result = await this.authService.register(email, password, role || 'user');

      // Log registration (non-blocking)
      auditLogAsync({
        action: 'register',
        resource: 'user',
        resourceId: result.user.id.toString(),
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
        success: true,
      });

      res.status(201).json({
        message: 'User registered successfully',
        ...result,
      });
    } catch (error: any) {
      logger.error('Registration error:', error);

      auditLogAsync({
        action: 'register',
        resource: 'user',
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
        success: false,
        details: { error: error.message },
      });

      res.status(400).json({ error: error.message || 'Registration failed' });
    }
  };

  login = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        logger.warn(`Login failed: Missing email or password`);
        res.status(400).json({ error: 'Email and password are required' });
        return;
      }

      logger.info(`Login attempt for: ${email}`);

      const result = await this.authService.login(email, password);

      logger.info(`Login successful for user: ${result.user.email} (${result.user.id})`);
      
      // Log login (non-blocking)
      auditLogAsync({
        userId: result.user.id.toString(),
        action: 'login',
        resource: 'auth',
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
        success: true,
      });
      
      res.status(200).json({
        message: 'Login successful',
        ...result,
      });
    } catch (error: any) {
      logger.error(`Login error (401): ${error.message}`, {
        email: req.body.email,
        error: error.message,
      });

      auditLogAsync({
        action: 'login',
        resource: 'auth',
        ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.get('user-agent'),
        success: false,
        details: { error: error.message, email: req.body.email },
      });

      res.status(401).json({ error: error.message || 'Login failed' });
    }
  };

  refresh = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        res.status(400).json({ error: 'Refresh token required' });
        return;
      }

      const accessToken = await this.authService.refreshAccessToken(refreshToken);

      res.json({
        accessToken,
      });
    } catch (error: any) {
      logger.error('Token refresh error:', error);
      res.status(401).json({ error: error.message || 'Token refresh failed' });
    }
  };

  logout = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      if (req.user) {
        auditLogAsync({
          userId: req.user.userId,
          action: 'logout',
          resource: 'auth',
          ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
          userAgent: req.get('user-agent'),
          success: true,
        });
      }

      res.json({ message: 'Logout successful' });
    } catch (error: any) {
      logger.error('Logout error:', error);
      res.status(500).json({ error: 'Logout failed' });
    }
  };
}

