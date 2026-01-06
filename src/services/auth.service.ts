import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import User from '../models/User';
import { config } from '../config/environment';
import { SecurityUtils } from '../utils/security';
import logger from '../utils/logger';

export class AuthService {
  private readonly JWT_SECRET: string;
  private readonly JWT_EXPIRES_IN: string;
  private readonly REFRESH_TOKEN_EXPIRES_IN: string;

  constructor() {
    this.JWT_SECRET = config.jwt.secret;
    this.JWT_EXPIRES_IN = config.jwt.expiresIn;
    this.REFRESH_TOKEN_EXPIRES_IN = config.jwt.refreshExpiresIn;
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, config.security.bcryptRounds);
  }

  async comparePassword(password: string, hash: string): Promise<boolean> {
    try {
      const result = await bcrypt.compare(password, hash);
      logger.info(`Password comparison result: ${result}`);
      return result;
    } catch (error: any) {
      logger.error(`Password comparison error: ${error.message}`);
      return false;
    }
  }

  generateAccessToken(userId: string, role: string): string {
    return jwt.sign(
      { userId, role, type: 'access' },
      this.JWT_SECRET,
      { expiresIn: this.JWT_EXPIRES_IN }
    );
  }

  generateRefreshToken(userId: string): string {
    return jwt.sign(
      { userId, type: 'refresh' },
      this.JWT_SECRET,
      { expiresIn: this.REFRESH_TOKEN_EXPIRES_IN }
    );
  }

  verifyToken(token: string): any {
    try {
      return jwt.verify(token, this.JWT_SECRET);
    } catch (error) {
      logger.error('Token verification failed:', error);
      throw new Error('Invalid or expired token');
    }
  }

  async register(email: string, password: string, role: 'admin' | 'user' | 'viewer' = 'user'): Promise<{
    user: any;
    accessToken: string;
    refreshToken: string;
  }> {
    // Validate email
    if (!SecurityUtils.validateEmail(email)) {
      throw new Error('Invalid email format');
    }

    // Validate password
    const passwordValidation = SecurityUtils.validatePassword(password);
    if (!passwordValidation.valid) {
      throw new Error(passwordValidation.message);
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new Error('User already exists');
    }

    // Hash password
    const hashedPassword = await this.hashPassword(password);

    // Create user
    const user = await User.create({
      email,
      password: hashedPassword,
      role,
    });

    const accessToken = this.generateAccessToken(user._id.toString(), user.role);
    const refreshToken = this.generateRefreshToken(user._id.toString());

    return {
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
      },
      accessToken,
      refreshToken,
    };
  }

  async login(email: string, password: string): Promise<{
    user: any;
    accessToken: string;
    refreshToken: string;
  }> {
    // Normalize email to lowercase (matching schema)
    const normalizedEmail = email.toLowerCase().trim();
    
    logger.info(`Login attempt for email: ${normalizedEmail}`);
    
    // First try exact match, then try case-insensitive
    let user = await User.findOne({ email: normalizedEmail, isActive: true });
    
    // If not found, try case-insensitive search
    if (!user) {
      user = await User.findOne({ 
        email: { $regex: new RegExp(`^${normalizedEmail}$`, 'i') }, 
        isActive: true 
      });
    }
    
    if (!user) {
      logger.warn(`Login failed: User not found or inactive - ${normalizedEmail}`);
      // Check if user exists but is inactive
      const inactiveUser = await User.findOne({ email: normalizedEmail });
      if (inactiveUser) {
        logger.warn(`User exists but is inactive: ${normalizedEmail}`);
      }
      throw new Error('Invalid credentials');
    }

    logger.info(`User found: ${user.email} (ID: ${user._id}), isActive: ${user.isActive}, comparing password...`);
    
    if (!user.password || !user.password.startsWith('$2')) {
      logger.error(`Invalid password hash format for user: ${user.email}`);
      throw new Error('Invalid credentials');
    }
    
    const isValid = await this.comparePassword(password, user.password);
    if (!isValid) {
      logger.warn(`Login failed: Invalid password for user - ${normalizedEmail}`);
      throw new Error('Invalid credentials');
    }

    logger.info(`Login successful for user: ${normalizedEmail} (ID: ${user._id})`);
    
    user.lastLogin = new Date();
    await user.save();

    const accessToken = this.generateAccessToken(user._id.toString(), user.role);
    const refreshToken = this.generateRefreshToken(user._id.toString());

    return {
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
      },
      accessToken,
      refreshToken,
    };
  }

  async refreshAccessToken(refreshToken: string): Promise<string> {
    const decoded = this.verifyToken(refreshToken) as any;
    
    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive) {
      throw new Error('User not found or inactive');
    }

    return this.generateAccessToken(user._id.toString(), user.role);
  }
}

