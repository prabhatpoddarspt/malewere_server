import rateLimit from 'express-rate-limit';
import { config } from '../config/environment';

export const apiLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit login attempts
  message: 'Too many login attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

export const fileStreamLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // Limit file stream requests
  message: 'Too many file stream requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

