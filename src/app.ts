import express from 'express';
import http from 'http';
import helmet from 'helmet';
import cors from 'cors';
import { SocketServer } from './socket/socket.io';
import { errorHandler, AppError } from './middleware/errorHandler.middleware';
import { connectDatabase, disconnectDatabase } from './config/database';
import { config } from './config/environment';
import logger from './utils/logger';
import { apiLimiter } from './middleware/rateLimit.middleware';
import { FileUtils } from './utils/fileUtils';
import morganMiddleware from './middleware/morgan.middleware';

// Import routes
import authRoutes from './routes/auth.routes';
import userRoutes from './routes/users.routes';
import deviceRoutes from './routes/devices.routes';
import fileRoutes from './routes/files.routes';
import auditLogRoutes from './routes/auditLogs.routes';
import settingsRoutes from './routes/settings.routes';

const app = express();
const server = http.createServer(app);

// Initialize Socket.io
const socketServer = new SocketServer(server);
const io = socketServer.getIO();

// Ensure upload directory exists
FileUtils.ensureDirectoryExists(config.file.uploadDir);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS configuration
app.use(cors({
  origin: config.cors.origin,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
app.use(apiLimiter);

// Request logging middleware
app.use(morganMiddleware);

// Health check endpoint
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: config.env,
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/devices', deviceRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/audit-logs', auditLogRoutes);
app.use('/api/settings', settingsRoutes);

// 404 handler
app.use((_req, _res, next) => {
  next(new AppError(`Route ${_req.method} ${_req.path} not found`, 404));
});

// Error handling middleware (must be last)
app.use(errorHandler);

// Graceful shutdown handler
const gracefulShutdown = async (signal: string) => {
  const isDevelopment = config.env === 'development';
  const reason = isDevelopment ? 'Development server restart (file change detected)' : 'Server shutdown';
  
  logger.info(`${signal} received. Starting graceful shutdown... (${reason})`);

  // Close all Socket.io connections gracefully
  if (io) {
    logger.info('Closing Socket.io connections...');
    io.close(() => {
      logger.info('All Socket.io connections closed');
    });
    
    // Disconnect all sockets
    io.disconnectSockets(true);
  }

  // Close HTTP server
  server.close(async () => {
    logger.info('HTTP server closed');

    try {
      await disconnectDatabase();
      logger.info('Database disconnected');
      logger.info('Graceful shutdown completed');
      process.exit(0);
    } catch (error) {
      logger.error('Error during shutdown:', error);
      process.exit(1);
    }
  });

  // Force close after 5 seconds (reduced from 10 for faster restarts in development)
  const timeout = isDevelopment ? 5000 : 10000;
  setTimeout(() => {
    logger.warn(`Forced shutdown after ${timeout}ms timeout`);
    if (io) {
      io.disconnectSockets(true);
    }
    process.exit(1);
  }, timeout);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Unhandled error handlers
process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
  const errorMessage = reason instanceof Error ? reason.message : String(reason);
  const errorStack = reason instanceof Error ? reason.stack : undefined;
  
  logger.error('Unhandled Rejection:', {
    reason: errorMessage,
    stack: errorStack,
    promise: promise.toString(),
  });
  
  // Don't exit in development to allow debugging
  if (config.env === 'production') {
    logger.error('Unhandled rejection in production - this should be fixed');
  }
});

process.on('uncaughtException', (error: Error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

// Start server
const startServer = async () => {
  try {
    // Connect to database
    await connectDatabase();

    // Start HTTP server
    // Listen on 0.0.0.0 to accept connections from network (for physical devices)
    server.listen(config.port, '0.0.0.0', () => {
      logger.info(`Server running on http://0.0.0.0:${config.port}`);
      logger.info(`Environment: ${config.env}`);
      logger.info(`WebSocket path: ${config.websocket.path}`);
      logger.info(`Accessible from network at: http://YOUR_LOCAL_IP:${config.port}`);
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

export default app;

