# Admin Panel Backend API

A secure Node.js backend API with MongoDB database that provides RESTful endpoints and WebSocket server for real-time file streaming, user management, and remote file access capabilities.

## Features

- 🔐 JWT-based authentication with refresh tokens
- 👥 User management with role-based access control (admin, user, viewer)
- 📱 Device management and registration
- 📁 File management with path authorization
- 🔄 Real-time file streaming via WebSocket
- 📊 Audit logging for all actions
- 🛡️ Security features (rate limiting, input validation, path traversal prevention)
- 📝 Comprehensive error handling

## Technology Stack

- **Node.js** 18+ (LTS)
- **Express.js** - REST API framework
- **Socket.io** - WebSocket server
- **MongoDB** - Database with Mongoose ODM
- **TypeScript** - Type safety
- **JWT** - Authentication
- **bcrypt** - Password hashing
- **Helmet** - Security headers
- **Winston** - Logging

## Prerequisites

- Node.js 18+ installed
- MongoDB 6.0+ running locally or connection string
- npm or yarn package manager

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd malwere_backend
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory (copy from `.env.example`):
```bash
cp .env.example .env
```

4. Configure environment variables in `.env`:
```env
NODE_ENV=development
PORT=3000
MONGODB_URI=mongodb://localhost:27017/admin-panel
JWT_SECRET=your-super-secret-jwt-key-change-this
CORS_ORIGIN=http://localhost:3000
```

## Running the Application

### Development Mode
```bash
npm run dev
```

### Production Mode
```bash
npm run build
npm start
```

The server will start on the port specified in your `.env` file (default: 3000).

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout user

### Users (Requires Authentication)
- `GET /api/users` - Get all users (admin only)
- `GET /api/users/:id` - Get user by ID
- `PUT /api/users/:id` - Update user (admin only)
- `DELETE /api/users/:id` - Delete user (admin only)
- `PUT /api/users/:id/permissions` - Update user permissions (admin only)
- `GET /api/users/:id/devices` - Get user devices

### Devices (Requires Authentication)
- `GET /api/devices` - Get all devices
- `GET /api/devices/:id` - Get device by ID
- `POST /api/devices` - Register new device
- `PUT /api/devices/:id` - Update device
- `DELETE /api/devices/:id` - Remove device
- `GET /api/devices/:id/status` - Get device connection status
- `POST /api/devices/:id/authorize` - Authorize device paths

### Files
- `GET /api/files/uploads` - List files in server uploads folder (Public - No authentication required)
- `GET /api/files/list?path=<path>&deviceId=<id>` - List files in directory (device paths) (Requires Authentication)
- `GET /api/files/info?path=<path>&deviceId=<id>` - Get file metadata (Requires Authentication)
- `GET /api/files/download?path=<path>&deviceId=<id>` - Download file (Requires Authentication)
- `POST /api/files/upload` - Upload file (multipart/form-data) (Requires Authentication)
- `DELETE /api/files/delete?path=<path>&deviceId=<id>` - Delete file (Requires Authentication)
- `GET /api/files/search?path=<path>&term=<term>&deviceId=<id>` - Search files (Requires Authentication)

## WebSocket Events

### Client to Server
- `device:connect` - Connect device with credentials
- `device:disconnect` - Disconnect device
- `device:heartbeat` - Send heartbeat to keep connection alive
- `stream:file:request` - Request file stream
- `stream:cancel` - Cancel active stream

### Server to Client
- `device:connect:success` - Device connection successful
- `device:connect:error` - Device connection failed
- `stream:start` - File stream started
- `stream:chunk` - File chunk data (base64 encoded)
- `stream:complete` - File stream completed
- `stream:error` - Stream error occurred
- `stream:cancelled` - Stream cancelled

## Authentication

All API endpoints (except `/api/auth/*`) require authentication. Include the JWT token in the Authorization header:

```
Authorization: Bearer <access_token>
```

For WebSocket connections, provide the token in the connection handshake:

```javascript
const socket = io('http://localhost:3000', {
  auth: {
    token: 'your-access-token'
  }
});
```

## Security Features

- ✅ JWT token expiration and refresh
- ✅ Password hashing with bcrypt (12 rounds)
- ✅ Input validation on all endpoints
- ✅ Path traversal prevention
- ✅ CORS configuration
- ✅ Rate limiting
- ✅ Security headers (Helmet)
- ✅ File type restrictions
- ✅ File size limits
- ✅ Audit logging
- ✅ Error message sanitization

## Project Structure

```
backend/
├── src/
│   ├── config/          # Configuration files
│   ├── models/          # MongoDB models
│   ├── routes/          # API routes
│   ├── controllers/     # Request handlers
│   ├── services/        # Business logic
│   ├── middleware/      # Express middleware
│   ├── utils/           # Utility functions
│   ├── types/           # TypeScript types
│   ├── socket/          # WebSocket handlers
│   └── app.ts           # Main application file
├── tests/               # Test files
├── .env.example         # Environment variables template
├── package.json
├── tsconfig.json
└── README.md
```

## Database Models

### User
- Email, password, role (admin/user/viewer)
- Permissions (canView, canDownload, canUpload, canDelete)
- Two-factor authentication support
- Associated devices

### Device
- Device ID, name, platform
- Connection status and last seen
- Authorized file paths
- Connection token

### FileAccess
- Audit log for file operations
- User, device, file path, action
- Success/failure status
- IP address and user agent

### AuditLog
- System-wide audit trail
- User actions and resource access
- Success/failure tracking

## Error Handling

The API uses consistent error responses:

```json
{
  "error": {
    "message": "Error description"
  }
}
```

In development mode, stack traces are included in error responses.

## Rate Limiting

- **API**: 100 requests per 15 minutes per IP
- **Authentication**: 5 requests per 15 minutes per IP
- **File Streaming**: 10 requests per minute per IP

## Logging

Logs are written to:
- Console (development mode)
- `./logs/app.log` (all logs)
- `./logs/app-error.log` (errors only)

## Testing

```bash
npm test
```

## Deployment

1. Set `NODE_ENV=production` in `.env`
2. Use a strong `JWT_SECRET`
3. Configure MongoDB connection string
4. Set up reverse proxy (Nginx) for HTTPS
5. Use PM2 for process management:
```bash
npm install -g pm2
pm2 start dist/app.js --name admin-panel-backend
```

## Security Checklist

- [ ] Change default JWT_SECRET
- [ ] Use HTTPS/WSS in production
- [ ] Configure CORS properly
- [ ] Set up MongoDB authentication
- [ ] Enable MongoDB replica set for production
- [ ] Configure firewall rules
- [ ] Set up monitoring and alerts
- [ ] Regular security audits
- [ ] Keep dependencies updated

## License

ISC

## Client Integration Guides

- **[Android Integration Guide](./ANDROID_INTEGRATION.md)** - Complete guide for integrating Android applications
- **Postman Collection** - Import `Admin_Panel_Backend_API.postman_collection.json` for API testing

## Support

For issues and questions, please open an issue in the repository.

