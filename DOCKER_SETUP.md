# Docker Setup Guide

This guide explains how to build and run the backend using Docker.

## Prerequisites

- Docker installed (version 20.10+)
- Docker Compose installed (version 2.0+)

## Quick Start

### Option 1: Using Docker Compose (Recommended)

This will start both the backend and MongoDB:

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f backend

# Stop services
docker-compose down

# Stop and remove volumes (clears database)
docker-compose down -v
```

### Option 2: Using Dockerfile Only

If you already have MongoDB running:

```bash
# Build the image
docker build -t malwere-backend .

# Run the container
docker run -d \
  --name malwere-backend \
  -p 8000:3000 \
  -e MONGODB_URI=mongodb://host.docker.internal:27017/admin-panel \
  -e JWT_SECRET=your-secret-key \
  -v $(pwd)/uploads:/app/uploads \
  -v $(pwd)/logs:/app/logs \
  malwere-backend
```

## Environment Variables

Create a `.env` file in the backend directory (or use environment variables):

```env
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb://mongo:27017/admin-panel
JWT_SECRET=your-super-secret-jwt-key
CORS_ORIGIN=*
```

## Port Mapping

- **Container Port**: 3000 (internal)
- **Host Port**: 8000 (external)
- Access at: `http://localhost:8000`

To change the host port, modify `docker-compose.yml`:
```yaml
ports:
  - "YOUR_PORT:3000"
```

## Volumes

The following directories are mounted as volumes:
- `./uploads` → Container uploads directory
- `./logs` → Container logs directory
- MongoDB data is persisted in Docker volumes

## Health Check

The container includes a health check that monitors `/health` endpoint:
- Check interval: 30 seconds
- Timeout: 3 seconds
- Retries: 3

View health status:
```bash
docker ps  # Check STATUS column
```

## Building for Production

```bash
# Build with no cache
docker build --no-cache -t malwere-backend .

# Build with specific tag
docker build -t malwere-backend:v1.0.0 .
```

## Troubleshooting

### Container won't start

```bash
# Check logs
docker-compose logs backend

# Check container status
docker ps -a

# Inspect container
docker inspect malwere-backend
```

### MongoDB connection issues

```bash
# Check MongoDB is running
docker-compose ps mongo

# Check MongoDB logs
docker-compose logs mongo

# Test MongoDB connection
docker exec -it malwere-mongo mongosh admin_panel
```

### Permission issues

If you encounter permission issues with volumes:
```bash
# Fix ownership (Linux/Mac)
sudo chown -R 1001:1001 uploads logs

# Or run with different user
docker run --user $(id -u):$(id -g) ...
```

### Port already in use

If port 8000 is already in use:
```bash
# Change port in docker-compose.yml
ports:
  - "8001:3000"  # Use port 8001 instead
```

## Development Mode

For development with hot reload, use:

```bash
# Run in development mode (mounts source code)
docker-compose -f docker-compose.dev.yml up
```

Or use the npm scripts directly:
```bash
npm run dev
```

## Production Deployment

1. **Set environment variables** in `.env` or use secrets management
2. **Build the image**:
   ```bash
   docker build -t malwere-backend:latest .
   ```
3. **Tag for registry** (if using):
   ```bash
   docker tag malwere-backend:latest your-registry/malwere-backend:latest
   ```
4. **Push to registry**:
   ```bash
   docker push your-registry/malwere-backend:latest
   ```
5. **Deploy**:
   ```bash
   docker-compose up -d
   ```

## Security Notes

- The container runs as non-root user (`nodejs`)
- Uses `dumb-init` for proper signal handling
- Health checks enabled
- Environment variables should be set securely (use secrets in production)

## Useful Commands

```bash
# View running containers
docker ps

# View all containers (including stopped)
docker ps -a

# View logs
docker logs -f malwere-backend

# Execute command in container
docker exec -it malwere-backend sh

# Restart container
docker restart malwere-backend

# Remove container
docker rm malwere-backend

# Remove image
docker rmi malwere-backend

# Clean up unused resources
docker system prune -a
```

