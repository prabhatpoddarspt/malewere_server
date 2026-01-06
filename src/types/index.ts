import { Request } from 'express';
import { JwtPayload } from 'jsonwebtoken';
import { IDevice } from '../models/Device';

export interface AuthenticatedRequest extends Request {
  user?: JwtPayload & {
    userId: string;
    role: string;
  };
  device?: IDevice;
}

export interface FileChunk {
  chunk: Buffer;
  progress: number;
}

export interface StreamComplete {
  totalSize: number;
}

export interface DeviceConnectionData {
  deviceId: string;
  deviceName: string;
  platform: string;
  ipAddress?: string;
}

export interface FileStreamRequest {
  path: string;
  deviceId: string;
}

