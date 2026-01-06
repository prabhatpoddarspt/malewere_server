import mongoose, { Schema, Document, Model } from 'mongoose';

export interface IFileAccess extends Document {
  userId?: mongoose.Types.ObjectId; // Optional for anonymous devices
  deviceId: mongoose.Types.ObjectId;
  filePath: string;
  action: 'view' | 'download' | 'upload' | 'delete';
  success: boolean;
  ipAddress: string;
  userAgent?: string;
  timestamp: Date;
}

const FileAccessSchema = new Schema<IFileAccess>(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: false }, // Optional for anonymous devices
    deviceId: { type: Schema.Types.ObjectId, ref: 'Device', required: true },
    filePath: { type: String, required: true },
    action: { type: String, enum: ['view', 'download', 'upload', 'delete'], required: true },
    success: { type: Boolean, required: true },
    ipAddress: { type: String, required: true },
    userAgent: { type: String },
    timestamp: { type: Date, default: Date.now },
  },
  {
    timestamps: true,
  }
);

FileAccessSchema.index({ userId: 1, timestamp: -1 });
FileAccessSchema.index({ deviceId: 1, timestamp: -1 });
FileAccessSchema.index({ filePath: 1 });
FileAccessSchema.index({ action: 1, timestamp: -1 });

const FileAccess: Model<IFileAccess> = mongoose.model<IFileAccess>('FileAccess', FileAccessSchema);

export default FileAccess;

