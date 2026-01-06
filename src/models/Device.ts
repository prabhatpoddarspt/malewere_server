import mongoose, { Schema, Document, Model } from 'mongoose';

export interface IDevice extends Document {
  userId?: mongoose.Types.ObjectId; // Optional for anonymous devices
  deviceId: string;
  deviceName: string;
  platform: string;
  isOnline: boolean;
  lastSeen: Date;
  ipAddress?: string;
  authorizedPaths: string[];
  connectionToken: string;
  createdAt: Date;
  updatedAt: Date;
}

const DeviceSchema = new Schema<IDevice>(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: false }, // Optional for anonymous devices
    deviceId: { type: String, required: true, unique: true },
    deviceName: { type: String, required: true },
    platform: { type: String, required: true },
    isOnline: { type: Boolean, default: false },
    lastSeen: { type: Date, default: Date.now },
    ipAddress: { type: String },
    authorizedPaths: [{ type: String }],
    connectionToken: { type: String, required: true, unique: true },
  },
  {
    timestamps: true,
  }
);

DeviceSchema.index({ userId: 1, deviceId: 1 });
// connectionToken index is automatically created by unique: true
DeviceSchema.index({ isOnline: 1 });

const Device: Model<IDevice> = mongoose.model<IDevice>('Device', DeviceSchema);

export default Device;

