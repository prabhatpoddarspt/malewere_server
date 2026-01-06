import mongoose, { Schema, Document, Model } from 'mongoose';

export interface IUser extends Document {
  email: string;
  password: string;
  role: 'admin' | 'user' | 'viewer';
  isActive: boolean;
  devices: mongoose.Types.ObjectId[];
  permissions: {
    canView: boolean;
    canDownload: boolean;
    canUpload: boolean;
    canDelete: boolean;
  };
  twoFactorEnabled: boolean;
  twoFactorSecret?: string;
  lastLogin?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const UserSchema = new Schema<IUser>(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user', 'viewer'], default: 'user' },
    isActive: { type: Boolean, default: true },
    devices: [{ type: Schema.Types.ObjectId, ref: 'Device' }],
    permissions: {
      canView: { type: Boolean, default: true },
      canDownload: { type: Boolean, default: false },
      canUpload: { type: Boolean, default: false },
      canDelete: { type: Boolean, default: false },
    },
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorSecret: { type: String },
    lastLogin: { type: Date },
  },
  {
    timestamps: true,
  }
);

// email index is automatically created by unique: true
UserSchema.index({ role: 1 });
UserSchema.index({ isActive: 1 });

const User: Model<IUser> = mongoose.model<IUser>('User', UserSchema);

export default User;

