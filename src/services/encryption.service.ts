import crypto from 'crypto';

export class EncryptionService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly keyLength = 32;
  private readonly ivLength = 16;
  private readonly saltLength = 64;
  private readonly tagLength = 16;
  private readonly tagPosition = this.saltLength + this.ivLength;
  private readonly encryptedPosition = this.tagPosition + this.tagLength;

  private getKey(secret: string): Buffer {
    return crypto.scryptSync(secret, 'salt', this.keyLength);
  }

  encrypt(text: string, secret: string): string {
    const key = this.getKey(secret);
    const iv = crypto.randomBytes(this.ivLength);
    const salt = crypto.randomBytes(this.saltLength);

    const cipher = crypto.createCipheriv(this.algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const tag = cipher.getAuthTag();

    // Combine salt + iv + tag + encrypted
    return salt.toString('hex') + iv.toString('hex') + tag.toString('hex') + encrypted;
  }

  decrypt(encryptedData: string, secret: string): string {
    const key = this.getKey(secret);

    // Extract salt, iv, tag, and encrypted data
    // const salt = Buffer.from(encryptedData.slice(0, this.saltLength * 2), 'hex'); // Unused
    const iv = Buffer.from(
      encryptedData.slice(this.saltLength * 2, this.tagPosition * 2),
      'hex'
    );
    const tag = Buffer.from(
      encryptedData.slice(this.tagPosition * 2, this.encryptedPosition * 2),
      'hex'
    );
    const encrypted = encryptedData.slice(this.encryptedPosition * 2);

    const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}

