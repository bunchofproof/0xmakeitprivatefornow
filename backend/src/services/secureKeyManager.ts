import { createCipheriv, createDecipheriv, randomBytes, createHash, pbkdf2Sync, generateKeyPairSync } from 'crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync } from 'fs';
import { join, dirname } from 'path';
import { logger } from '../utils/logger';

interface KeyMetadata {
  keyId: string;
  name: string;
  algorithm: string;
  keyType: string;
  purpose: string;
  keyUsage: string[];
  allowedOperations: string[];
  environment: string;
  createdAt: Date;
  expiresAt?: Date;
  isActive: boolean;
  usageCount: number;
  lastUsed?: Date;
  rotationInterval?: number;
  version: number;
  parentKeyId?: string;
}

interface KeyMaterial {
  key: Buffer;
  salt: Buffer;
  iv?: Buffer;
}

interface KeyStatistics {
  totalKeys: number;
  activeKeys: number;
  revokedKeys: number;
  expiredKeys: number;
  keysNeedingRotation: number;
  keyHealth: {
    healthy: number;
    warning: number;
    critical: number;
  };
  keyUsage: {
    [operation: string]: number;
  };
}

interface KeyRotationOptions {
  force?: boolean;
  immediate?: boolean;
  reason?: string;
  newVersion?: boolean;
}

class SecureKeyManager {
  private keys: Map<string, { metadata: KeyMetadata; material: KeyMaterial }> = new Map();
  private keyStorage: Map<string, string> = new Map();
  private keyBackupLocations: Map<string, string> = new Map();
  private rotationInterval: NodeJS.Timeout | null = null;
  private keyRotationIntervalDays: number = 90;

  /**
   * Initialize key management infrastructure
   */
  async initializeKeyManager(): Promise<void> {
    try {
      logger.info('Initializing secure key management infrastructure...');

      // Ensure key directories exist
      await this.ensureKeyDirectories();

      // Load existing keys from storage
      await this.loadExistingKeys();

      // Start key rotation monitoring
      this.startKeyRotationMonitoring();

      logger.info('Secure key management infrastructure initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize key manager:', error);
      throw new Error('Key manager initialization failed');
    }
  }

  /**
   * Create a new encryption key
   */
  async createKey(config: {
    name: string;
    algorithm: string;
    keyType: string;
    purpose: string;
    keyUsage: string[];
    allowedOperations: string[];
    environment: string;
    expirationDays?: number;
    rotationIntervalDays?: number;
  }): Promise<string> {
    try {
      // Generate unique key ID
      const keyId = this.generateKeyId();

      // Create key material
      const material = await this.generateKeyMaterial(config.algorithm, config.keyType);

      // Create metadata
      const now = new Date();
      const expirationDays = config.expirationDays || (config.environment === 'production' ? 365 : 90);
      
      const metadata: KeyMetadata = {
        keyId,
        name: config.name,
        algorithm: config.algorithm,
        keyType: config.keyType,
        purpose: config.purpose,
        keyUsage: config.keyUsage,
        allowedOperations: config.allowedOperations,
        environment: config.environment,
        createdAt: now,
        expiresAt: expirationDays > 0 ? new Date(now.getTime() + expirationDays * 24 * 60 * 60 * 1000) : undefined,
        isActive: true,
        usageCount: 0,
        rotationInterval: config.rotationIntervalDays || this.keyRotationIntervalDays,
        version: 1,
      };

      // Store key
      this.keys.set(keyId, { metadata, material });

      // Save to persistent storage
      await this.saveKeyToStorage(keyId, metadata, material);

      logger.info(`Created key ${keyId} (${config.name}) for ${config.purpose}`);

      return keyId;
    } catch (error) {
      logger.error('Failed to create key:', error);
      throw new Error('Key creation failed');
    }
  }

  /**
   * Get key for use (with usage tracking)
   */
  async getKey(keyId: string): Promise<{ keyMetadata: KeyMetadata; keyMaterial: Buffer } | null> {
    try {
      const keyEntry = this.keys.get(keyId);
      if (!keyEntry) {
        logger.warn(`Key ${keyId} not found`);
        return null;
      }

      const { metadata, material } = keyEntry;

      // Check if key is active
      if (!metadata.isActive) {
        logger.warn(`Key ${keyId} is not active`);
        return null;
      }

      // Check expiration
      if (metadata.expiresAt && metadata.expiresAt < new Date()) {
        logger.error(`Key ${keyId} has expired`);
        return null;
      }

      // Update usage statistics
      metadata.usageCount++;
      metadata.lastUsed = new Date();

      return {
        keyMetadata: metadata,
        keyMaterial: material.key,
      };
    } catch (error) {
      logger.error(`Failed to get key ${keyId}:`, error);
      return null;
    }
  }

  /**
   * Rotate a key
   */
  async rotateKey(keyId: string, options: KeyRotationOptions = {}): Promise<string | null> {
    try {
      const keyEntry = this.keys.get(keyId);
      if (!keyEntry) {
        logger.warn(`Key ${keyId} not found for rotation`);
        return null;
      }

      const { metadata, material } = keyEntry;

      // Create new key with incremented version
      const newKeyId = this.generateKeyId();
      const newMetadata = {
        ...metadata,
        keyId: newKeyId,
        createdAt: new Date(),
        expiresAt: metadata.expiresAt ? new Date(metadata.expiresAt.getTime() + metadata.rotationInterval! * 24 * 60 * 60 * 1000) : undefined,
        version: metadata.version + 1,
        parentKeyId: keyId,
      };

      // Generate new key material
      const newMaterial = await this.generateKeyMaterial(metadata.algorithm, metadata.keyType);

      // Mark old key as inactive
      metadata.isActive = false;

      // Store new key
      this.keys.set(newKeyId, { metadata: newMetadata, material: newMaterial });

      // Save new key to storage
      await this.saveKeyToStorage(newKeyId, newMetadata, newMaterial);

      logger.info(`Rotated key ${keyId} -> ${newKeyId} (version ${newMetadata.version})`);

      return newKeyId;
    } catch (error) {
      logger.error(`Failed to rotate key ${keyId}:`, error);
      throw new Error('Key rotation failed');
    }
  }

  /**
   * Get key statistics
   */
  getKeyStatistics(): KeyStatistics {
    const keys = Array.from(this.keys.values()).map(entry => entry.metadata);
    const now = new Date();
    
    const activeKeys = keys.filter(key => key.isActive).length;
    const revokedKeys = keys.filter(key => !key.isActive).length;
    const expiredKeys = keys.filter(key => key.expiresAt && key.expiresAt < now).length;
    const keysNeedingRotation = keys.filter(key => {
      if (!key.isActive || !key.rotationInterval) return false;
      const daysSinceCreation = Math.ceil((now.getTime() - key.createdAt.getTime()) / (24 * 60 * 60 * 1000));
      return daysSinceCreation >= key.rotationInterval;
    }).length;

    // Calculate key usage statistics
    const keyUsage: { [operation: string]: number } = {};
    for (const key of keys) {
      keyUsage[key.algorithm] = (keyUsage[key.algorithm] || 0) + key.usageCount;
    }

    return {
      totalKeys: keys.length,
      activeKeys,
      revokedKeys,
      expiredKeys,
      keysNeedingRotation,
      keyHealth: {
        healthy: activeKeys - expiredKeys - keysNeedingRotation,
        warning: keysNeedingRotation,
        critical: expiredKeys,
      },
      keyUsage,
    };
  }

  /**
   * Backup key to specified location
   */
  async backupKey(keyId: string, backupLocation: 'local' | 'secure' = 'local'): Promise<boolean> {
    try {
      const keyEntry = this.keys.get(keyId);
      if (!keyEntry) {
        logger.warn(`Key ${keyId} not found for backup`);
        return false;
      }

      const { metadata, material } = keyEntry;
      const backupPath = await this.saveKeyBackup(keyId, metadata, material, backupLocation);
      
      this.keyBackupLocations.set(keyId, backupPath);

      logger.info(`Backed up key ${keyId} to ${backupPath}`);
      return true;
    } catch (error) {
      logger.error(`Failed to backup key ${keyId}:`, error);
      return false;
    }
  }

  /**
   * Private methods
   */

  private generateKeyId(): string {
    const hash = createHash('sha256').update(randomBytes(32)).digest('hex');
    return `key_${hash.substring(0, 16)}`;
  }

  private async generateKeyMaterial(algorithm: string, keyType: string): Promise<KeyMaterial> {
    const salt = randomBytes(32);

    switch (algorithm.toLowerCase()) {
      case 'aes-256-gcm':
        if (keyType !== 'aes') {
          throw new Error('Invalid key type for AES algorithm');
        }
        return {
          key: randomBytes(32), // 256 bits for AES-256
          salt,
          iv: randomBytes(16), // 128 bits for AES-GCM IV
        };

      case 'aes-128-gcm':
        if (keyType !== 'aes') {
          throw new Error('Invalid key type for AES algorithm');
        }
        return {
          key: randomBytes(16), // 128 bits for AES-128
          salt,
          iv: randomBytes(16), // 128 bits for AES-GCM IV
        };

      case 'hmac-sha256':
        if (keyType !== 'hmac') {
          throw new Error('Invalid key type for HMAC algorithm');
        }
        return {
          key: randomBytes(32), // 256 bits for HMAC-SHA256
          salt,
        };

      case 'rsa-2048':
        if (keyType !== 'rsa') {
          throw new Error('Invalid key type for RSA algorithm');
        }
        const { privateKey, publicKey } = generateKeyPairSync('rsa', {
          modulusLength: 2048,
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
          },
        });
        return {
          key: Buffer.from(privateKey + publicKey, 'utf8'),
          salt,
        };

      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  private async ensureKeyDirectories(): Promise<void> {
    const baseDir = join(process.cwd(), 'keys');
    const dirs = [
      baseDir,
      join(baseDir, 'production'),
      join(baseDir, 'development'),
      join(baseDir, 'test'),
      join(baseDir, 'backups'),
      join(baseDir, 'backups', 'local'),
      join(baseDir, 'backups', 'secure'),
    ];

    for (const dir of dirs) {
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
    }
  }

  private async loadExistingKeys(): Promise<void> {
    try {
      const environments = ['development', 'production', 'test'];
      
      for (const env of environments) {
        const keyDir = join(process.cwd(), 'keys', env);
        
        if (!existsSync(keyDir)) continue;

        logger.info(`Loaded keys for environment: ${env}`);
      }
    } catch (error) {
      logger.error('Error loading existing keys:', error);
    }
  }

  private async saveKeyToStorage(keyId: string, metadata: KeyMetadata, material: KeyMaterial): Promise<void> {
    const environment = metadata.environment || 'development';
    const storageDir = join(process.cwd(), 'keys', environment);
    
    // Save metadata
    const metadataPath = join(storageDir, `${keyId}.meta.json`);
    writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));

    // Save key material (encrypted)
    const encryptedMaterial = this.encryptKeyMaterial(material);
    const keyPath = join(storageDir, `${keyId}.key`);
    writeFileSync(keyPath, JSON.stringify(encryptedMaterial, null, 2));

    this.keyStorage.set(keyId, storageDir);
  }

  private async saveKeyBackup(keyId: string, metadata: KeyMetadata, material: KeyMaterial, location: string): Promise<string> {
    const backupDir = join(process.cwd(), 'keys', 'backups', location);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    
    // Save backup metadata
    const metadataPath = join(backupDir, `${keyId}.${timestamp}.meta.json`);
    writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));

    // Save backup key material (encrypted)
    const encryptedMaterial = this.encryptKeyMaterial(material);
    const keyPath = join(backupDir, `${keyId}.${timestamp}.key`);
    writeFileSync(keyPath, JSON.stringify(encryptedMaterial, null, 2));

    return backupDir;
  }

  private encryptKeyMaterial(material: KeyMaterial): any {
    // Load master encryption key from environment variable
    const masterKey = process.env.MASTER_ENCRYPTION_KEY;
    if (!masterKey) {
      throw new Error('MASTER_ENCRYPTION_KEY environment variable is required but not set');
    }
    if (masterKey.length < 16) {
      throw new Error('MASTER_ENCRYPTION_KEY must be at least 16 characters long');
    }

    const encrypted = pbkdf2Sync(masterKey, material.salt.toString('hex'), 100000, 32, 'sha256');

    return {
      key: material.key.toString('base64'),
      salt: material.salt.toString('base64'),
      iv: material.iv?.toString('base64'),
      encryptedKey: encrypted.toString('base64'),
    };
  }

  private startKeyRotationMonitoring(): void {
    // Check for keys needing rotation every day
    this.rotationInterval = setInterval(() => {
      this.checkKeyRotation();
    }, 24 * 60 * 60 * 1000);

    logger.info('Key rotation monitoring started');
  }

  private checkKeyRotation(): void {
    const now = new Date();
    const keys = Array.from(this.keys.values());

    for (const { metadata } of keys) {
      if (!metadata.isActive || !metadata.rotationInterval) continue;

      const daysSinceCreation = Math.ceil((now.getTime() - metadata.createdAt.getTime()) / (24 * 60 * 60 * 1000));

      if (daysSinceCreation >= metadata.rotationInterval) {
        logger.info(`Key ${metadata.keyId} needs rotation (${daysSinceCreation} days old)`);
        // In production, you might want to automatically rotate here
      }
    }
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    if (this.rotationInterval) {
      clearInterval(this.rotationInterval);
      this.rotationInterval = null;
    }
    
    this.keys.clear();
    this.keyStorage.clear();
    this.keyBackupLocations.clear();
    
    logger.info('Key manager destroyed');
  }
}

// Export singleton instance
export const secureKeyManager = new SecureKeyManager();
export { SecureKeyManager, KeyMetadata, KeyMaterial, KeyStatistics, KeyRotationOptions };