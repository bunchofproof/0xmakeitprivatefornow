import { createCipheriv, createDecipheriv, randomBytes, createHash, pbkdf2Sync } from 'crypto';
import { config } from '../config';
import { logger } from './logger';

/**
 * Encrypts sensitive data using AES-256-GCM
 */
export function encryptData(data: string, key?: string): string {
  try {
    // Generate a random IV for each encryption
    const iv = randomBytes(16);

    // Use provided key or generate from config
    const secretKey = key || generateEncryptionKey();

    // Create cipher
    const cipher = createCipheriv(config.crypto.algorithm, secretKey, iv) as any;

    // Encrypt the data
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Get the auth tag
    const authTag = cipher.getAuthTag();

    // Combine IV, auth tag, and encrypted data
    const result = iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;

    return result;

  } catch (error) {
    logger.error('Error encrypting data:', error instanceof Error ? error : new Error(String(error)));
    throw new Error('Failed to encrypt data');
  }
}

/**
 * Decrypts data encrypted with encryptData
 */
export function decryptData(encryptedData: string, key?: string): string {
  try {
    // Split the encrypted data into components
    const parts = encryptedData.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format');
    }

    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];

    // Use provided key or generate from config
    const secretKey = key || generateEncryptionKey();

    // Create decipher
    const decipher = createDecipheriv(config.crypto.algorithm, secretKey, iv) as any;
    decipher.setAuthTag(authTag);

    // Decrypt the data
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;

  } catch (error) {
    logger.error('Error decrypting data:', error instanceof Error ? error : new Error(String(error)));
    throw new Error('Failed to decrypt data');
  }
}

/**
 * Generates a consistent encryption key from configuration
 */
export function generateEncryptionKey(): Buffer {
  try {
    // In production, this should come from environment variables
    const keyMaterial = process.env.ENCRYPTION_KEY || 'default-key-change-in-production';

    // Use PBKDF2 to derive a key from the material
    return pbkdf2Sync(keyMaterial, 'salt', 100000, 32, 'sha256');
  } catch (error) {
    logger.error('Error generating encryption key:', error instanceof Error ? error : new Error(String(error)));
    throw new Error('Failed to generate encryption key');
  }
}

/**
 * Creates a secure hash of input data
 */
export function createSecureHash(data: string, salt?: string): string {
  try {
    const hashSalt = salt || generateRandomSalt();
    const hash = createHash('sha256');

    hash.update(data + hashSalt);
    return hash.digest('hex');
  } catch (error) {
    logger.error('Error creating secure hash:', error instanceof Error ? error : new Error(String(error)));
    throw new Error('Failed to create secure hash');
  }
}

/**
 * Generates a random salt for hashing
 */
export function generateRandomSalt(length: number = 16): string {
  return randomBytes(length).toString('hex');
}

/**
 * Verifies if a hash matches the original data
 */
export function verifyHash(data: string, hash: string, salt: string): boolean {
  try {
    const computedHash = createSecureHash(data, salt);
    return computedHash === hash;
  } catch (error) {
    logger.error('Error verifying hash:', error instanceof Error ? error : new Error(String(error)));
    return false;
  }
}

/**
 * Generates a cryptographically secure random string
 */
export function generateSecureRandomString(length: number): string {
  const bytes = randomBytes(Math.ceil(length / 2));
  return bytes.toString('hex').substring(0, length);
}

/**
 * Constant-time string comparison to prevent timing attacks
 */
export function secureCompare(a: string, b: string): boolean {
   if (a.length !== b.length) {
     return false;
   }

   let result = 0;
   for (let i = 0; i < a.length; i++) {
     result |= a.charCodeAt(i) ^ b.charCodeAt(i);
   }

   return result === 0;
}

/**
 * Creates a HMAC-SHA256 signature for data integrity verification
 */
export function createHMACSignature(data: string, key?: string): string {
   try {
     const crypto = require('crypto');
     const secretKey = key || generateHMACKey();

     const hmac = crypto.createHmac('sha256', secretKey);
     hmac.update(data);
     return hmac.digest('hex');
   } catch (error) {
     logger.error('Error creating HMAC signature:', error instanceof Error ? error : new Error(String(error)));
     throw new Error('Failed to create HMAC signature');
   }
}

/**
 * Verifies HMAC signature for data integrity
 */
export function verifyHMACSignature(data: string, signature: string, key?: string): boolean {
   try {
     const computedSignature = createHMACSignature(data, key);
     return secureCompare(computedSignature, signature);
   } catch (error) {
     logger.error('Error verifying HMAC signature:', error instanceof Error ? error : new Error(String(error)));
     return false;
   }
}

/**
 * Generates a consistent HMAC key from configuration
 */
export function generateHMACKey(): Buffer {
   try {
     const keyMaterial = process.env.HMAC_KEY || 'default-hmac-key-change-in-production';
     return pbkdf2Sync(keyMaterial, 'hmac-salt', 100000, 32, 'sha256');
   } catch (error) {
     logger.error('Error generating HMAC key:', error instanceof Error ? error : new Error(String(error)));
     throw new Error('Failed to generate HMAC key');
   }
}

/**
 * Creates a proof hash for replay attack prevention
 */
export function createProofHash(proofData: any): string {
   try {
     // Normalize the proof data to ensure consistent hashing
     const normalizedData = JSON.stringify({
       circuitName: proofData.name,
       vkeyHash: proofData.vkeyHash,
       // Include essential proof components but exclude timestamps
       proof: proofData.proof,
     });

     return createSecureHash(normalizedData);
   } catch (error) {
     logger.error('Error creating proof hash:', error instanceof Error ? error : new Error(String(error)));
     throw new Error('Failed to create proof hash');
   }
}

/**
 * Validates proof data integrity and format
 */
export function validateProofData(proof: any): { isValid: boolean; error?: string } {
   try {
     // Check basic structure
     if (!proof || typeof proof !== 'object') {
       return { isValid: false, error: 'Invalid proof structure' };
     }

     // Check required fields
     const requiredFields = ['name', 'vkeyHash', 'proof', 'version'];
     for (const field of requiredFields) {
       if (!proof[field]) {
         return { isValid: false, error: `Missing required field: ${field}` };
       }
     }

     // Validate circuit name format
     if (typeof proof.name !== 'string' || proof.name.length === 0) {
       return { isValid: false, error: 'Invalid circuit name' };
     }

     // Validate vkey hash format (should be hex)
     if (!/^[a-fA-F0-9]+$/.test(proof.vkeyHash)) {
       return { isValid: false, error: 'Invalid verification key hash format' };
     }

     // Validate proof format (should be string)
     if (typeof proof.proof !== 'string' || proof.proof.length === 0) {
       return { isValid: false, error: 'Invalid proof data' };
     }

     // Check proof length (reasonable bounds)
     if (proof.proof.length < 100 || proof.proof.length > 10000) {
       return { isValid: false, error: 'Proof data length out of bounds' };
     }

     return { isValid: true };

   } catch (error) {
     logger.error('Error validating proof data:', error instanceof Error ? error : new Error(String(error)));
     return { isValid: false, error: 'Proof validation failed' };
   }
}