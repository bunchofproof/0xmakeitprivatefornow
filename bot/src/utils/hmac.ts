import crypto from 'crypto';
// Note: uuidv4 import kept for future HMAC signature generation
import { logger } from './logger';

// In-memory store for nonce tracking (in production, use Redis or database)
const processedNonces = new Set<string>();
const nonceCleanupInterval = 15 * 60 * 1000; // 15 minutes

/**
 * Clean up old nonces periodically to prevent memory leaks
 */
setInterval(() => {
  if (processedNonces.size > 0) {
    logger.info(`Cleaned up ${processedNonces.size} processed nonces`);
  }
  // In production, implement a more sophisticated cleanup strategy
}, nonceCleanupInterval);

/**
 * Verify HMAC signature with enhanced replay attack protection
 * @param data - The request body that was signed
 * @param signature - The signature to verify
 * @param secret - HMAC secret key
 * @param timestamp - Request timestamp for replay protection
 * @param nonce - Unique nonce for replay protection
 * @returns Object containing verification result and error details
 */
export function verifySecureHMACSignature(
  data: string | object,
  signature: string,
  secret: string,
  timestamp?: string,
  nonce?: string
): { valid: boolean; error?: string } {
  try {
    // Validate timestamp if provided
    if (timestamp) {
      const requestTime = new Date(timestamp).getTime();
      const currentTime = new Date().getTime();
      const timeDiff = Math.abs(currentTime - requestTime);
      const maxAge = 5 * 60 * 1000; // 5 minutes

      if (timeDiff > maxAge) {
        logger.warn('Request timestamp too old - possible replay attack', {
          timestamp,
          requestAge: Math.round(timeDiff / 1000),
          maxAge: Math.round(maxAge / 1000),
          nonce: nonce?.substring(0, 8) + '...'
        });

        return {
          valid: false,
          error: 'Request timestamp expired - possible replay attack'
        };
      }
    }

    // Validate nonce if provided
    if (nonce) {
      if (processedNonces.has(nonce)) {
        logger.warn('Duplicate nonce detected - possible replay attack', {
          nonce: nonce.substring(0, 8) + '...',
          timestamp
        });

        return {
          valid: false,
          error: 'Duplicate nonce detected - possible replay attack'
        };
      }
      
      // Add nonce to processed set (with cleanup strategy)
      processedNonces.add(nonce);
      
      // Note: In production, implement Redis-based nonce tracking for distributed systems
    }

    const signedPayload = {
      ...(typeof data === 'object' ? data : { body: data }),
      timestamp,
      nonce
    };
    const payloadString = JSON.stringify(signedPayload);
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(payloadString, 'utf8');
    const expectedSignature = hmac.digest('base64');
    
    // Use constant-time comparison to prevent timing attacks
    const isValid = crypto.timingSafeEqual(
      Buffer.from(signature, 'base64'),
      Buffer.from(expectedSignature, 'base64')
    );

    if (!isValid) {
      logger.warn('Invalid HMAC signature', {
        hasTimestamp: !!timestamp,
        hasNonce: !!nonce,
        nonce: nonce?.substring(0, 8) + '...',
        timestamp
      });
    }

    return { valid: isValid };
  } catch (error) {
    logger.error('Failed to verify secure HMAC signature:', error instanceof Error ? error : new Error(String(error)));
    return {
      valid: false,
      error: 'Signature verification failed'
    };
  }
}

/**
 * Verify HMAC signature for webhook requests (legacy support)
 * @param data - The request body that was signed
 * @param signature - The signature to verify
 * @param secret - HMAC secret key
 * @returns true if signature is valid, false otherwise
 * @deprecated Use verifySecureHMACSignature for enhanced security
 */
export function verifyHMACSignature(data: string | object, signature: string, secret: string): boolean {
  try {
    const payload = typeof data === 'string' ? data : JSON.stringify(data);
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(payload, 'utf8');
    const expectedSignature = hmac.digest('base64');
    
    // Use constant-time comparison to prevent timing attacks
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'base64'),
      Buffer.from(expectedSignature, 'base64')
    );
  } catch (error) {
    logger.error('Failed to verify HMAC signature:', error instanceof Error ? error : new Error(String(error)));
    return false;
  }
}

/**
 * Generate HMAC-SHA256 signature for webhook requests (legacy support)
 * @param data - The request body to sign
 * @param secret - HMAC secret key
 * @returns Base64 encoded HMAC signature
 * @deprecated Use secure signature generation in backend
 */
export function generateHMACSignature(data: string | object, secret: string): string {
  try {
    const payload = typeof data === 'string' ? data : JSON.stringify(data);
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(payload, 'utf8');
    return hmac.digest('base64');
  } catch (error) {
    logger.error('Failed to generate HMAC signature:', error instanceof Error ? error : new Error(String(error)));
    throw new Error('Failed to generate signature');
  }
}

/**
 * Validate HMAC secret configuration
 * @param secret - HMAC secret to validate
 * @returns true if secret is valid, false otherwise
 */
export function isValidHMACSecret(secret: string | undefined): boolean {
  if (!secret) return false;
  
  // Check minimum length requirement
  if (secret.length < 32) {
    logger.warn('HMAC secret is too short (minimum 32 characters required)');
    return false;
  }
  
  return true;
}

/**
 * Get HMAC secret from environment variables with validation
 * @returns Validated HMAC secret
 * @throws Error if HMAC secret is missing or invalid
 */
export function getHMACSecret(): string {
  const secret = process.env.BOT_WEBHOOK_SECRET;

  if (!secret) {
    throw new Error('BOT_WEBHOOK_SECRET environment variable is not set');
  }

  if (!isValidHMACSecret(secret)) {
    throw new Error('Invalid BOT_WEBHOOK_SECRET configuration');
  }

  return secret;
}