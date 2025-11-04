import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { logger } from './logger';

/**
 * Enhanced HMAC-SHA256 signature for webhook requests with replay protection
 * @param data - The request body to sign
 * @param secret - HMAC secret key
 * @returns Object containing signature and metadata for replay protection
 */
export function generateSecureHMACSignature(data: string | object, secret: string): {
  signature: string;
  timestamp: string;
  nonce: string;
  signedPayload: object;
} {
  try {
    const timestamp = new Date().toISOString();
    const nonce = uuidv4();
    
    const payload = typeof data === 'string' ? data : JSON.stringify(data);
    const signedPayload = {
      ...(typeof data === 'object' ? data : { body: data }),
      timestamp,
      nonce
    };
    
    const payloadString = JSON.stringify(signedPayload);
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(payloadString, 'utf8');
    const signature = hmac.digest('base64');
    
    logger.info('Generated secure HMAC signature with replay protection', {
      hasTimestamp: true,
      hasNonce: true,
      timestamp,
      nonce: nonce.substring(0, 8) + '...'
    });
    
    return {
      signature,
      timestamp,
      nonce,
      signedPayload
    };
  } catch (error) {
    logger.error('Failed to generate secure HMAC signature', { error });
    throw new Error('Failed to generate secure signature');
  }
}

/**
 * Legacy function - Generate HMAC-SHA256 signature for webhook requests
 * @param data - The request body to sign
 * @param secret - HMAC secret key
 * @returns Base64 encoded HMAC signature
 * @deprecated Use generateSecureHMACSignature for new implementations
 */
export function generateHMACSignature(data: string | object, secret: string): string {
  try {
    const payload = typeof data === 'string' ? data : JSON.stringify(data);
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(payload, 'utf8');
    return hmac.digest('base64');
  } catch (error) {
    logger.error('Failed to generate HMAC signature', { error });
    throw new Error('Failed to generate signature');
  }
}

/**
 * Verify HMAC signature for webhook requests
 * @param data - The request body that was signed
 * @param signature - The signature to verify
 * @param secret - HMAC secret key
 * @returns true if signature is valid, false otherwise
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
    logger.error('Failed to verify HMAC signature', { error });
    return false;
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
    logger.warn('HMAC secret is too short', { minimumLength: 32 });
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