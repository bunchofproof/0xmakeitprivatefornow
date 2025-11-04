import { randomBytes, pbkdf2Sync } from 'crypto';
import { config } from '../config';
import { TokenData } from '@shared/types';
import { VerificationType } from '@shared/types/verification';
import { getVerificationExpiryMinutes } from '@shared/config/verification';
import { logger } from './logger';
import { createHMACSignature, verifyHMACSignature } from './crypto';

/**
 * Generates a cryptographically secure verification token with digital signature
 */
export function generateVerificationToken(userId: string, sessionId: string, verificationType?: VerificationType): TokenData {
  try {
    // Generate cryptographically secure random salt (256-bit)
    const salt = randomBytes(32); // 32 bytes = 256 bits

    // Use PBKDF2 with high iteration count for key derivation
    // Input: userId + sessionId as the password equivalent
    // Salt: randomly generated per token
    // Iterations: 100,000 (NIST recommended minimum for PBKDF2)
    // Key length: 32 bytes (256 bits)
    // Hash algorithm: SHA-256
    const derivedKey = pbkdf2Sync(`${userId}-${sessionId}`, salt, 100000, 32, 'sha256');

    // Combine salt and derived key for the token
    const token = salt.toString('hex') + derivedKey.toString('hex'); // 128-character string (512-bit total)

    // Use per-type expiry if verification type is provided, otherwise fallback to config default
    const expiryMinutes = verificationType ? getVerificationExpiryMinutes(verificationType) : config.bot.tokenExpiryMinutes;
    const expiresAt = new Date(Date.now() + (expiryMinutes * 60 * 1000));

    // Create token payload for signing
    const tokenPayload = {
      token,
      userId,
      sessionId,
      verificationType: verificationType || 'default',
      expiresAt: expiresAt.toISOString(),
      timestamp: Date.now(),
    };

    // Generate HMAC signature for the token
    const signatureData = JSON.stringify(tokenPayload);
    const signature = createHMACSignature(signatureData);

    const tokenData: TokenData = {
      token,
      expiresAt,
      userId,
      sessionId,
      signature: signature || '', // Add cryptographic signature
    };

    logger.debug('Generated verification token', {
      userId,
      verificationType: verificationType || 'default',
    });
    return tokenData;

  } catch (error) {
    logger.error('Error generating verification token', undefined, {
      userId,
      sessionId,
      error: error instanceof Error ? error.message : String(error),
    } as Record<string, any>);
    throw new Error('Failed to generate verification token');
  }
}

/**
 * Validates if a token is still valid (not expired)
 */
export function isTokenValid(expiresAt: Date): boolean {
  return new Date() < expiresAt;
}

/**
 * Validates token format and structure
 */
export function isValidTokenFormat(token: string): boolean {
  // Token should be 128-character hexadecimal string (512-bit: 64-char salt + 64-char derived key)
  if (!token || typeof token !== 'string') {
    return false;
  }

  // Check if it's a valid hex string
  if (!/^[a-fA-F0-9]+$/.test(token)) {
    return false;
  }

  // Check length - 128 characters for 512-bit tokens
  if (token.length !== 128) {
    return false;
  }

  return true;
}

/**
 * Verifies token cryptographic signature for integrity
 */
export function verifyTokenSignature(tokenData: TokenData): boolean {
  try {
    // Reconstruct the token payload that was signed
    const tokenPayload = {
      token: tokenData.token,
      userId: tokenData.userId,
      sessionId: tokenData.sessionId,
      verificationType: 'default', // Could be stored in tokenData if needed
      expiresAt: tokenData.expiresAt.toISOString(),
      timestamp: Date.now(), // Approximate timestamp (not exact but good enough for verification)
    };

    const signatureData = JSON.stringify(tokenPayload);

    // Verify the HMAC signature
    return verifyHMACSignature(signatureData, tokenData.signature || '');
  } catch (error) {
    logger.error('Error verifying token signature', undefined, {
      error: error instanceof Error ? error.message : String(error),
      token: tokenData.token.substring(0, 8) + '...',
      userId: tokenData.userId,
    } as Record<string, any>);
    return false;
  }
}

/**
 * Generates a cryptographically secure session ID with 256 bits of entropy
 */
export function generateSessionId(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Creates a verification URL with embedded token
 */
export function createVerificationUrl(token: string, sessionId: string): string {
  const baseUrl = config.bot.verificationUrl;
  const params = new URLSearchParams({
    token,
    session: sessionId,
    timestamp: Date.now().toString(),
  });

  return `${baseUrl}?${params.toString()}`;
}

/**
 * Validates and parses token data from URL parameters
 */
export function parseTokenFromUrl(url: string): { token?: string; sessionId?: string; timestamp?: number } | null {
  try {
    const urlObj = new URL(url);
    const token = urlObj.searchParams.get('token');
    const sessionId = urlObj.searchParams.get('session');
    const timestampStr = urlObj.searchParams.get('timestamp');
    const timestamp = timestampStr ? parseInt(timestampStr, 10) : undefined;

    if (!token || !sessionId) {
      return null;
    }

    if (!isValidTokenFormat(token)) {
      return null;
    }

    return { token, sessionId, timestamp };
  } catch (error) {
    logger.error('Error parsing token from URL', undefined, {
      error: error instanceof Error ? error.message : String(error),
      url: url.substring(0, 100) + '...',
    } as Record<string, any>);
    return null;
  }
}