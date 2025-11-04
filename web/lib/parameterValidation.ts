/**
 * URL Parameter Validation Utilities
 * Provides secure validation for URL parameters to prevent injection attacks
 */

/**
 * Validates a UUID format (version 1-5)
 */
export function validateUUID(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

/**
 * Validates a verification token format (hexadecimal string of length 64)
 */
export function validateToken(token: string): boolean {
  // Tokens should be hexadecimal strings of expected length
  if (!token || typeof token !== 'string') {
    return false;
  }

  // Check if it's a valid hex string
  if (!/^[a-fA-F0-9]+$/.test(token)) {
    return false;
  }
  
  // Check length (64 characters for the token)
  return token.length === 64;
}

/**
 * Validates a Discord User ID (17-20 digit numeric string)
 */
export function validateDiscordId(discordId: string): boolean {
  return /^\d{17,20}$/.test(discordId);
}

/**
 * Validates verification type against allowed types
 */
export function validateVerificationType(type: string): boolean {
  const allowedTypes = ['personhood', 'age', 'nationality', 'residency', 'kyc'];
  return allowedTypes.includes(type);
}

/**
 * Validates alphanumeric parameter format
 */
export function validateAlphanumeric(param: string): boolean {
  return /^[a-zA-Z0-9]+$/.test(param);
}

/**
 * Sanitizes URL parameters to prevent injection attacks
 */
export function sanitizeUrlParameter(param: string): string {
  return param.replace(/[<>'"&]/g, '').trim();
}

/**
 * Validates all required URL parameters for verification
 */
export function validateVerificationParameters(token?: string, session?: string, type?: string): { isValid: boolean; errorType?: string } {
  if (!token || !validateToken(token)) {
    return { isValid: false, errorType: 'invalid_token' };
  }

  if (!session || !validateToken(session)) {
    return { isValid: false, errorType: 'invalid_session' };
  }

  if (type && !validateVerificationType(type)) {
    return { isValid: false, errorType: 'invalid_type' };
  }

  return { isValid: true };
}