// Re-export all authentication functions for backward compatibility
export { validateApiKey } from './tokenAuth';
export { validateToken, requireValidToken, checkVerificationStatus, checkVerificationRateLimit, cleanupRateLimitEntries, clearRateLimitMapForTesting, startRateLimitCleanup, stopRateLimitCleanup } from './sessionAuth';

// Re-export validation and security functions (keeping these in auth.ts as they are general-purpose)
export { validateAndSanitize, validateParams, securityValidation, checkValidationRateLimit, cleanupValidationFailureEntries, clearValidationFailureMapForTesting, startValidationFailureCleanup, stopValidationFailureCleanup, validateRequestSize, validateRequestHeaders } from './validationAuth';