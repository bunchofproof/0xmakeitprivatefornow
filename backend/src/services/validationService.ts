import Joi from 'joi';
import { UniversalInputValidator } from '@shared/utils/universalInputValidator';

// Enhanced Input sanitization functions with Universal Input Validator integration
export class InputSanitizer {
  /**
   * Enhanced string sanitization with comprehensive attack detection
   */
  static sanitizeString(input: string, maxLength: number = 1000): string {
    if (typeof input !== 'string') {
      throw new Error('Input must be a string');
    }

    // Use Universal Input Validator for comprehensive sanitization
    const result = UniversalInputValidator.validateInput(input, {
      maxLength,
      allowEmpty: false,
    });

    if (!result.isValid) {
      throw new Error(`Input validation failed: ${result.errors.join(', ')}`);
    }

    return result.sanitized;
  }

  /**
   * Enhanced domain sanitization with security validation
   */
  static sanitizeDomain(domain: string): string {
    if (typeof domain !== 'string') {
      throw new Error('Domain must be a string');
    }

    // Basic domain sanitization with Universal Input Validator
    let sanitized = domain.toLowerCase()
      .replace(/[^a-z0-9.-]/g, '') // Allow only alphanumeric, dots, and hyphens
      .replace(/^[.]+/, '') // Remove leading dots
      .replace(/[.]+$/, '') // Remove trailing dots
      .replace(/\.{2,}/g, '.') // Replace multiple dots with single dot
      .replace(/-/g, (match, offset) => offset === 0 || offset === domain.length - 1 ? '' : match); // Remove hyphens at start/end

    // Truncate to reasonable length
    if (sanitized.length > 253) { // Max domain length
      sanitized = sanitized.substring(0, 253);
    }

    // Final security validation
    const result = UniversalInputValidator.validateInput(sanitized, {
      maxLength: 253,
      forbiddenPatterns: [], // Allow dots and hyphens in domain context
    });

    if (!result.isValid) {
      throw new Error(`Domain validation failed: ${result.errors.join(', ')}`);
    }

    return sanitized;
  }

  /**
   * Enhanced email sanitization with RFC compliance
   */
  static sanitizeEmail(email: string): string {
    if (typeof email !== 'string') {
      throw new Error('Email must be a string');
    }

    const result = UniversalInputValidator.validateEmail(email);
    
    if (!result.isValid) {
      throw new Error(`Email validation failed: ${result.errors.join(', ')}`);
    }

    return result.sanitized;
  }

  /**
   * Comprehensive input validation with attack detection
   */
  static validateAndSanitize(input: any, type: 'string' | 'domain' | 'email' | 'token', maxLength: number = 1000): string {
    if (typeof input !== 'string') {
      throw new Error(`${type} input must be a string`);
    }

    let result: any;

    // Apply type-specific validation
    switch (type) {
      case 'domain':
        result = UniversalInputValidator.validateInput(input, {
          maxLength,
          forbiddenPatterns: [], // Allow dots and hyphens for domains
        });
        break;
      case 'email':
        result = UniversalInputValidator.validateEmail(input);
        break;
      case 'token':
        result = UniversalInputValidator.validateInput(input, {
          maxLength,
          customValidator: (value: string) => ({
            isValid: /^[a-fA-F0-9]+$/.test(value),
            threats: /^[a-fA-F0-9]+$/.test(value) ? [] : ['invalid_hex_format'],
          }),
        });
        break;
      default:
        result = UniversalInputValidator.validateInput(input, { maxLength });
    }

    if (!result.isValid) {
      throw new Error(`${type} validation failed: ${result.errors.join(', ')}`);
    }

    return result.sanitized;
  }
}

// Enhanced validation schemas with comprehensive security

// Verification routes schemas
export const verificationProofSchema = Joi.object({
  proofs: Joi.array().items(Joi.object()).min(1).required()
    .messages({
      'array.min': 'At least one proof is required',
      'array.base': 'Proofs must be an array of objects'
    }),
  sessionId: Joi.string().custom((value, helpers) => {
    try {
      return InputSanitizer.validateAndSanitize(value, 'token', 64);
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).pattern(/^[a-f0-9]{64}$/i).required()
    .messages({
      'string.pattern.base': 'Session ID must be a valid 64-character hexadecimal string',
      'any.required': 'Session ID is required'
    }),
  token: Joi.string().custom((value, helpers) => {
    try {
      return InputSanitizer.validateAndSanitize(value, 'token', 64);
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).pattern(/^[a-f0-9]{64}$/i).required()
    .messages({
      'string.pattern.base': 'Token must be a valid 64-character hexadecimal string',
      'any.required': 'Token is required'
    }),
  domain: Joi.string().custom((value, helpers) => {
    try {
      return InputSanitizer.validateAndSanitize(value, 'domain', 253);
    } catch (error) {
      return helpers.error('alternatives.match');
    }
  }).required()
    .messages({
      'alternatives.match': 'Domain must be a valid domain name or IP address with port',
      'string.min': 'Domain cannot be empty',
      'string.max': 'Domain must be at most 253 characters',
      'any.required': 'Domain is required'
    }),
  verificationType: Joi.string().valid('personhood', 'age', 'nationality', 'residency', 'kyc').min(1).max(20).optional().default('personhood')
    .messages({
      'any.only': 'Verification type must be one of: personhood, age, nationality, residency, kyc',
      'string.min': 'Verification type cannot be empty',
      'string.max': 'Verification type must be at most 20 characters'
    }),
  uniqueIdentifier: Joi.string().optional(), // Added during processing
}).strict();

export const verificationStatusSchema = Joi.object({
  token: Joi.string().custom((value, helpers) => {
    try {
      return InputSanitizer.validateAndSanitize(value, 'token', 64);
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).pattern(/^[a-f0-9]{64}$/i).required()
    .messages({
      'string.pattern.base': 'Token must be a valid 64-character hexadecimal string',
      'any.required': 'Token is required'
    })
});

export const verificationWebhookSchema = Joi.object({
  discordUserId: Joi.string().custom((value, helpers) => {
    try {
      const sanitized = InputSanitizer.validateAndSanitize(value, 'string', 20);
      if (!/^\d{17,20}$/.test(sanitized)) {
        return helpers.error('string.pattern.base');
      }
      return sanitized;
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).required()
    .messages({
      'string.pattern.base': 'Discord User ID must be a valid numeric ID (17-20 digits)',
      'any.required': 'Discord User ID is required'
    }),
  status: Joi.string().valid('completed', 'failed', 'pending').min(1).max(20).required()
    .messages({
      'any.only': 'Status must be one of: completed, failed, pending',
      'string.min': 'Status cannot be empty',
      'string.max': 'Status must be at most 20 characters',
      'any.required': 'Status is required'
    }),
  uniqueIdentifier: Joi.string().custom((value, helpers) => {
    try {
      return InputSanitizer.validateAndSanitize(value, 'string', 1000);
    } catch (error) {
      return helpers.error('string.max');
    }
  }).optional()
    .messages({
      'string.min': 'Unique identifier cannot be empty',
      'string.max': 'Unique identifier must be at most 1000 characters'
    })
}).strict();

// Admin routes schemas with enhanced sanitization
export const adminVerifyUserSchema = Joi.object({
  discordUserId: Joi.string().custom((value, helpers) => {
    try {
      const sanitized = InputSanitizer.validateAndSanitize(value, 'string', 20);
      if (!/^\d{17,20}$/.test(sanitized)) {
        return helpers.error('string.pattern.base');
      }
      return sanitized;
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).required()
    .messages({
      'string.pattern.base': 'Discord User ID must be a valid 17-20 digit numeric ID',
      'any.required': 'Discord User ID is required'
    }),
  adminUserId: Joi.string().custom((value, helpers) => {
    try {
      const sanitized = InputSanitizer.validateAndSanitize(value, 'string', 20);
      if (!/^\d{17,20}$/.test(sanitized)) {
        return helpers.error('string.pattern.base');
      }
      return sanitized;
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).optional()
    .messages({
      'string.pattern.base': 'Admin User ID must be a valid 17-20 digit numeric ID'
    })
});

export const adminRevokeUserSchema = Joi.object({
  discordUserId: Joi.string().custom((value, helpers) => {
    try {
      const sanitized = InputSanitizer.validateAndSanitize(value, 'string', 20);
      if (!/^\d{17,20}$/.test(sanitized)) {
        return helpers.error('string.pattern.base');
      }
      return sanitized;
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).required()
    .messages({
      'string.pattern.base': 'Discord User ID must be a valid 17-20 digit numeric ID',
      'any.required': 'Discord User ID is required'
    }),
  adminUserId: Joi.string().custom((value, helpers) => {
    try {
      const sanitized = InputSanitizer.validateAndSanitize(value, 'string', 20);
      if (!/^\d{17,20}$/.test(sanitized)) {
        return helpers.error('string.pattern.base');
      }
      return sanitized;
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).optional()
    .messages({
      'string.pattern.base': 'Admin User ID must be a valid 17-20 digit numeric ID'
    }),
  reason: Joi.string().custom((value, helpers) => {
    try {
      return InputSanitizer.validateAndSanitize(value, 'string', 500);
    } catch (error) {
      return helpers.error('string.max');
    }
  }).optional()
    .messages({
      'string.max': 'Reason must be at most 500 characters'
    })
});

// Discord routes schemas with enhanced sanitization
export const discordRegisterSchema = Joi.object({
  discordUserId: Joi.string().custom((value, helpers) => {
    try {
      const sanitized = InputSanitizer.validateAndSanitize(value, 'string', 20);
      if (!/^\d{17,20}$/.test(sanitized)) {
        return helpers.error('string.pattern.base');
      }
      return sanitized;
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).required()
    .messages({
      'string.pattern.base': 'Discord User ID must be a valid 17-20 digit numeric ID',
      'any.required': 'Discord User ID is required'
    }),
  verified: Joi.boolean().required()
    .messages({
      'boolean.base': 'Verified must be a boolean value',
      'any.required': 'Verified status is required'
    })
});

export const discordVerifySchema = Joi.object({
  discordUserId: Joi.string().custom((value, helpers) => {
    try {
      const sanitized = InputSanitizer.validateAndSanitize(value, 'string', 20);
      if (!/^\d{17,20}$/.test(sanitized)) {
        return helpers.error('string.pattern.base');
      }
      return sanitized;
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).required()
    .messages({
      'string.pattern.base': 'Discord User ID must be a valid 17-20 digit numeric ID',
      'any.required': 'Discord User ID is required'
    }),
  action: Joi.string().valid('assign', 'revoke').required()
    .messages({
      'any.only': 'Action must be either "assign" or "revoke"',
      'any.required': 'Action is required'
    })
});

export const discordUserIdParamSchema = Joi.object({
  userId: Joi.string().custom((value, helpers) => {
    try {
      const sanitized = InputSanitizer.validateAndSanitize(value, 'string', 20);
      if (!/^\d{17,20}$/.test(sanitized)) {
        return helpers.error('string.pattern.base');
      }
      return sanitized;
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).required()
    .messages({
      'string.pattern.base': 'User ID must be a valid 17-20 digit numeric ID',
      'any.required': 'User ID is required'
    })
});

// Webhook routes schemas with enhanced sanitization
export const webhookDiscordSchema = Joi.object({
  type: Joi.string().custom((value, helpers) => {
    try {
      return InputSanitizer.validateAndSanitize(value, 'string', 50);
    } catch (error) {
      return helpers.error('any.only');
    }
  }).valid('verification_started', 'verification_completed', 'verification_failed', 'role_updated').required()
    .messages({
      'any.only': 'Type must be one of: verification_started, verification_completed, verification_failed, role_updated',
      'any.required': 'Type is required'
    }),
  data: Joi.object().required()
    .messages({
      'object.base': 'Data must be an object',
      'any.required': 'Data is required'
    }),
  userId: Joi.string().custom((value, helpers) => {
    try {
      const sanitized = InputSanitizer.validateAndSanitize(value, 'string', 20);
      if (!/^\d{17,20}$/.test(sanitized)) {
        return helpers.error('string.pattern.base');
      }
      return sanitized;
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).optional()
    .messages({
      'string.pattern.base': 'User ID must be a valid 17-20 digit numeric ID'
    })
});

export const webhookVerificationSchema = Joi.object({
  sessionId: Joi.string().custom((value, helpers) => {
    try {
      return InputSanitizer.validateAndSanitize(value, 'token', 64);
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).pattern(/^[a-f0-9]{64}$/i).required()
    .messages({
      'string.pattern.base': 'Session ID must be a valid 64-character hexadecimal string',
      'any.required': 'Session ID is required'
    }),
  status: Joi.string().custom((value, helpers) => {
    try {
      return InputSanitizer.validateAndSanitize(value, 'string', 20);
    } catch (error) {
      return helpers.error('any.only');
    }
  }).valid('completed', 'failed', 'pending').required()
    .messages({
      'any.only': 'Status must be one of: completed, failed, pending',
      'any.required': 'Status is required'
    }),
  userId: Joi.string().custom((value, helpers) => {
    try {
      const sanitized = InputSanitizer.validateAndSanitize(value, 'string', 20);
      if (!/^\d{17,20}$/.test(sanitized)) {
        return helpers.error('string.pattern.base');
      }
      return sanitized;
    } catch (error) {
      return helpers.error('string.pattern.base');
    }
  }).required()
    .messages({
      'string.pattern.base': 'User ID must be a valid 17-20 digit numeric ID',
      'any.required': 'User ID is required'
    }),
  metadata: Joi.object().optional()
});

export const webhookHealthSchema = Joi.object({
  service: Joi.string().custom((value, helpers) => {
    try {
      return InputSanitizer.validateAndSanitize(value, 'string', 100);
    } catch (error) {
      return helpers.error('string.max');
    }
  }).required()
    .messages({
      'string.min': 'Service name cannot be empty',
      'string.max': 'Service name must be at most 100 characters',
      'any.required': 'Service is required'
    }),
  status: Joi.string().custom((value, helpers) => {
    try {
      return InputSanitizer.validateAndSanitize(value, 'string', 20);
    } catch (error) {
      return helpers.error('any.only');
    }
  }).valid('healthy', 'unhealthy').required()
    .messages({
      'any.only': 'Status must be either "healthy" or "unhealthy"',
      'any.required': 'Status is required'
    }),
  timestamp: Joi.string().isoDate().optional()
    .messages({
      'string.isoDate': 'Timestamp must be a valid ISO date string'
    })
});

// Validation functions
export function validateVerificationRequest(body: any) {
  return verificationProofSchema.validate(body);
}

export function validateVerificationStatus(params: any) {
  return verificationStatusSchema.validate(params);
}

export function validateVerificationWebhook(body: any) {
  return verificationWebhookSchema.validate(body);
}

export function validateAdminVerifyUser(body: any) {
  return adminVerifyUserSchema.validate(body);
}

export function validateAdminRevokeUser(body: any) {
  return adminRevokeUserSchema.validate(body);
}

export function validateDiscordRegister(body: any) {
  return discordRegisterSchema.validate(body);
}

export function validateDiscordVerify(body: any) {
  return discordVerifySchema.validate(body);
}

export function validateDiscordUserId(params: any) {
  return discordUserIdParamSchema.validate(params);
}

export function validateWebhookDiscord(body: any) {
  return webhookDiscordSchema.validate(body);
}

export function validateWebhookVerification(body: any) {
  return webhookVerificationSchema.validate(body);
}

export function validateWebhookHealth(body: any) {
  return webhookHealthSchema.validate(body);
}