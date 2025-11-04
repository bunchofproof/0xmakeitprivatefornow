import { CommandInteraction } from 'discord.js';
import { isValidDiscordUserId, sanitizeInput } from '@shared/utils';
import { logger } from '../utils/logger';
import { verifyTokenSignature } from '../utils/tokenGenerator';
import { TokenData } from '@shared/types';

export interface ValidationResult {
  isValid: boolean;
  error?: string;
  sanitizedValue?: string;
}

/**
 * Validates Discord user ID format
 */
export function validateDiscordUserId(userId: string): ValidationResult {
  const sanitized = sanitizeInput(userId);

  if (!sanitized) {
    return {
      isValid: false,
      error: 'User ID cannot be empty',
    };
  }

  if (!isValidDiscordUserId(sanitized)) {
    return {
      isValid: false,
      error: 'Invalid Discord user ID format',
    };
  }

  return {
    isValid: true,
    sanitizedValue: sanitized,
  };
}

/**
 * Validates command interaction inputs
 */
export function validateCommandInput(interaction: CommandInteraction): ValidationResult {
  try {
    // Check for basic interaction validity
    if (!interaction.user || !interaction.guild) {
      return {
        isValid: false,
        error: 'Invalid interaction context',
      };
    }

    // Validate user ID
    const userValidation = validateDiscordUserId(interaction.user.id);
    if (!userValidation.isValid) {
      return userValidation;
    }

    // Check for rate limiting (this would be implemented per-command)
    // TODO: Integrate with rate limiting system

    return { isValid: true };

  } catch (error) {
   logger.error('Error validating command input', error instanceof Error ? error : new Error(String(error)), {
     error: error instanceof Error ? error.message : String(error),
   });
   return {
     isValid: false,
     error: 'Failed to validate input',
   };
  }
}

/**
 * Validates admin permissions for restricted commands
 */
export function validateAdminPermissions(interaction: CommandInteraction): ValidationResult {
  try {
    const member = interaction.guild?.members.cache.get(interaction.user.id);

    if (!member) {
      return {
        isValid: false,
        error: 'Member not found in guild',
      };
    }

    // Check if user has any of the configured admin roles
    const { config } = require('../config');
    const hasAdminRole = config.bot.adminRoleIds.some((roleId: string) =>
      member.roles.cache.has(roleId)
    );

    if (!hasAdminRole) {
      return {
        isValid: false,
        error: 'Insufficient permissions. This command requires administrator privileges.',
      };
    }

    return { isValid: true };

  } catch (error) {
   logger.error('Error validating admin permissions', error instanceof Error ? error : new Error(String(error)), {
     error: error instanceof Error ? error.message : String(error),
   });
   return {
     isValid: false,
     error: 'Failed to validate permissions',
   };
  }
}

/**
 * Validates verification token format and integrity
 */
export function validateVerificationToken(token: string, tokenData?: TokenData): ValidationResult {
   const sanitized = sanitizeInput(token);

   if (!sanitized) {
     return {
       isValid: false,
       error: 'Token cannot be empty',
     };
   }

   // Check token length (should match config)
   const { config } = require('../config');
   if (sanitized.length !== config.crypto.tokenLength) {
     return {
       isValid: false,
       error: 'Invalid token length',
     };
   }

   // Check if token contains only valid characters
   if (!/^[a-fA-F0-9]+$/.test(sanitized)) {
     return {
       isValid: false,
       error: 'Invalid token format',
     };
   }

   // If tokenData is provided, verify cryptographic signature
   if (tokenData && !verifyTokenSignature(tokenData)) {
     return {
       isValid: false,
       error: 'Token signature verification failed',
     };
   }

   return {
     isValid: true,
     sanitizedValue: sanitized,
   };
}

/**
 * Validates reason input for admin actions
 */
export function validateReason(reason: string, maxLength: number = 500): ValidationResult {
  const sanitized = sanitizeInput(reason);

  if (!sanitized) {
    return {
      isValid: false,
      error: 'Reason cannot be empty',
    };
  }

  if (sanitized.length > maxLength) {
    return {
      isValid: false,
      error: `Reason cannot exceed ${maxLength} characters`,
    };
  }

  // Check for potentially harmful content
  const suspiciousPatterns = [
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<iframe/i,
    /<object/i,
    /<embed/i,
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(sanitized)) {
      return {
        isValid: false,
        error: 'Reason contains invalid content',
      };
    }
  }

  return {
    isValid: true,
    sanitizedValue: sanitized,
  };
}

/**
 * Validates session ID format
 */
export function validateSessionId(sessionId: string): ValidationResult {
  const sanitized = sanitizeInput(sessionId);

  if (!sanitized) {
    return {
      isValid: false,
      error: 'Session ID cannot be empty',
    };
  }

  // Session IDs should be 64-character hexadecimal strings (256 bits of entropy)
  if (!/^[a-f0-9]{64}$/i.test(sanitized)) {
    return {
      isValid: false,
      error: 'Invalid session ID format',
    };
  }

  return {
    isValid: true,
    sanitizedValue: sanitized,
  };
}

/**
 * Validates URL format for verification URLs
 */
export function validateVerificationUrl(url: string): ValidationResult {
  const sanitized = sanitizeInput(url);

  if (!sanitized) {
    return {
      isValid: false,
      error: 'URL cannot be empty',
    };
  }

  try {
    const urlObj = new URL(sanitized);

    // Check for valid HTTP/HTTPS protocols
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      return {
        isValid: false,
        error: 'URL must use HTTP or HTTPS protocol',
      };
    }

    // Check for valid hostname
    if (!urlObj.hostname) {
      return {
        isValid: false,
        error: 'Invalid URL hostname',
      };
    }

    return {
      isValid: true,
      sanitizedValue: sanitized,
    };

  } catch (error) {
    return {
      isValid: false,
      error: 'Invalid URL format',
    };
  }
}

/**
 * Middleware function to validate all inputs for a command
 */
export async function validateAllInputs(interaction: CommandInteraction): Promise<ValidationResult> {
  // Basic input validation
  const basicValidation = validateCommandInput(interaction);
  if (!basicValidation.isValid) {
    return basicValidation;
  }

  // Command-specific validations
  const commandName = interaction.commandName;

  switch (commandName) {
    case 'verify':
      // No additional validation needed for basic verify command
      break;

    case 'status':
      // Validate target user if provided
      const targetUser = (interaction as any).options.getUser('user');
      if (targetUser) {
        const userValidation = validateDiscordUserId(targetUser.id);
        if (!userValidation.isValid) {
          return userValidation;
        }
      }
      break;

    case 'adminstatus':
      // Admin commands need admin permission validation
      const adminValidation = validateAdminPermissions(interaction);
      if (!adminValidation.isValid) {
        return adminValidation;
      }

      // Validate subcommand-specific inputs
      const subcommand = (interaction as any).options.getSubcommand();

      if (subcommand === 'approve' || subcommand === 'reject') {
        const targetUserId = (interaction as any).options.getString('user_id', true);
        const userValidation = validateDiscordUserId(targetUserId);
        if (!userValidation.isValid) {
          return userValidation;
        }

        if (subcommand === 'reject') {
          const reason = (interaction as any).options.getString('reason', true);
          const reasonValidation = validateReason(reason);
          if (!reasonValidation.isValid) {
            return reasonValidation;
          }
        }
      }

      if (subcommand === 'approve') {
        const reason = (interaction as any).options.getString('reason');
        if (reason) {
          const reasonValidation = validateReason(reason);
          if (!reasonValidation.isValid) {
            return reasonValidation;
          }
        }
      }
      break;

    default:
      // Unknown command - this should be caught earlier but just in case
      return {
        isValid: false,
        error: 'Unknown command',
      };
  }

  return { isValid: true };
}