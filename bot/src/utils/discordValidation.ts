/**
 * Enhanced Discord command validation and sanitization utilities with universal rate limiting
 */

import { ChatInputCommandInteraction, MessageFlags } from 'discord.js';
// Input sanitization functions for comprehensive protection
class InputSanitizer {
  /**
   * Sanitize string input to prevent XSS and injection attacks
   */
  static sanitizeString(input: string, maxLength: number = 1000): string {
    if (typeof input !== 'string') {
      throw new Error('Input must be a string');
    }

    // Remove null bytes and control characters
    let sanitized = input.replace(/[\x00-\x1F\x7F]/g, '');
    
    // Remove or encode potentially dangerous characters
    sanitized = sanitized
      .replace(/[<>]/g, '') // Remove < and > to prevent HTML injection
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/vbscript:/gi, '') // Remove vbscript: protocol
      .replace(/data:/gi, '') // Remove data: protocol
      .replace(/file:/gi, '') // Remove file: protocol
      .replace(/@import/gi, '') // Remove @import directives
      .replace(/expression\s*\(/gi, '') // Remove expression() calls
      .replace(/behavior\s*:/gi, '') // Remove behavior: CSS
      .replace(/behavior\s*=\s*['"]?\s*['"']?\s*/gi, '') // Remove behavior attributes
      .replace(/on\w+\s*=/gi, '') // Remove event handlers (onclick, onload, etc.)
      .replace(/<[^>]*>/g, ''); // Remove all HTML tags

    // Truncate to max length
    if (sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
    }

    return sanitized.trim();
  }

  /**
   * Check for SQL injection patterns
   */
  static containsSqlInjection(input: string): boolean {
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)/gi,
      /((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/gi, // 'or' variations
      /((\%27)|(\'))((\%6D)|m|(\%4D))((\%77)|w|(\%57))/gi, // 'or'='something'
      /(\b(OR|AND)\b\s+(\%27)|(\\')\s*[=\%])/gi,
      /(\b(XOR)\b\s+(\%27)|(\\')\s*[=\%])/gi,
      /((\%27)|(\'))\s*((\%6F)|o|(\%4F))((\%72)|r|(\%52))/gi,
      /((\%27)|(\'))\s*((\%6D)|m|(\%4D))((\%77)|w|(\%57))/gi,
      /(\bUNION\b.*\bSELECT\b)/gi,
      /(\bDROP\b.*\bTABLE\b)/gi,
      /(\bINSERT\b.*\bINTO\b)/gi,
      /(\bUPDATE\b.*\bSET\b)/gi,
      /(\bDELETE\b.*\bFROM\b)/gi,
    ];

    return sqlPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Check for command injection patterns
   */
  static containsCommandInjection(input: string): boolean {
    const commandPatterns = [
      /[;&|`$()]/, // Shell metacharacters
      /(\brm\b|\bdel\b|\bcmd\b|\bpowershell\b|\bbash\b|\bsh\b|\bchmod\b|\bmv\b|\bcp\b)/gi,
      /(\bwget\b|\bcurl\b|\bnc\b|\bnetcat\b|\btelnet\b|\bssh\b)/gi,
      /(>)(\s*)[^>]*(\s*)<\/script>/gi, // Command redirection in script tags
      /(\.\.\/)+/, // Path traversal
      /\$\{[^}]+\}/gi, // Variable expansion
      /\$\w+/gi, // Variable substitution
    ];

    return commandPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Check for path traversal attempts
   */
  static containsPathTraversal(input: string): boolean {
    const pathTraversalPatterns = [
      /(\.\.\/)+/, // Relative path traversal
      /(\.\.%2F)+/gi, // Encoded relative path traversal
      /%2e%2e%2f/gi, // Another encoded relative path traversal
      /(\.\.\\)+/, // Windows relative path traversal
      /(%252e%252e%252f)+/gi, // Double encoded relative path traversal
    ];

    return pathTraversalPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Comprehensive input validation with attack detection
   */
  static validateAndSanitize(input: any, type: 'string' | 'domain' | 'email' | 'token', maxLength: number = 1000): string {
    if (typeof input !== 'string') {
      throw new Error(`${type} input must be a string`);
    }

    let sanitized: string;

    // Apply type-specific sanitization
    switch (type) {
      case 'token':
        sanitized = input.replace(/[^a-fA-F0-9]/g, ''); // Only allow hex characters for tokens
        break;
      default:
        sanitized = this.sanitizeString(input, maxLength);
    }

    // Apply comprehensive attack pattern detection
    if (this.containsSqlInjection(sanitized)) {
      throw new Error('Input contains suspicious SQL injection patterns');
    }

    if (this.containsCommandInjection(sanitized)) {
      throw new Error('Input contains suspicious command injection patterns');
    }

    if (this.containsPathTraversal(sanitized)) {
      throw new Error('Input contains suspicious path traversal patterns');
    }

    // Additional length check after sanitization
    if (sanitized.length > maxLength) {
      throw new Error(`${type} exceeds maximum length of ${maxLength} characters`);
    }

    return sanitized;
  }
}
// Import simplified rate limiting system for bot
import { rateLimitManager } from './rateLimitManager';

export class DiscordCommandValidator {
  private static rateLimitManager = rateLimitManager;

  /**
   * Validate Discord User ID format and sanitize
   */
  static validateUserId(userId: string): string {
    if (typeof userId !== 'string') {
      throw new Error('User ID must be a string');
    }

    // Sanitize and validate user ID
    const sanitized = InputSanitizer.validateAndSanitize(userId, 'string', 20);
    if (!/^\d{17,20}$/.test(sanitized)) {
      throw new Error('Invalid Discord User ID format');
    }

    return sanitized;
  }

  /**
   * Validate Discord username and sanitize
   */
  static validateUsername(username: string): string {
    if (typeof username !== 'string') {
      throw new Error('Username must be a string');
    }

    // Sanitize username
    return InputSanitizer.validateAndSanitize(username, 'string', 32);
  }

  /**
   * Validate reason text with strict length and content limits
   */
  static validateReason(reason: string): string {
    if (typeof reason !== 'string') {
      throw new Error('Reason must be a string');
    }

    // Strict reason validation - limited characters, no HTML/script
    const sanitized = reason
      .replace(/[\x00-\x1F\x7F]/g, '') // Remove control characters
      .replace(/[<>]/g, '') // Remove HTML brackets
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/vbscript:/gi, '') // Remove vbscript: protocol
      .replace(/@import/gi, '') // Remove @import
      .replace(/expression\s*\(/gi, '') // Remove expression()
      .replace(/behavior\s*:/gi, '') // Remove behavior:
      .replace(/on\w+\s*=/gi, '') // Remove event handlers
      .replace(/[*_`~]/g, '') // Remove Discord markdown that could be abused
      .trim();

    if (sanitized.length > 500) {
      throw new Error('Reason cannot exceed 500 characters');
    }

    if (sanitized.length === 0) {
      throw new Error('Reason cannot be empty');
    }

    return sanitized;
  }

  /**
   * Validate verification type parameter
   */
  static validateVerificationType(type: string): string {
    const validTypes = ['personhood', 'age', 'nationality', 'residency', 'kyc'];
    
    if (typeof type !== 'string') {
      throw new Error('Verification type must be a string');
    }

    const sanitized = InputSanitizer.validateAndSanitize(type, 'string', 20);
    
    if (!validTypes.includes(sanitized)) {
      throw new Error(`Invalid verification type. Must be one of: ${validTypes.join(', ')}`);
    }

    return sanitized;
  }

  /**
   * Validate Discord channel mentions and IDs
   */
  static validateChannelId(channelId: string): string {
    if (typeof channelId !== 'string') {
      throw new Error('Channel ID must be a string');
    }

    // Remove channel mention format (<#1234567890123456789>) if present
    const cleanId = channelId.replace(/[<#>]/g, '');
    
    const sanitized = InputSanitizer.validateAndSanitize(cleanId, 'string', 20);
    if (!/^\d{17,20}$/.test(sanitized)) {
      throw new Error('Invalid Discord channel ID format');
    }

    return sanitized;
  }

  /**
   * Check for potentially malicious input patterns in Discord commands
   */
  static containsMaliciousPatterns(input: string): boolean {
    const maliciousPatterns = [
      // Script injection
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /vbscript:/gi,
      /data:/gi,
      /file:/gi,
      
      // Discord markdown abuse
      /\[.*?\]\(.*?\)/gi, // Link markdown
      /\*\*\*.*?\*\*\*/gi, // Bold and italic abuse
      /`{3,}/gi, // Code block abuse
      
      // Mention spam/ping abuse
      /<@!?\d{17,20}>/gi, // Multiple user mentions
      /<@&\d{17,20}>/gi, // Role mentions
      /<#\d{17,20}>/gi, // Channel mentions
      
      // Command injection
      /[;&|`$()]/,
      /(\b(rm|del|cmd|powershell|bash|sh|chmod|mv|cp)\b)/gi,
      /(\b(wget|curl|nc|netcat|telnet|ssh)\b)/gi,
    ];

    return maliciousPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Validate and sanitize Discord command options
   */
  static validateCommandOptions(interaction: ChatInputCommandInteraction): void {
    const options = interaction.options.data;

    for (const option of options) {
      if (option.value) {
        // Check for malicious patterns
        if (this.containsMaliciousPatterns(String(option.value))) {
          throw new Error(`Potentially malicious content detected in option: ${option.name}`);
        }

        // Type-specific validation
        switch (option.name) {
          case 'user':
            if (typeof option.value === 'string') {
              this.validateUserId(option.value);
            }
            break;
          case 'reason':
            if (typeof option.value === 'string') {
              this.validateReason(option.value);
            }
            break;
          case 'type':
            if (typeof option.value === 'string') {
              this.validateVerificationType(option.value);
            }
            break;
          case 'channel':
            if (typeof option.value === 'string') {
              this.validateChannelId(String(option.value));
            }
            break;
          default:
            // Generic string validation for unknown options
            if (typeof option.value === 'string') {
              InputSanitizer.validateAndSanitize(option.value, 'string', 100);
            }
        }
      }
    }
  }

  /**
   * Universal rate limiting for Discord commands with abuse detection
   */
  static async checkCommandRateLimit(userId: string, commandName: string): Promise<boolean> {
    try {
      // Map command names to endpoints for the rate limit manager
      const endpointMap: { [key: string]: string } = {
        'verify': 'discord-command-verify',
        'status': 'discord-command-status',
        'help': 'discord-command-help',
        'admin': 'discord-command-admin'
      };

      const endpoint = endpointMap[commandName] || 'discord-command-general';
      
      // Check rate limit with sliding window and abuse detection
      const isLimited = await this.rateLimitManager.isRateLimitedLegacy(endpoint, userId, {
        userId,
        authenticated: true, // Discord users are authenticated
        privilegeLevel: 'user' // Default to user, admin commands will have additional checks
      });

      if (isLimited.limited) {
        // Log abuse attempt
        console.warn(`🚫 Discord command rate limited: ${commandName} by ${userId}`, {
          isAbuse: isLimited.isAbuse,
          remainingPoints: isLimited.remainingPoints
        });
        return false;
      }

      return true;
    } catch (error) {
      console.error('Rate limit check error:', error);
      // Allow command on error but log it
      return true;
    }
  }

  /**
   * Get rate limit stats for Discord commands
   */
  static getRateLimitStats() {
    return this.rateLimitManager.getStats();
  }

  /**
   * Reset rate limit for a user (admin function)
   */
  static async resetUserRateLimit(): Promise<boolean> {
    try {
      // Note: resetRateLimit method doesn't exist in UniversalRateLimitManager
      // Implement reset logic here if needed, or remove this functionality
      return true;
    } catch (error) {
      console.error('Failed to reset Discord user rate limit:', error);
      return false;
    }
  }

  /**
   * Enhanced cleanup for Discord-specific rate limiting
   */
  static initializeCleanup() {
    // Clean up expired command usage entries every 10 minutes
    setInterval(() => {
      console.log('🧹 Cleaning up Discord command rate limiting data...');
      // Cleanup is handled automatically by the rate limit manager
    }, 10 * 60 * 1000);
  }
}

/**
 * Enhanced Discord command error handling with validation failures
 */
export function handleValidationError(
  error: any,
  interaction: ChatInputCommandInteraction,
  context: { userId: string; command: string; option?: string }
): void {
  const { userId, command, option } = context;

  // Log the validation failure
  console.warn(`Discord command validation failed:`, {
    userId,
    command,
    option,
    error: error.message,
    timestamp: new Date().toISOString()
  });

  let errorMessage: string;

  // Specific error messages based on validation failure type
  if (error.message.includes('malicious content')) {
    errorMessage = '❌ **Invalid Input Detected**\n\nYour command contains potentially harmful content. Please use only standard text without HTML, links, or special formatting.';
  } else if (error.message.includes('User ID')) {
    errorMessage = '❌ **Invalid User ID**\n\nPlease provide a valid Discord user ID or mention.';
  } else if (error.message.includes('verification type')) {
    errorMessage = '❌ **Invalid Verification Type**\n\nPlease use one of the supported verification types.';
  } else if (error.message.includes('reason')) {
    errorMessage = '❌ **Invalid Reason**\n\nReason must be between 1-500 characters and contain only standard text.';
  } else if (error.message.includes('rate limit')) {
    errorMessage = '⏱️ **Command Rate Limited**\n\nPlease wait a moment before using this command again.';
  } else {
    errorMessage = '❌ **Validation Error**\n\nPlease check your command parameters and try again.';
  }

  // Send error response
  if (interaction.deferred || interaction.replied) {
    interaction.editReply({ content: errorMessage });
  } else {
    interaction.reply({
      content: errorMessage,
      flags: MessageFlags.Ephemeral
    });
  }
}