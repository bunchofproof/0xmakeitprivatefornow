import { auditLogger } from '@shared/services/auditLogger';
import { MessageFlags } from 'discord.js';

export interface UserFriendlyError {
  code: string;
  title: string;
  message: string;
  userMessage: string;
  recoverySuggestions: string[];
  retryable: boolean;
  technicalDetails?: string;
}

export interface ErrorContext {
  userId?: string;
  sessionId?: string;
  operation: string;
  verificationType?: string;
  ipAddress?: string;
  userAgent?: string;
}

// Error codes and their user-friendly mappings
export const ERROR_CODES = {
  // Network/API errors
  NETWORK_TIMEOUT: 'network_timeout',
  DISCORD_API_ERROR: 'discord_api_error',
  ZKPASS_SDK_ERROR: 'zkpass_sdk_error',

  // Authentication errors
  INVALID_SESSION_TOKEN: 'invalid_session_token',
  SESSION_EXPIRED: 'session_expired',
  UNAUTHORIZED_ACCESS: 'unauthorized_access',

  // Validation errors
  INVALID_REQUEST: 'invalid_request',
  INVALID_PROOF_DATA: 'invalid_proof_data',
  RATE_LIMIT_EXCEEDED: 'rate_limit_exceeded',

  // Security violations
  PROOF_REPLAY_ATTACK: 'proof_replay_attack',
  DUPLICATE_ID_VIOLATION: 'duplicate_id_violation',
  SECURITY_VIOLATION: 'security_violation',

  // System errors
  DATABASE_ERROR: 'database_error',
  INTERNAL_ERROR: 'internal_error',
  CONFIGURATION_ERROR: 'configuration_error',

  // User interaction errors
  USER_CANCELLED: 'user_cancelled',
  VERIFICATION_FAILED: 'verification_failed',
  ROLE_ASSIGNMENT_FAILED: 'role_assignment_failed',
} as const;

export type ErrorCode = typeof ERROR_CODES[keyof typeof ERROR_CODES];

// User-friendly error definitions
const USER_FRIENDLY_ERRORS: Record<ErrorCode, Omit<UserFriendlyError, 'technicalDetails'>> = {
  [ERROR_CODES.NETWORK_TIMEOUT]: {
    code: ERROR_CODES.NETWORK_TIMEOUT,
    title: 'Connection Timeout',
    message: 'The request took too long to complete. This might be due to network issues.',
    userMessage: 'Connection timed out. Please check your internet connection and try again.',
    recoverySuggestions: [
      'Check your internet connection',
      'Wait a moment and try again',
      'Contact support if the problem persists'
    ],
    retryable: true,
  },
  [ERROR_CODES.DISCORD_API_ERROR]: {
    code: ERROR_CODES.DISCORD_API_ERROR,
    title: 'Discord Service Unavailable',
    message: 'Unable to communicate with Discord services.',
    userMessage: 'Discord services are temporarily unavailable. Please try again in a few minutes.',
    recoverySuggestions: [
      'Wait a few minutes and try again',
      'Check Discord status page for outages',
      'Contact support if the problem continues'
    ],
    retryable: true,
  },
  [ERROR_CODES.ZKPASS_SDK_ERROR]: {
    code: ERROR_CODES.ZKPASS_SDK_ERROR,
    title: 'Verification Service Error',
    message: 'The ZKPassport verification service encountered an error.',
    userMessage: 'The verification service is experiencing issues. Please try again.',
    recoverySuggestions: [
      'Try the verification process again',
      'Make sure your ZKPassport app is up to date',
      'Contact support if issues persist'
    ],
    retryable: true,
  },
  [ERROR_CODES.INVALID_SESSION_TOKEN]: {
    code: ERROR_CODES.INVALID_SESSION_TOKEN,
    title: 'Invalid Session',
    message: 'The verification session token is invalid or has expired.',
    userMessage: 'Your verification session has expired. Please start the verification process again.',
    recoverySuggestions: [
      'Start the verification process again',
      'Use the /verify command in Discord',
      'Make sure to complete verification before the link expires'
    ],
    retryable: false,
  },
  [ERROR_CODES.SESSION_EXPIRED]: {
    code: ERROR_CODES.SESSION_EXPIRED,
    title: 'Session Expired',
    message: 'The verification session has expired.',
    userMessage: 'Your verification session has expired. Please start a new verification.',
    recoverySuggestions: [
      'Start the verification process again',
      'Complete verification within the time limit shown'
    ],
    retryable: false,
  },
  [ERROR_CODES.UNAUTHORIZED_ACCESS]: {
    code: ERROR_CODES.UNAUTHORIZED_ACCESS,
    title: 'Access Denied',
    message: 'You are not authorized to perform this action.',
    userMessage: 'You do not have permission to perform this verification.',
    recoverySuggestions: [
      'Make sure you are using the correct Discord account',
      'Contact server administrators if you believe this is an error'
    ],
    retryable: false,
  },
  [ERROR_CODES.INVALID_REQUEST]: {
    code: ERROR_CODES.INVALID_REQUEST,
    title: 'Invalid Request',
    message: 'The request contains invalid or malformed data.',
    userMessage: 'There was an issue with your verification request. Please try again.',
    recoverySuggestions: [
      'Start the verification process again',
      'Make sure you are following the instructions correctly'
    ],
    retryable: true,
  },
  [ERROR_CODES.INVALID_PROOF_DATA]: {
    code: ERROR_CODES.INVALID_PROOF_DATA,
    title: 'Invalid Proof Data',
    message: 'The verification proof data is invalid or corrupted.',
    userMessage: 'Your proof could not be validated. Please try the verification process again.',
    recoverySuggestions: [
      'Try the verification process again',
      'Make sure your ZKPassport app is properly set up',
      'Ensure you have a valid passport loaded'
    ],
    retryable: true,
  },
  [ERROR_CODES.RATE_LIMIT_EXCEEDED]: {
    code: ERROR_CODES.RATE_LIMIT_EXCEEDED,
    title: 'Rate Limit Exceeded',
    message: 'Too many verification attempts in a short time period.',
    userMessage: 'You have made too many verification attempts. Please wait before trying again.',
    recoverySuggestions: [
      'Wait the indicated time period before trying again',
      'Contact support if you need immediate assistance'
    ],
    retryable: false,
  },
  [ERROR_CODES.PROOF_REPLAY_ATTACK]: {
    code: ERROR_CODES.PROOF_REPLAY_ATTACK,
    title: 'Security Violation',
    message: 'Attempted to reuse a verification proof.',
    userMessage: 'This verification proof has already been used. Each proof can only be used once.',
    recoverySuggestions: [
      'Start a new verification process',
      'Contact support if you believe this is an error'
    ],
    retryable: false,
  },
  [ERROR_CODES.DUPLICATE_ID_VIOLATION]: {
    code: ERROR_CODES.DUPLICATE_ID_VIOLATION,
    title: 'Duplicate ID Detected',
    message: 'This identity has already been verified.',
    userMessage: 'This identity has already been verified on another account.',
    recoverySuggestions: [
      'Contact support if you believe this is an error',
      'Each identity can only be verified once'
    ],
    retryable: false,
  },
  [ERROR_CODES.SECURITY_VIOLATION]: {
    code: ERROR_CODES.SECURITY_VIOLATION,
    title: 'Security Violation',
    message: 'A security violation was detected.',
    userMessage: 'A security issue was detected. Please contact support.',
    recoverySuggestions: [
      'Contact server administrators',
      'Do not attempt to circumvent security measures'
    ],
    retryable: false,
  },
  [ERROR_CODES.DATABASE_ERROR]: {
    code: ERROR_CODES.DATABASE_ERROR,
    title: 'System Error',
    message: 'Unable to access the database.',
    userMessage: 'A system error occurred. Please try again later.',
    recoverySuggestions: [
      'Try again in a few minutes',
      'Contact support if the problem persists'
    ],
    retryable: true,
  },
  [ERROR_CODES.INTERNAL_ERROR]: {
    code: ERROR_CODES.INTERNAL_ERROR,
    title: 'Internal Error',
    message: 'An unexpected internal error occurred.',
    userMessage: 'An unexpected error occurred. Please try again.',
    recoverySuggestions: [
      'Try the verification process again',
      'Contact support if the problem continues'
    ],
    retryable: true,
  },
  [ERROR_CODES.CONFIGURATION_ERROR]: {
    code: ERROR_CODES.CONFIGURATION_ERROR,
    title: 'Configuration Error',
    message: 'The system is not properly configured.',
    userMessage: 'The verification system is not available. Please contact an administrator.',
    recoverySuggestions: [
      'Contact server administrators',
      'Try again later'
    ],
    retryable: false,
  },
  [ERROR_CODES.USER_CANCELLED]: {
    code: ERROR_CODES.USER_CANCELLED,
    title: 'Verification Cancelled',
    message: 'The user cancelled the verification process.',
    userMessage: 'Verification was cancelled.',
    recoverySuggestions: [
      'Start the verification process again when ready',
      'Follow the instructions carefully this time'
    ],
    retryable: true,
  },
  [ERROR_CODES.VERIFICATION_FAILED]: {
    code: ERROR_CODES.VERIFICATION_FAILED,
    title: 'Verification Failed',
    message: 'The verification proof could not be validated.',
    userMessage: 'Your verification could not be completed. Please try again.',
    recoverySuggestions: [
      'Try the verification process again',
      'Make sure you are using a valid passport',
      'Ensure you are following all instructions'
    ],
    retryable: true,
  },
  [ERROR_CODES.ROLE_ASSIGNMENT_FAILED]: {
    code: ERROR_CODES.ROLE_ASSIGNMENT_FAILED,
    title: 'Role Assignment Failed',
    message: 'Unable to assign the verified role.',
    userMessage: 'Verification succeeded but role assignment failed. Please contact an administrator.',
    recoverySuggestions: [
      'Contact server administrators to manually assign the role',
      'Your verification was successful even if the role assignment failed'
    ],
    retryable: false,
  },
};

/**
 * Classifies an error and returns a user-friendly error object
 */
export function classifyError(error: unknown, context: ErrorContext): UserFriendlyError {
  let errorCode: ErrorCode;
  let technicalDetails: string;

  // Classify the error based on its type and message
  if (error instanceof Error) {
    const message = error.message.toLowerCase();

    if (message.includes('timeout') || message.includes('etimedout')) {
      errorCode = ERROR_CODES.NETWORK_TIMEOUT;
    } else if (message.includes('discord') || message.includes('api')) {
      errorCode = ERROR_CODES.DISCORD_API_ERROR;
    } else if (message.includes('zkp') || message.includes('zkpass') || message.includes('proof')) {
      errorCode = ERROR_CODES.ZKPASS_SDK_ERROR;
    } else if (message.includes('session') || message.includes('token')) {
      errorCode = ERROR_CODES.INVALID_SESSION_TOKEN;
    } else if (message.includes('rate limit')) {
      errorCode = ERROR_CODES.RATE_LIMIT_EXCEEDED;
    } else if (message.includes('replay')) {
      errorCode = ERROR_CODES.PROOF_REPLAY_ATTACK;
    } else if (message.includes('duplicate') || message.includes('already exists')) {
      errorCode = ERROR_CODES.DUPLICATE_ID_VIOLATION;
    } else if (message.includes('database') || message.includes('db')) {
      errorCode = ERROR_CODES.DATABASE_ERROR;
    } else if (message.includes('config') || message.includes('configuration')) {
      errorCode = ERROR_CODES.CONFIGURATION_ERROR;
    } else {
      errorCode = ERROR_CODES.INTERNAL_ERROR;
    }

    technicalDetails = error.message;
  } else {
    errorCode = ERROR_CODES.INTERNAL_ERROR;
    technicalDetails = 'Unknown error type';
  }

  // Get the user-friendly error definition
  const friendlyError = USER_FRIENDLY_ERRORS[errorCode];

  // Log the error
  auditLogger.log({
    timestamp: new Date().toISOString(),
    event: 'verification_failure',
    userId: context.userId,
    sessionId: context.sessionId,
    verificationType: context.verificationType,
    ipAddress: context.ipAddress,
    userAgent: context.userAgent,
    success: false,
    details: {
      operation: context.operation,
      errorCode,
      technicalDetails,
      retryable: friendlyError.retryable,
    },
    error: friendlyError.message,
  });

  return {
    ...friendlyError,
    technicalDetails,
  };
}

/**
 * Creates a safe error message for Discord interactions
 */
export function createUserFriendlyMessage(error: UserFriendlyError): string {
  let message = `❌ **${error.title}**\n\n${error.userMessage}`;

  if (error.recoverySuggestions.length > 0) {
    message += '\n\n**What you can do:**\n';
    error.recoverySuggestions.forEach((suggestion, index) => {
      message += `${index + 1}. ${suggestion}\n`;
    });
  }

  if (error.retryable) {
    message += '\n💡 This error is retryable - you can try again.';
  }

  return message;
}

/**
 * Handles errors in Discord slash commands
 */
export async function handleDiscordCommandError(
  error: unknown,
  context: ErrorContext,
  interaction: any
): Promise<void> {
  const classifiedError = classifyError(error, context);
  const userMessage = createUserFriendlyMessage(classifiedError);

  try {
    if (interaction.deferred) {
      await interaction.editReply({
        content: userMessage,
        embeds: [],
        components: [],
      });
    } else if (interaction.replied) {
      await interaction.followUp({
        content: userMessage,
        flags: MessageFlags.Ephemeral,
      });
    } else {
      await interaction.reply({
        content: userMessage,
        flags: MessageFlags.Ephemeral,
      });
    }
  } catch (replyError) {
    // Fallback if reply fails
    console.error('Failed to send error message to Discord:', replyError);
  }
}

/**
 * Retry mechanism with exponential backoff
 */
export async function retryWithBackoff<T>(
  operation: () => Promise<T>,
  maxRetries: number = 3,
  baseDelay: number = 1000,
  context: ErrorContext
): Promise<T> {
  let lastError: unknown;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;

      const classifiedError = classifyError(error, {
        ...context,
        operation: `${context.operation} (attempt ${attempt + 1}/${maxRetries})`,
      });

      // Log retry attempt
      auditLogger.log({
        timestamp: new Date().toISOString(),
        event: 'verification_failure',
        userId: context.userId,
        sessionId: context.sessionId,
        verificationType: context.verificationType,
        success: false,
        details: {
          operation: context.operation,
          attempt: attempt + 1,
          maxRetries,
          errorCode: classifiedError.code,
          willRetry: attempt < maxRetries - 1,
        },
        error: classifiedError.message,
      });

      // Don't retry if error is not retryable
      if (!classifiedError.retryable) {
        throw error;
      }

      // Don't wait after the last attempt
      if (attempt < maxRetries - 1) {
        const delay = baseDelay * Math.pow(2, attempt);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  throw lastError;
}

/**
 * Timeout wrapper for operations
 */
export async function withTimeout<T>(
  operation: Promise<T>,
  timeoutMs: number,
  context: ErrorContext
): Promise<T> {
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => {
      reject(new Error(`Operation timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });

  try {
    return await Promise.race([operation, timeoutPromise]);
  } catch (error) {
    if ((error as Error).message.includes('timed out')) {
      const timeoutError = classifyError(error, {
        ...context,
        operation: `${context.operation} (timed out)`,
      });

      auditLogger.log({
        timestamp: new Date().toISOString(),
        event: 'verification_failure',
        userId: context.userId,
        sessionId: context.sessionId,
        verificationType: context.verificationType,
        success: false,
        details: {
          operation: context.operation,
          timeoutMs,
          errorCode: timeoutError.code,
        },
        error: timeoutError.message,
      });
    }
    throw error;
  }
}