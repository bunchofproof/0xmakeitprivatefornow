import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';
import { generateSecureHMACSignature, getHMACSecret } from '../utils/hmac';

interface DiscordMessage {
userId: string;
channelId?: string;
content: string;
embed?: any;
}

interface WebhookResponse {
success: boolean;
}

class DiscordService {

/**
 * Assign admin role to verified user
 */
async assignAdminRole(discordUserId: string): Promise<boolean> {
  // Force real API call even in development to test full integration
  return await this.sendWebhookToBot(discordUserId, 'assign', 'ZKPassport verification successful');
}

/**
 * Remove admin role from user
 */
async removeAdminRole(discordUserId: string): Promise<boolean> {
  return await this.sendWebhookToBot(discordUserId, 'revoke', 'ZKPassport verification failed or expired');
}

/**
 * Send direct message to user (legacy - use webhooks instead)
 */
async sendDirectMessage(_userId: string, _message: DiscordMessage): Promise<boolean> {
  logger.warn('sendDirectMessage is deprecated - use notification service instead');
  return false;
}

/**
 * Get user information (legacy - use database queries instead)
 */
async getUserInfo(_discordUserId: string) {
  logger.warn('getUserInfo is deprecated - use database queries instead');
  return null;
}

/**
 * Check if user has admin role (legacy - use database queries instead)
 */
async hasAdminRole(_discordUserId: string): Promise<boolean> {
  logger.warn('hasAdminRole is deprecated - use database queries instead');
  return false;
}

/**
 * Update user roles based on verification status
 */
async updateRolesForVerification(discordUserId: string, verified: boolean): Promise<boolean> {
  try {
    if (verified) {
      return await this.assignAdminRole(discordUserId);
    } else {
      return await this.removeAdminRole(discordUserId);
    }
  } catch (error) {
    logger.error(`Error updating roles for user ${discordUserId}:`, error);
    return false;
  }
}

/**
 * Send secure webhook request to bot for role management with replay protection
 */
async sendWebhookToBot(userId: string, action: 'assign' | 'revoke', reason?: string): Promise<boolean> {
  try {
    const hmacSecret = getHMACSecret();
    logger.debug(`Attempting webhook call for user ${userId}, action: ${action}, HMAC secret length: ${hmacSecret?.length || 0}`);

    const basePayload = {
      userId,
      action,
      reason: reason || `ZKPassport verification completed`,
      requestId: uuidv4(),
    };

    // Log the exact payload being sent
    const payloadString = JSON.stringify(basePayload);
    logger.debug(`Webhook payload to send: ${payloadString}`);
    logger.debug(`Payload length: ${payloadString.length} characters`);

    // Generate secure HMAC signature with replay protection
    const secureSignature = generateSecureHMACSignature(basePayload, hmacSecret);
    logger.debug(`Generated HMAC signature for webhook: ${secureSignature.signature ? secureSignature.signature.substring(0, 10) + '...' : 'undefined'}`);
    logger.debug(`HMAC signature full length: ${secureSignature.signature?.length || 0}`);
    logger.debug(`Timestamp: ${secureSignature.timestamp}, Nonce: ${secureSignature.nonce}`);

    const webhookUrl = `http://localhost:3002/api/webhooks/role-update`;
    logger.debug(`Making webhook request to: ${webhookUrl}`);

    // Construct headers
    const requestHeaders = {
      'Content-Type': 'application/json',
      'X-Signature-256': secureSignature.signature,
      'X-Timestamp': secureSignature.timestamp,
      'X-Nonce': secureSignature.nonce,
    };
    logger.debug(`Request headers:`, requestHeaders);

    // Send the original payload in body, signature metadata in headers
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: requestHeaders,
      body: payloadString,
    });

    logger.debug(`Webhook response status: ${response.status}`);
    // Note: Headers.entries() is not available in Node.js fetch API, removing debug logging to avoid compilation error

    if (!response.ok) {
      const errorText = await response.text();
      logger.error(`Webhook request failed with status ${response.status}: ${errorText}`);
      throw new Error(`Webhook request failed: ${response.status} ${errorText}`);
    }

    const result = await response.json() as WebhookResponse;
    logger.info(`Secure webhook response result type: ${typeof result}, value:`, result);
    logger.info(`Webhook call successful for user ${userId}, action: ${action}`);
    return result.success;

  } catch (error) {
    logger.error(`Secure webhook request failed for user ${userId}, action: ${action}:`, error);
    // REMOVED: Dangerous fallback that caused infinite loop
    // Instead, just fail gracefully and let verification handle it
    return false;
  }
}

  /**
   * Send verification success message
   */
  async sendVerificationSuccessMessage(discordUserId: string): Promise<boolean> {
    const successMessage: DiscordMessage = {
      userId: discordUserId,
      content: '✅ **Verification Successful!**\n\nYour ZKPassport verification has been completed successfully. You now have admin access to the server.',
    };

    return await this.sendDirectMessage(discordUserId, successMessage);
  }

  /**
   * Send verification failure message
   */
  async sendVerificationFailureMessage(discordUserId: string, reason?: string): Promise<boolean> {
    const failureMessage: DiscordMessage = {
      userId: discordUserId,
      content: `❌ **Verification Failed**\n\nYour verification could not be completed.${reason ? ` Reason: ${reason}` : ''}\n\nPlease try again or contact an administrator for assistance.`,
    };

    return await this.sendDirectMessage(discordUserId, failureMessage);
  }


 /**
  * Health check for Discord service (checks webhook connectivity)
  */
 async healthCheck(): Promise<boolean> {
   try {
     const botWebhookPort = process.env.BOT_WEBHOOK_PORT || '3001';
     const hmacSecret = getHMACSecret();

     // Generate secure HMAC signature for health check payload
     const healthPayload = {
       service: 'backend',
       type: 'health_check'
     };

     const secureSignature = generateSecureHMACSignature(healthPayload, hmacSecret);

     const response = await fetch(`http://localhost:${botWebhookPort}/health`, {
       method: 'GET',
       headers: {
         'X-Signature-256': secureSignature.signature,
         'X-Timestamp': secureSignature.timestamp,
         'X-Nonce': secureSignature.nonce,
       },
       signal: AbortSignal.timeout(5000), // 5 second timeout
     });

     return response.ok;

   } catch (error) {
     logger.error('Discord service health check failed:', error);
     return false;
   }
 }
}

// Export singleton instance
export const discordService = new DiscordService();
