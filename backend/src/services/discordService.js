"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.discordService = void 0;
const logger_1 = require("../utils/logger");
class DiscordService {
    /**
     * Assign admin role to verified user
     */
    async assignAdminRole(discordUserId) {
        return await this.sendWebhookToBot(discordUserId, 'assign', 'ZKPassport verification successful');
    }
    /**
     * Remove admin role from user
     */
    async removeAdminRole(discordUserId) {
        return await this.sendWebhookToBot(discordUserId, 'revoke', 'ZKPassport verification failed or expired');
    }
    /**
     * Send direct message to user (legacy - use webhooks instead)
     */
    async sendDirectMessage(userId, message) {
        logger_1.logger.warn('sendDirectMessage is deprecated - use notification service instead');
        return false;
    }
    /**
     * Get user information (legacy - use database queries instead)
     */
    async getUserInfo(discordUserId) {
        logger_1.logger.warn('getUserInfo is deprecated - use database queries instead');
        return null;
    }
    /**
     * Check if user has admin role (legacy - use database queries instead)
     */
    async hasAdminRole(discordUserId) {
        logger_1.logger.warn('hasAdminRole is deprecated - use database queries instead');
        return false;
    }
    /**
     * Update user roles based on verification status
     */
    async updateRolesForVerification(discordUserId, verified) {
        try {
            if (verified) {
                return await this.assignAdminRole(discordUserId);
            }
            else {
                return await this.removeAdminRole(discordUserId);
            }
        }
        catch (error) {
            logger_1.logger.error(`Error updating roles for user ${discordUserId}:`, error);
            return false;
        }
    }
    /**
     * Send webhook request to bot for role management
     */
    async sendWebhookToBot(userId, action, reason) {
        try {
            const botWebhookUrl = process.env.BOT_WEBHOOK_URL;
            const apiKey = process.env.BOT_WEBHOOK_API_KEY;
            if (!botWebhookUrl || !apiKey) {
                logger_1.logger.warn('Bot webhook configuration missing, falling back to direct Discord API');
                return action === 'assign' ? await this.assignAdminRole(userId) : await this.removeAdminRole(userId);
            }
            const payload = {
                userId,
                action,
                reason: reason || `Role ${action} via verification system`,
                requestId: `req_${Date.now()}_${Math.random().toString(36).substring(2)}`,
            };
            const response = await fetch(`${botWebhookUrl}/api/webhooks/role-update`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': apiKey,
                },
                body: JSON.stringify(payload),
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Webhook request failed: ${response.status} ${errorText}`);
            }
            const result = await response.json();
            logger_1.logger.info(`Webhook response result type: ${typeof result}, value:`, result);
            return result.success;
        }
        catch (error) {
            logger_1.logger.error(`Webhook request failed for user ${userId}:`, error);
            // Fallback to direct Discord API call
            logger_1.logger.info(`Falling back to direct Discord API for user ${userId}`);
            return action === 'assign' ? await this.assignAdminRole(userId) : await this.removeAdminRole(userId);
        }
    }
    /**
     * Send verification success message
     */
    async sendVerificationSuccessMessage(discordUserId) {
        const successMessage = {
            userId: discordUserId,
            content: '✅ **Verification Successful!**\n\nYour ZKPassport verification has been completed successfully. You now have admin access to the server.',
        };
        return await this.sendDirectMessage(discordUserId, successMessage);
    }
    /**
     * Send verification failure message
     */
    async sendVerificationFailureMessage(discordUserId, reason) {
        const failureMessage = {
            userId: discordUserId,
            content: `❌ **Verification Failed**\n\nYour verification could not be completed.${reason ? ` Reason: ${reason}` : ''}\n\nPlease try again or contact an administrator for assistance.`,
        };
        return await this.sendDirectMessage(discordUserId, failureMessage);
    }
    /**
     * Log role changes for audit purposes (deprecated - now using auditLogger)
     */
    async logRoleChange(update) {
        logger_1.logger.info(`Role ${update.action}: User ${update.userId}, Role ${update.roleId}${update.reason ? `, Reason: ${update.reason}` : ''}`);
    }
    /**
     * Health check for Discord service (checks webhook connectivity)
     */
    async healthCheck() {
        try {
            const botWebhookUrl = process.env.BOT_WEBHOOK_URL;
            const apiKey = process.env.BOT_WEBHOOK_API_KEY;
            if (!botWebhookUrl || !apiKey) {
                logger_1.logger.warn('Bot webhook configuration missing for health check');
                return false;
            }
            const response = await fetch(`${botWebhookUrl}/health`, {
                method: 'GET',
                headers: {
                    'x-api-key': apiKey,
                },
                signal: AbortSignal.timeout(5000), // 5 second timeout
            });
            return response.ok;
        }
        catch (error) {
            logger_1.logger.error('Discord service health check failed:', error);
            return false;
        }
    }
}
// Export singleton instance
exports.discordService = new DiscordService();
//# sourceMappingURL=discordService.js.map