interface DiscordMessage {
    userId: string;
    channelId?: string;
    content: string;
    embed?: any;
}
declare class DiscordService {
    /**
     * Assign admin role to verified user
     */
    assignAdminRole(discordUserId: string): Promise<boolean>;
    /**
     * Remove admin role from user
     */
    removeAdminRole(discordUserId: string): Promise<boolean>;
    /**
     * Send direct message to user (legacy - use webhooks instead)
     */
    sendDirectMessage(userId: string, message: DiscordMessage): Promise<boolean>;
    /**
     * Get user information (legacy - use database queries instead)
     */
    getUserInfo(discordUserId: string): Promise<null>;
    /**
     * Check if user has admin role (legacy - use database queries instead)
     */
    hasAdminRole(discordUserId: string): Promise<boolean>;
    /**
     * Update user roles based on verification status
     */
    updateRolesForVerification(discordUserId: string, verified: boolean): Promise<boolean>;
    /**
     * Send webhook request to bot for role management
     */
    private sendWebhookToBot;
    /**
     * Send verification success message
     */
    sendVerificationSuccessMessage(discordUserId: string): Promise<boolean>;
    /**
     * Send verification failure message
     */
    sendVerificationFailureMessage(discordUserId: string, reason?: string): Promise<boolean>;
    /**
     * Log role changes for audit purposes (deprecated - now using auditLogger)
     */
    private logRoleChange;
    /**
     * Health check for Discord service (checks webhook connectivity)
     */
    healthCheck(): Promise<boolean>;
}
export declare const discordService: DiscordService;
export {};
//# sourceMappingURL=discordService.d.ts.map