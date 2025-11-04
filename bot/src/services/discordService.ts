import { Client } from 'discord.js';
import { config } from '../config';
import { logger } from '../utils/logger';

class BotDiscordService {
  constructor(private client: Client) {}

  /**
   * Assign admin role to verified user
   */
  public async assignAdminRole(discordUserId: string): Promise<boolean> {
    try {
      const guild = await this.client.guilds.fetch(config.bot.guildId);
      const member = await guild.members.fetch(discordUserId);

      // Find the admin role to assign
      const adminRoleId = config.bot.adminRoleIds[0]; // Use first admin role
      if (!adminRoleId) {
        throw new Error('No admin role configured');
      }

      const role = await guild.roles.fetch(adminRoleId);
      if (!role) {
        throw new Error(`Admin role ${adminRoleId} not found`);
      }

      // THIS IS THE CRITICAL FIX. THIS IS THE LINE THAT IS FAILING SILENTLY.
      await member.roles.add(role);

      logger.info(`Successfully assigned admin role to user ${discordUserId}`);
      return true;

    } catch (error) {
      // THIS IS THE CRITICAL FIX. THIS LINE MUST BE HERE.
      console.error('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
      console.error('!!! DISCORD.JS API CALL FAILED - THIS IS THE ROOT CAUSE !!!');
      console.error('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
      console.error(error); // Log the actual Discord API error

      // IMPORTANT: Now, re-throw the error to stop the loop
      throw error;
    }
  }

  /**
   * Remove admin role from user
   */
  async removeAdminRole(discordUserId: string): Promise<boolean> {
    try {
      const guild = await this.client.guilds.fetch(config.bot.guildId);
      const member = await guild.members.fetch(discordUserId);

      // Find the admin role to remove
      const adminRoleId = config.bot.adminRoleIds[0]; // Use first admin role
      if (!adminRoleId) {
        throw new Error('No admin role configured');
      }

      const role = await guild.roles.fetch(adminRoleId);
      if (!role) {
        throw new Error(`Admin role ${adminRoleId} not found`);
      }

      // THIS IS THE CRITICAL FIX. THIS IS THE LINE THAT IS FAILING SILENTLY.
      await member.roles.remove(role);

      logger.info(`Successfully removed admin role from user ${discordUserId}`);
      return true;

    } catch (error) {
      // THIS IS THE CRITICAL FIX. THIS LINE MUST BE HERE.
      console.error('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
      console.error('!!! DISCORD.JS API CALL FAILED - THIS IS THE ROOT CAUSE !!!');
      console.error('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
      console.error(error); // Log the actual Discord API error

      // IMPORTANT: Now, re-throw the error to stop the loop
      throw error;
    }
  }

  /**
   * Check if user has admin role
   */
  async hasAdminRole(discordUserId: string): Promise<boolean> {
    try {
      const guild = await this.client.guilds.fetch(config.bot.guildId);
      const member = await guild.members.fetch(discordUserId);

      return config.bot.adminRoleIds.some(roleId => member.roles.cache.has(roleId));
    } catch (error) {
      logger.error(`Error checking admin role for user ${discordUserId}`, error instanceof Error ? error : new Error(String(error)));
      return false;
    }
  }
}

// Export singleton instance - will be initialized with client
export let botDiscordService: BotDiscordService;

// Function to initialize the service with the Discord client
export function initializeBotDiscordService(client: Client): void {
  botDiscordService = new BotDiscordService(client);
  logger.info('Bot Discord service initialized');
}