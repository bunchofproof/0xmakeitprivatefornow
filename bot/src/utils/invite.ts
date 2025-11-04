import { config } from '../config';

/**
 * Generates a Discord bot invite link with the required permissions for verification functionality
 */
export function generateInviteLink(): string {
  const permissions = 2416004096; // Sum of required permissions: Manage Roles + Send Messages + Use Slash Commands + Embed Links + Read Message History + View Channels
  const scope = 'bot%20applications.commands';

  if (!config.bot.clientId) {
    throw new Error('CLIENT_ID is required to generate invite link');
  }

  return `https://discord.com/api/oauth2/authorize?client_id=${config.bot.clientId}&permissions=${permissions}&scope=${scope}`;
}