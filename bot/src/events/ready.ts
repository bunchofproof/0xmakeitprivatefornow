import { Client } from 'discord.js';
import { logger } from '../utils/logger';
import { generateInviteLink } from '../utils/invite';

export async function handleReady(client: Client): Promise<void> {
  logger.info('Bot is ready', {
    username: client.user?.tag,
    guildsCount: client.guilds.cache.size
  });
  logger.info('Connected to guilds', {
    guildCount: client.guilds.cache.size
  });

  // Set bot status
  client.user?.setPresence({
    activities: [
      {
        name: 'ZKPassport Verifications',
        type: 3, // WATCHING
      },
    ],
    status: 'online',
  });

  // Log information about each guild
  client.guilds.cache.forEach((guild) => {
    logger.info('Guild connected', {
      guildName: guild.name,
      guildId: guild.id,
      memberCount: guild.memberCount
    });
  });

  // Generate and display invite link
  try {
    const inviteLink = generateInviteLink();
    if (process.env.NODE_ENV !== 'production') {
      console.log('═══════════════════════════════════════════════════════════════════════');
      console.log('🤖 Discord Bot is now online and ready!');
      console.log('');
      console.log('📋 Invite Link (expires in 24 hours):');
      console.log(inviteLink);
      console.log('');
      console.log('🔗 Simply click the link above and select your server to add the bot!');
      console.log('═══════════════════════════════════════════════════════════════════════');
    }
  } catch (error) {
    logger.error('Failed to generate invite link', error as Error);
    if (process.env.NODE_ENV !== 'production') {
      console.log('❌ Failed to generate invite link. Please check CLIENT_ID configuration.');
    }
  }
}