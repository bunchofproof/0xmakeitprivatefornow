import { Client, GatewayIntentBits, REST, Routes, Events } from 'discord.js';
import { config } from './config';
import { commands } from './commands';
import { loadScheduledReminders } from './utils/scheduler';
import { initializeDatabase } from './utils/database';
import { logger } from './utils/logger';
import { handleReady } from './events/ready';
import { handleInteractionCreate } from './events/interactionCreate';
import { handleGuildMemberUpdate } from './events/guildMemberUpdate';
import { envValidator } from './utils/envValidator';
import { setupWebhookServer } from './webhooks/server';
import { initializeBotDiscordService } from './services/discordService';
import { disconnectDatabase } from './utils/database';

const gracefulShutdown = async () => {
  console.log('Graceful shutdown initiated. Closing database connection...');
  logger.info('Graceful shutdown initiated. Closing database connection...');

  try {
    // Close database connection first
    await disconnectDatabase();

    // Log out of Discord client
    if (client && typeof client.destroy === 'function') {
      client.destroy();
    }

    logger.info('Graceful shutdown completed');
    console.log('Graceful shutdown completed');
  } catch (error) {
    logger.error('Error during graceful shutdown:', error instanceof Error ? error : new Error(String(error)));
    console.error('Error during graceful shutdown:', error);
  } finally {
    // Force the process to exit with success code
    process.exit(0);
  }
};

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.MessageContent
  ]
});

const rest = new REST({ version: '10' }).setToken(config.bot.discordBotToken);

// Event handlers
client.on(Events.ClientReady, () => handleReady(client));

client.on('interactionCreate', (interaction) => handleInteractionCreate(interaction));

client.on('guildMemberUpdate', (oldMember, newMember) =>
  handleGuildMemberUpdate(oldMember, newMember)
);

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('SIGINT received - triggering graceful shutdown');
  logger.info('SIGINT signal received');
  gracefulShutdown();
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received - triggering graceful shutdown');
  logger.info('SIGTERM signal received');
  gracefulShutdown();
});

async function main() {
  try {
    logger.info('Starting ZKPassport Discord Verification Bot...');

    // Validate environment configuration
    if (!envValidator.validate()) {
      logger.error('Environment validation failed, exiting...');
      process.exit(1);
    }

    // Initialize database connection
    await initializeDatabase();
    logger.info('Database initialized successfully');

    // Load scheduled reminders
    await loadScheduledReminders();
    logger.info('Scheduled reminders loaded');

    // Initialize bot Discord service with client
    initializeBotDiscordService(client);
    logger.info('Bot Discord service initialized');

    // Start webhook server for backend communication
    await setupWebhookServer();
    logger.info('Webhook server started successfully');

    // Register slash commands
    logger.info('Registering slash commands...');
    await rest.put(Routes.applicationCommands(config.bot.clientId), {
      body: commands.map(command => command.data),
    });
    logger.info(`Successfully registered ${commands.length} slash commands`);

    // Start the bot
    await client.login(config.bot.discordBotToken);
    logger.info('Bot logged in successfully');

  } catch (error) {
   logger.error('Failed to start bot', error instanceof Error ? error : new Error(String(error)), {
     error: error instanceof Error ? error.message : String(error),
   });
   process.exit(1);
  }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', reason instanceof Error ? reason : new Error(String(reason)), {
    promise: String(promise),
    reason: reason instanceof Error ? reason.message : String(reason),
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', error instanceof Error ? error : new Error(String(error)), {
    error: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack : undefined,
  });
  process.exit(1);
});

main();