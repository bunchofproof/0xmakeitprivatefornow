import { Interaction, ChatInputCommandInteraction, MessageFlags } from 'discord.js';
import { commands } from '../commands';
import { logger } from '../utils/logger';
import { DiscordCommandValidator, handleValidationError } from '../utils/discordValidation';

export async function handleInteractionCreate(interaction: Interaction): Promise<void> {
  // Only handle chat input commands
  if (!interaction.isChatInputCommand()) return;

  const commandInteraction = interaction as ChatInputCommandInteraction;
  const userId = interaction.user.id;
  const username = interaction.user.username;

  try {
    // GUARD: Only allow commands in servers
    if (!commandInteraction.inGuild()) {
      await commandInteraction.reply({
        content: '❌ **Commands can only be used in a server!**\n\nAdmin verification commands are not available in DMs for security reasons.',
        flags: MessageFlags.Ephemeral
      });
      return; // Stop execution
    }

    // ENHANCED: Universal command rate limiting with abuse detection
    const isAllowed = await DiscordCommandValidator.checkCommandRateLimit(userId, interaction.commandName);
    if (!isAllowed) {
      // const stats = DiscordCommandValidator.getRateLimitStats(); // Unused variable removed
      await commandInteraction.reply({
        content: '⏱️ **Command Rate Limited**\n\nYou\'re using commands too quickly. Please wait a moment before using this command again.\n\nIf this continues, you may be temporarily blocked from using commands.',
        flags: MessageFlags.Ephemeral
      });
      return;
    }

    // Find the command
    const command = commands.find(cmd => cmd.data.name === interaction.commandName);

    if (!command) {
      logger.warn('Unknown command received', {
        commandName: interaction.commandName
      });
      await interaction.reply({
        content: '❌ Unknown command. Use `/help` to see available commands.',
        flags: MessageFlags.Ephemeral,
      });
      return;
    }

    try {
      // ENHANCED: Validate command options before execution
      DiscordCommandValidator.validateCommandOptions(commandInteraction);

      // Log command usage
      logger.info('Command executed', {
        commandName: interaction.commandName,
        username,
        userId
      });

      // Execute the command
      await command.execute(interaction);

    } catch (validationError) {
      // Handle validation errors specifically
      handleValidationError(validationError, commandInteraction, {
        userId,
        command: interaction.commandName
      });

      logger.warn('Validation failed for command', {
        commandName: interaction.commandName,
        username,
        userId,
        validationError: validationError instanceof Error ? validationError.message : String(validationError)
      });
    }

  } catch (error) {
    logger.error('Error executing command', undefined, {
      commandName: interaction.commandName,
      error: error instanceof Error ? error.message : String(error),
    } as Record<string, any>);

    // Check if interaction was already replied to
    if (interaction.replied || interaction.deferred) {
      await interaction.editReply({
        content: '❌ An error occurred while processing your command. Please try again.',
      });
    } else {
      await interaction.reply({
        content: '❌ An error occurred while processing your command. Please try again.',
        flags: MessageFlags.Ephemeral,
      });
    }
  }
}