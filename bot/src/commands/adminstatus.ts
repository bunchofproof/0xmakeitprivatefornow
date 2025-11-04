import { CommandInteraction, SlashCommandBuilder, MessageFlags } from 'discord.js';
import { createSafeErrorMessage } from '@shared/utils';
import { handlePendingCommand, handleStatsCommand, handleApproveCommand, handleRejectCommand, handleCleanupCommand, handleHealthCommand, checkAdminPermissions } from '../services/adminService';
import { logger } from '../utils/logger';

export const data = new SlashCommandBuilder()
  .setName('adminstatus')
  .setDescription('Admin verification management (Admin Only)')
  .addSubcommand(subcommand =>
    subcommand
      .setName('pending')
      .setDescription('View pending verifications')
      .addIntegerOption(option =>
        option.setName('limit')
          .setDescription('Maximum number of results')
          .setRequired(false)
          .setMinValue(1)
          .setMaxValue(50)
      )
  )
  .addSubcommand(subcommand =>
    subcommand
      .setName('stats')
      .setDescription('View verification statistics')
  )
  .addSubcommand(subcommand =>
    subcommand
      .setName('approve')
      .setDescription('Approve a pending verification')
      .addStringOption(option =>
        option.setName('user_id')
          .setDescription('Discord user ID to approve')
          .setRequired(true)
      )
      .addStringOption(option =>
        option.setName('reason')
          .setDescription('Approval reason')
          .setRequired(false)
      )
  )
  .addSubcommand(subcommand =>
    subcommand
      .setName('reject')
      .setDescription('Reject a pending verification')
      .addStringOption(option =>
        option.setName('user_id')
          .setDescription('Discord user ID to reject')
          .setRequired(true)
      )
      .addStringOption(option =>
        option.setName('reason')
          .setDescription('Rejection reason')
          .setRequired(true)
      )
  )
  .addSubcommand(subcommand =>
    subcommand
      .setName('cleanup')
      .setDescription('Manually trigger session cleanup')
      .addBooleanOption(option =>
        option.setName('dry_run')
          .setDescription('Preview cleanup without making changes')
          .setRequired(false)
      )
  )
  .addSubcommand(subcommand =>
    subcommand
      .setName('health')
      .setDescription('View session and database health statistics')
  );

export async function execute(interaction: CommandInteraction) {
  try {
    // Check admin permissions
    if (!(await checkAdminPermissions(interaction))) {
      await interaction.reply({
        content: '❌ This command is only available to administrators.',
        flags: MessageFlags.Ephemeral,
      });
      return;
    }

    await interaction.deferReply({ flags: MessageFlags.Ephemeral });

    const subcommand = (interaction as any).options.getSubcommand();

    switch (subcommand) {
      case 'pending':
        await handlePendingCommand(interaction);
        break;
      case 'stats':
        await handleStatsCommand(interaction);
        break;
      case 'approve':
        await handleApproveCommand(interaction);
        break;
      case 'reject':
        await handleRejectCommand(interaction);
        break;
      case 'cleanup':
        await handleCleanupCommand(interaction);
        break;
      case 'health':
        await handleHealthCommand(interaction);
        break;
      default:
        await interaction.editReply({
          content: '❌ Unknown subcommand.',
        });
    }

  } catch (error) {
    logger.error('Error in adminstatus command', undefined, {
      error: error instanceof Error ? error.message : String(error),
    } as Record<string, any>);

    const safeMessage = createSafeErrorMessage(error);
    await interaction.editReply({
      content: `❌ ${safeMessage}`,
    });
  }
}

;