import { CommandInteraction, EmbedBuilder, ButtonBuilder, ActionRowBuilder, ButtonStyle, MessageFlags } from 'discord.js';
import { formatTimestamp } from '@shared/utils';
import { BotDatabaseService } from './botDatabaseService';
import { logger } from '../utils/logger';
import { config } from '../config';

export async function handlePendingCommand(interaction: CommandInteraction) {
  const limit = (interaction as any).options.getInteger('limit') || 10;

  const pendingVerifications = await BotDatabaseService.getPendingVerifications(limit);

  if (pendingVerifications.length === 0) {
    await interaction.editReply({
      content: '✅ No pending verifications found.',
    });
    return;
  }

  const embed = new EmbedBuilder()
    .setTitle(`⏳ Pending Verifications (${pendingVerifications.length})`)
    .setDescription(`Showing the ${limit} most recent pending verifications.`)
    .setColor(0xffa500)
    .setTimestamp();

  let description = '';
  for (const verification of pendingVerifications) {
    const verificationData = verification as any;
    const userMention = `<@${verificationData.discordUserId}>`;
    const startedAt = formatTimestamp(verificationData.createdAt);

    description += `**${userMention}**\n`;
    description += `Started: ${startedAt}\n`;
    description += `Status: ${verificationData.status}\n`;
    if (verificationData.reason) {
      description += `Reason: ${verificationData.reason}\n`;
    }
    description += '\n';
  }

  embed.setDescription(description);

  // Add approve/reject buttons for the first verification
  if (pendingVerifications.length > 0) {
    const firstVerification = pendingVerifications[0] as any;
    const approveButton = new ButtonBuilder()
      .setCustomId(`approve_${firstVerification.discordUserId}`)
      .setLabel('Approve')
      .setStyle(ButtonStyle.Success);

    const rejectButton = new ButtonBuilder()
      .setCustomId(`reject_${firstVerification.discordUserId}`)
      .setLabel('Reject')
      .setStyle(ButtonStyle.Danger);

    const row = new ActionRowBuilder<ButtonBuilder>()
      .addComponents(approveButton, rejectButton);

    await interaction.editReply({
      embeds: [embed],
      components: [row],
    });
  } else {
    await interaction.editReply({ embeds: [embed] });
  }
}

export async function handleStatsCommand(interaction: CommandInteraction) {
  const stats = await BotDatabaseService.getVerificationStats();

  const embed = new EmbedBuilder()
    .setTitle('📊 Verification Statistics')
    .setColor(0x0099ff)
    .addFields([
      {
        name: 'Total Users',
        value: `${stats.totalUsers}`,
        inline: true,
      },
      {
        name: 'Verified Users',
        value: `${stats.verifiedUsers}`,
        inline: true,
      },
      {
        name: 'Pending Verifications',
        value: `${stats.pendingVerifications}`,
        inline: true,
      },
      {
        name: 'Verification Rate',
        value: `${stats.verificationRate}%`,
        inline: true,
      },
      {
        name: 'Today\'s Verifications',
        value: `${stats.todayVerifications}`,
        inline: true,
      },
      {
        name: 'This Week\'s Verifications',
        value: `${stats.weekVerifications}`,
        inline: true,
      },
    ])
    .setTimestamp();

  await interaction.editReply({ embeds: [embed] });
}

export async function handleApproveCommand(interaction: CommandInteraction) {
  const userId = (interaction as any).options.getString('user_id', true);
  // Reason not used in updated function signature

  try {
    const success = await BotDatabaseService.approveVerification(userId, interaction.user.id);

    if (success) {
      await interaction.editReply({
        content: `✅ Successfully approved verification for user <@${userId}>.`,
      });

      logger.info(`Admin ${interaction.user.username} approved verification for user ${userId}`);
    } else {
      await interaction.editReply({
        content: '❌ Failed to approve verification. User may not exist or may not have a pending verification.',
      });
    }
  } catch (error) {
   logger.error('Error approving verification', undefined, {
     error: error instanceof Error ? error.message : String(error),
   } as Record<string, any>);
   await interaction.editReply({
     content: '❌ An error occurred while approving the verification.',
   });
  }
}

export async function handleRejectCommand(interaction: CommandInteraction) {
  const userId = (interaction as any).options.getString('user_id', true);
  const reason = (interaction as any).options.getString('reason', true);

  try {
    const success = await BotDatabaseService.rejectVerification(userId, interaction.user.id, reason);

    if (success) {
      await interaction.editReply({
        content: `❌ Successfully rejected verification for user <@${userId}>.\nReason: ${reason}`,
      });

      logger.info(`Admin ${interaction.user.username} rejected verification for user ${userId}. Reason: ${reason}`);
    } else {
      await interaction.editReply({
        content: '❌ Failed to reject verification. User may not exist or may not have a pending verification.',
      });
    }
  } catch (error) {
   logger.error('Error rejecting verification', undefined, {
     error: error instanceof Error ? error.message : String(error),
   } as Record<string, any>);
   await interaction.editReply({
     content: '❌ An error occurred while rejecting the verification.',
   });
  }
}

export async function handleCleanupCommand(interaction: CommandInteraction) {
  const dryRun = (interaction as any).options.getBoolean('dry_run') || false;

  try {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });

    const result = await BotDatabaseService.performSessionCleanup();

    const embed = new EmbedBuilder()
      .setTitle(dryRun ? '🔍 Session Cleanup Preview' : '🧹 Session Cleanup Results')
      .setColor(dryRun ? 0xffa500 : 0x00ff00)
      .addFields([
        {
          name: 'Sessions Cleaned',
          value: `${result.sessionsCleaned}`,
          inline: true,
        },
        {
          name: 'Admin Verifications Deactivated',
          value: `${result.adminVerificationsDeactivated}`,
          inline: true,
        },
        {
          name: 'History Records Cleaned',
          value: `${result.historyCleaned}`,
          inline: true,
        },
      ])
      .setFooter({ text: dryRun ? 'This was a preview - no changes made' : 'Cleanup completed successfully' })
      .setTimestamp();

    if (result.errors.length > 0) {
      embed.addFields({
        name: '⚠️ Errors',
        value: result.errors.slice(0, 3).join('\n'), // Show first 3 errors
        inline: false,
      });
    }

    await interaction.editReply({ embeds: [embed] });

    logger.info(`Admin ${interaction.user.username} performed ${dryRun ? 'dry-run ' : ''}session cleanup: sessions=${result.sessionsCleaned}, admin_verifications=${result.adminVerificationsDeactivated}, history=${result.historyCleaned}`);

  } catch (error) {
   logger.error('Error in cleanup command', undefined, {
     error: error instanceof Error ? error.message : String(error),
   } as Record<string, any>);
   await interaction.editReply({
     content: '❌ An error occurred while performing cleanup.',
   });
  }
}

export async function handleHealthCommand(interaction: CommandInteraction) {
   try {
     await interaction.deferReply({ flags: MessageFlags.Ephemeral });

    const stats = await BotDatabaseService.getSessionHealthStats();

    const embed = new EmbedBuilder()
      .setTitle('🏥 Session Health Statistics')
      .setColor(0x0099ff)
      .addFields([
        {
          name: '📊 Sessions',
          value: `Total: ${stats.totalSessions}\nActive: ${stats.activeSessions}\nExpired: ${stats.expiredSessions}`,
          inline: true,
        },
        {
          name: '✅ Admin Verifications',
          value: `Total: ${stats.totalAdminVerifications}\nActive: ${stats.activeAdminVerifications}\nExpired: ${stats.expiredAdminVerifications}`,
          inline: true,
        },
        {
          name: '📜 History Records',
          value: `${stats.totalHistoryRecords}`,
          inline: true,
        },
      ])
      .setTimestamp();

    // Add health warnings
    const warnings: string[] = [];

    const sessionExpiredRatio = stats.totalSessions > 0 ? stats.expiredSessions / stats.totalSessions : 0;
    if (sessionExpiredRatio > 0.5) {
      warnings.push(`⚠️ High expired session ratio: ${(sessionExpiredRatio * 100).toFixed(1)}%`);
    }

    const adminExpiredRatio = stats.totalAdminVerifications > 0 ? stats.expiredAdminVerifications / stats.totalAdminVerifications : 0;
    if (adminExpiredRatio > 0.2) {
      warnings.push(`⚠️ High expired admin verification ratio: ${(adminExpiredRatio * 100).toFixed(1)}%`);
    }

    if (warnings.length > 0) {
      embed.addFields({
        name: '⚠️ Health Warnings',
        value: warnings.join('\n'),
        inline: false,
      });
    }

    await interaction.editReply({ embeds: [embed] });

  } catch (error) {
   logger.error('Error in health command', undefined, {
     error: error instanceof Error ? error.message : String(error),
   } as Record<string, any>);
   await interaction.editReply({
     content: '❌ An error occurred while retrieving health statistics.',
   });
  }
}

/**
 * Check if the user has admin permissions
 */
export async function checkAdminPermissions(interaction: CommandInteraction): Promise<boolean> {
  const member = interaction.guild?.members.cache.get(interaction.user.id);

  if (!member) return false;

  // Check if user has any of the configured admin roles
  return config.bot.adminRoleIds.some(roleId => member.roles.cache.has(roleId));
}