import { ChatInputCommandInteraction, SlashCommandBuilder, EmbedBuilder, MessageFlags } from 'discord.js';
import { createSafeErrorMessage, daysUntilExpiration, isExpired } from '@shared/utils';
import { formatTimestamp } from '@shared/utils';
import { getUserVerificationStatus } from '../utils/database';
import { logger } from '../utils/logger';
import { config } from '../config';

export const data = new SlashCommandBuilder()
  .setName('status')
  .setDescription('Check your verification status')
  .addUserOption(option =>
    option.setName('user')
      .setDescription('Check status for another user (admin only)')
      .setRequired(false)
  );

export async function execute(interaction: ChatInputCommandInteraction) {
  try {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });

    const targetUser = interaction.options.getUser('user') || interaction.user;
    const isAdmin = await checkAdminPermissions(interaction);

    // Only admins can check other users' status
    if (targetUser.id !== interaction.user.id && !isAdmin) {
      await interaction.editReply({
        content: '❌ You can only check your own verification status. Admins can check other users\' status.',
      });
      return;
    }

    // Get verification status from database
    const verification = await getUserVerificationStatus(targetUser.id);

    if (!verification) {
      // User not found in database
      const embed = new EmbedBuilder()
        .setTitle('❓ Verification Status')
        .setDescription(`${targetUser.username} has not started the verification process yet.`)
        .setColor(0xffa500)
        .addFields([
          {
            name: 'How to Verify',
            value: 'Use the `/verify` command to start the verification process.',
            inline: false,
          },
        ])
        .setThumbnail(targetUser.displayAvatarURL())
        .setTimestamp();

      await interaction.editReply({ embeds: [embed] });
      return;
    }

    // Build status embed based on verification state
    let embed: EmbedBuilder;

    if (verification.isVerified) {
      embed = new EmbedBuilder()
        .setTitle('✅ Verified')
        .setDescription(`${targetUser.username} is successfully verified with ZKPassport.`)
        .setColor(0x00ff00)
        .setThumbnail(targetUser.displayAvatarURL())
        .addFields([
          {
            name: 'Verified At',
            value: formatTimestamp(verification.verifiedAt!),
            inline: true,
          },
          {
            name: 'Expires',
            value: verification.expiresAt
              ? (isExpired(verification.expiresAt)
                  ? '⚠️ **EXPIRED**'
                  : `<t:${Math.floor(verification.expiresAt.getTime() / 1000)}:R>`)
              : 'Never',
            inline: true,
          },
          {
            name: 'Verification Method',
            value: 'ZKPassport',
            inline: true,
          },
        ])
        .setTimestamp();

      if (verification.expiresAt && !isExpired(verification.expiresAt)) {
        const daysLeft = daysUntilExpiration(verification.expiresAt);
        embed.addFields([
          {
            name: 'Days Until Expiration',
            value: `${daysLeft} days`,
            inline: true,
          },
        ]);
      }

    } else {
      // Not verified - show pending status
      const embed = new EmbedBuilder()
        .setTitle('⏳ Verification Pending')
        .setDescription(`${targetUser.username} has started but not completed the verification process.`)
        .setColor(0xffa500)
        .setThumbnail(targetUser.displayAvatarURL())
        .addFields([
          {
            name: 'Started At',
            value: verification.lastVerificationDate
              ? formatTimestamp(verification.lastVerificationDate)
              : 'Unknown',
            inline: true,
          },
          {
            name: 'Status',
            value: verification.adminVerified ? 'Admin Review' : 'Pending User Action',
            inline: true,
          },
          {
            name: 'Next Steps',
            value: 'Use the `/verify` command to get a new verification link.',
            inline: false,
          },
        ])
        .setTimestamp();

      // Add admin verification info if applicable
      if (verification.adminVerified && verification.adminVerifiedBy) {
        embed.addFields([
          {
            name: 'Admin Review By',
            value: `<@${verification.adminVerifiedBy}>`,
            inline: true,
          },
          {
            name: 'Reviewed At',
            value: verification.adminVerifiedAt
              ? formatTimestamp(verification.adminVerifiedAt)
              : 'Pending',
            inline: true,
          },
        ]);
      }

      await interaction.editReply({ embeds: [embed] });
      return;
    }

    await interaction.editReply({ embeds: [embed] });

    logger.info('Status check for user', {
      targetUsername: targetUser.username,
      targetUserId: targetUser.id,
      requesterUsername: interaction.user.username
    });

  } catch (error) {
    logger.error('Error in status command', undefined, {
      error: error instanceof Error ? error.message : String(error),
    } as Record<string, any>);

   const safeMessage = createSafeErrorMessage(error);
    await interaction.editReply({
      content: `❌ ${safeMessage}`,
    });
  }
}

/**
 * Check if the user has admin permissions
 */
async function checkAdminPermissions(interaction: ChatInputCommandInteraction): Promise<boolean> {
  const member = interaction.guild?.members.cache.get(interaction.user.id);

  if (!member) return false;

  // Check if user has any of the configured admin roles
  return config.bot.adminRoleIds.some(roleId => member.roles.cache.has(roleId));
}