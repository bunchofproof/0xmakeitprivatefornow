import { ChatInputCommandInteraction, SlashCommandBuilder, EmbedBuilder, MessageFlags } from 'discord.js';
import { config } from '../config';
import { generateSecureToken, isValidDiscordUserId } from '@shared/utils';
import { VerificationSession } from '@shared/types';
import { VerificationType, VERIFICATION_TYPE_CONFIGS } from '@shared/types/verification';
import { verificationConfig, getEnabledTypes, isVerificationEnabled, getVerificationExpiryMinutes } from '@shared/config/verification';
import { createVerificationSession, checkRateLimit } from '../utils/database';
import { logger } from '../utils/logger';
import { handleDiscordCommandError, classifyError, createUserFriendlyMessage } from '../utils/errorHandler';

// Get enabled verification types dynamically
const enabledTypes = getEnabledTypes();

// Create dynamic choices based on enabled verification types
const verificationChoices = enabledTypes.map(type => ({
  name: VERIFICATION_TYPE_CONFIGS[type].name,
  value: type
}));

export const data = new SlashCommandBuilder()
  .setName('verify')
  .setDescription('Start ZKPassport verification process')
  .addStringOption(option =>
    option.setName('method')
      .setDescription('Verification method')
      .setRequired(false)
      .addChoices(...verificationChoices)
  );

export async function execute(interaction: ChatInputCommandInteraction) {
  const userId = interaction.user.id;
  const username = interaction.user.username;

  try {
    // Check if any verification types are enabled
    if (enabledTypes.length === 0) {
      const error = classifyError(
        new Error('No verification methods enabled'),
        {
          userId,
          operation: 'check_enabled_types',
          ipAddress: interaction.guild?.id ? undefined : 'DM',
        }
      );

      await interaction.reply({
        content: createUserFriendlyMessage(error),
        flags: MessageFlags.Ephemeral,
      });
      return;
    }

    // Defer reply to give us time to process
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });

    // Get selected verification method
    const selectedMethod = interaction.options.getString('method');

    // Validate and type the verification type
    const validTypes: VerificationType[] = ['personhood', 'age', 'nationality', 'residency', 'kyc'];
    let verificationType: VerificationType;
    if (selectedMethod && validTypes.includes(selectedMethod as VerificationType)) {
      verificationType = selectedMethod as VerificationType;
    } else {
      verificationType = verificationConfig.defaultVerificationType;
    }

    // Validate selected verification type is enabled
    if (!isVerificationEnabled(verificationType)) {
      const error = classifyError(
        new Error(`Verification type '${verificationType}' not enabled`),
        {
          userId,
          operation: 'validate_verification_type',
          verificationType,
          ipAddress: interaction.guild?.id ? undefined : 'DM',
        }
      );

      await interaction.editReply({
        content: `${createUserFriendlyMessage(error)}\n\n**Available methods:** ${enabledTypes.join(', ')}`,
      });
      return;
    }

    // Validate Discord user ID
    if (!isValidDiscordUserId(userId)) {
      const error = classifyError(
        new Error('Invalid Discord user ID format'),
        {
          userId,
          operation: 'validate_user_id',
          ipAddress: interaction.guild?.id ? undefined : 'DM',
        }
      );

      await interaction.editReply({
        content: createUserFriendlyMessage(error),
      });
      return;
    }

    // Check rate limiting
    const rateLimitResult = await checkRateLimit(userId);
    if (!rateLimitResult.allowed) {
      const resetIn = rateLimitResult.resetTime
        ? Math.ceil((rateLimitResult.resetTime - Date.now()) / 60000)
        : 1; // Default to 1 minute if resetTime is undefined

      const error = classifyError(
        new Error('Rate limit exceeded'),
        {
          userId,
          operation: 'rate_limit_check',
          ipAddress: interaction.guild?.id ? undefined : 'DM',
        }
      );

      await interaction.editReply({
        content: `${createUserFriendlyMessage(error)}\n\n**Wait time:** ${resetIn} minutes`,
      });
      return;
    }

    // Generate TWO SEPARATE cryptographically secure values (256-bit each)
    // SECURITY: sessionId and token must be completely different values
    const sessionId = generateSecureToken(config.crypto.tokenLength);
    const token = generateSecureToken(config.crypto.tokenLength);
    const expiryMinutes = getVerificationExpiryMinutes(verificationType as VerificationType);
    const expiresAt = new Date(Date.now() + (expiryMinutes * 60 * 1000));

    // Create verification session in database with verification type
    const sessionData: Partial<VerificationSession> = {
      id: sessionId,           // Include the generated session ID
      token,
      discordUserId: userId,
      status: 'pending' as const,
      expiresAt,
      // Note: attempts and maxAttempts will be handled by the database driver
      // to ensure consistency across different database backends
    };

    const session = await createVerificationSession(sessionData);

    // Log the successful session creation
    logger.info('Session created successfully', {
      discordUserId: userId,
      verificationType,
      sessionId: session.id,
      expiresAt: session.expiresAt.toISOString()
    });

    // Log verification attempt (use the session.id returned from database)
    logger.logVerificationAttempt(userId, session.id, verificationType as string, {
      expiryMinutes,
      tokenLength: config.crypto.tokenLength,
      sessionIdGenerated: sessionId, // Log both for debugging
      ipAddress: interaction.guild?.id ? undefined : 'DM', // We don't have IP in Discord context
    });

    // Get verification type configuration and create URL
    const verificationTypeConfig = VERIFICATION_TYPE_CONFIGS[verificationType];
    // Use SEPARATE sessionId and token values for security compliance
    const verificationUrl = `${config.bot.verificationUrl}?token=${token}&session=${sessionId}&type=${verificationType}`;
    const displayName = verificationTypeConfig.name;

    // Create embed with verification information
    const embed = new EmbedBuilder()
      .setTitle(`🔐 ${displayName}`)
      .setDescription(`Complete your verification by clicking the link below. This link will expire in ${expiryMinutes} minutes.`)
      .setColor(0x00ff00)
      .addFields([
        {
          name: 'Verification Link',
          value: `[Click here to verify](${verificationUrl})`,
          inline: false,
        },
        {
          name: 'Expires',
          value: `<t:${Math.floor(expiresAt.getTime() / 1000)}:R>`,
          inline: true,
        },
        {
          name: 'Attempts Remaining',
          value: `${config.bot.maxVerificationAttempts - 1}`,
          inline: true,
        },
      ])
      .setFooter({
        text: 'Keep this link secure and do not share it with others.',
      })
      .setTimestamp();

    // Send DM with verification link (with retry logic)
    try {
      await interaction.user.send({ embeds: [embed] });

      // Confirm in channel that DM was sent
      await interaction.editReply({
        content: `✅ Verification link sent to your DMs! Check your direct messages for the verification link.\n\n📋 **What happens next:**\n• Scan the QR code with your ZKPassport app\n• Complete the verification process\n• Your admin role will be assigned automatically`,
      });

      logger.info('Verification session created for user', {
        username,
        userId
      });

    } catch (dmError) {
      // Classify DM error
      const dmErrorClassified = classifyError(dmError, {
        userId,
        sessionId: session.id,
        operation: 'send_dm',
        verificationType,
        ipAddress: interaction.guild?.id ? undefined : 'DM',
      });

      // If DM fails, provide link in ephemeral reply with better formatting
      const fallbackEmbed = new EmbedBuilder()
        .setTitle(`🔐 ${displayName} - Direct Link`)
        .setDescription(`Since we couldn't send you a DM, here's your verification link directly.`)
        .setColor(0xffa500)
        .addFields([
          {
            name: 'Verification Link',
            value: `[Click here to verify](${verificationUrl})`,
            inline: false,
          },
          {
            name: 'Expires',
            value: `<t:${Math.floor(expiresAt.getTime() / 1000)}:R>`,
            inline: true,
          },
          {
            name: 'Attempts Remaining',
            value: `${config.bot.maxVerificationAttempts - 1}`,
            inline: true,
          },
          {
            name: '💡 Why this happened',
            value: dmErrorClassified.userMessage,
            inline: false,
          },
        ])
        .setFooter({
          text: 'Keep this link secure and do not share it with others.',
        })
        .setTimestamp();

      await interaction.editReply({
        embeds: [fallbackEmbed],
      });
    }

  } catch (error) {
    // Use centralized error handling
    await handleDiscordCommandError(error, {
      userId,
      operation: 'verify_command',
      ipAddress: interaction.guild?.id ? undefined : 'DM',
    }, interaction);
  }
}