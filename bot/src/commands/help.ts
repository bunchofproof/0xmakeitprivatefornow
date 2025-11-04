import { CommandInteraction, SlashCommandBuilder, EmbedBuilder, MessageFlags } from 'discord.js';

export const data = new SlashCommandBuilder()
  .setName('help')
  .setDescription('Get help information about the verification bot');

export async function execute(interaction: CommandInteraction) {
  const embed = new EmbedBuilder()
    .setTitle('🔐 ZKPassport Verification Bot Help')
    .setDescription('This bot helps manage ZKPassport verification for Discord server members.')
    .setColor(0x0099ff)
    .addFields([
      {
        name: '📋 Available Commands',
        value: 'Here are the commands you can use:',
        inline: false,
      },
      {
        name: '`/verify`',
        value: 'Start the ZKPassport verification process. You\'ll receive a secure link in your DMs to complete verification.',
        inline: false,
      },
      {
        name: '`/status [user]`',
        value: 'Check your verification status. Admins can check other users\' status by providing a user ID.',
        inline: false,
      },
      {
        name: '`/help`',
        value: 'Show this help message with information about available commands.',
        inline: false,
      },
      {
        name: '🔧 Admin Commands',
        value: 'The following commands are only available to administrators:',
        inline: false,
      },
      {
        name: '`/adminstatus pending [limit]`',
        value: 'View pending verifications that need admin approval.',
        inline: false,
      },
      {
        name: '`/adminstatus stats`',
        value: 'View verification statistics for the server.',
        inline: false,
      },
      {
        name: '`/adminstatus approve <user_id> [reason]`',
        value: 'Approve a pending verification for a specific user.',
        inline: false,
      },
      {
        name: '`/adminstatus reject <user_id> <reason>`',
        value: 'Reject a pending verification with a required reason.',
        inline: false,
      },
    ])
    .addFields([
      {
        name: '🔒 Security Features',
        value: '• Verification links expire after 15 minutes\n• Rate limiting prevents spam\n• All tokens are cryptographically secure\n• No sensitive data is logged',
        inline: false,
      },
      {
        name: '📞 Support',
        value: 'If you need help or encounter issues, please contact an administrator.',
        inline: false,
      },
    ])
    .setFooter({
      text: 'ZKPassport Verification Bot',
    })
    .setTimestamp();

  await interaction.reply({ embeds: [embed], flags: MessageFlags.Ephemeral });
}