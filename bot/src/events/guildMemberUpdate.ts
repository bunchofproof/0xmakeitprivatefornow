import { GuildMember, PartialGuildMember } from 'discord.js';
import { logger } from '../utils/logger';
import { config } from '../config';
import { auditLogger } from '@shared/services/auditLogger';

export async function handleGuildMemberUpdate(
  oldMember: GuildMember | PartialGuildMember,
  newMember: GuildMember
): Promise<void> {
  try {
    // Check if roles changed
    const oldRoles = oldMember.roles?.cache || oldMember.roles.cache;
    const newRoles = newMember.roles.cache;

    const addedRoles = newRoles.filter(role => !oldRoles.has(role.id));
    const removedRoles = oldRoles.filter(role => !newRoles.has(role.id));

    // Log role changes if any occurred
    if (addedRoles.size > 0 || removedRoles.size > 0) {
      logger.info('Role changes for user', {
        username: newMember.user.username,
        userId: newMember.id,
      });

      if (addedRoles.size > 0) {
        logger.info('Added roles', {
          userId: newMember.id,
          roles: addedRoles.map(r => r.name).join(', ')
        });

        // Check if admin roles were added
        const adminRolesAdded = addedRoles.filter(role => config.bot.adminRoleIds.includes(role.id));
        if (adminRolesAdded.size > 0) {
          logger.info('Admin roles added to user', {
            userId: newMember.id,
            roles: adminRolesAdded.map(r => r.name).join(', ')
          });

          // Log admin role assignment for audit
          for (const role of adminRolesAdded.values()) {
            auditLogger.logRoleChange('system', 'external', 'assignment', role.name, {
              userId: newMember.id,
              roleId: role.id,
              reason: 'Role added externally (possibly manual admin action)',
            });
          }
        }
      }

      if (removedRoles.size > 0) {
        logger.info('Removed roles', {
          userId: newMember.id,
          roles: removedRoles.map(r => r.name).join(', ')
        });

        // Check if admin roles were removed
        const adminRolesRemoved = removedRoles.filter(role => config.bot.adminRoleIds.includes(role.id));
        if (adminRolesRemoved.size > 0) {
          logger.warn('Admin roles removed from user', {
            userId: newMember.id,
            roles: adminRolesRemoved.map(r => r.name).join(', ')
          });

          // Log admin role removal for audit
          for (const role of adminRolesRemoved.values()) {
            auditLogger.logRoleChange('system', 'external', 'removal', role.name, {
              userId: newMember.id,
              roleId: role.id,
              reason: 'Role removed externally (possibly manual admin action or verification revocation)',
            });
          }
        }
      }

      // Additional logic for role-based verification triggers could be added here
      // For example, automatically trigger verification status updates when admin roles change
    }

    // Check for nickname changes
    if (oldMember.nickname !== newMember.nickname) {
      logger.info('Nickname changed', {
        username: newMember.user.username,
        userId: newMember.id,
        oldNickname: oldMember.nickname,
        newNickname: newMember.nickname
      });

      // Log nickname change for audit purposes
      auditLogger.logAdminAction('system', 'nickname_change', newMember.id, {
        oldNickname: oldMember.nickname,
        newNickname: newMember.nickname,
      });
    }

  } catch (error) {
    logger.error('Error handling guild member update', undefined, {
      error: error instanceof Error ? error.message : String(error),
      userId: newMember.id,
    } as Record<string, any>);

   // Log error in audit system
    auditLogger.logSecurityViolation('system', 'guild_member_update_error', {
      userId: newMember.id,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}