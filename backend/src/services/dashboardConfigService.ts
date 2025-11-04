import { readFileSync } from 'fs';
import { join } from 'path';
import { logger } from '../utils/logger';

interface GuardianConfig {
  reverificationIntervalDays: number;
  lockdownThreshold: number;
  alertChannelId: string | null;
}

interface DashboardConfig {
  default: GuardianConfig;
  guilds: Record<string, GuardianConfig>;
}

let configCache: DashboardConfig | null = null;

function loadConfig(): DashboardConfig {
  if (configCache) {
    return configCache;
  }

  try {
    const configPath = join(__dirname, '../../temp-dashboard/dashboardConfig.json');
    const configData = readFileSync(configPath, 'utf-8');
    configCache = JSON.parse(configData);
    return configCache;
  } catch (error) {
    logger.error('Failed to load dashboard configuration:', error);
    // Return default configuration on error
    return {
      default: {
        reverificationIntervalDays: 90,
        lockdownThreshold: 50,
        alertChannelId: null
      },
      guilds: {}
    };
  }
}

export function getConfigForGuild(guildId: string): GuardianConfig {
  const config = loadConfig();

  if (config.guilds && config.guilds[guildId]) {
    return config.guilds[guildId];
  }

  return config.default;
}