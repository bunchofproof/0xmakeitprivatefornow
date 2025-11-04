import { getConfigForGuild } from '../backend/src/services/configManager';

jest.mock('fs', () => ({
  readFileSync: jest.fn(),
}));

jest.mock('../backend/src/utils/logger', () => ({
  logger: {
    error: jest.fn(),
  },
}));

import { readFileSync } from 'fs';
import { logger } from '../backend/src/utils/logger';

const mockReadFileSync = readFileSync as jest.MockedFunction<typeof readFileSync>;
const mockLogger = logger as jest.Mocked<typeof logger>;

describe('configManager', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    // Clear the cache after each test
    const configManager = require('../backend/src/services/configManager');
    configManager.configCache = null;
  });

  describe('getConfigForGuild', () => {
    it('should return specific configuration for existing guild ID', () => {
      const mockConfigData = {
        default: {
          reverificationIntervalDays: 90,
          lockdownThreshold: 50,
          alertChannelId: null
        },
        guilds: {
          '1038523194409230387': {
            comment: 'This is an example override for Devin | Kong\'s server',
            reverificationIntervalDays: 30,
            lockdownThreshold: 75,
            alertChannelId: '1170229906785972270'
          }
        }
      };

      mockReadFileSync.mockReturnValue(JSON.stringify(mockConfigData));

      const result = getConfigForGuild('1038523194409230387');

      expect(result).toEqual({
        comment: 'This is an example override for Devin | Kong\'s server',
        reverificationIntervalDays: 30,
        lockdownThreshold: 75,
        alertChannelId: '1170229906785972270'
      });
      // File should be read due to caching from previous test
    });

    it('should return default configuration for non-existent guild ID', () => {
      const mockConfigData = {
        default: {
          reverificationIntervalDays: 90,
          lockdownThreshold: 50,
          alertChannelId: null
        },
        guilds: {
          '1038523194409230387': {
            comment: 'This is an example override for Devin | Kong\'s server',
            reverificationIntervalDays: 30,
            lockdownThreshold: 75,
            alertChannelId: '1170229906785972270'
          }
        }
      };

      mockReadFileSync.mockReturnValue(JSON.stringify(mockConfigData));

      const result = getConfigForGuild('non-existent-guild');

      expect(result).toEqual({
        reverificationIntervalDays: 90,
        lockdownThreshold: 50,
        alertChannelId: null
      });
    });


  });
});