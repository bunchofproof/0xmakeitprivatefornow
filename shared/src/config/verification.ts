import 'dotenv/config';
import { envsafe, str, bool, num } from 'envsafe';
import {
  VerificationConfig,
  VerificationType,
  getEnabledVerificationTypes
} from '../types/verification';
import { CleanupConfig } from '../../../bot/src/utils/sessionManager';

// Environment validation using envsafe following existing patterns
const env = envsafe({
  // Discord role configuration (removed from web app)
  // DISCORD_VERIFIED_ROLE_IDS: str({
  //   devDefault: 'verified_role_1,verified_role_2',
  //   default: '',
  //   desc: 'Comma-separated list of Discord role IDs to assign on successful verification'
  // }),

  // Individual verification type flags
  ENABLE_PERSONHOOD: bool({
    devDefault: true,
    default: true,
    desc: 'Controls personhood verification'
  }),
  ENABLE_AGE_VERIFICATION: bool({
    devDefault: true,
    default: true,
    desc: 'Controls age verification (adult checks)'
  }),
  ENABLE_NATIONALITY: bool({
    devDefault: true,
    default: true,
    desc: 'Controls nationality verification'
  }),
  ENABLE_RESIDENCY: bool({
    devDefault: true,
    default: true,
    desc: 'Controls residency verification'
  }),
  ENABLE_KYC: bool({
    devDefault: true,
    default: false,
    desc: 'Controls KYC verification'
  }),

  // Default verification type
  DEFAULT_VERIFICATION_TYPE: str({
    devDefault: 'personhood',
    default: 'personhood',
    choices: ['personhood', 'age', 'nationality', 'residency', 'kyc'],
    desc: 'Default verification type when none specified'
  }),

  // Minimum verification types
  MIN_VERIFICATION_TYPES: num({
    devDefault: 1,
    default: 1,
    desc: 'Minimum number of verification types that must be enabled'
  }),

  // Verification type expiry times (in minutes)
  VERIFICATION_EXPIRY_PERSONHOOD: num({
    devDefault: 15,
    default: 15,
    desc: 'Expiry time for personhood verification tokens'
  }),
  VERIFICATION_EXPIRY_AGE: num({
    devDefault: 10,
    default: 10,
    desc: 'Expiry time for age verification tokens'
  }),
  VERIFICATION_EXPIRY_NATIONALITY: num({
    devDefault: 20,
    default: 20,
    desc: 'Expiry time for nationality verification tokens'
  }),
  VERIFICATION_EXPIRY_RESIDENCY: num({
    devDefault: 25,
    default: 25,
    desc: 'Expiry time for residency verification tokens'
  }),
  VERIFICATION_EXPIRY_KYC: num({
    devDefault: 30,
    default: 30,
    desc: 'Expiry time for KYC verification tokens'
  }),

  // Session cleanup configuration
  SESSION_CLEANUP_ENABLED: bool({
    devDefault: true,
    default: true,
    desc: 'Enable automatic session cleanup'
  }),
  SESSION_RETENTION_HOURS: num({
    devDefault: 24,
    default: 24,
    desc: 'Hours to retain expired sessions before cleanup'
  }),
  ADMIN_VERIFICATION_RETENTION_HOURS: num({
    devDefault: 720, // 30 days
    default: 720,
    desc: 'Hours to retain expired admin verifications before deactivation'
  }),
  CLEANUP_BATCH_SIZE: num({
    devDefault: 1000,
    default: 1000,
    desc: 'Batch size for cleanup operations'
  }),
  CLEANUP_DRY_RUN: bool({
    devDefault: false,
    default: false,
    desc: 'Enable dry-run mode for cleanup operations'
  }),
  HISTORY_RETENTION_DAYS: num({
    devDefault: 90,
    default: 90,
    desc: 'Days to retain verification history records'
  }),

  // Environment
  NODE_ENV: str({
    devDefault: 'development',
    choices: ['development', 'test', 'production'],
    default: 'development',
  }),
});

// Parse Discord verified role IDs (removed from web app)
// const discordVerifiedRoleIds = env.DISCORD_VERIFIED_ROLE_IDS
//   ? env.DISCORD_VERIFIED_ROLE_IDS.split(',').map(id => id.trim()).filter(id => id.length > 0)
//   : [];

// Create the verification configuration object
export const verificationConfig: VerificationConfig = {
  // discordVerifiedRoleIds, // Removed from web app
  enablePersonhood: env.ENABLE_PERSONHOOD,
  enableAgeVerification: env.ENABLE_AGE_VERIFICATION,
  enableNationality: env.ENABLE_NATIONALITY,
  enableResidency: env.ENABLE_RESIDENCY,
  enableKyc: env.ENABLE_KYC,
  defaultVerificationType: env.DEFAULT_VERIFICATION_TYPE as VerificationType,
  minVerificationTypes: env.MIN_VERIFICATION_TYPES,
  env: env.NODE_ENV as 'development' | 'test' | 'production',
  // Per-verification-type expiry times
  verificationExpiry: {
    personhood: env.VERIFICATION_EXPIRY_PERSONHOOD,
    age: env.VERIFICATION_EXPIRY_AGE,
    nationality: env.VERIFICATION_EXPIRY_NATIONALITY,
    residency: env.VERIFICATION_EXPIRY_RESIDENCY,
    kyc: env.VERIFICATION_EXPIRY_KYC,
  },
};

// Session cleanup configuration
export const cleanupConfig: CleanupConfig = {
  sessionRetentionHours: env.SESSION_RETENTION_HOURS,
  adminVerificationRetentionHours: env.ADMIN_VERIFICATION_RETENTION_HOURS,
  batchSize: env.CLEANUP_BATCH_SIZE,
  dryRun: env.CLEANUP_DRY_RUN,
};

// Validation functions
export const validateVerificationConfig = (config: VerificationConfig): void => {
  const enabledTypes = getEnabledVerificationTypes(config);

  // Ensure minimum number of verification types are enabled
  if (enabledTypes.length < config.minVerificationTypes) {
    throw new Error(
      `At least ${config.minVerificationTypes} verification type(s) must be enabled. ` +
      `Currently enabled: ${enabledTypes.join(', ')}`
    );
  }

  // Validate that the default verification type is enabled
  if (!enabledTypes.includes(config.defaultVerificationType)) {
    throw new Error(
      `Default verification type '${config.defaultVerificationType}' is not enabled. ` +
      `Enabled types: ${enabledTypes.join(', ')}`
    );
  }

  // Validate minimum verification types range
  if (config.minVerificationTypes < 1) {
    throw new Error('MIN_VERIFICATION_TYPES must be at least 1');
  }

  if (config.minVerificationTypes > 5) {
    throw new Error('MIN_VERIFICATION_TYPES cannot exceed 5 (total verification types)');
  }
};

// Run validation on startup
validateVerificationConfig(verificationConfig);

// Export utility functions for working with the configuration
export const isVerificationEnabled = (type: VerificationType): boolean => {
  switch (type) {
    case 'personhood': return verificationConfig.enablePersonhood;
    case 'age': return verificationConfig.enableAgeVerification;
    case 'nationality': return verificationConfig.enableNationality;
    case 'residency': return verificationConfig.enableResidency;
    case 'kyc': return verificationConfig.enableKyc;
    default: return false;
  }
};

export const getEnabledTypes = (): VerificationType[] => {
  return getEnabledVerificationTypes(verificationConfig);
};

export const getDefaultType = (): VerificationType => {
  return verificationConfig.defaultVerificationType;
};

export const getMinimumTypes = (): number => {
  return verificationConfig.minVerificationTypes;
};

// Utility function to get expiry time for a specific verification type
export const getVerificationExpiryMinutes = (type: VerificationType): number => {
  return verificationConfig.verificationExpiry[type];
};

// Export the config as default for convenience
export default verificationConfig;