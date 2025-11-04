"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getVerificationExpiryMinutes = exports.getMinimumTypes = exports.getDefaultType = exports.getEnabledTypes = exports.isVerificationEnabled = exports.validateVerificationConfig = exports.cleanupConfig = exports.verificationConfig = void 0;
require("dotenv/config");
const envsafe_1 = require("envsafe");
const verification_1 = require("../types/verification");
// Environment validation using envsafe following existing patterns
const env = (0, envsafe_1.envsafe)({
    // Discord role configuration
    DISCORD_VERIFIED_ROLE_IDS: (0, envsafe_1.str)({
        devDefault: 'verified_role_1,verified_role_2',
        default: '',
        desc: 'Comma-separated list of Discord role IDs to assign on successful verification'
    }),
    // Individual verification type flags
    ENABLE_PERSONHOOD: (0, envsafe_1.bool)({
        devDefault: true,
        default: true,
        desc: 'Controls personhood verification'
    }),
    ENABLE_AGE_VERIFICATION: (0, envsafe_1.bool)({
        devDefault: true,
        default: true,
        desc: 'Controls age verification (adult checks)'
    }),
    ENABLE_NATIONALITY: (0, envsafe_1.bool)({
        devDefault: true,
        default: true,
        desc: 'Controls nationality verification'
    }),
    ENABLE_RESIDENCY: (0, envsafe_1.bool)({
        devDefault: true,
        default: true,
        desc: 'Controls residency verification'
    }),
    ENABLE_KYC: (0, envsafe_1.bool)({
        devDefault: true,
        default: false,
        desc: 'Controls KYC verification'
    }),
    // Default verification type
    DEFAULT_VERIFICATION_TYPE: (0, envsafe_1.str)({
        devDefault: 'personhood',
        default: 'personhood',
        choices: ['personhood', 'age', 'nationality', 'residency', 'kyc'],
        desc: 'Default verification type when none specified'
    }),
    // Minimum verification types
    MIN_VERIFICATION_TYPES: (0, envsafe_1.num)({
        devDefault: 1,
        default: 1,
        desc: 'Minimum number of verification types that must be enabled'
    }),
    // Verification type expiry times (in minutes)
    VERIFICATION_EXPIRY_PERSONHOOD: (0, envsafe_1.num)({
        devDefault: 15,
        default: 15,
        desc: 'Expiry time for personhood verification tokens'
    }),
    VERIFICATION_EXPIRY_AGE: (0, envsafe_1.num)({
        devDefault: 10,
        default: 10,
        desc: 'Expiry time for age verification tokens'
    }),
    VERIFICATION_EXPIRY_NATIONALITY: (0, envsafe_1.num)({
        devDefault: 20,
        default: 20,
        desc: 'Expiry time for nationality verification tokens'
    }),
    VERIFICATION_EXPIRY_RESIDENCY: (0, envsafe_1.num)({
        devDefault: 25,
        default: 25,
        desc: 'Expiry time for residency verification tokens'
    }),
    VERIFICATION_EXPIRY_KYC: (0, envsafe_1.num)({
        devDefault: 30,
        default: 30,
        desc: 'Expiry time for KYC verification tokens'
    }),
    // Session cleanup configuration
    SESSION_CLEANUP_ENABLED: (0, envsafe_1.bool)({
        devDefault: true,
        default: true,
        desc: 'Enable automatic session cleanup'
    }),
    SESSION_RETENTION_HOURS: (0, envsafe_1.num)({
        devDefault: 24,
        default: 24,
        desc: 'Hours to retain expired sessions before cleanup'
    }),
    ADMIN_VERIFICATION_RETENTION_HOURS: (0, envsafe_1.num)({
        devDefault: 720, // 30 days
        default: 720,
        desc: 'Hours to retain expired admin verifications before deactivation'
    }),
    CLEANUP_BATCH_SIZE: (0, envsafe_1.num)({
        devDefault: 1000,
        default: 1000,
        desc: 'Batch size for cleanup operations'
    }),
    CLEANUP_DRY_RUN: (0, envsafe_1.bool)({
        devDefault: false,
        default: false,
        desc: 'Enable dry-run mode for cleanup operations'
    }),
    HISTORY_RETENTION_DAYS: (0, envsafe_1.num)({
        devDefault: 90,
        default: 90,
        desc: 'Days to retain verification history records'
    }),
    // Environment
    NODE_ENV: (0, envsafe_1.str)({
        devDefault: 'development',
        choices: ['development', 'test', 'production'],
        default: 'development',
    }),
});
// Parse Discord verified role IDs
const discordVerifiedRoleIds = env.DISCORD_VERIFIED_ROLE_IDS
    ? env.DISCORD_VERIFIED_ROLE_IDS.split(',').map(id => id.trim()).filter(id => id.length > 0)
    : [];
// Create the verification configuration object
exports.verificationConfig = {
    discordVerifiedRoleIds,
    enablePersonhood: env.ENABLE_PERSONHOOD,
    enableAgeVerification: env.ENABLE_AGE_VERIFICATION,
    enableNationality: env.ENABLE_NATIONALITY,
    enableResidency: env.ENABLE_RESIDENCY,
    enableKyc: env.ENABLE_KYC,
    defaultVerificationType: env.DEFAULT_VERIFICATION_TYPE,
    minVerificationTypes: env.MIN_VERIFICATION_TYPES,
    env: env.NODE_ENV,
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
exports.cleanupConfig = {
    sessionRetentionHours: env.SESSION_RETENTION_HOURS,
    adminVerificationRetentionHours: env.ADMIN_VERIFICATION_RETENTION_HOURS,
    batchSize: env.CLEANUP_BATCH_SIZE,
    dryRun: env.CLEANUP_DRY_RUN,
};
// Validation functions
const validateVerificationConfig = (config) => {
    const enabledTypes = (0, verification_1.getEnabledVerificationTypes)(config);
    // Ensure minimum number of verification types are enabled
    if (enabledTypes.length < config.minVerificationTypes) {
        throw new Error(`At least ${config.minVerificationTypes} verification type(s) must be enabled. ` +
            `Currently enabled: ${enabledTypes.join(', ')}`);
    }
    // Validate that the default verification type is enabled
    if (!enabledTypes.includes(config.defaultVerificationType)) {
        throw new Error(`Default verification type '${config.defaultVerificationType}' is not enabled. ` +
            `Enabled types: ${enabledTypes.join(', ')}`);
    }
    // Validate minimum verification types range
    if (config.minVerificationTypes < 1) {
        throw new Error('MIN_VERIFICATION_TYPES must be at least 1');
    }
    if (config.minVerificationTypes > 5) {
        throw new Error('MIN_VERIFICATION_TYPES cannot exceed 5 (total verification types)');
    }
};
exports.validateVerificationConfig = validateVerificationConfig;
// Run validation on startup
(0, exports.validateVerificationConfig)(exports.verificationConfig);
// Export utility functions for working with the configuration
const isVerificationEnabled = (type) => {
    switch (type) {
        case 'personhood': return exports.verificationConfig.enablePersonhood;
        case 'age': return exports.verificationConfig.enableAgeVerification;
        case 'nationality': return exports.verificationConfig.enableNationality;
        case 'residency': return exports.verificationConfig.enableResidency;
        case 'kyc': return exports.verificationConfig.enableKyc;
        default: return false;
    }
};
exports.isVerificationEnabled = isVerificationEnabled;
const getEnabledTypes = () => {
    return (0, verification_1.getEnabledVerificationTypes)(exports.verificationConfig);
};
exports.getEnabledTypes = getEnabledTypes;
const getDefaultType = () => {
    return exports.verificationConfig.defaultVerificationType;
};
exports.getDefaultType = getDefaultType;
const getMinimumTypes = () => {
    return exports.verificationConfig.minVerificationTypes;
};
exports.getMinimumTypes = getMinimumTypes;
// Utility function to get expiry time for a specific verification type
const getVerificationExpiryMinutes = (type) => {
    return exports.verificationConfig.verificationExpiry[type];
};
exports.getVerificationExpiryMinutes = getVerificationExpiryMinutes;
// Export the config as default for convenience
exports.default = exports.verificationConfig;
//# sourceMappingURL=verification.js.map