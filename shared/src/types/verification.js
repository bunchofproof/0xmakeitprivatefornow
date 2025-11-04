"use strict";
// Verification type definitions and interfaces for the ZKPassport Discord verification system
Object.defineProperty(exports, "__esModule", { value: true });
exports.getDefaultVerificationType = exports.isVerificationTypeEnabled = exports.getEnabledVerificationTypes = exports.VERIFICATION_TYPE_CONFIGS = void 0;
// Predefined configurations for each verification type
exports.VERIFICATION_TYPE_CONFIGS = {
    personhood: {
        name: 'Personhood Verification',
        description: 'Verify that you are a unique human being',
        requirements: {}
    },
    age: {
        name: 'Age Verification',
        description: 'Verify that you are of legal adult age',
        requirements: {
            age: 18
        }
    },
    nationality: {
        name: 'Nationality Verification',
        description: 'Verify your nationality for access requirements',
        requirements: {
            nationality: 'US' // Default, can be made configurable
        }
    },
    residency: {
        name: 'Residency Verification',
        description: 'Verify your residency status for access requirements',
        requirements: {
            residency: 'US' // Default, can be made configurable
        }
    },
    kyc: {
        name: 'KYC Verification',
        description: 'Complete identity verification with full KYC process',
        requirements: {
            kyc: true
        }
    }
};
// Utility functions for verification configuration
const getEnabledVerificationTypes = (config) => {
    const enabled = [];
    if (config.enablePersonhood)
        enabled.push('personhood');
    if (config.enableAgeVerification)
        enabled.push('age');
    if (config.enableNationality)
        enabled.push('nationality');
    if (config.enableResidency)
        enabled.push('residency');
    if (config.enableKyc)
        enabled.push('kyc');
    return enabled;
};
exports.getEnabledVerificationTypes = getEnabledVerificationTypes;
const isVerificationTypeEnabled = (config, type) => {
    switch (type) {
        case 'personhood': return config.enablePersonhood;
        case 'age': return config.enableAgeVerification;
        case 'nationality': return config.enableNationality;
        case 'residency': return config.enableResidency;
        case 'kyc': return config.enableKyc;
        default: return false;
    }
};
exports.isVerificationTypeEnabled = isVerificationTypeEnabled;
const getDefaultVerificationType = (config) => {
    if ((0, exports.isVerificationTypeEnabled)(config, config.defaultVerificationType)) {
        return config.defaultVerificationType;
    }
    // Fallback to first enabled type
    const enabled = (0, exports.getEnabledVerificationTypes)(config);
    return enabled.length > 0 ? enabled[0] : 'personhood';
};
exports.getDefaultVerificationType = getDefaultVerificationType;
//# sourceMappingURL=verification.js.map