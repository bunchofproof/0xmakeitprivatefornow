"use strict";
// Shared types for ZKPassport Discord verification system
Object.defineProperty(exports, "__esModule", { value: true });
exports.VERIFICATION_TYPES = void 0;
// Verification type configurations
exports.VERIFICATION_TYPES = {
    personhood: {
        type: 'personhood',
        scope: 'personhood',
        name: 'ZKPassport Discord Verification',
        purpose: 'Verify your identity for Discord admin access',
        logo: '/logo.png',
        requirements: {}
    },
    adult: {
        type: 'adult',
        scope: 'adult',
        name: 'Discord Admin Age Verification',
        purpose: 'Verify you are over 18 for Discord admin access',
        logo: '/logo.png',
        requirements: {
            age: 18
        }
    },
    nationality: {
        type: 'nationality',
        scope: 'nationality',
        name: 'Discord Admin Nationality Verification',
        purpose: 'Verify your nationality for Discord admin access',
        logo: '/logo.png',
        requirements: {
            nationality: 'US' // Default to US, could be made configurable
        }
    },
    kyc: {
        type: 'kyc',
        scope: 'kyc',
        name: 'Discord Admin KYC Verification',
        purpose: 'Complete identity verification for Discord admin access',
        logo: '/logo.png',
        requirements: {
            kyc: true
        }
    }
};
//# sourceMappingURL=index.js.map