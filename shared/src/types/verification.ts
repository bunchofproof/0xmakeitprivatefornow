// Verification type definitions and interfaces for the ZKPassport Discord verification system

export type VerificationType = 'personhood' | 'age' | 'nationality' | 'residency' | 'kyc';
export type OldVerificationType = 'personhood' | 'adult' | 'nationality' | 'kyc';

export interface VerificationTypeConfig {
  enabled: boolean;
  name: string;
  description: string;
  requirements?: {
    age?: number;
    nationality?: string;
    residency?: string;
    kyc?: boolean;
  };
}

export interface ErrorRecoverySuggestion {
  action: string;
  description: string;
  userMessage: string;
  priority: 'high' | 'medium' | 'low';
  requiresUserAction: boolean;
}

export interface VerificationError {
  code: string;
  title: string;
  userMessage: string;
  technicalMessage: string;
  recoverySuggestions: ErrorRecoverySuggestion[];
  retryable: boolean;
  timeoutMs?: number;
  maxRetries?: number;
}

export interface VerificationConfig {
  // Discord role configuration (removed from web app)
  // discordVerifiedRoleIds: string[];

  // Individual verification type flags
  enablePersonhood: boolean;
  enableAgeVerification: boolean;
  enableNationality: boolean;
  enableResidency: boolean;
  enableKyc: boolean;

  // Default verification type when none specified
  defaultVerificationType: VerificationType;

  // Minimum number of verification types that must be enabled
  minVerificationTypes: number;

  // Environment-specific settings
  env: 'development' | 'test' | 'production';

  // Per-verification-type expiry times (in minutes)
  verificationExpiry: Record<VerificationType, number>;
}

// Predefined configurations for each verification type
export const VERIFICATION_TYPE_CONFIGS: Record<VerificationType, Omit<VerificationTypeConfig, 'enabled'>> = {
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
export const getEnabledVerificationTypes = (config: VerificationConfig): VerificationType[] => {
  const enabled: VerificationType[] = [];

  if (config.enablePersonhood) enabled.push('personhood');
  if (config.enableAgeVerification) enabled.push('age');
  if (config.enableNationality) enabled.push('nationality');
  if (config.enableResidency) enabled.push('residency');
  if (config.enableKyc) enabled.push('kyc');

  return enabled;
};

export const isVerificationTypeEnabled = (config: VerificationConfig, type: VerificationType): boolean => {
  switch (type) {
    case 'personhood': return config.enablePersonhood;
    case 'age': return config.enableAgeVerification;
    case 'nationality': return config.enableNationality;
    case 'residency': return config.enableResidency;
    case 'kyc': return config.enableKyc;
    default: return false;
  }
};

export const getDefaultVerificationType = (config: VerificationConfig): VerificationType => {
  if (isVerificationTypeEnabled(config, config.defaultVerificationType)) {
    return config.defaultVerificationType;
  }

  // Fallback to first enabled type
  const enabled = getEnabledVerificationTypes(config);
  return enabled.length > 0 ? enabled[0] : 'personhood';
};