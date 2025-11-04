// Shared types for ZKPassport Discord verification system

export interface DiscordUser {
  id: string;
  username: string;
  discriminator: string;
  avatar?: string;
}

export interface VerificationSession {
  id: string;
  token: string;
  discordUserId: string;
  status: 'pending' | 'completed' | 'expired' | 'failed';
  createdAt: Date;
  expiresAt: Date;
  completedAt?: Date;
  attempts: number;
  maxAttempts: number;
}

export interface UserVerification {
  id: string;
  discordUserId: string;
  isVerified: boolean;
  verifiedAt?: Date;
  lastVerificationDate?: Date;
  expiresAt?: Date;
  adminVerified: boolean;
  adminVerifiedBy?: string;
  adminVerifiedAt?: Date;
}

export interface VerificationHistory {
  id: string;
  discordUserId: string;
  sessionId: string;
  action: 'created' | 'completed' | 'expired' | 'failed' | 'admin_verified';
  timestamp: Date;
  metadata?: Record<string, any>;
}

export interface AdminVerification {
  id: string;
  discordUserId: string;
  adminUserId: string;
  status: 'pending' | 'approved' | 'rejected';
  reason?: string;
  createdAt: Date;
  reviewedAt?: Date;
  expiresAt: Date;
}

export interface BotConfig {
  discordToken: string;
  clientId: string;
  guildId: string;
  databaseUrl: string;
  verificationUrl: string;
  adminRoleIds: string[];
  maxVerificationAttempts: number;
  tokenExpiryMinutes: number;
  reminderSchedule: string; // cron format
}

export interface CommandContext {
  user: DiscordUser;
  guild?: {
    id: string;
    name: string;
  };
  channel?: {
    id: string;
    name: string;
  };
}

export interface VerificationResult {
  success: boolean;
  message: string;
  data?: any;
  error?: string;
}

export interface ScheduledReminder {
  id: string;
  discordUserId: string;
  scheduledFor: Date;
  type: 'verification_reminder' | 'admin_review';
  message: string;
  sent: boolean;
  attempts: number;
}

export interface TokenData {
   token: string;
   expiresAt: Date;
   userId: string;
   sessionId: string;
   signature?: string;
 }

export interface CryptoConfig {
  algorithm: string;
  secretLength: number;
  tokenLength: number;
}

export interface DatabaseConfig {
  url: string;
  provider: 'postgresql' | 'mysql' | 'sqlite';
  ssl?: boolean;
  connectionLimit?: number;
}

export type Environment = 'development' | 'test' | 'production';

export interface AppConfig {
  env: Environment;
  bot: BotConfig;
  crypto: CryptoConfig;
  database: DatabaseConfig;
  logging: {
    level: 'debug' | 'info' | 'warn' | 'error';
    format: 'json' | 'text';
  };
  web?: {
    url: string;
    port: number;
    cors: {
      origins: string[];
    };
  };
}

// Web-specific types for ZKPassport integration
export interface ZKPassportVerificationRequest {
  proofs: any[];
  token: string;
  domain: string;
}

export interface ZKPassportVerificationResponse {
  verified: boolean;
  uniqueIdentifier?: string;
  message: string;
  sessionId?: string;
  discordUserId?: string;
}

export interface TokenValidationResponse {
  valid: boolean;
  sessionId?: string;
  discordUserId?: string;
  expiresAt?: Date;
  message: string;
}

export interface WebConfig {
  nextAuth?: {
    secret: string;
    url: string;
  };
  zkPassport: {
    devMode: boolean;
    domain: string;
  };
  rateLimiting: {
    enabled: boolean;
    maxRequests: number;
    windowMs: number;
  };
  security: {
    corsOrigins: string[];
    allowedOrigins: string[];
  };
}

export interface QRCodeData {
  url: string;
  expiresAt: Date;
  sessionId: string;
}

export interface VerificationPageProps {
  token: string;
  initialValidation?: TokenValidationResponse;
}

// Legacy verification type definitions (deprecated, use shared/src/types/verification.ts)
export type VerificationType = 'personhood' | 'adult' | 'nationality' | 'kyc';

// Use the new verification configuration types from verification.ts
export type { VerificationType as NewVerificationType } from './verification';

export type {
  VerificationTypeConfig,
  VerificationConfig as NewVerificationConfig,
} from './verification.js';

export interface VerificationConfig {
  type: VerificationType;
  scope: string;
  name: string;
  purpose: string;
  logo: string;
  requirements?: {
    age?: number;
    nationality?: string;
    kyc?: boolean;
  };
}

export interface ZKPassportConfig {
  domain: string;
  devMode: boolean;
  verificationType: VerificationType;
}

// Legacy verification type configurations (deprecated, use VERIFICATION_TYPE_CONFIGS from verification.ts)
// These remain for backward compatibility but should be migrated to the new VERIFICATION_TYPE_CONFIGS
export const VERIFICATION_TYPES: Record<VerificationType, VerificationConfig> = {
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