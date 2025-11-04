// Database abstraction interfaces for switching between local JSON and Prisma storage

export interface VerificationSession {
  id: string;
  discordUserId: string;
  token: string;
  expiresAt: Date;
  createdAt: Date;
  used: boolean;
  attempts: number;
  maxAttempts: number;
  status: string;
  bindingHash: string;
  lastContextHash: string;
}

export interface AdminVerification {
  id: string;
  discordUserId: string;
  uniqueIdentifier: string;
  passportFingerprint: string;
  isActive: boolean;
  lastVerified: Date;
  createdAt: Date;
  expiryDate?: Date;
}

export interface VerificationHistory {
  id: string;
  discordUserId: string;
  success: boolean;
  errorMessage: string | null;
  timestamp: Date;
  createdAt: Date;
}

export interface DatabaseOperations {
  // Verification Sessions
  findVerificationSession(id: string): Promise<VerificationSession | null>;
  createVerificationSession(session: Omit<VerificationSession, 'createdAt'>): Promise<VerificationSession>;
  updateVerificationSession(id: string, updates: Partial<VerificationSession>): Promise<VerificationSession | null>;
  markSessionAsUsed(id: string): Promise<boolean>;

  // Admin Verifications
  findAdminVerification(discordUserId: string): Promise<AdminVerification | null>;
  findVerificationByUniqueIdentifier(uniqueIdentifier: string): Promise<AdminVerification | null>;
  findVerificationByFingerprint(passportFingerprint: string): Promise<AdminVerification | null>;
  upsertAdminVerification(verification: Omit<AdminVerification, 'createdAt'>): Promise<AdminVerification>;

  // Verification History
  createVerificationHistory(history: Omit<VerificationHistory, 'id' | 'createdAt'>): Promise<VerificationHistory>;

  // Transaction support for unified operations
  executeTransaction<T = any>(resourceNames: string[], transactionFn: (tx: any) => Promise<T>): Promise<T>;

  // Health check
  healthCheck(): Promise<boolean>;
}