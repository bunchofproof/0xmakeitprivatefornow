import { logger } from '../utils/logger';
import { secureAuditLogger } from '@shared/security/secureAuditLogger';
import { database } from '../database';

export interface VerificationStateDecision {
  action: 'new' | 'reactivate';
}

export class VerificationStateError extends Error {
  constructor(public message: string, public statusCode: number) {
    super(message);
    this.name = 'VerificationStateError';
  }
}

/**
 * Guardian Protocol V2: Checks verification state and determines whether to proceed with verification.
 * Handles database lookups, state determination, logging, and security auditing.
 * Throws VerificationStateError for rejection cases (409 Conflict).
 */
export async function checkVerificationState(
  discordUserId: string,
  passportFingerprint: string
): Promise<VerificationStateDecision> {
  // Guardian Protocol V2: Critical Security Checks (The Triage)
  const existingVerificationByPassport = await database.findVerificationByFingerprint(passportFingerprint);
  const existingVerificationByUser = await database.findAdminVerification(discordUserId);

  console.log('DEBUG: Database query results:', {
    existingVerificationByPassport: !!existingVerificationByPassport,
    existingVerificationByUser: !!existingVerificationByUser,
    passportFingerprint: passportFingerprint?.substring(0, 10) + '...',
    userIsActive: existingVerificationByUser?.isActive,
    discordUserId
  });

  logger.debug('Guardian Protocol V2 Triage Results:', {
    discordUserId,
    passportFingerprint: passportFingerprint?.substring(0, 10) + '...',
    existingVerificationByPassport: !!existingVerificationByPassport,
    existingVerificationByUser: !!existingVerificationByUser,
    passportOwner: existingVerificationByPassport?.discordUserId,
    userIsActive: existingVerificationByUser?.isActive
  });

  // Add specific logs for each scenario to diagnose logic issues
  if (existingVerificationByPassport) {
    if (existingVerificationByPassport.discordUserId === discordUserId) {
      logger.debug(`Scenario 1 (Re-Verification): User ${discordUserId} re-verifying with same passport, isActive: ${existingVerificationByUser?.isActive}`);
    } else {
      logger.debug(`Scenario 2 (Sybil Attack): User ${discordUserId} attempting to use passport owned by ${existingVerificationByPassport.discordUserId}`);
    }
  } else if (existingVerificationByUser) {
    logger.debug(`Scenario 3 (New Passport): User ${discordUserId} attempting verification with different passport, current passport: ${existingVerificationByUser.passportFingerprint?.substring(0, 10)}...`);
  } else {
    logger.debug(`Scenario 4 (New User): Brand new verification for user ${discordUserId}`);
  }

  // Guardian Protocol V2: Decision Logic (The Brain)
  if (existingVerificationByPassport) {
    console.log('DEBUG: Entering case A - existing passport found');
    // Case A: We have seen this passport before.
    if (existingVerificationByPassport.discordUserId === discordUserId) {
      console.log('DEBUG: Entering case A.1 - same user');
      // Case A.1: Re-Verification attempt by the legitimate owner.
      if (existingVerificationByUser && existingVerificationByUser.isActive) {
        console.log('DEBUG: Rejecting case A.1 - user active, re-verification');
        // Action: REJECT (409 Conflict) - Re-verification of active user
        logger.warn(`Re-verification rejected: User ${discordUserId} already has active verification`);
        throw new VerificationStateError('Re-Verification Active: User already has active admin verification', 409);
      } else {
        console.log('DEBUG: Proceeding case A.1 - re-activating inactive user');
        // Action: PROCEED to main transaction to re-activate them.
        // Log: "Re-activating user."
        logger.info(`Re-activating user ${discordUserId} with existing passport.`);
        return { action: 'reactivate' };
      }
    } else {
      console.log('DEBUG: Entering case A.2 - different user, sybil attack');
      // Case A.2: Sybil Attack. A different user is trying to use a claimed passport.
      // Action: REJECT (409 Conflict)
      logger.warn(`Sybil attack detected: User ${discordUserId} attempted to use passport already claimed by ${existingVerificationByPassport.discordUserId}`);
      throw new VerificationStateError('This passport has already been used to verify a different Discord account. Each passport can only be linked to one user.', 409);
    }
  } else if (existingVerificationByUser && existingVerificationByUser.isActive) {
    console.log('DEBUG: Entering case B - existing user active, new passport');
    // Case B: We have not seen this passport, but we have seen this user with active verification. (New Passport)
    // Action: REJECT (409 Conflict)
    // Admin Trust Layer Action: Log a high-severity security event.
    logger.warn(`New passport attempt rejected: User ${discordUserId} already has active verification with different passport`);
    secureAuditLogger.logSecurityViolationEvent(discordUserId, 'user_attempted_verification_with_new_passport', {
      discordUserId,
      newPassportFingerprint: passportFingerprint,
      existingPassportFingerprint: existingVerificationByUser.passportFingerprint
    });
    throw new VerificationStateError('Re-Verification New Passport: User already has active admin verification', 409);
  } else {
    console.log('DEBUG: Entering case C - new verification');
    // Case C: Brand New Verification or re-activation of inactive user.
    // Action: PROCEED to main transaction.
    // Log: "New user verification."
    logger.info(`New user verification for ${discordUserId}.`);
    return { action: 'new' };
  }
}