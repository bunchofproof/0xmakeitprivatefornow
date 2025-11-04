import { config } from '../config';
import { logger } from '../utils/logger';
import * as crypto from 'crypto';

interface ProofData {
  type?: string;
  data?: any;
}

/**
 * Sanitize proofs for deterministic hashing by removing non-deterministic fields and ensuring consistent ordering
 */
function sanitizeProofsForHash(proofs: ProofData[]) {
  logger.debug('sanitizeProofsForHash called with proofs:', proofs);
  if (!proofs || proofs.length === 0) {
    logger.debug('No proofs provided, returning empty array');
    return [];
  }

  return proofs.map(proof => {
    // Create a deep clone to avoid modifying the original object
    const sanitizedProof = JSON.parse(JSON.stringify(proof));

    // Recursively sanitize the entire object to catch nested random data
    const recursivelySanitize = (obj: any) => {
      if (!obj || typeof obj !== 'object') return;
      for (const key in obj) {
        if (key === 'timestamp' || key.endsWith('At') || key.includes('nonce') || key === 'proof') {
          logger.debug(`Deleting key '${key}' from proof object during sanitization for hash`);
          delete obj[key];
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          recursivelySanitize(obj[key]);
        }
      }
    };

    recursivelySanitize(sanitizedProof);

    // ADD THE FINAL FIX
    delete sanitizedProof.vkeyHash;

    return sanitizedProof; // Return the fully sanitized object

  }).sort((a, b) => {
    // Sort by stringified sanitized proof for consistent hashing
    return JSON.stringify(a).localeCompare(JSON.stringify(b));
  });
}

/**
 * Generate deterministic mock values from proof data
 */
function generateDeterministicMockValues(proofs: ProofData[]) {
  // Use sanitized proofs for consistent hashing
  const sanitizedProofs = sanitizeProofsForHash(proofs);
  console.log('--- SANITIZED PROOFS FOR HASH ---');
  console.log(JSON.stringify(sanitizedProofs, null, 2));
  console.log('---------------------------------');
  const content = JSON.stringify(sanitizedProofs);
  console.log('--- FINAL STRING BEING HASHED ---');
  console.log(content);
  console.log('--------------------------------');
  const passportFingerprint = crypto.createHash('sha256').update(content).digest('hex');
  const uniqueIdentifier = crypto.createHash('sha256').update(content + '_unique').digest('hex').substring(0, 32);
  logger.debug('Generated deterministic values from proofs:', {
    proofs_count: proofs.length,
    content_hash_input: content.substring(0, 50) + '...',
    fingerprint: passportFingerprint.substring(0, 10) + '...',
    uniqueId: uniqueIdentifier.substring(0, 10) + '...'
  });
  return { passportFingerprint, uniqueIdentifier };
}

/**
 * Generate mock verification result for development
 * Generates deterministic values when DETERMINISTIC_MOCK_FINGERPRINTS=true or when proofs are provided
 */
export function generateMockVerificationResult(proofs?: ProofData[]) {
  const isDeterministic = config.deterministicMockFingerprints;

  logger.debug('generateMockVerificationResult debug:', {
    config_deterministic: config.deterministicMockFingerprints,
    config_deterministic_type: typeof config.deterministicMockFingerprints,
    is_deterministic: isDeterministic,
    proofs_provided: !!proofs,
    proofs_length: proofs?.length
  });

  if (proofs) {
    logger.debug('Proofs provided:', proofs.map(p => ({
      type: p.type,
      data_keys: p.data ? Object.keys(p.data) : [],
      data_preview: p.data ? JSON.stringify(p.data).substring(0, 100) : 'undefined'
    })));
  }

  let passportFingerprint: string;
  let uniqueIdentifier: string;

  if (isDeterministic) {
    // Generate deterministic values only when flag is set to true
    const { passportFingerprint: detFingerprint, uniqueIdentifier: detUniqueId } = generateDeterministicMockValues(proofs || []);
    passportFingerprint = detFingerprint;
    uniqueIdentifier = detUniqueId;
  } else {
    // Generate random values when flag is false
    passportFingerprint = crypto.randomBytes(32).toString('hex');
    uniqueIdentifier = `dev_session_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }

  return {
    verified: true,
    uniqueIdentifier: uniqueIdentifier,
    passportFingerprint: passportFingerprint
  };
}

/**
 * Generate mock unique identifier for development
 */
export function generateMockUniqueIdentifier(): string {
  return `dev_session_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
}