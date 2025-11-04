/**
 * Verification recipes defining the operations required for each verification type
 * Based on audit findings from the Alignment Mission
 */

import { VerificationType } from '../types/verification';

/**
 * Available operation types for verification recipes
 */
export type VerificationOperation =
  | 'disclose'
  | 'compare_age'
  | 'inclusion_check_country'
  | 'exclusion_check_country'
  | 'composite_uniqueness';

/**
 * Verification recipe defining the operations for a specific verification type
 */
export interface VerificationRecipe {
  /** The verification type this recipe applies to */
  type: VerificationType;
  /** Array of operations required for this verification type */
  operations: VerificationOperation[];
  /** Whether this recipe is currently broken/incomplete */
  broken?: boolean;
  /** Additional notes about the recipe */
  notes?: string;
}

/**
 * Complete set of verification recipes based on audit findings
 */
export const VERIFICATION_RECIPES: Record<VerificationType, VerificationRecipe> = {
  kyc: {
    type: 'kyc',
    operations: ['disclose', 'disclose', 'disclose', 'disclose'], // 4 disclose operations
    notes: 'The 5th proof for \'document_number\' is failing in the ZKPassport mobile app\'s test environment.',
  },
  age: {
    type: 'age',
    operations: ['disclose', 'compare_age'], // disclose and compare_age
  },
  nationality: {
    type: 'nationality',
    operations: ['disclose', 'inclusion_check_country', 'exclusion_check_country'], // disclose, inclusion_check_country, exclusion_check_country
  },
  personhood: {
    type: 'personhood',
    operations: [
      'composite_uniqueness',
      'composite_uniqueness',
      'composite_uniqueness',
      'composite_uniqueness'
    ], // 4 composite_uniqueness operations
  },
  residency: {
    type: 'residency',
    operations: ['disclose', 'disclose', 'inclusion_check_country'], // disclose, disclose, inclusion_check_country
    broken: true, // noting it's broken
    notes: 'Residency verification is currently broken and requires fixes',
  },
};

/**
 * Get the verification recipe for a specific type
 */
export const getVerificationRecipe = (type: VerificationType): VerificationRecipe => {
  return VERIFICATION_RECIPES[type];
};

/**
 * Get all operations for a verification type
 */
export const getVerificationOperations = (type: VerificationType): VerificationOperation[] => {
  return VERIFICATION_RECIPES[type].operations;
};

/**
 * Check if a verification type's recipe is marked as broken
 */
export const isVerificationRecipeBroken = (type: VerificationType): boolean => {
  return VERIFICATION_RECIPES[type].broken === true;
};

/**
 * Get all verification types that have broken recipes
 */
export const getBrokenVerificationRecipes = (): VerificationType[] => {
  return Object.values(VERIFICATION_RECIPES)
    .filter(recipe => recipe.broken)
    .map(recipe => recipe.type);
};