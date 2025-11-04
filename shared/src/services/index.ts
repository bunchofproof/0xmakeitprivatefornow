// Export all verification type modules
export { PersonhoodVerification, personhoodVerification } from './verificationTypes/personhood';
export type { PersonhoodVerificationResult, PersonhoodVerificationOptions } from './verificationTypes/personhood';

export { AgeVerification, ageVerification } from './verificationTypes/ageVerification';
export type { AgeVerificationResult, AgeVerificationOptions } from './verificationTypes/ageVerification';

export { NationalityVerification, nationalityVerification } from './verificationTypes/nationality';
export type { NationalityVerificationResult, NationalityVerificationOptions } from './verificationTypes/nationality';

export { ResidencyVerification, residencyVerification } from './verificationTypes/residency';
export type { ResidencyVerificationResult, ResidencyVerificationOptions } from './verificationTypes/residency';

export { KYCVerification, kycVerification } from './verificationTypes/kyc';
export type { KYCVerificationResult, KYCVerificationOptions } from './verificationTypes/kyc';

// Re-export common types for convenience
export type { QueryResult, ProofResult } from "@zkpassport/sdk";
export { EU_COUNTRIES, SANCTIONED_COUNTRIES } from "@zkpassport/sdk";