import { config } from '../config';
import { logger } from '../utils/logger';
import { prisma } from '../utils/database';
import { generateMockVerificationResult, generateMockUniqueIdentifier } from '../utils/mockProofService';
import {
  personhoodVerification,
  ageVerification,
  kycVerification,
  nationalityVerification,
  residencyVerification
} from '@shared/services/index.js';

interface VerificationResult {
  verified: boolean;
  uniqueIdentifier?: string;
  passportFingerprint?: string;
  message: string;
  details?: {
    ageVerified?: boolean;
    sanctionsVerified?: boolean;
    personhoodVerified?: boolean;
    nationalityVerified?: boolean;
    residencyVerified?: boolean;
    kycVerified?: boolean;
    kycData?: {
      nationality?: string;
      birthdate?: string;
      fullname?: string;
      expiry_date?: string;
      document_number?: string;
    };
  };
}

interface ProofData {
  type?: string;
  data?: any;
}

class ZKVerificationService {

  constructor() {
    // Initialize SDK asynchronously - called from verification methods as needed
  }


  /**
    * Verify ZKPassport proofs with type-specific validation logic
    */
   async verifyProofs(proofs: ProofData[], domain: string, verificationType: string = 'personhood'): Promise<VerificationResult> {
     try {
       console.log('--- RAW PROOFS RECEIVED ---');
       console.log(JSON.stringify(proofs, null, 2));
       console.log('---------------------------');

       logger.info(`Verifying ${proofs.length} proofs for domain: ${domain}, type: ${verificationType}`);

       // Route to type-specific verification logic
       switch (verificationType) {
         case 'personhood':
           return await this.verifyPersonhood(proofs, domain);

         case 'age':
           return await this.verifyAge(proofs, domain);

         case 'nationality':
           return await this.verifyNationality(proofs, domain);

         case 'residency':
           return await this.verifyResidency(proofs, domain);

         case 'kyc':
           return await this.verifyKYC(proofs, domain);

         default:
           return {
             verified: false,
             message: `Unsupported verification type: ${verificationType}. Supported types: personhood, age, nationality, residency, kyc`,
           };
       }

     } catch (error) {
       logger.error('Proof verification error:', error);

       return {
         verified: false,
         message: `Verification error: ${error instanceof Error ? error.message : 'Unknown error'}`,
       };
     }
   }





  /**
   * Verify personhood - only validate uniqueness, no personal data checks
   */
  private async verifyPersonhood(proofs: ProofData[], domain: string): Promise<VerificationResult> {
    try {
      logger.info('verifyPersonhood: devMode =', config.zkPassport.devMode);
      if (config.zkPassport.devMode) {
        logger.info('Using mock verification for dev mode');
        // Generate mock verification result for development
        const verificationResult = generateMockVerificationResult(proofs);
        return {
          verified: true,
          uniqueIdentifier: verificationResult.uniqueIdentifier,
          passportFingerprint: verificationResult.passportFingerprint,
          message: 'Personhood verified successfully (development mode)',
          details: {
            personhoodVerified: true,
          },
        };
      }

      // Use shared personhood verification service
      const result = await personhoodVerification.verify(proofs as any, {} as any, { domain, devMode: false });

      // Ensure we have valid identifiers for production
      if (!result.uniqueIdentifier) {
        throw new Error('Personhood verification failed to return unique identifier');
      }

      return {
        verified: result.verified,
        uniqueIdentifier: result.uniqueIdentifier,
        passportFingerprint: result.passportFingerprint,
        message: result.message,
        details: {
          personhoodVerified: result.verified,
        },
      };
    } catch (error) {
      logger.error('Personhood verification error:', error);
      // In development mode, fall back to mock result even on error
      if (config.zkPassport.devMode) {
        logger.warn('Falling back to mock verification result due to error in dev mode');
        const verificationResult = generateMockVerificationResult(proofs);
        return {
          verified: true,
          uniqueIdentifier: verificationResult.uniqueIdentifier,
          passportFingerprint: verificationResult.passportFingerprint,
          message: 'Personhood verified successfully (development mode fallback)',
          details: {
            personhoodVerified: true,
          },
        };
      }
      return {
        verified: false,
        message: `Personhood verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: {
          personhoodVerified: false,
        },
      };
    }
  }

  /**
   * Verify age - only validate age-related queries, no uniqueness or other checks
   */
  private async verifyAge(proofs: ProofData[], domain: string): Promise<VerificationResult> {
    try {
      if (config.zkPassport.devMode) {
        // Generate mock verification result for development
        const verificationResult = generateMockVerificationResult();
        return {
          verified: true,
          uniqueIdentifier: verificationResult.uniqueIdentifier,
          passportFingerprint: verificationResult.passportFingerprint,
          message: 'Age verified successfully (development mode)',
          details: {
            ageVerified: true,
          },
        };
      }

      // Use shared age verification service with default min age of 18
      const result = await ageVerification.verify(proofs as any, {} as any, { domain, minAge: 18, devMode: false });

      return {
        verified: result.verified,
        uniqueIdentifier: generateMockUniqueIdentifier(), // Age verification doesn't provide uniqueness
        message: result.message,
        details: {
          ageVerified: result.ageVerified,
          personhoodVerified: result.verified, // Age verification implies personhood
        },
      };
    } catch (error) {
      logger.error('Age verification error:', error);
      return {
        verified: false,
        message: `Age verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: {
          ageVerified: false,
        },
      };
    }
  }

  /**
   * Verify nationality - only validate nationality queries, no age or other checks
   */
  private async verifyNationality(proofs: ProofData[], domain: string): Promise<VerificationResult> {
    try {
      if (config.zkPassport.devMode) {
        // Generate mock verification result for development
        const verificationResult = generateMockVerificationResult();
        return {
          verified: true,
          uniqueIdentifier: verificationResult.uniqueIdentifier,
          passportFingerprint: verificationResult.passportFingerprint,
          message: 'Nationality verified successfully (development mode)',
          details: {
            nationalityVerified: true,
            personhoodVerified: true, // Nationality verification implies personhood
          },
        };
      }

      // Use shared nationality verification service
      const result = await nationalityVerification.verify(proofs as any, {} as any, { domain, devMode: false });

      return {
        verified: result.verified,
        uniqueIdentifier: generateMockUniqueIdentifier(), // Nationality verification doesn't provide uniqueness
        message: result.message,
        details: {
          nationalityVerified: result.nationalityVerified,
          personhoodVerified: result.verified, // Nationality verification implies personhood
        },
      };
    } catch (error) {
      logger.error('Nationality verification error:', error);
      return {
        verified: false,
        message: `Nationality verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: {
          nationalityVerified: false,
        },
      };
    }
  }

  /**
   * Verify residency - only validate residency queries, no citizenship or other checks
   */
  private async verifyResidency(proofs: ProofData[], domain: string): Promise<VerificationResult> {
    try {
      if (config.zkPassport.devMode) {
        // Generate mock verification result for development
        const verificationResult = generateMockVerificationResult();
        return {
          verified: true,
          uniqueIdentifier: verificationResult.uniqueIdentifier,
          passportFingerprint: verificationResult.passportFingerprint,
          message: 'Residency verified successfully (development mode)',
          details: {
            residencyVerified: true,
            personhoodVerified: true, // Residency verification implies personhood
          },
        };
      }

      // Use shared residency verification service
      const result = await residencyVerification.verify(proofs as any, {} as any, { domain, devMode: false });

      return {
        verified: result.verified,
        uniqueIdentifier: generateMockUniqueIdentifier(), // Residency verification doesn't provide uniqueness
        message: result.message,
        details: {
          residencyVerified: result.residencyVerified,
          personhoodVerified: result.verified, // Residency verification implies personhood
        },
      };
    } catch (error) {
      logger.error('Residency verification error:', error);
      return {
        verified: false,
        message: `Residency verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: {
          residencyVerified: false,
        },
      };
    }
  }

  /**
   * Verify KYC - only validate KYC data, no other verification checks
   */
  private async verifyKYC(proofs: ProofData[], domain: string): Promise<VerificationResult> {
    try {
      if (config.zkPassport.devMode) {
        // Generate mock verification result for development
        const verificationResult = generateMockVerificationResult();
        const mockKycData = {
          nationality: "US",
          birthdate: "1990-01-01",
          fullname: "John Doe",
          expiry_date: "2030-01-01",
          document_number: "A123456789",
        };

        return {
          verified: true,
          uniqueIdentifier: verificationResult.uniqueIdentifier,
          passportFingerprint: verificationResult.passportFingerprint,
          message: 'KYC verified successfully (development mode)',
          details: {
            kycVerified: true,
            personhoodVerified: true, // KYC verification implies personhood
            kycData: mockKycData,
          },
        };
      }

      // Use shared KYC verification service
      const result = await kycVerification.verify(proofs as any, {} as any, { domain, devMode: false });

      return {
        verified: result.verified,
        uniqueIdentifier: generateMockUniqueIdentifier(), // KYC verification doesn't provide uniqueness
        message: result.message,
        details: {
          kycVerified: result.kycVerified,
          personhoodVerified: result.verified, // KYC verification implies personhood
          kycData: result.kycData,
        },
      };
    } catch (error) {
      logger.error('KYC verification error:', error);
      return {
        verified: false,
        message: `KYC verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: {
          kycVerified: false,
        },
      };
    }
  }




  /**
   * Check if a unique identifier already exists in database
   */
  async checkExistingVerification(uniqueIdentifier: string): Promise<boolean> {
    try {
      const existing = await prisma.adminVerification.findUnique({
        where: { uniqueIdentifier },
      });

      return !!existing;
    } catch (error) {
      logger.error('Error checking existing verification:', error);
      return false;
    }
  }

  /**
   * Get verification details by unique identifier
   */
  async getVerificationByIdentifier(uniqueIdentifier: string) {
    try {
      return await prisma.adminVerification.findUnique({
        where: { uniqueIdentifier },
        include: {
          history: {
            orderBy: { timestamp: 'desc' },
            take: 10,
          },
        },
      });
    } catch (error) {
      logger.error('Error getting verification by identifier:', error);
      return null;
    }
  }
}

// Export singleton instance
export const zkVerificationService = new ZKVerificationService();