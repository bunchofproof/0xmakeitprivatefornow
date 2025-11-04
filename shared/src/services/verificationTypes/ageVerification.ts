// Types from ZKPassport SDK (no static import for ESM compatibility)
// Using any for types to avoid static import issues
export type QueryResult = any;
export type ProofResult = any;


export interface AgeVerificationResult {
  verified: boolean;
  ageVerified?: boolean;
  message: string;
  age?: number;
}

export interface AgeVerificationOptions {
  domain: string;
  minAge?: number;
  devMode?: boolean;
}

/**
 * Age Verification - Age checks only
 * Verifies if user is over a specified age (default 18) or within age range.
 * Uses gte("age", minAge) query pattern.
 */
export class AgeVerification {
  private zkPassport: any = null; // Use any for dynamic import compatibility
  private defaultMinAge: number = 18;

  private async getZKPassport(domain: string) {
    if (!this.zkPassport) {
      try {
        const { ZKPassport } = await import("@zkpassport/sdk");
        this.zkPassport = new ZKPassport(domain);
      } catch (error) {
        throw new Error(`Failed to load ZKPassport SDK: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
    return this.zkPassport;
  }

  /**
   * Verify user is at least the minimum age
   * @param proofs - ZKPassport proofs
   * @param queryResult - Query result from ZKPassport
   * @param options - Verification options with minAge
   * @returns Verification result with age verification status
   */
  async verify(
    proofs: ProofResult[],
    queryResult: QueryResult,
    options: AgeVerificationOptions = { domain: "", devMode: false }
  ): Promise<AgeVerificationResult> {
    try {
      const minAge = options.minAge || this.defaultMinAge;

      // In development mode, simulate age verification
      if (options.devMode) {
        const mockAge = Math.floor(Math.random() * 50) + 18; // Random age 18-67 for testing
        const ageVerified = mockAge >= minAge;

        return {
          verified: ageVerified,
          ageVerified,
          message: ageVerified
            ? `Age verified: ${mockAge} >= ${minAge} (development mode)`
            : `Age verification failed: ${mockAge} < ${minAge} (development mode)`,
          age: mockAge,
        };
      }

      // Production verification using ZKPassport SDK constraint validation
      const zkPassport = await this.getZKPassport(options.domain);
      const verificationResult = await zkPassport.verify({
        proofs,
        queryResult,
        devMode: false,
      });

      if (!verificationResult.verified) {
        return {
          verified: false,
          ageVerified: false,
          message: "Proof verification failed",
        };
      }

      // Use SDK constraint validation result
      const ageVerified = (verificationResult as any).result?.age?.gte?.result === true;

      return {
        verified: ageVerified,
        ageVerified,
        message: ageVerified
          ? `Age verification successful: >= ${minAge}`
          : `Age verification failed: < ${minAge}`,
      };
    } catch (error) {
      return {
        verified: false,
        ageVerified: false,
        message: `Age verification error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }


  /**
   * Verify age range (e.g., 18-25)
   * @param proofs - ZKPassport proofs
   * @param minAge - Minimum age
   * @param maxAge - Maximum age
   * @returns Verification result for age range
   */
  async verifyAgeRange(
    proofs: ProofResult[],
    queryResult: QueryResult,
    minAge: number,
    maxAge: number,
    options: Omit<AgeVerificationOptions, 'minAge'> = { domain: "", devMode: false }
  ): Promise<AgeVerificationResult> {
    try {
      // In development mode, simulate age range verification
      if (options.devMode) {
        const mockAge = Math.floor(Math.random() * 50) + 18;
        const ageVerified = mockAge >= minAge && mockAge <= maxAge;

        return {
          verified: ageVerified,
          ageVerified,
          message: ageVerified
            ? `Age range verified: ${mockAge} in [${minAge}-${maxAge}] (development mode)`
            : `Age range verification failed: ${mockAge} not in [${minAge}-${maxAge}] (development mode)`,
          age: mockAge,
        };
      }

      // Production verification using ZKPassport SDK with range constraints
      const zkPassport = await this.getZKPassport(options.domain);
      const verificationResult = await zkPassport.verify({
        proofs,
        queryResult,
        devMode: false,
      });

      if (!verificationResult.verified) {
        return {
          verified: false,
          ageVerified: false,
          message: "Proof verification failed",
        };
      }

      // Use SDK constraint validation result for range
      const ageVerified = (verificationResult as any).result?.age?.range?.result === true;

      return {
        verified: ageVerified,
        ageVerified,
        message: ageVerified
          ? `Age range verification successful: within [${minAge}-${maxAge}]`
          : `Age range verification failed: not within [${minAge}-${maxAge}]`,
      };
    } catch (error) {
      return {
        verified: false,
        ageVerified: false,
        message: `Age range verification error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }


  /**
   * Generate age verification request
   * @param userId - User identifier
   * @param minAge - Minimum age requirement
   * @returns Query for age verification
   */
  generateRequest(userId: string, minAge?: number) {
    const ageThreshold = minAge || this.defaultMinAge;

    return {
      type: 'age',
      userId,
      disclosures: ['age'], // Only disclose age for verification
      constraints: {
        gte: { age: ageThreshold }, // gte("age", minAge) pattern
      },
    };
  }
}

// Export singleton instance for convenience
export const ageVerification = new AgeVerification();