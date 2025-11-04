// Types from ZKPassport SDK (no static import for ESM compatibility)
// Using any for types to avoid static import issues
export type QueryResult = any;
export type ProofResult = any;

export interface PersonhoodVerificationResult {
  verified: boolean;
  uniqueIdentifier?: string;
  passportFingerprint?: string;
  message: string;
}

export interface PersonhoodVerificationOptions {
  domain: string;
  devMode?: boolean;
}

/**
 * Personhood Verification - Unique ID only
 * Generates ZKPassport request with no information disclosure.
 * Only checks uniqueness without revealing personal info.
 */
export class PersonhoodVerification {
  private zkPassport: any = null; // Use any for dynamic import compatibility

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
   * Verify personhood without disclosing any personal information
   * @param proofs - ZKPassport proofs
   * @param queryResult - Query result from ZKPassport
   * @param options - Verification options
   * @returns Verification result with unique identifier
   */
  async verify(
    proofs: ProofResult[],
    queryResult: QueryResult,
    options: PersonhoodVerificationOptions = { domain: "", devMode: false }
  ): Promise<PersonhoodVerificationResult> {
    try {
      // In development mode, simulate verification
      if (options.devMode) {
        // Generate mock unique identifier for development
        const uniqueIdentifier = `personhood_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;

        return {
          verified: true,
          uniqueIdentifier,
          passportFingerprint: `fingerprint_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`,
          message: "Personhood verified successfully (development mode)",
        };
      }

      // Production verification using ZKPassport SDK
      const zkPassport = await this.getZKPassport(options.domain);
      const { verified, uniqueIdentifier } = await zkPassport.verify({
        proofs,
        queryResult,
        devMode: false,
      });

      return {
        verified,
        uniqueIdentifier,
        message: verified
          ? "Personhood verified successfully"
          : "Personhood verification failed",
      };
    } catch (error) {
      return {
        verified: false,
        message: `Personhood verification error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        passportFingerprint: undefined,
      };
    }
  }

  /**
   * Generate a personhood verification request (no disclosures)
   * @param userId - User identifier for the request
   * @returns Query for personhood verification
   */
  generateRequest(userId: string) {
    // Personhood verification requires no specific disclosures
    // The ZKPassport SDK will handle generating the appropriate query
    return {
      type: 'personhood',
      userId,
      disclosures: [], // No personal information disclosed
    };
  }
}

// Export singleton instance for convenience
export const personhoodVerification = new PersonhoodVerification();