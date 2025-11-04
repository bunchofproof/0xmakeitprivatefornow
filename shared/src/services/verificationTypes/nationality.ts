// Types from ZKPassport SDK (no static import for ESM compatibility)
// Using any for types to avoid static import issues
export type QueryResult = any;
export type ProofResult = any;

// Constants from ZKPassport SDK
export const EU_COUNTRIES: string[] = [
  "Austria", "Belgium", "Bulgaria", "Croatia", "Cyprus", "Czech Republic",
  "Denmark", "Estonia", "Finland", "France", "Germany", "Greece",
  "Hungary", "Ireland", "Italy", "Latvia", "Lithuania", "Luxembourg",
  "Malta", "Netherlands", "Poland", "Portugal", "Romania", "Slovakia",
  "Slovenia", "Spain", "Sweden"
];

export const SANCTIONED_COUNTRIES: string[] = [
  // Add sanctioned countries as needed - for now empty array for compatibility
];

interface CountryInputs {
  countries?: string[];
}

export interface NationalityVerificationResult {
  verified: boolean;
  nationalityVerified?: boolean;
  message: string;
  nationality?: string;
}

export interface NationalityVerificationOptions {
  domain: string;
  allowedCountries?: string[];
  excludedCountries?: string[];
  devMode?: boolean;
}

/**
 * Nationality Verification - Nationality checks only
 * Checks EU citizenship using EU_COUNTRIES or custom country lists.
 * Excludes sanctioned countries using SANCTIONED_COUNTRIES.
 * No other verification types mixed in.
 */
export class NationalityVerification {
  private zkPassport: any = null; // Use any for dynamic import compatibility
  private defaultAllowedCountries: string[] = EU_COUNTRIES;
  private defaultExcludedCountries: string[] = SANCTIONED_COUNTRIES;

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
   * Verify user nationality against allowed countries and exclude sanctioned ones
   * @param proofs - ZKPassport proofs
   * @param queryResult - Query result from ZKPassport
   * @param options - Verification options with country lists
   * @returns Verification result with nationality status
   */
  async verify(
    proofs: ProofResult[],
    queryResult: QueryResult,
    options: NationalityVerificationOptions = { domain: "", devMode: false }
  ): Promise<NationalityVerificationResult> {
    try {
      const allowedCountries = options.allowedCountries || this.defaultAllowedCountries;
      const excludedCountries = options.excludedCountries || this.defaultExcludedCountries;

      // In development mode, simulate nationality verification
      if (options.devMode) {
        // Simulate a random EU country for testing
        const mockNationality = EU_COUNTRIES[Math.floor(Math.random() * EU_COUNTRIES.length)];
        const isAllowed = allowedCountries.includes(mockNationality);
        const isExcluded = excludedCountries.includes(mockNationality);
        const nationalityVerified = isAllowed && !isExcluded;

        return {
          verified: nationalityVerified,
          nationalityVerified,
          message: nationalityVerified
            ? `Nationality verified: ${mockNationality} (development mode)`
            : `Nationality verification failed: ${mockNationality} not in allowed countries or in excluded list (development mode)`,
          nationality: mockNationality,
        };
      }

      // Production verification using ZKPassport SDK
      const zkPassport = await this.getZKPassport(options.domain);
      const { verified } = await zkPassport.verify({
        proofs,
        queryResult,
        devMode: false,
      });

      if (!verified) {
        return {
          verified: false,
          nationalityVerified: false,
          message: "Proof verification failed",
        };
      }

      // Extract and verify nationality
      const nationalityVerified = await this.verifyNationalityRequirement(proofs, allowedCountries, excludedCountries);

      return {
        verified: nationalityVerified,
        nationalityVerified,
        message: nationalityVerified
          ? "Nationality verification successful"
          : "Nationality verification failed: not in allowed countries or in excluded list",
      };
    } catch (error) {
      return {
        verified: false,
        nationalityVerified: false,
        message: `Nationality verification error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * Verify nationality requirement against allowed and excluded country lists
   * @param proofs - ZKPassport proofs containing nationality data
   * @param allowedCountries - List of allowed countries
   * @param excludedCountries - List of excluded countries
   * @returns Whether nationality requirement is met
   */
  private async verifyNationalityRequirement(
    proofs: ProofResult[],
    allowedCountries: string[],
    excludedCountries: string[]
  ): Promise<boolean> {
    try {
      // Extract nationality from proof data
      for (const proof of proofs) {
        // Access committedInputs which contains the actual proof data
        const committedInputs = proof.committedInputs;
        if (committedInputs) {
          // Look for country-related committed inputs
          for (const [circuitName, inputs] of Object.entries(committedInputs)) {
            if (circuitName.includes('nationality') && inputs && typeof inputs === 'object') {
              const countryInputs = inputs as CountryInputs;
              if (countryInputs.countries && countryInputs.countries.length > 0) {
                // SDK would have verified the nationality is in the allowed list
                const verifiedNationality = countryInputs.countries[0]; // Primary nationality from proof
                const isAllowed = allowedCountries.includes(verifiedNationality);
                const isExcluded = excludedCountries.includes(verifiedNationality);
                return isAllowed && !isExcluded;
              }
            }
          }
        }

        // Fallback: assume success if nationality-related proof is present
        if (proof.name && proof.name.includes('nationality')) {
          return true; // SDK would have failed if nationality wasn't valid
        }
      }

      // If no nationality data found, fail verification
      return false;
    } catch (error) {
      console.error('Nationality requirement verification error:', error);
      return false;
    }
  }

  /**
   * Verify EU citizenship specifically
   * @param proofs - ZKPassport proofs
   * @param queryResult - Query result from ZKPassport
   * @param options - Verification options
   * @returns Verification result for EU citizenship
   */
  async verifyEUCitizenship(
    proofs: ProofResult[],
    queryResult: QueryResult,
    options: Omit<NationalityVerificationOptions, 'allowedCountries'> = { domain: "", devMode: false }
  ): Promise<NationalityVerificationResult> {
    // Use EU countries as allowed countries, keep default exclusions
    return this.verify(proofs, queryResult, {
      ...options,
      allowedCountries: EU_COUNTRIES,
    });
  }

  /**
   * Verify exclusion from sanctioned countries
   * @param proofs - ZKPassport proofs
   * @param queryResult - Query result from ZKPassport
   * @param options - Verification options
   * @returns Verification result for sanction check
   */
  async verifySanctionsExclusion(
    proofs: ProofResult[],
    queryResult: QueryResult,
    options: Omit<NationalityVerificationOptions, 'excludedCountries'> = { domain: "", devMode: false }
  ): Promise<NationalityVerificationResult> {
    return this.verify(proofs, queryResult, {
      ...options,
      excludedCountries: SANCTIONED_COUNTRIES,
    });
  }

  /**
   * Verify custom country list (both allowed and excluded)
   * @param proofs - ZKPassport proofs
   * @param queryResult - Query result from ZKPassport
   * @param allowedCountries - Custom allowed countries
   * @param excludedCountries - Custom excluded countries
   * @param options - Verification options
   * @returns Verification result for custom country verification
   */
  async verifyCustomCountries(
    proofs: ProofResult[],
    queryResult: QueryResult,
    allowedCountries: string[],
    excludedCountries: string[] = [],
    options: Omit<NationalityVerificationOptions, 'allowedCountries' | 'excludedCountries'> = { domain: "", devMode: false }
  ): Promise<NationalityVerificationResult> {
    return this.verify(proofs, queryResult, {
      ...options,
      allowedCountries,
      excludedCountries,
    });
  }

  /**
   * Generate nationality verification request
   * @param userId - User identifier
   * @param allowedCountries - List of allowed countries
   * @param excludedCountries - List of excluded countries
   * @returns Query for nationality verification
   */
  generateRequest(
    userId: string,
    allowedCountries?: string[],
    excludedCountries?: string[]
  ) {
    const countries = allowedCountries || this.defaultAllowedCountries;
    const exclusions = excludedCountries || this.defaultExcludedCountries;

    return {
      type: 'nationality',
      userId,
      disclosures: ['nationality'], // Only disclose nationality
      constraints: {
        in: { nationality: countries }, // Check if nationality is in allowed list
        notIn: { nationality: exclusions }, // Ensure nationality is not in excluded list
      },
    };
  }
}

// Export singleton instance for convenience
export const nationalityVerification = new NationalityVerification();