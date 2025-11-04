import { z } from "zod";
import { ProofResult } from "@zkpassport/sdk";
import { VerificationType } from "../../../shared/src/types/verification";

interface VerificationRequestBody {
  proofs: ProofResult[];
  sessionId: string;
  token: string;
  domain: string;
  verificationType?: VerificationType;
}

// 64-character hexadecimal string validation regex
const sessionIdRegex = /^[a-f0-9]{64}$/i;

// Request validation schema
const verificationRequestSchema = z.object({
  proofs: z.array(z.unknown()).min(1, "At least one proof is required"),
  sessionId: z.string().min(1, "Session ID is required").regex(sessionIdRegex, "Session ID must be a valid 64-character hexadecimal string"),
  token: z.string().min(1, "Token is required").regex(sessionIdRegex, "Token must be a valid 64-character hexadecimal string"),
  domain: z.string().min(1, "Domain is required"),
  verificationType: z.enum(['personhood', 'age', 'nationality', 'residency', 'kyc']).optional().default('personhood'),
});

export interface VerificationResponse {
  verified: boolean;
  uniqueIdentifier?: string;
  message?: string;
  error?: string;
}

export const validateVerificationRequest = (body: VerificationRequestBody) => {
  return verificationRequestSchema.safeParse(body);
};