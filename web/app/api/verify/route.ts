import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";

// Token validation schema
const tokenQuerySchema = z.object({
  token: z.string().min(1, "Token is required"),
});

async function validateTokenFromBackend(token: string): Promise<{
  valid: boolean;
  sessionId?: string;
  discordUserId?: string;
  expiresAt?: Date;
  message?: string;
}> {
  try {
    // Call backend API for token validation
    const response = await fetch(`http://localhost:3001/api/verify/status/${token}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json();
      return {
        valid: false,
        message: errorData.message || `Backend validation failed: ${response.status}`,
      };
    }

    const data = await response.json();

    if (!data.valid) {
      return {
        valid: false,
        message: data.message || "Token validation failed",
      };
    }

    return {
      valid: true,
      sessionId: data.sessionId,
      discordUserId: data.discordUserId,
      expiresAt: data.expiresAt ? new Date(data.expiresAt) : undefined,
      message: data.message || "Token is valid",
    };
  } catch (error) {
    console.error("Backend validation error:", error);
    return {
      valid: false,
      message: "Backend service unavailable",
    };
  }
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const token = searchParams.get("token");

    // Validate query parameters
    const validationResult = tokenQuerySchema.safeParse({ token });

    if (!validationResult.success) {
      return NextResponse.json(
        {
          valid: false,
          message: "Invalid request parameters",
          errors: validationResult.error.errors,
        },
        { status: 400 }
      );
    }

    // Validate token against backend
    const tokenValidation = await validateTokenFromBackend(validationResult.data.token);

    if (!tokenValidation.valid) {
      return NextResponse.json(
        {
          valid: false,
          message: tokenValidation.message || "Invalid or expired token",
        },
        { status: 401 }
      );
    }

    // Return session information for the frontend
    return NextResponse.json({
      valid: true,
      sessionId: tokenValidation.sessionId,
      discordUserId: tokenValidation.discordUserId,
      expiresAt: tokenValidation.expiresAt,
      message: "Token is valid. You can proceed with verification.",
    });

  } catch (error) {
    console.error("Token validation error:", error);

    return NextResponse.json(
      {
        valid: false,
        message: "Internal server error during token validation",
      },
      { status: 500 }
    );
  }
}

// Handle preflight requests for CORS
export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}
