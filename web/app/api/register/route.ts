// Global deduplication map for in-flight requests
const inFlightRequests = new Map<string, NodeJS.Timeout>();

import { NextRequest, NextResponse } from "next/server";
import { validateVerificationRequest } from "../../services/webVerificationService";

export async function POST(request: NextRequest) {
  let requestKey = '';
  let timeoutId: NodeJS.Timeout | null = null;
  
  try {
    console.log("🔍 REGISTER API - STARTING PROXY REQUEST HANDLING");

    const body = await request.json();
    console.log("🔍 REGISTER API - BODY PARSED:", !!body);

    // Server-side deduplication check
    requestKey = `${body.sessionId || 'no-session'}-${body.verificationType || 'personhood'}-${body.proofs?.length || 0}`;
    
    // Check if request is already in progress
    if (inFlightRequests.has(requestKey)) {
      console.log('🚫 SERVER DUPLICATE BLOCKED - Request already in progress:', requestKey);
      return NextResponse.json(
        {
          verified: false,
          message: "Verification already in progress",
          duplicate: true,
        },
        { status: 429 } // Too Many Requests
      );
    }

    // Mark request as in progress
    timeoutId = setTimeout(() => {
      inFlightRequests.delete(requestKey);
      console.log('🧹 CLEANUP - Removed stale request:', requestKey);
    }, 30000); // 30 second timeout
    
    inFlightRequests.set(requestKey, timeoutId);

    // Validate request body before proxying
    const validationResult = validateVerificationRequest(body);

    if (!validationResult.success) {
      // Clean up on validation failure
      if (timeoutId) clearTimeout(timeoutId);
      if (requestKey) inFlightRequests.delete(requestKey);
      
      return NextResponse.json(
        {
          verified: false,
          message: "Invalid request body",
          errors: validationResult.error.errors,
        },
        { status: 400 }
      );
    }

    const { proofs, domain, verificationType = 'personhood' } = validationResult.data;

    // Extract token and session from request URL parameters
    const url = new URL(request.url);
    const token = url.searchParams.get('token');
    const sessionIdFromUrl = url.searchParams.get('session');

    if (!token || !sessionIdFromUrl) {
      return NextResponse.json(
        {
          verified: false,
          message: "Token and session are required in URL parameters",
        },
        { status: 400 }
      );
    }

    console.log("🔍 REGISTER API - PROXYING TO BACKEND");

    // Proxy the request to backend verification endpoint
    const response = await fetch('http://localhost:3001/api/verify/proof', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        proofs,
        sessionId: sessionIdFromUrl,
        token: sessionIdFromUrl, // Use sessionId as the token for backend validation
        domain,
        verificationType,
      }),
    });

    if (!response.ok) {
      console.error('❌ Backend verification failed:', response.status);
      const errorText = await response.text();
      return NextResponse.json(
        {
          verified: false,
          message: `Backend verification failed: ${errorText}`,
        },
        { status: response.status }
      );
    }

    const backendResult = await response.json();
    console.log("✅ REGISTER API - BACKEND RESPONSE RECEIVED");

    return NextResponse.json(backendResult);
  } catch (error) {
    // Clean up on any error
    if (timeoutId) clearTimeout(timeoutId);
    if (requestKey) inFlightRequests.delete(requestKey);
    
    console.error("Web app proxy API error:", error);

    if (process.env.NODE_ENV === 'production') {
      return NextResponse.json(
        {
          verified: false,
          message: "Internal server error",
        },
        { status: 500 }
      );
    } else {
      return NextResponse.json(
        {
          verified: false,
          message: "Internal server error during verification proxy",
          error: error instanceof Error ? error.message : String(error),
        },
        { status: 500 }
      );
    }
  } finally {
    // Always clean up the request tracking
    if (requestKey) {
      const timeout = inFlightRequests.get(requestKey);
      if (timeout) {
        clearTimeout(timeout);
        inFlightRequests.delete(requestKey);
        console.log('🧹 CLEANUP - Completed request:', requestKey);
      }
    }
  }
}

// Legacy implementation removed - kept for reference if needed

export const config = {
  runtime: "nodejs",
};

// Handle preflight requests for CORS
export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}