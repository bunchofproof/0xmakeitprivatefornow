import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Rate limiting removed for Edge Runtime compatibility

// ===================================================================
// PRODUCTION STARTUP VALIDATION - SECURITY FAIL-SAFE
// ===================================================================

const NODE_ENV = process.env.NODE_ENV || 'development';

// CRITICAL: Validate CORS configuration at startup in production
if (NODE_ENV === 'production') {
  const allowedOrigins = process.env.ALLOWED_ORIGINS;
  
  if (!allowedOrigins) {
    console.error('FATAL: ALLOWED_ORIGINS environment variable is required in production!');
    console.error('Security Risk: Application cannot start without proper CORS configuration.');
    console.error('Please set: ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com');
    console.error('Example: ALLOWED_ORIGINS=https://example.com');
    throw new Error('FATAL: ALLOWED_ORIGINS environment variable is required in production!');
  }
  
  // Security validation: Ensure no wildcards in production
  const origins = allowedOrigins.split(',').map(origin => origin.trim());
  if (origins.includes('*')) {
    console.error('FATAL: Wildcard (*) is strictly forbidden in ALLOWED_ORIGINS for production!');
    console.error('Security Risk: Wildcard allows ANY origin to access your API.');
    console.error('Please specify explicit origins only.');
    console.error(`Current value: "${allowedOrigins}"`);
    console.error('Example: ALLOWED_ORIGINS=https://example.com,https://app.example.com');
    throw new Error('FATAL: Wildcard (*) is strictly forbidden in ALLOWED_ORIGINS for production!');
  }
  
  // Validate origin format (basic HTTPS check)
  const invalidOrigins = origins.filter(origin => !origin.startsWith('https://') && !origin.startsWith('http://'));
  if (invalidOrigins.length > 0) {
    console.error('FATAL: Invalid origin(s) detected in ALLOWED_ORIGINS!');
    console.error('All origins must include protocol (http:// or https://)');
    console.error(`Invalid origins: ${invalidOrigins.join(', ')}`);
    console.error(`Current value: "${allowedOrigins}"`);
    throw new Error('FATAL: Invalid origin(s) detected in ALLOWED_ORIGINS!');
  }
  
  console.log(`✅ Production CORS configuration validated: ${origins.length} allowed origin(s)`);
}

// Generate secure nonce for inline scripts (all environments) - Edge Runtime compatible
const scriptNonce = globalThis.crypto?.getRandomValues ?
  btoa(String.fromCharCode(...globalThis.crypto.getRandomValues(new Uint8Array(32)))) :
  'fallback-nonce-32-chars-minimum-length';

// Environment-specific security headers configuration
const securityHeaders: Record<string, string> = {
  // Core Security Headers (common to all environments)
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block; report=/api/security/xss-report",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  
  // Additional Security Headers (common to all environments)
  "X-Permitted-Cross-Domain-Policies": "none",
  "X-Download-Options": "noopen",
  "X-DNS-Prefetch-Control": "off",
  "X-Response-Time": "", // Will be set dynamically
  
  // Cross-Origin Security Headers (environment-specific with IP address compatibility)
  "Cross-Origin-Opener-Policy": NODE_ENV === 'production' ? 'same-origin' : 'unsafe-none',
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Resource-Policy": "same-origin",
  
  // Content Security Policy (DUAL POLICIES BASED ON ENVIRONMENT)
  ...(NODE_ENV === 'production' ? {
    // PRODUCTION MODE: Strict CSP WITHOUT 'unsafe-inline'
    "Content-Security-Policy": [
      "default-src 'self'",
      `script-src 'self' 'nonce-${scriptNonce}'`,
      "style-src 'self'",  // No 'unsafe-inline' in production
      "img-src 'self' data: https:",
      "font-src 'self' data:",
      "connect-src 'self' https://*.zkpassport.id wss://bridge.zkpassport.id https://eth-sepolia.g.alchemy.com https://crs.aztec.network data: blob:",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-src 'none'",
      "media-src 'none'",
      "worker-src 'self'",
      "manifest-src 'self'",
      "upgrade-insecure-requests",
      "block-all-mixed-content",
      "require-trusted-types-for 'script'"
    ].join("; ")
  } : {
    // DEVELOPMENT MODE: Relaxed CSP WITH 'unsafe-inline' and 'unsafe-eval'
    "Content-Security-Policy": [
      "default-src 'self'",
      `script-src 'self' 'nonce-${scriptNonce}' 'unsafe-eval' 'unsafe-inline'`,  // Allow inline scripts in development
      "style-src 'self' 'unsafe-inline'",  // Allow inline styles in development
      "img-src 'self' data: https:",
      "font-src 'self' data:",
      "connect-src 'self' https://*.zkpassport.id wss://bridge.zkpassport.id https://eth-sepolia.g.alchemy.com https://crs.aztec.network data: blob:",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-src 'none'",
      "media-src 'none'",
      "worker-src 'self'",
      "manifest-src 'self'",
      // "upgrade-insecure-requests",  // REMOVED for IP address compatibility
      "require-trusted-types-for 'script'"
    ].join("; ")
  }),

  // Enhanced Permissions Policy for ZK Discord Verification (common to all environments)
  // Only includes widely supported and standard features to avoid warnings
  "Permissions-Policy": [
    "accelerometer=()",
    "autoplay=()",
    "camera=()",
    "cross-origin-isolated=()",
    "display-capture=()",
    "encrypted-media=()",
    "fullscreen=(self)",
    "geolocation=()",
    "gyroscope=()",
    "magnetometer=()",
    "microphone=()",
    "midi=()",
    "payment=()",
    "picture-in-picture=()",
    "publickey-credentials-get=()",
    "screen-wake-lock=()",
    "sync-xhr=()",
    "usb=()",
    "web-share=()",
    "xr-spatial-tracking=()"
  ].join(", "),
  
  // Trusted Types Policy for additional XSS protection (common to all environments)
  "Trusted-Types-Policy": [
    "allow-duplicates",
    "default 'self'",
    "payment-handler 'self'"
  ].join("; "),
  
  // Reporting and Monitoring Headers (common to all environments)
  "Reporting-Endpoints": `default="${NODE_ENV === 'production' ? '/api/security/reports' : '/dev-api/security/reports'}"`,
  "NEL": JSON.stringify({
    report_to: 'default',
    max_age: 2592000, // 30 days
    include_subdomains: true,
    failure_fraction: 0.1
  }).replace(/"/g, "'")
};

// Transport security headers - PRODUCTION ONLY (NO HSTS in development)
if (NODE_ENV === 'production') {
  securityHeaders["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload; report-uri=/api/security/hsts-report";
  securityHeaders["Expect-CT"] = "max-age=86400, enforce, report-uri=/api/security/ct-report";
  
  // Remove server information in production
  securityHeaders["Server"] = "";
}
// IMPORTANT: NO HSTS headers in development mode to prevent browser caching issues

/**
 * Enhanced Universal Rate Limiting for Web Interface
 */
export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Apply security headers to all routes
  const response = NextResponse.next();

  // Add nonce to response headers for Next.js to use
  if (scriptNonce) {
    response.headers.set('x-nonce', scriptNonce);
  }

  Object.entries(securityHeaders).forEach(([key, value]) => {
    response.headers.set(key, value);
  });

  // API-specific security headers (rate limiting removed for Edge Runtime compatibility)
  if (pathname.startsWith("/api/")) {
    // Additional API-specific security headers
    response.headers.set("Cache-Control", "no-cache, no-store, must-revalidate");
    response.headers.set("Pragma", "no-cache");
    response.headers.set("Expires", "0");
  }

  // SECURE CORS CONFIGURATION
  let corsOrigin;
  if (NODE_ENV === "production") {
    // Production: Use only specific origins (no wildcards allowed)
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(",").map(origin => origin.trim()) || [];
    const origin = request.headers.get("origin");
    
    // Strict production validation: origin must be in allowed list
    if (origin && allowedOrigins.includes(origin)) {
      corsOrigin = origin;
    } else {
      corsOrigin = null; // Deny access
    }
  } else {
    // Development: Allow wildcard for local development
    corsOrigin = "*";
  }

  // CORS handling for API routes
  if (pathname.startsWith("/api/")) {
    // Handle preflight requests
    if (request.method === "OPTIONS") {
      return new NextResponse(null, {
        status: corsOrigin ? 200 : 403,
        headers: {
          ...(corsOrigin && {
            "Access-Control-Allow-Origin": corsOrigin,
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Max-Age": "86400", // 24 hours
          }),
          "Vary": "Origin",
        },
      });
    }

    // Set CORS headers for actual requests
    if (corsOrigin) {
      response.headers.set("Access-Control-Allow-Origin", corsOrigin);
      if (corsOrigin !== "*") {
        response.headers.set("Access-Control-Allow-Credentials", "true");
      }
      response.headers.set("Vary", "Origin");
    }
    // If corsOrigin is null, no CORS headers are set (denied access)
  }

  return response;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder files
     */
    "/((?!_next/static|_next/image|favicon.ico|public/).*)",
  ],
};