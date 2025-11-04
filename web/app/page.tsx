"use client";

import { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { WebInputValidator } from "../lib/validation";

function HomeContent() {
  const [token, setToken] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();
  const searchParams = useSearchParams();

  // Check for verification parameters on page load and redirect if present
  useEffect(() => {
    const tokenParam = searchParams.get("token");
    const sessionParam = searchParams.get("session");
    const typeParam = searchParams.get("type");

    // Validate parameters before processing
    if (tokenParam && sessionParam) {
      const params = new URLSearchParams();
      params.append("token", tokenParam);
      params.append("session", sessionParam);
      if (typeParam) params.append("type", typeParam);

      const validation = WebInputValidator.validateSearchParams(params);

      if (!validation.isValid) {
        // Redirect to error page with specific error type
        router.replace(`/error?type=invalid_parameters&message=${encodeURIComponent(validation.error || 'Invalid parameters')}`);
        return;
      }

      // Only redirect if parameters are valid
      router.replace(`/verify?token=${encodeURIComponent(tokenParam)}&session=${encodeURIComponent(sessionParam)}${typeParam ? `&type=${encodeURIComponent(typeParam)}` : ''}`);
    }
  }, [searchParams, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    // Validate token using enhanced validation
    const tokenValidation = WebInputValidator.validateToken(token);

    if (!tokenValidation.isValid) {
      setError(tokenValidation.error || "Invalid token format");
      setIsLoading(false);
      return;
    }

    // Check client-side rate limiting
    if (!WebInputValidator.checkClientRateLimit('token_validation', 5)) {
      setError("Too many validation attempts. Please wait a moment before trying again.");
      setIsLoading(false);
      return;
    }

    try {
      const response = await fetch(`/api/verify?token=${encodeURIComponent(tokenValidation.value!)}`);
      
      if (response.ok) {
        router.push(`/verify?token=${encodeURIComponent(tokenValidation.value!)}`);
      } else {
        const errorData = await response.json();
        setError(errorData.message || "Invalid or expired token");
      }
    } catch (err) {
      setError("Failed to validate token. Please try again.");
      console.error("Token validation error:", err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div className="verification-card">
          <div className="text-center">
            <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
              Discord Admin Verification
            </h2>
            <p className="text-gray-600 dark:text-gray-400 mb-8">
              Enter your verification token to begin the ZKPassport verification process.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="token" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Verification Token
              </label>
              <input
                id="token"
                type="text"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="Enter your verification token"
                disabled={isLoading}
              />
            </div>

            {error && (
              <div className="status-message status-error">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading}
              className="w-full button-primary disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
            >
              {isLoading ? (
                <>
                  <div className="loading-spinner mr-2"></div>
                  Validating...
                </>
              ) : (
                "Start Verification"
              )}
            </button>
          </form>

          <div className="mt-8 text-center">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Don&apos;t have a token? Use the Discord bot command to get one.
            </p>
          </div>
        </div>

        <div className="text-center">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            How it works
          </h3>
          <div className="space-y-3 text-sm text-gray-600 dark:text-gray-400">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-6 h-6 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center text-xs font-medium text-blue-600 dark:text-blue-400">
                1
              </div>
              <p>Get your verification token from the Discord bot</p>
            </div>
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-6 h-6 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center text-xs font-medium text-blue-600 dark:text-blue-400">
                2
              </div>
              <p>Enter the token above to start verification</p>
            </div>
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-6 h-6 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center text-xs font-medium text-blue-600 dark:text-blue-400">
                3
              </div>
              <p>Scan the QR code with your ZKPassport mobile app</p>
            </div>
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-6 h-6 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center text-xs font-medium text-blue-600 dark:text-blue-400">
                4
              </div>
              <p>Complete verification to gain admin access</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Home() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <HomeContent />
    </Suspense>
  );
}