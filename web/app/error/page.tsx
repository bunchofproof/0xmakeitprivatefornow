"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";

function ErrorContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const errorType = searchParams.get("type") || "unknown";

  const getErrorMessage = (type: string) => {
    switch (type) {
      case "invalid_session":
        return {
          title: "Invalid Session",
          description: "The verification session is invalid or has expired. Please request a new verification token from the Discord bot.",
          action: "Go Back Home"
        };
      case "invalid_token":
        return {
          title: "Invalid Token",
          description: "The verification token provided is not valid. Please check your token and try again.",
          action: "Go Back Home"
        };
      case "invalid_type":
        return {
          title: "Invalid Verification Type",
          description: "The verification type requested is not supported. Please contact an administrator.",
          action: "Go Back Home"
        };
      case "missing_parameters":
        return {
          title: "Missing Parameters",
          description: "Required verification parameters are missing. Please ensure you have a valid verification link.",
          action: "Go Back Home"
        };
      default:
        return {
          title: "Verification Error",
          description: "An unexpected error occurred during verification. Please try again or contact support.",
          action: "Go Back Home"
        };
    }
  };

  const error = getErrorMessage(errorType);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div className="verification-card">
          <div className="text-center">
            <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 dark:bg-red-900">
              <svg className="h-6 w-6 text-red-600 dark:text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
            <h2 className="mt-6 text-3xl font-bold text-gray-900 dark:text-white">
              {error.title}
            </h2>
            <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
              {error.description}
            </p>
          </div>

          <div className="mt-8">
            <button
              onClick={() => router.push("/")}
              className="w-full button-primary"
            >
              {error.action}
            </button>
          </div>

          <div className="mt-6 text-center">
            <p className="text-xs text-gray-500 dark:text-gray-400">
              If you continue to experience issues, please contact the server administrators for assistance.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function ErrorPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <ErrorContent />
    </Suspense>
  );
}