import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */

  

  // Environment-specific configurations
  ...(process.env.NODE_ENV === 'production' && {
    // Production optimizations
    compiler: {
      removeConsole: process.env.NODE_ENV === 'production',
    },
    experimental: {
      optimizeCss: true,
      optimizePackageImports: ['@aztec/bb.js'],
    },
  }),

  // Development-specific configurations
  ...(process.env.NODE_ENV === 'development' && {
    // Development helpers
  }),

  async headers() {
    const isProduction = process.env.NODE_ENV === 'production';
    const allowedOrigins = process.env.ALLOWED_ORIGINS || 'http://192.168.1.8:3000';

    return [
      {
        source: "/(.*)",
        headers: [
          ...(isProduction ? [{
            key: "Strict-Transport-Security",
            value: "max-age=31536000; includeSubDomains"
          }] : [{
            key: "X-Environment",
            value: "development"
          }])
        ]
      }
    ];
  },
  outputFileTracingIncludes: {
    "/api/register": [
      "./node_modules/@aztec/bb.js/dest/node/**/*",
      "./node_modules/@aztec/bb.js/dest/node-cjs/**/*",
    ],
  },
  webpack: (config, { isServer }) => {
    if (isServer) {
      config.externals.push({
        "@aztec/bb.js": "@aztec/bb.js",
      });
    }

    // Handle WASM files
    config.experiments = {
      ...config.experiments,
      asyncWebAssembly: true,
    };

    return config;
  },
};

export default nextConfig;