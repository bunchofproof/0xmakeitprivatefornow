#!/usr/bin/env node

/**
 * Environment validation script for Next.js web application
 * This script validates all required environment variables before starting the server
 */

import { webEnvValidator } from '../lib/envValidator.js';

try {
  if (!webEnvValidator.validate()) {
    console.error('❌ Environment validation failed!');
    process.exit(1);
  }

  console.log('✅ Environment validation successful');
  process.exit(0);

} catch (error) {
  console.error('❌ Error during environment validation:', error instanceof Error ? error.message : String(error));
  process.exit(1);
}