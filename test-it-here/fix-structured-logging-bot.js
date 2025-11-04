const fs = require('fs');
const path = require('path');

const botSrcPath = path.join(__dirname, '..', 'bot', 'src');

// Files to process - include all utils files
const filesToProcess = [
  'index.ts',
  'middleware/validation.ts',
  'services/adminService.ts',
  'services/botDatabaseService.ts',
  'services/discordService.ts',
  'commands/adminstatus.ts',
  'commands/status.ts',
  'commands/verify.ts',
  'events/guildMemberUpdate.ts',
  'events/interactionCreate.ts',
  'events/ready.ts',
  'webhooks/server.ts',
  'utils/circuitBreaker.ts',
  'utils/crypto.ts',
  'utils/database.ts',
  'utils/databaseConcurrencyControl.ts',
  'utils/drivers/jsonDriver.ts',
  'utils/drivers/prismaDriver.ts',
  'utils/drivers/sqliteDriver.ts',
  'utils/enhancedSessionSecurity.ts',
  'utils/errorHandler.ts',
  'utils/hmac.ts',
  'utils/migrationUtility.ts',
  'utils/performanceMonitor.ts',
  'utils/rateLimitManager.ts',
  'utils/scheduler.ts',
  'utils/securityTests.ts',
  'utils/sessionCleanupService.ts',
  'utils/sessionManager.ts',
  'utils/sessionReplayTests.ts',
  'utils/sessionSecurityDeployment.ts',
  'utils/sessionSecurityManager.ts',
  'utils/sessionStatsService.ts',
  'utils/tokenGenerator.ts',
];

console.log('Starting to fix structured logging in bot...');

// Process each file
filesToProcess.forEach(filePath => {
  const fullPath = path.join(botSrcPath, filePath);

  if (!fs.existsSync(fullPath)) {
    console.log(`File not found: ${fullPath}`);
    return;
  }

  console.log(`Processing: ${filePath}`);
  let content = fs.readFileSync(fullPath, 'utf8');

  // Pattern 1: logger.error('message', undefined, { ... }) -> logger.error('message', error, { ... })
  content = content.replace(
    /logger\.error\('([^']*)',\s*undefined,\s*({[^}]*})\s*as\s*Record<string,\s*any>\s*\);?/g,
    (match, message, meta) => {
      // Extract error from meta object if present
      const errorMatch = meta.match(/error:\s*(error\s*instanceof\s*Error\s*\?\s*error\s*:\s*String\(error\))/);
      if (errorMatch) {
        return `logger.error('${message}', ${errorMatch[1]}, ${meta});`;
      }
      return match; // Keep original if can't fix
    }
  );

  // Pattern 2: logger.error('message', undefined, { ... }) -> logger.error('message', error, { ... })
  content = content.replace(
    /logger\.error\('([^']*)',\s*undefined,\s*({[^}]*})\)/g,
    (match, message, meta) => {
      // Try to extract error from meta
      const errorMatch = meta.match(/error:\s*([^,}\n]+)/);
      if (errorMatch) {
        const errorExpr = errorMatch[1].trim();
        return `logger.error('${message}', ${errorExpr}, ${meta});`;
      }
      return match; // Keep original if can't fix
    }
  );

  // Pattern 3: logger.error('message', error) -> keep as is (already correct)
  // Pattern 4: logger.error('message', new Error(...)) -> keep as is

  // Pattern 5: logger.info/warn/error with concatenated strings -> split into message + meta
  content = content.replace(
    /logger\.(info|warn|error)\('([^']*'\s*\+\s*[^']*)'/g,
    (match, level, concatMessage) => {
      return `logger.${level}('Message', { message: ${concatMessage} });`;
    }
  );

  fs.writeFileSync(fullPath, content);
});

console.log('Completed fixing structured logging in bot files.');