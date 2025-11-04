# ZKPassport Discord Verification Bot

A comprehensive Discord bot for managing ZKPassport verification processes with admin controls, automated scheduling, and secure token management.

## 🚀 Features

### Core Functionality
- **Secure Verification Process**: Cryptographically secure token generation and validation
- **Admin Management**: Complete admin dashboard for managing verifications
- **Automated Scheduling**: Automated reminders and cleanup tasks
- **Rate Limiting**: Built-in protection against spam and abuse
- **Input Validation**: Comprehensive validation and sanitization
- **Database Integration**: Prisma-based database operations

### Commands
- `/verify` - Start ZKPassport verification process
- `/status [user]` - Check verification status (admin can check others)
- `/adminstatus` - Admin-only verification management commands
- `/help` - Display help information

## 📋 Prerequisites

- Node.js 18.0.0 or higher
- Discord Bot Token
- Database (PostgreSQL, MySQL, or SQLite)
- ZKPassport verification web interface

## 🛠️ Installation

1. **Clone and Setup**
   ```bash
   cd zk-discord-verifier/bot
   npm install
   ```

2. **Environment Configuration**
   ```bash
   cp .env.example .env
   ```

   Fill in your configuration values in `.env`:
   ```env
   DISCORD_TOKEN=your_bot_token_here
   CLIENT_ID=your_client_id_here
   GUILD_ID=your_guild_id_here
   DATABASE_URL=your_database_url_here
   VERIFICATION_URL=https://your-domain.com/verify
   ADMIN_ROLE_IDS=role_id_1,role_id_2
   ```

3. **Database Setup**
   ```bash
   # Generate Prisma client
   npx prisma generate

   # Run database migrations
   npx prisma db push
   ```

4. **Register Commands**
   ```bash
   npm run register-commands
   ```

## 🏃‍♂️ Running the Bot

### Development Mode
```bash
npm run dev
```

### Production Mode
```bash
npm run build
npm run start
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `DISCORD_TOKEN` | Discord bot token | Yes | - |
| `CLIENT_ID` | Discord application client ID | Yes | - |
| `GUILD_ID` | Target Discord server ID | Yes | - |
| `DATABASE_URL` | Database connection URL | Yes | - |
| `VERIFICATION_URL` | ZKPassport verification web URL | Yes | - |
| `ADMIN_ROLE_IDS` | Comma-separated admin role IDs | Yes | - |
| `MAX_VERIFICATION_ATTEMPTS` | Max attempts per user per hour | No | 3 |
| `TOKEN_EXPIRY_MINUTES` | Token expiration time | No | 15 |
| `REMINDER_SCHEDULE` | Cron schedule for reminders | No | `0 9 * * 1` |
| `LOG_LEVEL` | Logging level | No | `info` |
| `LOG_FORMAT` | Log format (`json` or `text`) | No | `text` |

### Security Configuration

#### Token Security
- Tokens are 32 characters long by default
- Tokens expire after 15 minutes
- Uses cryptographically secure random generation
- SHA-256 hashing for collision resistance

#### Rate Limiting
- Maximum 3 verification attempts per hour per user
- Configurable rate limits per command
- Automatic cleanup of expired rate limit records

#### Input Validation
- All user inputs are sanitized
- Discord user ID format validation
- Token format and length validation
- Protection against injection attacks

## 📊 Database Schema

The bot uses Prisma with the following main models:

### VerificationSession
- `id`: Unique session identifier
- `token`: Secure verification token
- `discordUserId`: Discord user ID
- `status`: Current session status
- `createdAt`: Session creation timestamp
- `expiresAt`: Session expiration timestamp
- `attempts`: Number of attempts used

### UserVerification
- `discordUserId`: Discord user ID (Primary Key)
- `isVerified`: Verification status
- `verifiedAt`: Verification completion timestamp
- `adminVerified`: Admin verification flag
- `adminVerifiedBy`: Admin who verified
- `adminVerifiedAt`: Admin verification timestamp

### AdminVerification
- `id`: Unique verification record ID
- `discordUserId`: Discord user ID
- `adminUserId`: Admin performing action
- `status`: Verification status
- `reason`: Reason for admin action
- `expiresAt`: Record expiration timestamp

### VerificationHistory
- `id`: Unique history record ID
- `discordUserId`: Discord user ID
- `action`: Type of action performed
- `timestamp`: Action timestamp
- `metadata`: Additional action data

## 🔐 Security Considerations

### Implemented Security Measures

1. **Cryptographic Security**
   - Uses Node.js `crypto.randomBytes()` for secure token generation
   - SHA-256 hashing for token derivation
   - AES-256-GCM encryption for sensitive data

2. **Rate Limiting**
   - Per-user rate limiting for verification attempts
   - Configurable limits and windows
   - Automatic cleanup of expired records

3. **Input Validation**
   - Comprehensive input sanitization
   - Discord user ID format validation
   - Token format and length validation
   - Protection against XSS and injection attacks

4. **Error Handling**
   - Safe error messages that don't leak sensitive information
   - Proper logging without exposing tokens or personal data
   - Graceful handling of edge cases

### Security Best Practices

- **Token Management**: Tokens are never logged and expire quickly
- **Permission Validation**: Admin permissions are validated for each command
- **Data Sanitization**: All inputs are sanitized before processing
- **Error Isolation**: Errors don't expose internal system details

## 🛠️ Development

### Project Structure
```
bot/
├── src/
│   ├── commands/           # Discord slash commands
│   │   ├── verify.ts       # Main verification command
│   │   ├── status.ts       # Status check command
│   │   ├── adminstatus.ts  # Admin management command
│   │   └── help.ts         # Help command
│   ├── events/             # Discord event handlers
│   │   ├── ready.ts        # Bot startup handler
│   │   ├── interactionCreate.ts # Command interaction handler
│   │   └── guildMemberUpdate.ts # Role change monitoring
│   ├── utils/              # Utility functions
│   │   ├── database.ts     # Database operations
│   │   ├── scheduler.ts    # Scheduled tasks
│   │   ├── tokenGenerator.ts # Token generation
│   │   ├── crypto.ts       # Encryption utilities
│   │   └── logger.ts       # Logging utility
│   ├── middleware/         # Input validation
│   │   └── validation.ts   # Validation middleware
│   ├── types/              # TypeScript type definitions
│   └── index.ts            # Main bot entry point
├── package.json            # Dependencies and scripts
├── tsconfig.json           # TypeScript configuration
└── README.md              # This file

shared/
└── src/
    ├── types/             # Shared type definitions
    └── utils/             # Shared utility functions
```

### Adding New Commands

1. Create a new command file in `src/commands/`
2. Export both `data` (SlashCommandBuilder) and `execute` function
3. Add the command to `src/commands/index.ts`
4. Register commands: `npm run register-commands`

### Database Operations

All database operations are handled through Prisma:

```typescript
import { prisma } from './utils/database';

// Create verification session
const session = await prisma.verificationSession.create({
  data: {
    token: 'secure_token',
    discordUserId: 'user_id',
    status: 'pending',
    expiresAt: new Date(Date.now() + 15 * 60 * 1000),
  },
});
```

## 🔧 Troubleshooting

### Common Issues

1. **Bot doesn't respond to commands**
   - Ensure bot has been invited with `applications.commands` scope
   - Run `npm run register-commands` to register commands
   - Check that `GUILD_ID` is correct

2. **Database connection errors**
   - Verify `DATABASE_URL` format and credentials
   - Ensure database server is running
   - Check network connectivity

3. **Token validation failures**
   - Verify `TOKEN_EXPIRY_MINUTES` is set appropriately
   - Check system time synchronization
   - Ensure tokens aren't being logged anywhere

4. **Permission errors**
   - Verify admin role IDs in `ADMIN_ROLE_IDS`
   - Check bot's role hierarchy in Discord
   - Ensure bot has necessary permissions

### Logging

The bot provides structured logging with configurable levels:

- `debug`: Detailed debugging information
- `info`: General information (default)
- `warn`: Warning messages
- `error`: Error conditions

Set `LOG_LEVEL` in environment variables to control verbosity.
