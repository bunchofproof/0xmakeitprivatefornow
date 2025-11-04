interface EnvironmentConfig {
  NODE_ENV: string;
  DISCORD_BOT_TOKEN: string;
  JWT_SECRET?: string;
  CLIENT_ID: string;
  GUILD_ID: string;
  DATABASE_URL: string;
  VERIFICATION_URL: string;
  ADMIN_ROLE_IDS: string;
  ENCRYPTION_KEY?: string;
}

class EnvironmentValidator {
  private config: Partial<EnvironmentConfig>;
  private errors: string[] = [];

  constructor() {
    this.config = process.env as any;
  }

  validate(): boolean {
    this.errors = [];
    this.validateRequiredFields();
    this.validateEnvironmentSpecific();
    this.validateSecurity();

    if (this.errors.length > 0) {
      console.error('❌ Environment validation failed:');
      this.errors.forEach(error => console.error(`  - ${error}`));
      return false;
    }

    if (process.env.NODE_ENV !== 'production') {
      console.log('✅ Environment validation passed');
    }
    return true;
  }

  private validateRequiredFields(): void {
    const requiredFields: (keyof EnvironmentConfig)[] = [
      'NODE_ENV',
      'DISCORD_BOT_TOKEN',
      'JWT_SECRET',
      'CLIENT_ID',
      'GUILD_ID',
      'DATABASE_URL',
      'VERIFICATION_URL',
      'ADMIN_ROLE_IDS'
    ];

    requiredFields.forEach(field => {
      if (!this.config[field]) {
        this.errors.push(`${field} is required but not set`);
      }
    });
  }

  private validateEnvironmentSpecific(): void {
    const env = this.config.NODE_ENV;

    switch (env) {
      case 'production':
        this.validateProduction();
        break;
      case 'test':
        this.validateTest();
        break;
      case 'development':
        this.validateDevelopment();
        break;
      default:
        this.errors.push(`Invalid NODE_ENV: ${env}. Must be development, test, or production`);
    }
  }

  private validateProduction(): void {
    if (!this.config.ENCRYPTION_KEY) {
      this.errors.push('ENCRYPTION_KEY is required for production environment');
    } else if (this.config.ENCRYPTION_KEY.length < 32) {
      this.errors.push('ENCRYPTION_KEY must be at least 32 characters for production');
    }

    // Validate production URLs
    if (this.config.VERIFICATION_URL?.startsWith('http://')) {
      this.errors.push('VERIFICATION_URL must use HTTPS in production');
    }
  }

  private validateTest(): void {
    // More permissive for testing
    if (!this.config.ENCRYPTION_KEY) {
      if (process.env.NODE_ENV !== 'production') {
        console.warn('⚠️  ENCRYPTION_KEY not set for test environment');
      }
    }
  }

  private validateDevelopment(): void {
    // Most permissive for development
    if (!this.config.ENCRYPTION_KEY) {
      if (process.env.NODE_ENV !== 'production') {
        console.warn('⚠️  ENCRYPTION_KEY not set for development environment');
      }
    }
  }

  private validateSecurity(): void {
    // Check for common security issues
    if (this.config.DISCORD_BOT_TOKEN?.length && this.config.DISCORD_BOT_TOKEN.length < 50) {
      this.errors.push('DISCORD_BOT_TOKEN appears to be invalid (too short)');
    }

    if (this.config.JWT_SECRET?.length && this.config.JWT_SECRET.length < 32) {
      this.errors.push('JWT_SECRET must be at least 32 characters long for security');
    }

    if (this.config.ENCRYPTION_KEY === 'development_32_character_key_for_encryption') {
      this.errors.push('ENCRYPTION_KEY appears to be using default development value');
    }
  }

  getErrors(): string[] {
    return [...this.errors];
  }
}

export const envValidator = new EnvironmentValidator();
export default EnvironmentValidator;