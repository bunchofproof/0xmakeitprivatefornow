interface WebEnvironmentConfig {
  NODE_ENV: string;
  NEXT_PUBLIC_APP_URL: string;
  NEXT_PUBLIC_API_URL: string;
  LOG_LEVEL?: string;
}

class WebEnvironmentValidator {
  private config: Partial<WebEnvironmentConfig>;
  private errors: string[] = [];

  constructor() {
    // CRITICAL SECURITY FIX: Only expose safe, public environment variables
    // Server-side secrets must NOT be accessible from client-side code
    this.config = {
      NODE_ENV: process.env.NODE_ENV || 'development',
      NEXT_PUBLIC_APP_URL: process.env.NEXT_PUBLIC_APP_URL || '',
      NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || '',
      LOG_LEVEL: process.env.LOG_LEVEL || 'info'
    } as Partial<WebEnvironmentConfig>;
  }

  validate(): boolean {
    this.errors = [];
    this.validateRequiredFields();
    this.validateEnvironmentSpecific();
    this.validateSecurity();

    if (this.errors.length > 0) {
      console.error('❌ Web environment validation failed:');
      this.errors.forEach(error => console.error(`  - ${error}`));
      return false;
    }

    console.log('✅ Web environment validation passed');
    return true;
  }

  private validateRequiredFields(): void {
    const requiredFields: (keyof WebEnvironmentConfig)[] = [
      'NODE_ENV',
      'NEXT_PUBLIC_APP_URL',
      'NEXT_PUBLIC_API_URL'
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
    // Validate production URLs must use HTTPS
    if (this.config.NEXT_PUBLIC_APP_URL && !this.config.NEXT_PUBLIC_APP_URL.startsWith('https://')) {
      this.errors.push('NEXT_PUBLIC_APP_URL must use HTTPS in production');
    }

    if (this.config.NEXT_PUBLIC_API_URL && !this.config.NEXT_PUBLIC_API_URL.startsWith('https://')) {
      this.errors.push('NEXT_PUBLIC_API_URL must use HTTPS in production');
    }

    // Note: Server-side secret validation should be done in backend services
    // to maintain security separation between client and server environments
  }

  private validateTest(): void {
    // More permissive for testing - no specific checks needed for public variables
    console.log('ℹ️  Web environment validation: Using test configuration');
  }

  private validateDevelopment(): void {
    // Most permissive for development - no specific checks needed for public variables
    console.log('ℹ️  Web environment validation: Using development configuration');
  }

  private validateSecurity(): void {
    // Only validate public-facing environment variables for security
    // Note: Server-side secrets should be validated in backend services only
    
    // Validate NEXT_PUBLIC_APP_URL format
    if (this.config.NEXT_PUBLIC_APP_URL &&
        !this.config.NEXT_PUBLIC_APP_URL.match(/^https?:\/\/.+/)) {
      this.errors.push('NEXT_PUBLIC_APP_URL must be a valid HTTP/HTTPS URL');
    }

    // Validate NEXT_PUBLIC_API_URL format
    if (this.config.NEXT_PUBLIC_API_URL &&
        !this.config.NEXT_PUBLIC_API_URL.match(/^https?:\/\/.+/)) {
      this.errors.push('NEXT_PUBLIC_API_URL must be a valid HTTP/HTTPS URL');
    }
  }

  getErrors(): string[] {
    return [...this.errors];
  }
}

export const webEnvValidator = new WebEnvironmentValidator();
export default WebEnvironmentValidator;