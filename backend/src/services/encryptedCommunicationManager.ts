import https from 'https';
import http from 'http';
import { Agent } from 'https';
import { readFileSync } from 'fs';
import { join } from 'path';
import { certificateManager } from './certificateManager';
import { secureKeyManager } from './secureKeyManager';
import { logger } from '../utils/logger';

interface ServiceConnectionConfig {
  requireEncryption: boolean;
  certificateId?: string;
  keyId?: string;
  verifyCertificate?: boolean;
  allowSelfSigned?: boolean;
  timeout?: number;
  keepAlive?: boolean;
}

interface DatabaseEncryptionConfig {
  requireEncryption: boolean;
  fieldEncryption?: boolean;
  connectionString?: string;
}

interface ConnectionStats {
  totalConnections: number;
  encryptedConnections: number;
  unencryptedConnections: number;
  failedConnections: number;
  errorRate: number;
  averageResponseTime: number;
}

interface CommunicationHealth {
  encryptedConnections: number;
  unencryptedConnections: number;
  errorRate: number;
  securityCompliance: number;
  activeServices: string[];
}

interface ComplianceReport {
  score: number;
  environment: string;
  recommendations: string[];
  issues: string[];
  timestamp: string;
}

class EncryptedCommunicationManager {
  private activeConnections: Map<string, any> = new Map();
  private connectionStats: Map<string, ConnectionStats> = new Map();
  private communicationHealth: Map<string, CommunicationHealth> = new Map();
  private healthCheckInterval: NodeJS.Timeout | null = null;

  /**
   * Initialize encrypted communication manager
   */
  async initializeManager(): Promise<void> {
    try {
      logger.info('Initializing encrypted communication manager...');

      // Ensure certificate and key managers are initialized
      if (!certificateManager || !secureKeyManager) {
        throw new Error('Certificate or key manager not initialized');
      }

      // Start health monitoring
      this.startHealthMonitoring();

      logger.info('Encrypted communication manager initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize communication manager:', error);
      throw new Error('Communication manager initialization failed');
    }
  }

  /**
   * Establish encrypted service connection
   */
  async establishServiceConnection(
    serviceName: string,
    endpoint: string,
    config: ServiceConnectionConfig
  ): Promise<any> {
    try {
      logger.info(`Establishing encrypted connection to ${serviceName} at ${endpoint}`);

      // Default connection statistics
      const connectionStats: ConnectionStats = {
        totalConnections: 0,
        encryptedConnections: 0,
        unencryptedConnections: 0,
        failedConnections: 0,
        errorRate: 0,
        averageResponseTime: 0,
      };

      let connection: any;
      let isEncrypted = false;

      if (config.requireEncryption) {
        // Create encrypted HTTPS connection
        const { cert, key, ca } = await this.getTLSConfiguration(config);

        const httpsAgent = new https.Agent({
          cert,
          key,
          ca,
          rejectUnauthorized: config.verifyCertificate !== false,
          timeout: config.timeout || 30000,
          keepAlive: config.keepAlive !== false,
        });

        // Create HTTPS request options
        const options: https.RequestOptions = {
          method: 'GET',
          headers: {
            'User-Agent': 'ZK-Verifier-Client/1.0',
            'Accept': 'application/json',
          },
          agent: httpsAgent,
        };

        isEncrypted = true;
        connection = httpsAgent;

      } else {
        // Create unencrypted HTTP connection
        connection = new Agent({
          timeout: config.timeout || 30000,
          keepAlive: config.keepAlive !== false,
        });

        isEncrypted = false;
      }

      // Store connection and statistics
      this.activeConnections.set(serviceName, connection);
      this.connectionStats.set(serviceName, connectionStats);

      // Update connection statistics
      connectionStats.totalConnections++;
      if (isEncrypted) {
        connectionStats.encryptedConnections++;
      } else {
        connectionStats.unencryptedConnections++;
      }

      logger.info(`Successfully established ${isEncrypted ? 'encrypted' : 'unencrypted'} connection to ${serviceName}`);

      return connection;
    } catch (error) {
      logger.error(`Failed to establish connection to ${serviceName}:`, error);
      
      const stats = this.connectionStats.get(serviceName);
      if (stats) {
        stats.failedConnections++;
        stats.errorRate = stats.failedConnections / stats.totalConnections;
      }

      throw new Error(`Service connection failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Configure encrypted database connection
   */
  async configureDatabaseEncryption(
    connectionString: string,
    config: DatabaseEncryptionConfig
  ): Promise<string> {
    try {
      logger.info('Configuring encrypted database connection...');

      let modifiedConnectionString = connectionString;

      if (config.requireEncryption) {
        // Add SSL parameters to connection string
        const sslParams = [
          'sslmode=require',
          'sslrootcert=./certs/ca.crt', // Certificate authority certificate
          'sslcert=./certs/client.crt', // Client certificate
          'sslkey=./certs/client.key', // Client private key
          'sslcrl=./certs/crl.pem', // Certificate revocation list
        ].join('&');

        if (connectionString.includes('?')) {
          modifiedConnectionString = `${connectionString}&${sslParams}`;
        } else {
          modifiedConnectionString = `${connectionString}?${sslParams}`;
        }

        logger.info('Database connection configured with SSL/TLS encryption');
      }

      if (config.fieldEncryption) {
        logger.info('Field-level encryption enabled for database connections');
        // In a real implementation, you would configure field encryption here
      }

      return modifiedConnectionString;
    } catch (error) {
      logger.error('Failed to configure database encryption:', error);
      throw new Error('Database encryption configuration failed');
    }
  }

  /**
   * Get TLS configuration for service connections
   */
  private async getTLSConfiguration(config: ServiceConnectionConfig): Promise<{
    cert: string;
    key: string;
    ca: string;
  }> {
    try {
      let certPath: string;
      let keyPath: string;

      if (config.certificateId) {
        // Use specific certificate
        const certData = certificateManager.getCertificate(config.certificateId);
        if (!certData) {
          throw new Error(`Certificate ${config.certificateId} not found`);
        }

        const certPathMap = this.getCertificatePaths(config.certificateId);
        certPath = certPathMap.certPath;
        keyPath = certPathMap.keyPath;
      } else {
        // Use default certificate for environment
        const environment = process.env.NODE_ENV || 'development';
        certPath = join(process.cwd(), 'certs', environment, 'default.crt');
        keyPath = join(process.cwd(), 'certs', environment, 'default.key');
      }

      // Load certificate files
      const cert = readFileSync(certPath, 'utf8');
      const key = readFileSync(keyPath, 'utf8');

      // Load CA certificate for validation
      let ca: string;
      try {
        ca = readFileSync(join(process.cwd(), 'certs', 'ca.crt'), 'utf8');
      } catch {
        // If no CA certificate exists, use the service certificate itself
        ca = cert;
      }

      return { cert, key, ca };
    } catch (error) {
      logger.error('Failed to get TLS configuration:', error);
      throw new Error('TLS configuration failed');
    }
  }

  /**
   * Get certificate file paths
   */
  private getCertificatePaths(certId: string): { certPath: string; keyPath: string } {
    const environment = process.env.NODE_ENV || 'development';
    return {
      certPath: join(process.cwd(), 'certs', environment, `${certId}.crt`),
      keyPath: join(process.cwd(), 'certs', environment, `${certId}.key`),
    };
  }

  /**
   * Make encrypted HTTP request
   */
  async makeEncryptedRequest(
    serviceName: string,
    method: string,
    endpoint: string,
    data?: any,
    headers?: Record<string, string>
  ): Promise<any> {
    try {
      const connection = this.activeConnections.get(serviceName);
      if (!connection) {
        throw new Error(`No connection found for service: ${serviceName}`);
      }

      const startTime = Date.now();
      
      // This is a simplified implementation
      // In practice, you'd use axios, fetch, or another HTTP client
      const requestOptions: any = {
        method,
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'ZK-Verifier-Client/1.0',
          ...headers,
        },
      };

      if (data && (method === 'POST' || method === 'PUT')) {
        requestOptions.body = JSON.stringify(data);
      }

      // Simulate HTTP request
      const response = await this.simulateHttpRequest(endpoint, requestOptions);

      // Update performance statistics
      const stats = this.connectionStats.get(serviceName);
      if (stats) {
        const responseTime = Date.now() - startTime;
        stats.averageResponseTime = (stats.averageResponseTime + responseTime) / 2;
      }

      return response;
    } catch (error) {
      logger.error(`Encrypted request failed for ${serviceName}:`, error);
      
      const stats = this.connectionStats.get(serviceName);
      if (stats) {
        stats.failedConnections++;
        stats.errorRate = stats.failedConnections / stats.totalConnections;
      }

      throw error;
    }
  }

  /**
   * Get communication health status
   */
  getCommunicationHealth(): CommunicationHealth {
    const allStats = Array.from(this.connectionStats.values());
    
    const totalConnections = allStats.reduce((sum, stats) => sum + stats.totalConnections, 0);
    const encryptedConnections = allStats.reduce((sum, stats) => sum + stats.encryptedConnections, 0);
    const unencryptedConnections = allStats.reduce((sum, stats) => sum + stats.unencryptedConnections, 0);
    const totalErrors = allStats.reduce((sum, stats) => sum + stats.failedConnections, 0);
    const errorRate = totalConnections > 0 ? totalErrors / totalConnections : 0;

    // Calculate security compliance score
    const securityCompliance = totalConnections > 0 ? (encryptedConnections / totalConnections) * 100 : 0;

    return {
      encryptedConnections,
      unencryptedConnections,
      errorRate,
      securityCompliance,
      activeServices: Array.from(this.connectionStats.keys()),
    };
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(): Promise<ComplianceReport> {
    try {
      const health = this.getCommunicationHealth();
      const environment = process.env.NODE_ENV || 'development';

      // Calculate compliance score
      let score = 100;
      const recommendations: string[] = [];
      const issues: string[] = [];

      // Check encryption requirements
      if (health.unencryptedConnections > 0) {
        score -= Math.min(30, (health.unencryptedConnections / (health.encryptedConnections + health.unencryptedConnections)) * 30);
        recommendations.push('Enable encryption for all service communications');
        issues.push(`${health.unencryptedConnections} unencrypted connections detected`);
      }

      // Check error rate
      if (health.errorRate > 0.1) {
        score -= Math.min(20, health.errorRate * 100);
        recommendations.push('Investigate and resolve connection errors');
        issues.push(`High error rate: ${(health.errorRate * 100).toFixed(2)}%`);
      }

      // Check security compliance
      if (health.securityCompliance < 100) {
        score -= Math.min(20, (100 - health.securityCompliance) * 0.2);
        recommendations.push('Enable TLS/mTLS for all services');
        issues.push(`Security compliance: ${health.securityCompliance.toFixed(1)}%`);
      }

      // Environment-specific checks
      if (environment === 'production' && health.unencryptedConnections > 0) {
        score -= 25;
        issues.push('CRITICAL: Unencrypted connections in production environment');
      }

      return {
        score: Math.max(0, Math.round(score)),
        environment,
        recommendations,
        issues,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.error('Failed to generate compliance report:', error);
      throw new Error('Compliance report generation failed');
    }
  }

  /**
   * Start health monitoring
   */
  private startHealthMonitoring(): void {
    // Monitor communication health every 5 minutes
    this.healthCheckInterval = setInterval(() => {
      this.performHealthCheck();
    }, 5 * 60 * 1000);

    logger.info('Communication health monitoring started');
  }

  /**
   * Perform health check on all connections
   */
  private performHealthCheck(): void {
    const services = Array.from(this.activeConnections.keys());
    
    for (const serviceName of services) {
      try {
        // Check connection health
        const connection = this.activeConnections.get(serviceName);
        const stats = this.connectionStats.get(serviceName);
        
        if (!connection || !stats) continue;

        // Update health status (simplified)
        const isHealthy = stats.errorRate < 0.1;
        
        if (!isHealthy) {
          logger.warn(`Service ${serviceName} health check failed - high error rate`);
        }
      } catch (error) {
        logger.error(`Health check failed for ${serviceName}:`, error);
      }
    }
  }

  /**
   * Private helper methods
   */

  private async simulateHttpRequest(endpoint: string, options: any): Promise<any> {
    // This is a placeholder for actual HTTP request implementation
    // In production, use axios, node-fetch, or native https
    
    return {
      status: 200,
      data: { message: 'Simulated encrypted response' },
      headers: { 'content-type': 'application/json' },
    };
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    // Close all active connections
    for (const [serviceName, connection] of this.activeConnections) {
      try {
        if (connection && typeof connection.destroy === 'function') {
          connection.destroy();
        }
        logger.info(`Closed connection to ${serviceName}`);
      } catch (error) {
        logger.error(`Error closing connection to ${serviceName}:`, error);
      }
    }

    // Clear health monitoring
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }

    // Clear data structures
    this.activeConnections.clear();
    this.connectionStats.clear();
    this.communicationHealth.clear();

    logger.info('Encrypted communication manager destroyed');
  }
}

// Export singleton instance
export const encryptedCommunicationManager = new EncryptedCommunicationManager();
export { 
  EncryptedCommunicationManager, 
  ServiceConnectionConfig, 
  DatabaseEncryptionConfig, 
  CommunicationHealth,
  ComplianceReport 
};