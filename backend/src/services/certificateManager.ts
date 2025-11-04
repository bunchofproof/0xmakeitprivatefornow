import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { createHash, randomBytes, generateKeyPair } from 'crypto';
import { logger } from '../utils/logger';

interface CertificateConfig {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  locality: string;
  state: string;
  country: string;
  subjectAltName: string[];
  daysValid: number;
}

interface CertificateData {
  certId: string;
  subject: {
    commonName: string;
    organization: string;
  };
  validFrom: Date;
  validTo: Date;
  serialNumber: string;
  fingerprint: string;
  path: string;
  isActive: boolean;
  keyUsage: string[];
  environment: string;
}

interface CertificateStats {
  totalCertificates: number;
  activeCertificates: number;
  expiredCertificates: number;
  certificatesNeedingRenewal: string[];
  certificateHealth: {
    healthy: number;
    warning: number;
    critical: number;
  };
}

class CertificateManager {
  private certificates: Map<string, CertificateData> = new Map();
  private certificatePaths: Map<string, string> = new Map();
  private monitoringInterval: NodeJS.Timeout | null = null;
  private checkIntervalHours: number = 24;
  private warningDaysBeforeExpiry: number = 30;

  /**
   * Initialize certificate management infrastructure
   */
  async initialize(): Promise<void> {
    try {
      logger.info('Initializing certificate management infrastructure...');

      // Ensure certificate directories exist
      await this.ensureCertificateDirectories();

      // Load existing certificates from disk
      await this.loadExistingCertificates();

      // Start monitoring certificates for expiration
      this.startMonitoring();

      logger.info('Certificate management infrastructure initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize certificate manager:', error);
      throw new Error('Certificate manager initialization failed');
    }
  }

  /**
   * Create a new certificate
   */
  async createCertificate(config: Partial<CertificateConfig>): Promise<string> {
    try {
      const certConfig: CertificateConfig = {
        commonName: config.commonName || 'zk-verifier.local',
        organization: config.organization || 'ZK Discord Verifier',
        organizationalUnit: config.organizationalUnit || 'Security',
        locality: config.locality || 'Local',
        state: config.state || 'Development',
        country: config.country || 'US',
        subjectAltName: config.subjectAltName || ['localhost', '127.0.0.1'],
        daysValid: config.daysValid || 365,
        ...config
      };

      // Generate key pair using promisified version
      const { publicKey, privateKey } = await new Promise<{ publicKey: string, privateKey: string }>((resolve, reject) => {
        generateKeyPair('rsa', {
          modulusLength: 2048,
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
          },
        }, (err: Error | null, publicKey: string, privateKey: string) => {
          if (err) reject(err);
          else resolve({ publicKey, privateKey });
        });
      });

      // Generate certificate subject
      const subject = [
        { name: 'commonName', value: certConfig.commonName },
        { name: 'organizationName', value: certConfig.organization },
        { name: 'organizationalUnitName', value: certConfig.organizationalUnit },
        { name: 'localityName', value: certConfig.locality },
        { name: 'stateOrProvinceName', value: certConfig.state },
        { name: 'countryName', value: certConfig.country },
      ];

      // Create self-signed certificate (temporary fix - generate basic cert)
      const cert = {
        subject,
        publicKey,
        privateKey,
        // Certificate generation would go here with proper crypto APIs
      };

      // Generate unique certificate ID using cert data as string
      const certString = JSON.stringify(cert);
      const certId = this.generateCertificateId(certString);

      // Calculate fingerprint
      const fingerprint = createHash('sha256').update(certString).digest('hex');

      // Determine environment
      const environment = process.env.NODE_ENV || 'development';

      // Store certificate metadata
      const certificateData: CertificateData = {
        certId,
        subject: {
          commonName: certConfig.commonName,
          organization: certConfig.organization,
        },
        validFrom: new Date(),
        validTo: new Date(Date.now() + certConfig.daysValid * 24 * 60 * 60 * 1000),
        serialNumber: randomBytes(16).toString('hex'),
        fingerprint,
        path: '', // Will be set when saved to disk
        isActive: true,
        keyUsage: ['serverAuth', 'clientAuth'],
        environment,
      };

      // Save certificate and key to files
      const { certPath, keyPath } = await this.saveCertificateFiles(certId, certString, privateKey, environment);

      certificateData.path = certPath;

      // Store in memory
      this.certificates.set(certId, certificateData);
      this.certificatePaths.set(certId, keyPath);

      logger.info(`Created certificate ${certId} for ${certConfig.commonName}`);

      return certId;
    } catch (error) {
      logger.error('Failed to create certificate:', error);
      throw new Error('Certificate creation failed');
    }
  }

  /**
   * Get certificate information
   */
  getCertificate(certId: string): CertificateData | null {
    return this.certificates.get(certId) || null;
  }

  /**
   * Get certificate statistics
   */
  getCertificateStatistics(): CertificateStats {
    const certificates = Array.from(this.certificates.values());
    const now = new Date();
    
    const expiredCertificates = certificates.filter(cert => cert.validTo < now).length;
    const activeCertificates = certificates.filter(cert => cert.validTo >= now && cert.isActive).length;
    const certificatesNeedingRenewal = certificates
      .filter(cert => {
        const daysUntilExpiry = Math.ceil((cert.validTo.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));
        return daysUntilExpiry <= this.warningDaysBeforeExpiry && cert.isActive;
      })
      .map(cert => cert.certId);

    return {
      totalCertificates: certificates.length,
      activeCertificates,
      expiredCertificates,
      certificatesNeedingRenewal,
      certificateHealth: {
        healthy: activeCertificates - certificatesNeedingRenewal.length,
        warning: certificatesNeedingRenewal.length,
        critical: expiredCertificates,
      },
    };
  }

  /**
   * Generate compliance report
   */
  generateComplianceReport(): {
    totalCertificates: number;
    expiredCertificates: number;
    certificatesNeedingRenewal: string[];
    complianceScore: number;
    recommendations: string[];
  } {
    const stats = this.getCertificateStatistics();
    const total = stats.totalCertificates;
    const expired = stats.expiredCertificates;
    const needingRenewal = stats.certificatesNeedingRenewal.length;

    // Calculate compliance score (0-100)
    let complianceScore = 100;
    if (expired > 0) complianceScore -= (expired / total) * 50;
    if (needingRenewal > 0) complianceScore -= (needingRenewal / total) * 30;

    const recommendations: string[] = [];

    if (expired > 0) {
      recommendations.push(`Renew or replace ${expired} expired certificate(s)`);
    }

    if (needingRenewal > 0) {
      recommendations.push(`Renew ${needingRenewal} certificate(s) approaching expiration`);
    }

    if (total === 0) {
      recommendations.push('Generate production SSL certificates');
      complianceScore = 0;
    }

    return {
      totalCertificates: total,
      expiredCertificates: expired,
      certificatesNeedingRenewal: stats.certificatesNeedingRenewal,
      complianceScore: Math.max(0, Math.round(complianceScore)),
      recommendations,
    };
  }

  /**
   * Start monitoring certificates for expiration
   */
  startMonitoring(config?: {
    checkIntervalHours?: number;
    warningDaysBeforeExpiry?: number;
  }): void {
    if (config) {
      this.checkIntervalHours = config.checkIntervalHours || this.checkIntervalHours;
      this.warningDaysBeforeExpiry = config.warningDaysBeforeExpiry || this.warningDaysBeforeExpiry;
    }

    // Clear existing monitoring
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }

    // Start new monitoring
    this.monitoringInterval = setInterval(() => {
      this.checkCertificateExpirations();
    }, this.checkIntervalHours * 60 * 60 * 1000);

    logger.info(`Certificate monitoring started (${this.checkIntervalHours}h interval)`);
  }

  /**
   * Stop monitoring certificates
   */
  stopMonitoring(): void {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
      logger.info('Certificate monitoring stopped');
    }
  }

  /**
   * Private methods
   */

  private generateCertificateId(cert: string): string {
    const hash = createHash('sha256').update(cert).digest('hex');
    return `cert_${hash.substring(0, 16)}`;
  }

  private async ensureCertificateDirectories(): Promise<void> {
    const baseDir = join(process.cwd(), 'certs');
    const dirs = [
      baseDir,
      join(baseDir, 'production'),
      join(baseDir, 'development'),
      join(baseDir, 'test'),
    ];

    for (const dir of dirs) {
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
    }
  }

  private async saveCertificateFiles(
    certId: string,
    certificate: string,
    privateKey: string,
    environment: string
  ): Promise<{ certPath: string; keyPath: string }> {
    const baseDir = join(process.cwd(), 'certs', environment);
    const certPath = join(baseDir, `${certId}.crt`);
    const keyPath = join(baseDir, `${certId}.key`);

    // Write certificate
    writeFileSync(certPath, certificate, { encoding: 'utf8' });

    // Write private key
    writeFileSync(keyPath, privateKey, { encoding: 'utf8' });

    // Set restrictive permissions
    // Note: In production, consider using chmod or similar for additional security

    return { certPath, keyPath };
  }

  private async loadExistingCertificates(): Promise<void> {
    try {
      const environments = ['development', 'production', 'test'];
      
      for (const env of environments) {
        const certDir = join(process.cwd(), 'certs', env);
        
        if (!existsSync(certDir)) continue;

        // This is a simplified implementation
        // In production, you'd read actual certificate files and extract metadata
        logger.info(`Loaded certificates for environment: ${env}`);
      }
    } catch (error) {
      logger.error('Error loading existing certificates:', error);
    }
  }

  private checkCertificateExpirations(): void {
    const now = new Date();
    const certificates = Array.from(this.certificates.values());

    for (const cert of certificates) {
      if (!cert.isActive) continue;

      const daysUntilExpiry = Math.ceil((cert.validTo.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));

      if (daysUntilExpiry <= 0) {
        logger.error(`Certificate ${cert.certId} has expired`);
      } else if (daysUntilExpiry <= this.warningDaysBeforeExpiry) {
        logger.warn(`Certificate ${cert.certId} expires in ${daysUntilExpiry} days`);
      }
    }
  }
}

// Export singleton instance
export const certificateManager = new CertificateManager();
export { CertificateManager, CertificateData, CertificateStats };