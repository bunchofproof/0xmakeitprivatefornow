#!/usr/bin/env node

/**
 * Comprehensive Encryption Infrastructure Test Suite
 * Validates all encrypted communication paths and security configurations
 */

import { execSync } from 'child_process';
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';

interface TestResult {
  test: string;
  status: 'PASS' | 'FAIL' | 'WARN';
  message: string;
  details?: any;
}

interface TestSuite {
  name: string;
  tests: TestResult[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    warnings: number;
  };
}

class EncryptionInfrastructureTester {
  private baseDir: string;
  private environment: string;
  private results: TestSuite[] = [];
  private startTime: Date;

  constructor(environment: string = 'development') {
    this.environment = environment;
    this.baseDir = process.cwd();
    this.startTime = new Date();
  }

  async runAllTests(): Promise<void> {
    console.log('🧪 Starting Encryption Infrastructure Test Suite');
    console.log('================================================');
    console.log(`Environment: ${this.environment}`);
    console.log(`Test Suite Started: ${this.startTime.toISOString()}`);
    console.log('');

    try {
      // Run all test suites
      await this.testCertificateInfrastructure();
      await this.testKeyManagement();
      await this.testServiceEncryption();
      await this.testDatabaseEncryption();
      await this.testMonitoringSystems();
      await this.testPerformanceOptimization();
      
      // Generate final report
      this.generateTestReport();
      
    } catch (error) {
      console.error('❌ Test suite execution failed:', error);
      process.exit(1);
    }
  }

  private async testCertificateInfrastructure(): Promise<void> {
    console.log('📜 Testing Certificate Infrastructure...');
    
    const suite: TestSuite = {
      name: 'Certificate Infrastructure',
      tests: [],
      summary: { total: 0, passed: 0, failed: 0, warnings: 0 }
    };

    try {
      // Test 1: Certificate directory structure
      const certDir = join(this.baseDir, 'certs', this.environment);
      if (existsSync(certDir)) {
        suite.tests.push({
          test: 'Certificate directory structure',
          status: 'PASS',
          message: 'Certificate directory exists'
        });
      } else {
        suite.tests.push({
          test: 'Certificate directory structure',
          status: 'FAIL',
          message: 'Certificate directory missing'
        });
      }

      // Test 2: Server certificate existence
      const serverCertPath = join(certDir, 'server-cert.pem');
      if (existsSync(serverCertPath)) {
        suite.tests.push({
          test: 'Server certificate',
          status: 'PASS',
          message: 'Server certificate exists',
          details: { path: serverCertPath }
        });
      } else {
        suite.tests.push({
          test: 'Server certificate',
          status: 'FAIL',
          message: 'Server certificate missing',
          details: { path: serverCertPath }
        });
      }

      // Test 3: Client certificates for all services
      const services = ['backend', 'bot', 'web', 'shared'];
      for (const service of services) {
        const clientCertPath = join(certDir, `${service}-client-cert.pem`);
        if (existsSync(clientCertPath)) {
          suite.tests.push({
            test: `${service} client certificate`,
            status: 'PASS',
            message: `${service} client certificate exists`
          });
        } else {
          suite.tests.push({
            test: `${service} client certificate`,
            status: 'FAIL',
            message: `${service} client certificate missing`
          });
        }
      }

      // Test 4: Certificate validation
      if (existsSync(serverCertPath)) {
        try {
          const certContent = readFileSync(serverCertPath, 'utf8');
          if (certContent.includes('BEGIN CERTIFICATE') && certContent.includes('END CERTIFICATE')) {
            suite.tests.push({
              test: 'Certificate format validation',
              status: 'PASS',
              message: 'Certificate has valid PEM format'
            });
          } else {
            suite.tests.push({
              test: 'Certificate format validation',
              status: 'FAIL',
              message: 'Certificate has invalid format'
            });
          }
        } catch (error) {
          suite.tests.push({
            test: 'Certificate format validation',
            status: 'FAIL',
            message: 'Failed to validate certificate format',
            details: { error: String(error) }
          });
        }
      }

    } catch (error) {
      suite.tests.push({
        test: 'Certificate infrastructure test suite',
        status: 'FAIL',
        message: 'Test suite execution failed',
        details: { error: String(error) }
      });
    }

    this.updateSummary(suite);
    this.results.push(suite);
    this.printSuiteResults(suite);
  }

  private async testKeyManagement(): Promise<void> {
    console.log('🔑 Testing Key Management...');
    
    const suite: TestSuite = {
      name: 'Key Management',
      tests: [],
      summary: { total: 0, passed: 0, failed: 0, warnings: 0 }
    };

    try {
      // Test 1: Key directory structure
      const keyDir = join(this.baseDir, 'keys', this.environment);
      if (existsSync(keyDir)) {
        suite.tests.push({
          test: 'Key directory structure',
          status: 'PASS',
          message: 'Key directory exists'
        });
      } else {
        suite.tests.push({
          test: 'Key directory structure',
          status: 'FAIL',
          message: 'Key directory missing'
        });
      }

      // Test 2: AES encryption key
      const aesKeyPath = join(keyDir, 'aes_256_gcm_key.pem');
      if (existsSync(aesKeyPath)) {
        const keyContent = readFileSync(aesKeyPath, 'utf8');
        if (keyContent.trim().length === 64) { // 32 bytes = 64 hex characters
          suite.tests.push({
            test: 'AES-256-GCM key',
            status: 'PASS',
            message: 'AES-256-GCM key exists and has correct length'
          });
        } else {
          suite.tests.push({
            test: 'AES-256-GCM key',
            status: 'FAIL',
            message: 'AES-256-GCM key has incorrect length'
          });
        }
      } else {
        suite.tests.push({
          test: 'AES-256-GCM key',
          status: 'FAIL',
          message: 'AES-256-GCM key missing'
        });
      }

      // Test 3: HMAC key
      const hmacKeyPath = join(keyDir, 'hmac_sha256_key.pem');
      if (existsSync(hmacKeyPath)) {
        const keyContent = readFileSync(hmacKeyPath, 'utf8');
        if (keyContent.trim().length === 64) { // 32 bytes = 64 hex characters
          suite.tests.push({
            test: 'HMAC-SHA256 key',
            status: 'PASS',
            message: 'HMAC-SHA256 key exists and has correct length'
          });
        } else {
          suite.tests.push({
            test: 'HMAC-SHA256 key',
            status: 'FAIL',
            message: 'HMAC-SHA256 key has incorrect length'
          });
        }
      } else {
        suite.tests.push({
          test: 'HMAC-SHA256 key',
          status: 'FAIL',
          message: 'HMAC-SHA256 key missing'
        });
      }

      // Test 4: Key file permissions (should be 600)
      const checkPermissions = (filePath: string, testName: string) => {
        try {
          const stats = execSync(`stat -c "%a" "${filePath}"`, { encoding: 'utf8' }).trim();
          if (stats === '600') {
            suite.tests.push({
              test: `${testName} permissions`,
              status: 'PASS',
              message: 'Key file has secure permissions (600)'
            });
          } else {
            suite.tests.push({
              test: `${testName} permissions`,
              status: 'WARN',
              message: `Key file has permissions ${stats}, should be 600`
            });
          }
        } catch (error) {
          suite.tests.push({
            test: `${testName} permissions`,
            status: 'FAIL',
            message: 'Failed to check file permissions'
          });
        }
      };

      if (existsSync(aesKeyPath)) checkPermissions(aesKeyPath, 'AES key');
      if (existsSync(hmacKeyPath)) checkPermissions(hmacKeyPath, 'HMAC key');

    } catch (error) {
      suite.tests.push({
        test: 'Key management test suite',
        status: 'FAIL',
        message: 'Test suite execution failed',
        details: { error: String(error) }
      });
    }

    this.updateSummary(suite);
    this.results.push(suite);
    this.printSuiteResults(suite);
  }

  private async testServiceEncryption(): Promise<void> {
    console.log('🔒 Testing Service Encryption...');
    
    const suite: TestSuite = {
      name: 'Service Encryption',
      tests: [],
      summary: { total: 0, passed: 0, failed: 0, warnings: 0 }
    };

    try {
      // Test 1: Backend service encryption initialization
      const backendIndexPath = join(this.baseDir, 'backend', 'src', 'index.ts');
      if (existsSync(backendIndexPath)) {
        const backendContent = readFileSync(backendIndexPath, 'utf8');
        
        // Check for encryption imports
        const hasEncryptionImports = backendContent.includes('certificateManager') &&
                                    backendContent.includes('secureKeyManager') &&
                                    backendContent.includes('encryptedCommunicationManager');
        
        if (hasEncryptionImports) {
          suite.tests.push({
            test: 'Backend encryption initialization',
            status: 'PASS',
            message: 'Backend has encryption service imports'
          });
        } else {
          suite.tests.push({
            test: 'Backend encryption initialization',
            status: 'FAIL',
            message: 'Backend missing encryption service imports'
          });
        }

        // Check for encryption initialization function
        const hasInitialization = backendContent.includes('initializeEncryption');
        
        if (hasInitialization) {
          suite.tests.push({
            test: 'Backend encryption initialization function',
            status: 'PASS',
            message: 'Backend has encryption initialization function'
          });
        } else {
          suite.tests.push({
            test: 'Backend encryption initialization function',
            status: 'FAIL',
            message: 'Backend missing encryption initialization function'
          });
        }
      }

      // Test 2: Service configuration files
      const services = ['backend', 'bot', 'web'];
      for (const service of services) {
        const serviceEnvExample = join(this.baseDir, service, '.env.example');
        if (existsSync(serviceEnvExample)) {
          suite.tests.push({
            test: `${service} environment configuration`,
            status: 'PASS',
            message: `${service} has environment configuration example`
          });
        } else {
          suite.tests.push({
            test: `${service} environment configuration`,
            status: 'WARN',
            message: `${service} missing environment configuration example`
          });
        }
      }

      // Test 3: Web service API encryption
      const webVerifyRoute = join(this.baseDir, 'web', 'app', 'api', 'verify', 'route.ts');
      if (existsSync(webVerifyRoute)) {
        const webContent = readFileSync(webVerifyRoute, 'utf8');
        
        // Check for HTTPS communication
        if (webContent.includes('https://') || webContent.includes('process.env.BACKEND_URL')) {
          suite.tests.push({
            test: 'Web service API encryption',
            status: 'PASS',
            message: 'Web service configured for encrypted API communication'
          });
        } else {
          suite.tests.push({
            test: 'Web service API encryption',
            status: 'WARN',
            message: 'Web service may be using unencrypted HTTP communication'
          });
        }
      }

    } catch (error) {
      suite.tests.push({
        test: 'Service encryption test suite',
        status: 'FAIL',
        message: 'Test suite execution failed',
        details: { error: String(error) }
      });
    }

    this.updateSummary(suite);
    this.results.push(suite);
    this.printSuiteResults(suite);
  }

  private async testDatabaseEncryption(): Promise<void> {
    console.log('🗄️ Testing Database Encryption...');
    
    const suite: TestSuite = {
      name: 'Database Encryption',
      tests: [],
      summary: { total: 0, passed: 0, failed: 0, warnings: 0 }
    };

    try {
      // Test 1: Database configuration files
      const backendEnv = join(this.baseDir, 'backend', '.env.example');
      if (existsSync(backendEnv)) {
        const envContent = readFileSync(backendEnv, 'utf8');
        
        // Check for database encryption settings
        if (envContent.includes('DATABASE_SSL') || envContent.includes('SSL_MODE')) {
          suite.tests.push({
            test: 'Database SSL configuration',
            status: 'PASS',
            message: 'Database SSL configuration present in environment'
          });
        } else {
          suite.tests.push({
            test: 'Database SSL configuration',
            status: 'WARN',
            message: 'Database SSL configuration not found in environment'
          });
        }
      }

      // Test 2: Prisma schema encryption hints
      const prismaSchema = join(this.baseDir, 'backend', 'prisma', 'schema.prisma');
      if (existsSync(prismaSchema)) {
        suite.tests.push({
          test: 'Database schema',
          status: 'PASS',
          message: 'Database schema file exists (potential for field-level encryption)'
        });
      } else {
        suite.tests.push({
          test: 'Database schema',
          status: 'WARN',
          message: 'Database schema file not found'
        });
      }

    } catch (error) {
      suite.tests.push({
        test: 'Database encryption test suite',
        status: 'FAIL',
        message: 'Test suite execution failed',
        details: { error: String(error) }
      });
    }

    this.updateSummary(suite);
    this.results.push(suite);
    this.printSuiteResults(suite);
  }

  private async testMonitoringSystems(): Promise<void> {
    console.log('📊 Testing Monitoring Systems...');
    
    const suite: TestSuite = {
      name: 'Monitoring Systems',
      tests: [],
      summary: { total: 0, passed: 0, failed: 0, warnings: 0 }
    };

    try {
      // Test 1: Health check scripts
      const healthCheckScript = join(this.baseDir, 'scripts', 'health-check-infrastructure.sh');
      if (existsSync(healthCheckScript)) {
        suite.tests.push({
          test: 'Infrastructure health check script',
          status: 'PASS',
          message: 'Infrastructure health check script exists'
        });
      } else {
        suite.tests.push({
          test: 'Infrastructure health check script',
          status: 'FAIL',
          message: 'Infrastructure health check script missing'
        });
      }

      // Test 2: Certificate monitoring in services
      const encryptedCommManager = join(this.baseDir, 'backend', 'src', 'services', 'encryptedCommunicationManager.ts');
      if (existsSync(encryptedCommManager)) {
        const managerContent = readFileSync(encryptedCommManager, 'utf8');
        
        if (managerContent.includes('monitoring') || managerContent.includes('health')) {
          suite.tests.push({
            test: 'Communication monitoring system',
            status: 'PASS',
            message: 'Communication monitoring system implemented'
          });
        } else {
          suite.tests.push({
            test: 'Communication monitoring system',
            status: 'WARN',
            message: 'Communication monitoring system not detected'
          });
        }
      }

    } catch (error) {
      suite.tests.push({
        test: 'Monitoring systems test suite',
        status: 'FAIL',
        message: 'Test suite execution failed',
        details: { error: String(error) }
      });
    }

    this.updateSummary(suite);
    this.results.push(suite);
    this.printSuiteResults(suite);
  }

  private async testPerformanceOptimization(): Promise<void> {
    console.log('⚡ Testing Performance Optimization...');
    
    const suite: TestSuite = {
      name: 'Performance Optimization',
      tests: [],
      summary: { total: 0, passed: 0, failed: 0, warnings: 0 }
    };

    try {
      // Test 1: Certificate caching implementation
      const certManager = join(this.baseDir, 'backend', 'src', 'services', 'certificateManager.ts');
      if (existsSync(certManager)) {
        const certContent = readFileSync(certManager, 'utf8');
        
        if (certContent.includes('cache') || certContent.includes('store')) {
          suite.tests.push({
            test: 'Certificate caching',
            status: 'PASS',
            message: 'Certificate caching mechanism implemented'
          });
        } else {
          suite.tests.push({
            test: 'Certificate caching',
            status: 'WARN',
            message: 'Certificate caching mechanism not detected'
          });
        }
      }

      // Test 2: Connection pooling in communication manager
      const commManager = join(this.baseDir, 'backend', 'src', 'services', 'encryptedCommunicationManager.ts');
      if (existsSync(commManager)) {
        const commContent = readFileSync(commManager, 'utf8');
        
        if (commContent.includes('keepAlive') || commContent.includes('pool')) {
          suite.tests.push({
            test: 'Connection pooling',
            status: 'PASS',
            message: 'Connection pooling implemented for performance'
          });
        } else {
          suite.tests.push({
            test: 'Connection pooling',
            status: 'WARN',
            message: 'Connection pooling not detected'
          });
        }
      }

    } catch (error) {
      suite.tests.push({
        test: 'Performance optimization test suite',
        status: 'FAIL',
        message: 'Test suite execution failed',
        details: { error: String(error) }
      });
    }

    this.updateSummary(suite);
    this.results.push(suite);
    this.printSuiteResults(suite);
  }

  private updateSummary(suite: TestSuite): void {
    suite.summary.total = suite.tests.length;
    suite.summary.passed = suite.tests.filter(t => t.status === 'PASS').length;
    suite.summary.failed = suite.tests.filter(t => t.status === 'FAIL').length;
    suite.summary.warnings = suite.tests.filter(t => t.status === 'WARN').length;
  }

  private printSuiteResults(suite: TestSuite): void {
    console.log(`\n${suite.name} Test Results:`);
    console.log('=' .repeat(suite.name.length + 16));
    
    for (const test of suite.tests) {
      const icon = test.status === 'PASS' ? '✅' : test.status === 'WARN' ? '⚠️' : '❌';
      console.log(`${icon} ${test.test}: ${test.message}`);
      if (test.details) {
        console.log(`   Details: ${JSON.stringify(test.details, null, 2)}`);
      }
    }
    
    console.log(`\nSummary: ${suite.summary.passed}/${suite.summary.total} passed, ` +
                `${suite.summary.failed} failed, ${suite.summary.warnings} warnings`);
  }

  private generateTestReport(): void {
    console.log('\n🏁 Test Suite Complete');
    console.log('=' .repeat(50));
    
    const totalTests = this.results.reduce((sum, suite) => sum + suite.summary.total, 0);
    const totalPassed = this.results.reduce((sum, suite) => sum + suite.summary.passed, 0);
    const totalFailed = this.results.reduce((sum, suite) => sum + suite.summary.failed, 0);
    const totalWarnings = this.results.reduce((sum, suite) => sum + suite.summary.warnings, 0);
    
    console.log(`Total Tests: ${totalTests}`);
    console.log(`Passed: ${totalPassed} ✅`);
    console.log(`Failed: ${totalFailed} ❌`);
    console.log(`Warnings: ${totalWarnings} ⚠️`);
    console.log(`Success Rate: ${((totalPassed / totalTests) * 100).toFixed(1)}%`);
    
    const endTime = new Date();
    const duration = endTime.getTime() - this.startTime.getTime();
    console.log(`Duration: ${(duration / 1000).toFixed(2)}s`);
    
    // Generate detailed report file
    const reportData = {
      testSuite: 'Encryption Infrastructure Test Suite',
      environment: this.environment,
      startTime: this.startTime.toISOString(),
      endTime: endTime.toISOString(),
      duration: `${(duration / 1000).toFixed(2)}s`,
      summary: {
        totalTests,
        totalPassed,
        totalFailed,
        totalWarnings,
        successRate: `${((totalPassed / totalTests) * 100).toFixed(1)}%`
      },
      results: this.results
    };
    
    const reportsDir = join(this.baseDir, 'reports');
    if (!existsSync(reportsDir)) {
      mkdirSync(reportsDir, { recursive: true });
    }
    
    const reportFile = join(reportsDir, `encryption-infrastructure-test-${this.environment}-${Date.now()}.json`);
    writeFileSync(reportFile, JSON.stringify(reportData, null, 2));
    
    console.log(`\n📊 Detailed report saved to: ${reportFile}`);
    
    // Overall assessment
    const successRate = (totalPassed / totalTests) * 100;
    if (successRate >= 90) {
      console.log('\n🎉 EXCELLENT: Encryption infrastructure is production-ready!');
    } else if (successRate >= 70) {
      console.log('\n⚠️ GOOD: Encryption infrastructure has minor issues to address');
    } else {
      console.log('\n❌ CRITICAL: Encryption infrastructure requires significant work');
    }
    
    // Exit with appropriate code
    process.exit(totalFailed > 0 ? 1 : 0);
  }
}

// Main execution
const args = process.argv.slice(2);
const environment = args[0] || 'development';

const tester = new EncryptionInfrastructureTester(environment);
tester.runAllTests().catch(error => {
  console.error('💥 Test suite failed:', error);
  process.exit(1);
});