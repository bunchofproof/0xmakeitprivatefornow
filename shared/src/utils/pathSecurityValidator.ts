/**
 * Path Security Validator - Citadel 2.0 Security Module
 * 
 * This module provides comprehensive path validation and canonicalization
 * to prevent path traversal attacks and ensure file operations remain
 * within allowed directory boundaries.
 * 
 * Security Features:
 * - Path normalization and canonicalization
 * - Directory boundary enforcement
 * - Invalid character filtering
 * - Null byte injection prevention
 * - Security event logging
 */

import * as path from 'path';
import { auditLogger } from '../services/auditLogger';

export interface PathValidationResult {
  isValid: boolean;
  sanitizedPath?: string;
  canonicalPath?: string;
  error?: string;
  securityViolation?: boolean;
}

export interface PathSecurityConfig {
  allowedBases: string[];
  maxPathLength: number;
  allowedExtensions: string[];
  blockAbsolutePaths: boolean;
  blockDeviceFiles: boolean;
}

/**
 * Default security configuration
 */
const DEFAULT_CONFIG: PathSecurityConfig = {
  allowedBases: [
    path.join(process.cwd(), 'logs'),
    path.join(process.cwd(), 'data'),
    path.join(process.cwd(), 'temp'),
    path.join(process.cwd(), 'uploads')
  ],
  maxPathLength: 4096,
  allowedExtensions: ['.log', '.json', '.jsonl', '.tmp', '.lock', '.txt', '.csv'],
  blockAbsolutePaths: true,
  blockDeviceFiles: true
};

/**
 * Security violation types for audit logging
 */
export type SecurityViolationType = 
  | 'path_traversal_attempt'
  | 'absolute_path_blocked'
  | 'invalid_characters'
  | 'null_byte_injection'
  | 'device_file_access'
  | 'path_too_long'
  | 'forbidden_extension'
  | 'unauthorized_base_directory';

/**
 * Comprehensive path security validator
 */
export class PathSecurityValidator {
  private config: PathSecurityConfig;

  constructor(config?: Partial<PathSecurityConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.normalizeAllowedBases();
  }

  /**
   * Validate and sanitize a file path
   * @param inputPath - The path to validate
   * @param allowedBase - The base directory this path must be within
   * @returns Validation result with sanitized path if valid
   */
  validatePath(inputPath: string, allowedBase: string): PathValidationResult {
    try {
      // 1. Check for null bytes and control characters
      if (this.containsInvalidCharacters(inputPath)) {
        this.logSecurityViolation('null_byte_injection', inputPath);
        return {
          isValid: false,
          error: 'Path contains invalid characters',
          securityViolation: true
        };
      }

      // 2. Normalize the path
      const normalizedPath = path.normalize(inputPath);
      
      // 3. Check path length
      if (normalizedPath.length > this.config.maxPathLength) {
        this.logSecurityViolation('path_too_long', inputPath);
        return {
          isValid: false,
          error: 'Path exceeds maximum length',
          securityViolation: true
        };
      }

      // 4. Block absolute paths if configured
      if (this.config.blockAbsolutePaths && path.isAbsolute(normalizedPath)) {
        this.logSecurityViolation('absolute_path_blocked', inputPath);
        return {
          isValid: false,
          error: 'Absolute paths are not allowed',
          securityViolation: true
        };
      }

      // 5. Check for path traversal attempts
      if (this.containsPathTraversal(normalizedPath)) {
        this.logSecurityViolation('path_traversal_attempt', inputPath);
        return {
          isValid: false,
          error: 'Path traversal sequences not allowed',
          securityViolation: true
        };
      }

      // 6. Block device files on Windows
      if (this.config.blockDeviceFiles && this.isDeviceFile(normalizedPath)) {
        this.logSecurityViolation('device_file_access', inputPath);
        return {
          isValid: false,
          error: 'Device file access not allowed',
          securityViolation: true
        };
      }

      // 7. Canonicalize the path to resolve symbolic links and relative components
      const canonicalPath = this.canonicalizePath(normalizedPath, allowedBase);
      
      // 8. Verify the canonical path is within allowed base
      if (!this.isWithinBase(canonicalPath, allowedBase)) {
        this.logSecurityViolation('unauthorized_base_directory', inputPath);
        return {
          isValid: false,
          error: 'Path is outside allowed directory',
          securityViolation: true
        };
      }

      // 9. Check file extensions if specified
      if (!this.hasAllowedExtension(canonicalPath)) {
        this.logSecurityViolation('forbidden_extension', inputPath);
        return {
          isValid: false,
          error: 'File extension not allowed',
          securityViolation: true
        };
      }

      return {
        isValid: true,
        sanitizedPath: canonicalPath,
        canonicalPath
      };

    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      this.logSecurityViolation('invalid_characters', inputPath);
      return {
        isValid: false,
        error: `Path validation failed: ${err.message}`,
        securityViolation: true
      };
    }
  }

  /**
   * Quick safety check for paths
   * @param inputPath - Path to check
   * @param allowedBase - Base directory
   * @returns True if path is safe
   */
  isPathSafe(inputPath: string, allowedBase: string): boolean {
    const result = this.validatePath(inputPath, allowedBase);
    return result.isValid;
  }

  /**
   * Get the relative path within the base directory (for path joining)
   * @param inputPath - Path to check
   * @param allowedBase - Base directory
   * @returns Relative path safe for joining, or null if invalid
   */
  getRelativePath(inputPath: string, allowedBase: string): string | null {
    const result = this.validatePath(inputPath, allowedBase);
    if (!result.isValid) return null;
    
    // If the sanitized path is absolute, convert to relative for safe joining
    if (path.isAbsolute(result.sanitizedPath!)) {
      const relative = path.relative(allowedBase, result.sanitizedPath!);
      return relative.startsWith('..') ? path.basename(result.sanitizedPath!) : relative;
    }
    
    return result.sanitizedPath!;
  }

  /**
   * Sanitize a path by removing dangerous components
   * @param inputPath - Path to sanitize
   * @returns Sanitized path
   */
  sanitizePath(inputPath: string): string {
    // Remove null bytes and control characters
    let sanitized = inputPath.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
    
    // Remove path traversal sequences
    sanitized = sanitized.replace(/\.\.[/\\]/g, '');
    
    // Normalize path separators
    sanitized = path.normalize(sanitized);
    
    // Remove any remaining traversal attempts
    sanitized = sanitized.replace(/^[.][/\\]/, '');
    
    return sanitized;
  }

  /**
   * Canonicalize path and ensure it's within base directory
   * @param inputPath - Path to canonicalize
   * @param allowedBase - Base directory
   * @returns Canonical path
   */
  canonicalizePath(inputPath: string, allowedBase: string): string {
    // Combine with base directory
    const combinedPath = path.join(allowedBase, inputPath);
    
    // Resolve to absolute path and normalize
    let canonical = path.resolve(combinedPath);
    
    // Normalize to remove redundant separators and resolve . and ..
    canonical = path.normalize(canonical);
    
    return canonical;
  }

  /**
   * Check if a path is within the allowed base directory
   * @param canonicalPath - Canonical path to check
   * @param allowedBase - Base directory
   * @returns True if path is within base
   */
  private isWithinBase(canonicalPath: string, allowedBase: string): boolean {
    try {
      const relative = path.relative(allowedBase, canonicalPath);
      
      // If relative path starts with '..' or is absolute, it's outside
      return !relative.startsWith('..') && !path.isAbsolute(relative);
    } catch {
      return false;
    }
  }

  /**
   * Check for path traversal sequences in path
   * @param inputPath - Path to check
   * @returns True if traversal sequences found
   */
  private containsPathTraversal(inputPath: string): boolean {
    // Check for .. sequences
    if (inputPath.includes('..')) {
      return true;
    }
    
    // Check for URL encoded traversal sequences
    if (inputPath.includes('%2e%2e') || inputPath.includes('%252e%252e')) {
      return true;
    }
    
    // Check for double URL encoded traversal
    if (inputPath.includes('..%2f') || inputPath.includes('..%5c') ||
        inputPath.includes('%2f..') || inputPath.includes('%5c..')) {
      return true;
    }
    
    // Check for null byte injection attempts
    if (inputPath.includes('\0') || inputPath.includes('%00')) {
      return true;
    }
    
    return false;
  }

  /**
   * Check for invalid characters in path
   * @param inputPath - Path to check
   * @returns True if invalid characters found
   */
  private containsInvalidCharacters(inputPath: string): boolean {
    // Check for null bytes and control characters
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(inputPath)) {
      return true;
    }
    
    // Check for control characters
    if (/[\x80-\xFF]/.test(inputPath)) {
      return true;
    }
    
    return false;
  }

  /**
   * Check if path refers to a device file (Windows)
   * @param inputPath - Path to check
   * @returns True if device file detected
   */
  private isDeviceFile(inputPath: string): boolean {
    const lowerPath = inputPath.toLowerCase();
    
    // Windows device files that should never be accessible
    const deviceFiles = [
      'con', 'conin$', 'conout$',
      'prn', 'aux', 'nul',
      'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
      'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
      'clock$'
    ];
    
    return deviceFiles.some(device => lowerPath.startsWith(device + path.sep) || lowerPath === device);
  }

  /**
   * Check if file has allowed extension
   * @param filePath - Path to check
   * @returns True if extension is allowed
   */
  private hasAllowedExtension(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return this.config.allowedExtensions.includes(ext);
  }

  /**
   * Normalize allowed base directories
   */
  private normalizeAllowedBases(): void {
    this.config.allowedBases = this.config.allowedBases.map(base => 
      path.resolve(base)
    );
  }

  /**
   * Log security violations for audit trail
   * @param violationType - Type of violation
   * @param details - Additional details about the violation
   */
  private logSecurityViolation(violationType: SecurityViolationType, details: string): void {
    try {
      auditLogger.logSecurityEvent('path_traversal_security_violation', {
        violationType,
        originalPath: details,
        timestamp: new Date().toISOString(),
        processId: process.pid,
        userId: 'system'
      });
    } catch (error) {
      // If audit logging fails, at least log to console for debugging
      console.error(`[SECURITY] Path validation violation: ${violationType}`, error);
    }
  }

  /**
   * Get configuration for testing/debugging
   */
  getConfig(): PathSecurityConfig {
    return { ...this.config };
  }

  /**
   * Add an allowed base directory at runtime
   * @param basePath - Base directory to add
   */
  addAllowedBase(basePath: string): void {
    const normalized = path.resolve(basePath);
    if (!this.config.allowedBases.includes(normalized)) {
      this.config.allowedBases.push(normalized);
      this.normalizeAllowedBases();
    }
  }

  /**
   * Update configuration at runtime
   * @param configUpdates - Configuration updates to apply
   */
  updateConfig(configUpdates: Partial<PathSecurityConfig>): void {
    this.config = { ...this.config, ...configUpdates };
    this.normalizeAllowedBases();
  }
}

// Export singleton instance with default configuration
export const pathValidator = new PathSecurityValidator();

// Export default class for custom configurations
export default PathSecurityValidator;