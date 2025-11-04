import { IncomingMessage } from 'http';
import { WebSocket } from 'ws';
import { logger } from '../utils/logger';
import { rateLimitManager } from '../utils/rateLimitManager';
import crypto from 'crypto';

// WebSocket security configuration
interface WebSocketSecurityConfig {
  maxConnectionsPerIP: number;
  maxTotalConnections: number;
  connectionRateLimit: number; // connections per minute per IP
  messageSizeLimit: number; // bytes
  messageRateLimit: number; // messages per minute per connection
  connectionTimeout: number; // milliseconds
  authenticationTimeout: number; // milliseconds
  maxAuthAttempts: number;
}

interface WebSocketClientInfo {
  id: string;
  ip: string;
  userAgent?: string;
  connectedAt: number;
  lastActivity: number;
  messageCount: number;
  lastMessageAt: number;
  isAuthenticated: boolean;
  authToken?: string;
  authAttempts: number;
  isBlocked: boolean;
  blockReason?: string;
  blockedUntil?: number;
}

interface ConnectionAttempt {
  ip: string;
  timestamp: number;
}

class WebSocketSecurityManager {
  private clients: Map<string, WebSocketClientInfo> = new Map();
  private connectionAttempts: Map<string, ConnectionAttempt[]> = new Map();
  private blockedIPs: Map<string, { blockedUntil: number; reason: string }> = new Map();
  
  private config: WebSocketSecurityConfig;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    this.config = this.loadConfig();
    this.startCleanup();
  }

  private loadConfig(): WebSocketSecurityConfig {
    return {
      maxConnectionsPerIP: parseInt(process.env.WS_MAX_CONNECTIONS_PER_IP || '5'),
      maxTotalConnections: parseInt(process.env.WS_MAX_TOTAL_CONNECTIONS || '100'),
      connectionRateLimit: parseInt(process.env.WS_CONNECTION_RATE_LIMIT || '10'),
      messageSizeLimit: parseInt(process.env.WS_MESSAGE_SIZE_LIMIT || '1024'), // 1KB
      messageRateLimit: parseInt(process.env.WS_MESSAGE_RATE_LIMIT || '60'), // 60 per minute
      connectionTimeout: parseInt(process.env.WS_CONNECTION_TIMEOUT || '300000'), // 5 minutes
      authenticationTimeout: parseInt(process.env.WS_AUTH_TIMEOUT || '30000'), // 30 seconds
      maxAuthAttempts: parseInt(process.env.WS_MAX_AUTH_ATTEMPTS || '3'),
    };
  }

  /**
   * Validate and authorize new WebSocket connection
   */
  validateConnection(request: IncomingMessage): { allowed: boolean; reason?: string; clientId?: string } {
    try {
      const ip = this.getClientIP(request);
      const userAgent = request.headers['user-agent'];

      // Check if IP is blocked
      const blockInfo = this.blockedIPs.get(ip);
      if (blockInfo && blockInfo.blockedUntil > Date.now()) {
        return { 
          allowed: false, 
          reason: `IP blocked until ${new Date(blockInfo.blockedUntil).toISOString()}` 
        };
      }

      // Check total connection limit
      if (this.clients.size >= this.config.maxTotalConnections) {
        this.blockIP(ip, 'Total connection limit exceeded', 60000); // Block for 1 minute
        logger.warn(`WebSocket connection rejected: Total connection limit exceeded from ${ip}`);
        return { allowed: false, reason: 'Server at maximum capacity' };
      }

      // Check per-IP connection limit
      const ipConnections = this.getConnectionsByIP(ip);
      if (ipConnections.length >= this.config.maxConnectionsPerIP) {
        this.blockIP(ip, 'Per-IP connection limit exceeded', 120000); // Block for 2 minutes
        logger.warn(`WebSocket connection rejected: Per-IP limit exceeded from ${ip}`);
        return { allowed: false, reason: 'Too many connections from this IP' };
      }

      // Check connection rate limiting
      if (!this.checkConnectionRateLimit(ip)) {
        this.blockIP(ip, 'Connection rate limit exceeded', 300000); // Block for 5 minutes
        logger.warn(`WebSocket connection rejected: Rate limit exceeded from ${ip}`);
        return { allowed: false, reason: 'Connection rate limit exceeded' };
      }

      // Generate secure client ID
      const clientId = this.generateSecureClientId();

      // Record connection attempt
      this.recordConnectionAttempt(ip);

      logger.info(`WebSocket connection authorized: ${clientId} from ${ip}`);
      
      return { allowed: true, clientId };

    } catch (error) {
      logger.error('Error validating WebSocket connection:', error);
      return { allowed: false, reason: 'Validation error' };
    }
  }

  /**
   * Register new WebSocket client
   */
  registerClient(clientId: string, ip: string, userAgent?: string, authToken?: string): void {
    const clientInfo: WebSocketClientInfo = {
      id: clientId,
      ip,
      userAgent,
      connectedAt: Date.now(),
      lastActivity: Date.now(),
      messageCount: 0,
      lastMessageAt: 0,
      isAuthenticated: !!authToken,
      authToken,
      authAttempts: 0,
      isBlocked: false,
    };

    this.clients.set(clientId, clientInfo);
    logger.debug(`WebSocket client registered: ${clientId} from ${ip}`);
  }

  /**
   * Validate message from client
   */
  validateMessage(clientId: string, data: Buffer | ArrayBuffer | Buffer[] | string): { 
    allowed: boolean; 
    reason?: string; 
    sanitizedData?: string 
  } {
    try {
      const client = this.clients.get(clientId);
      if (!client) {
        return { allowed: false, reason: 'Client not found' };
      }

      // Check if client is blocked
      if (client.isBlocked) {
        return { allowed: false, reason: 'Client is blocked' };
      }

      // Check message size
      const dataSize = Buffer.isBuffer(data) ? data.length : Buffer.from(String(data)).length;
      if (dataSize > this.config.messageSizeLimit) {
        this.handleMessageSizeViolation(clientId, dataSize);
        return { allowed: false, reason: 'Message size exceeds limit' };
      }

      // Check message rate limiting
      if (!this.checkMessageRateLimit(clientId)) {
        this.handleMessageRateViolation(clientId);
        return { allowed: false, reason: 'Message rate limit exceeded' };
      }

      // Parse and validate message structure
      const messageStr = data.toString();
      let parsedMessage: any;
      
      try {
        parsedMessage = JSON.parse(messageStr);
      } catch {
        return { allowed: false, reason: 'Invalid JSON format' };
      }

      // Validate message structure
      const validation = this.validateMessageStructure(parsedMessage);
      if (!validation.valid) {
        return { allowed: false, reason: validation.reason };
      }

      // Sanitize message
      const sanitizedMessage = this.sanitizeMessage(parsedMessage);

      // Update client activity
      client.lastActivity = Date.now();
      client.messageCount++;
      client.lastMessageAt = Date.now();

      return { allowed: true, sanitizedData: JSON.stringify(sanitizedMessage) };

    } catch (error) {
      logger.error(`Error validating message from client ${clientId}:`, error);
      return { allowed: false, reason: 'Validation error' };
    }
  }

  /**
   * Handle client authentication
   */
  authenticateClient(clientId: string, authToken: string): { 
    success: boolean; 
    reason?: string; 
    expiresAt?: number 
  } {
    try {
      const client = this.clients.get(clientId);
      if (!client) {
        return { success: false, reason: 'Client not found' };
      }

      // Check if already authenticated
      if (client.isAuthenticated) {
        return { success: true };
      }

      // Validate authentication token
      const tokenValidation = this.validateAuthToken(authToken, client.ip);
      if (!tokenValidation.valid) {
        client.authAttempts++;
        
        if (client.authAttempts >= this.config.maxAuthAttempts) {
          this.blockClient(clientId, 'Too many authentication failures');
          logger.warn(`WebSocket client ${clientId} blocked for excessive auth attempts`);
        }

        return { success: false, reason: tokenValidation.reason };
      }

      // Authentication successful
      client.isAuthenticated = true;
      client.authToken = authToken;
      client.authAttempts = 0;

      const expiresAt = Date.now() + (24 * 60 * 60 * 1000); // 24 hours

      logger.info(`WebSocket client authenticated: ${clientId}`);
      return { success: true, expiresAt };

    } catch (error) {
      logger.error(`Error authenticating client ${clientId}:`, error);
      return { success: false, reason: 'Authentication error' };
    }
  }

  /**
   * Check if client is still active and should be kept alive
   */
  shouldKeepAlive(clientId: string): boolean {
    const client = this.clients.get(clientId);
    if (!client) return false;

    const now = Date.now();
    const timeSinceLastActivity = now - client.lastActivity;

    // Check connection timeout
    if (timeSinceLastActivity > this.config.connectionTimeout) {
      logger.info(`WebSocket client ${clientId} timed out after ${timeSinceLastActivity}ms`);
      return false;
    }

    // Check if unauthenticated client has exceeded auth timeout
    if (!client.isAuthenticated && timeSinceLastActivity > this.config.authenticationTimeout) {
      logger.info(`WebSocket client ${clientId} timed out during authentication after ${timeSinceLastActivity}ms`);
      return false;
    }

    return true;
  }

  /**
   * Get connection statistics
   */
  getStats() {
    const now = Date.now();
    const stats = {
      totalConnections: this.clients.size,
      authenticatedConnections: 0,
      unauthenticatedConnections: 0,
      blockedIPs: this.blockedIPs.size,
      connectionAttempts: 0,
      securityEvents: {
        blockedConnections: 0,
        rateLimitedConnections: 0,
        messageSizeViolations: 0,
        messageRateViolations: 0,
        authFailures: 0,
      }
    };

    for (const client of this.clients.values()) {
      if (client.isAuthenticated) {
        stats.authenticatedConnections++;
      } else {
        stats.unauthenticatedConnections++;
      }
    }

    // Count connection attempts in last minute
    for (const attempts of this.connectionAttempts.values()) {
      const recentAttempts = attempts.filter(a => now - a.timestamp < 60000);
      stats.connectionAttempts += recentAttempts.length;
    }

    return stats;
  }

  /**
   * Unregister client (cleanup)
   */
  unregisterClient(clientId: string): void {
    const client = this.clients.get(clientId);
    if (client) {
      this.clients.delete(clientId);
      logger.debug(`WebSocket client unregistered: ${clientId} from ${client.ip}`);
    }
  }

  // Private helper methods

  private getClientIP(request: IncomingMessage): string {
    return (
      request.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() ||
      request.headers['x-real-ip']?.toString() ||
      request.connection.remoteAddress ||
      request.socket.remoteAddress ||
      'unknown'
    );
  }

  private getConnectionsByIP(ip: string): string[] {
    const connections: string[] = [];
    for (const [clientId, client] of this.clients) {
      if (client.ip === ip) {
        connections.push(clientId);
      }
    }
    return connections;
  }

  private generateSecureClientId(): string {
    return `ws_${Date.now()}_${crypto.randomBytes(16).toString('hex')}`;
  }

  private checkConnectionRateLimit(ip: string): boolean {
    const attempts = this.connectionAttempts.get(ip) || [];
    const now = Date.now();
    const oneMinuteAgo = now - 60000;

    // Clean old attempts
    const recentAttempts = attempts.filter(a => a.timestamp > oneMinuteAgo);
    this.connectionAttempts.set(ip, recentAttempts);

    return recentAttempts.length < this.config.connectionRateLimit;
  }

  private recordConnectionAttempt(ip: string): void {
    const attempts = this.connectionAttempts.get(ip) || [];
    attempts.push({ ip, timestamp: Date.now() });
    this.connectionAttempts.set(ip, attempts);
  }

  private checkMessageRateLimit(clientId: string): boolean {
    const client = this.clients.get(clientId);
    if (!client) return false;

    const now = Date.now();
    const oneMinuteAgo = now - 60000;

    // Reset counter if enough time has passed
    if (client.lastMessageAt < oneMinuteAgo) {
      client.messageCount = 0;
      return true;
    }

    return client.messageCount < this.config.messageRateLimit;
  }

  private validateMessageStructure(message: any): { valid: boolean; reason?: string } {
    // Check if message is an object
    if (typeof message !== 'object' || message === null) {
      return { valid: false, reason: 'Message must be an object' };
    }

    // Check for required fields
    if (!message.type || typeof message.type !== 'string') {
      return { valid: false, reason: 'Message must have a string type field' };
    }

    // Validate allowed message types
    const allowedTypes = ['authenticate', 'subscribe', 'ping', 'unsubscribe'];
    if (!allowedTypes.includes(message.type)) {
      return { valid: false, reason: `Message type '${message.type}' is not allowed` };
    }

    // Check for suspicious patterns
    if (this.containsSuspiciousContent(message)) {
      return { valid: false, reason: 'Message contains suspicious content' };
    }

    return { valid: true };
  }

  private sanitizeMessage(message: any): any {
    // Deep sanitize message object
    const sanitized = JSON.parse(JSON.stringify(message));
    
    // Remove potentially dangerous fields
    this.removeDangerousFields(sanitized);
    
    return sanitized;
  }

  private removeDangerousFields(obj: any): void {
    if (typeof obj !== 'object' || obj === null) return;

    const dangerousFields = ['__proto__', 'constructor', 'prototype', 'global', 'window'];
    
    for (const key in obj) {
      if (dangerousFields.includes(key)) {
        delete obj[key];
      } else if (typeof obj[key] === 'object') {
        this.removeDangerousFields(obj[key]);
      }
    }
  }

  private containsSuspiciousContent(message: any): boolean {
    const jsonString = JSON.stringify(message).toLowerCase();
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /vbscript:/i,
      /onload=/i,
      /onerror=/i,
      /eval\(/i,
      /function\(/i,
      /process\./i,
      /require\(/i,
      /import\s+/i,
    ];

    return suspiciousPatterns.some(pattern => pattern.test(jsonString));
  }

  private validateAuthToken(token: string, ip: string): { valid: boolean; reason?: string } {
    // Token must be at least 32 characters and contain only valid characters
    if (!token || token.length < 32 || token.length > 256) {
      return { valid: false, reason: 'Invalid token format' };
    }

    // Token must contain only base64url characters
    const base64UrlRegex = /^[A-Za-z0-9_-]+$/;
    if (!base64UrlRegex.test(token)) {
      return { valid: false, reason: 'Invalid token characters' };
    }

    // In a real implementation, validate against stored tokens
    // For now, accept tokens that start with 'ws_' and are properly formatted
    if (!token.startsWith('ws_')) {
      return { valid: false, reason: 'Invalid token prefix' };
    }

    return { valid: true };
  }

  private handleMessageSizeViolation(clientId: string, size: number): void {
    const client = this.clients.get(clientId);
    if (client) {
      logger.warn(`WebSocket message size violation from ${clientId}: ${size} bytes (limit: ${this.config.messageSizeLimit})`);
      // Could implement progressive blocking here
    }
  }

  private handleMessageRateViolation(clientId: string): void {
    const client = this.clients.get(clientId);
    if (client) {
      logger.warn(`WebSocket message rate violation from ${clientId}`);
      // Could implement progressive throttling here
    }
  }

  private blockIP(ip: string, reason: string, duration: number): void {
    const blockedUntil = Date.now() + duration;
    this.blockedIPs.set(ip, { blockedUntil, reason });
    
    // Clean up old blocks periodically
    this.cleanupBlockedIPs();
  }

  private blockClient(clientId: string, reason: string): void {
    const client = this.clients.get(clientId);
    if (client) {
      client.isBlocked = true;
      client.blockReason = reason;
      client.blockedUntil = Date.now() + (60 * 60 * 1000); // Block for 1 hour
    }
  }

  private cleanupBlockedIPs(): void {
    const now = Date.now();
    for (const [ip, blockInfo] of this.blockedIPs.entries()) {
      if (blockInfo.blockedUntil <= now) {
        this.blockedIPs.delete(ip);
      }
    }
  }

  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanupBlockedIPs();
      this.cleanupStaleConnections();
      this.cleanupConnectionAttempts();
    }, 60000); // Run every minute
  }

  private cleanupStaleConnections(): void {
    const now = Date.now();
    const staleClients: string[] = [];

    for (const [clientId, client] of this.clients) {
      if (!this.shouldKeepAlive(clientId)) {
        staleClients.push(clientId);
      }
    }

    // Remove stale connections
    staleClients.forEach(clientId => {
      this.unregisterClient(clientId);
    });

    if (staleClients.length > 0) {
      logger.info(`Cleaned up ${staleClients.length} stale WebSocket connections`);
    }
  }

  private cleanupConnectionAttempts(): void {
    const now = Date.now();
    const oneHourAgo = now - (60 * 60 * 1000);

    for (const [ip, attempts] of this.connectionAttempts.entries()) {
      const recentAttempts = attempts.filter(a => a.timestamp > oneHourAgo);
      if (recentAttempts.length === 0) {
        this.connectionAttempts.delete(ip);
      } else {
        this.connectionAttempts.set(ip, recentAttempts);
      }
    }
  }

  /**
   * Shutdown the security manager
   */
  shutdown(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.clients.clear();
    this.connectionAttempts.clear();
    this.blockedIPs.clear();
    logger.info('WebSocket security manager shutdown complete');
  }
}

export const webSocketSecurityManager = new WebSocketSecurityManager();
export { WebSocketSecurityManager };
export type { WebSocketSecurityConfig, WebSocketClientInfo };