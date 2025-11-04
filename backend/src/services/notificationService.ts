import WebSocket, { WebSocketServer } from 'ws';
import { IncomingMessage } from 'http';
import { logger } from '../utils/logger';
import { discordService } from './discordService';
import { webSocketSecurityManager } from './webSocketSecurity';

interface WebSocketClient {
  ws: WebSocket;
  userId?: string;
  isAlive: boolean;
  lastPing: number;
  securityValidated: boolean;
  ip: string;
}

interface VerificationUpdate {
  discordUserId: string;
  status: 'pending' | 'completed' | 'failed' | 'expired';
  verified?: boolean;
  uniqueIdentifier?: string;
  timestamp?: Date;
}

class NotificationService {
  private clients: Map<string, WebSocketClient> = new Map();
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    this.startHeartbeat();
    this.startCleanup();
    this.startSecurityCleanup();
  }

  /**
   * Initialize WebSocket server
   */
  initializeWebSocketServer(_wss: WebSocketServer) {
    logger.info('Notification service WebSocket server initialized');
  }

  /**
   * Handle new WebSocket connection
   */
  handleConnection(ws: WebSocket, request: IncomingMessage) {
    try {
      // Use security manager to validate connection
      const validation = webSocketSecurityManager.validateConnection(request);
      
      if (!validation.allowed) {
        logger.warn(`WebSocket connection rejected: ${validation.reason}`);
        ws.close(1008, validation.reason || 'Connection not allowed');
        return;
      }

      const clientId = validation.clientId!;
      const ip = webSocketSecurityManager['getClientIP'](request); // Access private method for logging
      
      const client: WebSocketClient = {
        ws,
        isAlive: true,
        lastPing: Date.now(),
        securityValidated: true,
        ip,
      };

      // Register client with security manager
      webSocketSecurityManager.registerClient(clientId, ip, request.headers['user-agent']);

      this.clients.set(clientId, client);
      logger.info(`WebSocket client connected securely: ${clientId} from ${ip}`);

      // Set up event handlers with security checks
      ws.on('pong', () => {
        client.isAlive = true;
        client.lastPing = Date.now();
      });

      ws.on('message', (data) => {
        this.handleMessageWithSecurity(clientId, data);
      });

      ws.on('close', () => {
        this.handleDisconnection(clientId);
      });

      ws.on('error', (error) => {
        logger.error(`WebSocket client ${clientId} error:`, error);
        this.handleDisconnection(clientId);
      });

      // Send welcome message
      this.sendToClient(clientId, {
        type: 'connected',
        clientId,
        timestamp: new Date().toISOString(),
        requiresAuth: true,
      });

    } catch (error) {
      logger.error('Error handling WebSocket connection:', error);
      ws.close(1011, 'Internal server error');
    }
  }

  /**
   * Handle incoming WebSocket messages with security validation
   */
  private handleMessageWithSecurity(clientId: string, data: Buffer | ArrayBuffer | Buffer[] | string) {
    try {
      // Validate message with security manager
      const validation = webSocketSecurityManager.validateMessage(clientId, data);
      
      if (!validation.allowed) {
        logger.warn(`WebSocket message rejected from ${clientId}: ${validation.reason}`);
        this.sendToClient(clientId, {
          type: 'error',
          message: validation.reason || 'Message rejected',
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const message = JSON.parse(validation.sanitizedData!);
      const client = this.clients.get(clientId);

      if (!client) {
        return;
      }

      switch (message.type) {
        case 'authenticate':
          this.handleAuthenticationSecure(clientId, message.token);
          break;

        case 'subscribe':
          this.handleSubscriptionSecure(clientId, message.channel);
          break;

        case 'ping':
          this.sendToClient(clientId, { type: 'pong' });
          break;

        default:
          logger.warn(`Unknown message type from client ${clientId}:`, message.type);
      }

    } catch (error) {
      logger.error(`Error handling WebSocket message from client ${clientId}:`, error);
      this.sendToClient(clientId, {
        type: 'error',
        message: 'Message processing error',
        timestamp: new Date().toISOString(),
      });
    }
  }

  /**
   * Handle client authentication with security validation
   */
  private handleAuthenticationSecure(clientId: string, token: string) {
    const client = this.clients.get(clientId);
    if (!client) {
      return;
    }

    // Validate authentication with security manager
    const authResult = webSocketSecurityManager.authenticateClient(clientId, token);
    
    if (!authResult.success) {
      logger.warn(`WebSocket authentication failed for ${clientId}: ${authResult.reason}`);
      this.sendToClient(clientId, {
        type: 'auth_error',
        message: authResult.reason || 'Authentication failed',
        timestamp: new Date().toISOString(),
      });
      return;
    }

    // Update client with user ID from token (in real implementation, decode token)
    client.userId = `user_${clientId.substring(3, 10)}`; // Extract from token for demo
    client.isAlive = true; // Reset alive status on successful auth
    
    logger.info(`WebSocket client authenticated: ${clientId} as ${client.userId}`);

    this.sendToClient(clientId, {
      type: 'authenticated',
      userId: client.userId,
      expiresAt: authResult.expiresAt,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Handle subscription requests with security checks
   */
  private handleSubscriptionSecure(clientId: string, channel: string) {
    const client = this.clients.get(clientId);
    if (!client) {
      return;
    }

    // Check if client is authenticated
    if (!client.userId) {
      this.sendToClient(clientId, {
        type: 'error',
        message: 'Authentication required before subscribing',
        timestamp: new Date().toISOString(),
      });
      return;
    }

    // Validate channel (whitelist approach)
    const allowedChannels = ['verification_updates', 'admin_notifications'];
    if (!allowedChannels.includes(channel)) {
      logger.warn(`WebSocket client ${clientId} attempted to subscribe to unauthorized channel: ${channel}`);
      this.sendToClient(clientId, {
        type: 'error',
        message: 'Channel not authorized',
        timestamp: new Date().toISOString(),
      });
      return;
    }

    logger.info(`WebSocket client ${clientId} subscribed to channel: ${channel}`);

    this.sendToClient(clientId, {
      type: 'subscribed',
      channel,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Handle client authentication
   */
  private handleAuthentication(clientId: string, userId: string) {
    const client = this.clients.get(clientId);
    if (client) {
      client.userId = userId;
      logger.info(`WebSocket client ${clientId} authenticated as user ${userId}`);

      this.sendToClient(clientId, {
        type: 'authenticated',
        userId,
        timestamp: new Date().toISOString(),
      });
    }
  }

  /**
   * Handle subscription requests
   */
  private handleSubscription(clientId: string, channel: string) {
    logger.info(`WebSocket client ${clientId} subscribed to channel: ${channel}`);

    this.sendToClient(clientId, {
      type: 'subscribed',
      channel,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Handle client disconnection
   */
  private handleDisconnection(clientId: string) {
    this.clients.delete(clientId);
    logger.info(`WebSocket client disconnected: ${clientId}`);
  }

  /**
   * Send message to specific client
   */
  private sendToClient(clientId: string, message: any) {
    const client = this.clients.get(clientId);
    if (client && client.ws.readyState === WebSocket.OPEN) {
      try {
        client.ws.send(JSON.stringify(message));
      } catch (error) {
        logger.error(`Error sending message to client ${clientId}:`, error);
        this.handleDisconnection(clientId);
      }
    }
  }

  /**
   * Broadcast message to all connected clients
   */
  broadcast(message: any) {
    const messageStr = JSON.stringify({
      ...message,
      timestamp: new Date().toISOString(),
    });

    let sentCount = 0;
    for (const [clientId, client] of this.clients) {
      if (client.ws.readyState === WebSocket.OPEN) {
        try {
          client.ws.send(messageStr);
          sentCount++;
        } catch (error) {
          logger.error(`Error broadcasting to client ${clientId}:`, error);
          this.clients.delete(clientId);
        }
      }
    }

    logger.debug(`Broadcast message sent to ${sentCount} clients`);
  }

  /**
   * Broadcast verification update to relevant clients
   */
  broadcastVerificationUpdate(update: VerificationUpdate) {
    const message = {
      type: 'verification_update',
      data: {
        ...update,
        timestamp: new Date(),
      },
    };

    // Send to specific user if they're connected
    if (update.discordUserId) {
      for (const [, client] of this.clients) {
        if (client.userId === update.discordUserId && client.ws.readyState === WebSocket.OPEN) {
          try {
            client.ws.send(JSON.stringify(message));
          } catch (error) {
            logger.error(`Error sending verification update to user ${update.discordUserId}:`, error);
          }
        }
      }
    }

    // Also broadcast to all clients for general notifications
    this.broadcast(message);
  }

  /**
   * Send verification success notification
   */
  async sendVerificationSuccess(discordUserId: string): Promise<boolean> {
    try {
      // Send Discord DM
      const discordSuccess = await discordService.sendVerificationSuccessMessage(discordUserId);

      // Broadcast WebSocket update
      this.broadcastVerificationUpdate({
        discordUserId,
        status: 'completed',
        verified: true,
        timestamp: new Date(),
      });

      return discordSuccess;
    } catch (error) {
      logger.error(`Error sending verification success notification to user ${discordUserId}:`, error);
      return false;
    }
  }

  /**
   * Send verification failure notification
   */
  async sendVerificationFailure(discordUserId: string, reason?: string): Promise<boolean> {
    try {
      // Send Discord DM
      const discordSuccess = await discordService.sendVerificationFailureMessage(discordUserId, reason);

      // Broadcast WebSocket update
      this.broadcastVerificationUpdate({
        discordUserId,
        status: 'failed',
        verified: false,
        timestamp: new Date(),
      });

      return discordSuccess;
    } catch (error) {
      logger.error(`Error sending verification failure notification to user ${discordUserId}:`, error);
      return false;
    }
  }

  /**
   * Generate unique client ID
   */
  private generateClientId(): string {
    return `ws_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  }

  /**
   * Start heartbeat mechanism to detect dead connections
   */
  private startHeartbeat() {
    this.heartbeatInterval = setInterval(() => {
      const now = Date.now();
      
      for (const [clientId, client] of this.clients) {
        // Use security manager to check if connection should be kept alive
        if (!webSocketSecurityManager.shouldKeepAlive(clientId)) {
          logger.info(`Terminating inactive WebSocket client: ${clientId}`);
          client.ws.terminate();
          this.clients.delete(clientId);
          webSocketSecurityManager.unregisterClient(clientId);
          continue;
        }

        if (!client.isAlive) {
          logger.info(`Terminating dead WebSocket client: ${clientId}`);
          client.ws.terminate();
          this.clients.delete(clientId);
          webSocketSecurityManager.unregisterClient(clientId);
          continue;
        }

        client.isAlive = false;
        if (client.ws.readyState === WebSocket.OPEN) {
          try {
            client.ws.ping();
          } catch (error) {
            logger.error(`Error sending ping to client ${clientId}:`, error);
            this.clients.delete(clientId);
            webSocketSecurityManager.unregisterClient(clientId);
          }
        }
      }
    }, 30000); // Ping every 30 seconds
  }

  /**
   * Start cleanup mechanism for old connections
   */
  private startCleanup() {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      const maxAge = 24 * 60 * 60 * 1000; // 24 hours

      for (const [clientId, client] of this.clients) {
        if (now - client.lastPing > maxAge) {
          logger.info(`Cleaning up old WebSocket client: ${clientId}`);
          client.ws.close();
          this.clients.delete(clientId);
          webSocketSecurityManager.unregisterClient(clientId);
        }
      }
    }, 60 * 60 * 1000); // Cleanup every hour
  }

  /**
   * Start security cleanup mechanism
   */
  private startSecurityCleanup() {
    setInterval(() => {
      const stats = webSocketSecurityManager.getStats();
      if (stats.securityEvents.blockedConnections > 0 ||
          stats.securityEvents.rateLimitedConnections > 0 ||
          stats.securityEvents.messageSizeViolations > 0 ||
          stats.securityEvents.messageRateViolations > 0) {
        
        logger.info('WebSocket Security Stats:', {
          totalConnections: stats.totalConnections,
          blockedIPs: stats.blockedIPs,
          securityEvents: stats.securityEvents
        });
      }
    }, 5 * 60 * 1000); // Log security stats every 5 minutes
  }

  /**
   * Get connection statistics including security metrics
   */
  getStats() {
    let activeConnections = 0;
    let authenticatedUsers = 0;

    for (const client of this.clients.values()) {
      if (client.ws.readyState === WebSocket.OPEN) {
        activeConnections++;
        if (client.userId) {
          authenticatedUsers++;
        }
      }
    }

    // Get security statistics from security manager
    const securityStats = webSocketSecurityManager.getStats();

    return {
      totalConnections: this.clients.size,
      activeConnections,
      authenticatedUsers,
      uptime: process.uptime(),
      security: {
        ...securityStats,
        securityEnabled: true,
        version: '2.0.0-secure'
      }
    };
  }

  /**
   * Gracefully shutdown the notification service
   */
  async shutdown() {
    logger.info('Shutting down notification service...');

    // Clear intervals
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    // Close all connections
    for (const [clientId, client] of this.clients) {
      try {
        client.ws.close(1000, 'Server shutdown');
      } catch (error) {
        logger.error(`Error closing WebSocket client ${clientId}:`, error);
      }
    }

    // Shutdown security manager
    webSocketSecurityManager.shutdown();

    this.clients.clear();
    logger.info('Notification service shutdown complete');
  }
}

// Export singleton instance
export const notificationService = new NotificationService();

// Export WebSocket handler function for the main server
export function handleWebSocketConnection(ws: WebSocket, request: IncomingMessage) {
  notificationService.handleConnection(ws, request);
}