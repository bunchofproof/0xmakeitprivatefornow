import { logger } from './logger';

export interface DatabaseOperationMetrics {
  operation: string;
  duration: number;
  success: boolean;
  timestamp: number;
  error?: string;
  recordCount?: number;
}

export interface PerformanceStats {
  totalOperations: number;
  successfulOperations: number;
  failedOperations: number;
  averageResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  operationsPerSecond: number;
  errorRate: number;
  lastUpdated: number;
}

export interface DatabaseHealthMetrics {
  connectionStatus: 'healthy' | 'degraded' | 'unhealthy';
  activeConnections: number;
  totalConnections: number;
  connectionPoolUtilization: number;
  memoryUsage: number;
  diskUsage?: number;
  lastHealthCheck: number;
}

/**
 * Performance monitoring for database operations
 */
export class DatabasePerformanceMonitor {
  private metrics: DatabaseOperationMetrics[] = [];
  private maxMetricsHistory = 10000; // Keep last 10k operations
  private statsWindowMs = 300000; // 5 minutes for rolling stats

  /**
   * Record a database operation
   */
  recordOperation(
    operation: string,
    duration: number,
    success: boolean,
    error?: string,
    recordCount?: number
  ): void {
    const metric: DatabaseOperationMetrics = {
      operation,
      duration,
      success,
      timestamp: Date.now(),
      error,
      recordCount
    };

    this.metrics.push(metric);

    // Maintain max history size
    if (this.metrics.length > this.maxMetricsHistory) {
      this.metrics.shift();
    }

    // Log significant performance issues
    if (duration > 5000) { // 5 seconds
      logger.warn(`Slow database operation: ${operation} took ${duration}ms`);
    } else if (!success) {
      logger.error(`Database operation failed: ${operation}`, error ? new Error(error) : undefined);
    }
  }

  /**
   * Get performance statistics
   */
  getPerformanceStats(): PerformanceStats {
    const now = Date.now();
    const windowStart = now - this.statsWindowMs;

    // Filter metrics within the time window
    const recentMetrics = this.metrics.filter(m => m.timestamp >= windowStart);

    if (recentMetrics.length === 0) {
      return {
        totalOperations: 0,
        successfulOperations: 0,
        failedOperations: 0,
        averageResponseTime: 0,
        p95ResponseTime: 0,
        p99ResponseTime: 0,
        operationsPerSecond: 0,
        errorRate: 0,
        lastUpdated: now
      };
    }

    const successfulOps = recentMetrics.filter(m => m.success);
    const failedOps = recentMetrics.filter(m => !m.success);

    const durations = recentMetrics.map(m => m.duration).sort((a, b) => a - b);
    const avgResponseTime = durations.reduce((sum, d) => sum + d, 0) / durations.length;

    const p95Index = Math.floor(durations.length * 0.95);
    const p99Index = Math.floor(durations.length * 0.99);

    const operationsPerSecond = recentMetrics.length / (this.statsWindowMs / 1000);
    const errorRate = failedOps.length / recentMetrics.length;

    return {
      totalOperations: recentMetrics.length,
      successfulOperations: successfulOps.length,
      failedOperations: failedOps.length,
      averageResponseTime: Math.round(avgResponseTime),
      p95ResponseTime: durations[p95Index] || 0,
      p99ResponseTime: durations[p99Index] || 0,
      operationsPerSecond: Math.round(operationsPerSecond * 100) / 100,
      errorRate: Math.round(errorRate * 10000) / 100, // Percentage with 2 decimal places
      lastUpdated: now
    };
  }

  /**
   * Get operation-specific metrics
   */
  getOperationMetrics(operation?: string): Record<string, PerformanceStats> {
    const now = Date.now();
    const windowStart = now - this.statsWindowMs;

    let filteredMetrics = this.metrics.filter(m => m.timestamp >= windowStart);
    if (operation) {
      filteredMetrics = filteredMetrics.filter(m => m.operation === operation);
    }

    // Group by operation
    const operationGroups: Record<string, DatabaseOperationMetrics[]> = {};
    for (const metric of filteredMetrics) {
      if (!operationGroups[metric.operation]) {
        operationGroups[metric.operation] = [];
      }
      operationGroups[metric.operation].push(metric);
    }

    const result: Record<string, PerformanceStats> = {};

    for (const [op, metrics] of Object.entries(operationGroups)) {
      const successfulOps = metrics.filter(m => m.success);
      const failedOps = metrics.filter(m => !m.success);

      const durations = metrics.map(m => m.duration).sort((a, b) => a - b);
      const avgResponseTime = durations.reduce((sum, d) => sum + d, 0) / durations.length;

      const p95Index = Math.floor(durations.length * 0.95);
      const p99Index = Math.floor(durations.length * 0.99);

      const operationsPerSecond = metrics.length / (this.statsWindowMs / 1000);
      const errorRate = failedOps.length / metrics.length;

      result[op] = {
        totalOperations: metrics.length,
        successfulOperations: successfulOps.length,
        failedOperations: failedOps.length,
        averageResponseTime: Math.round(avgResponseTime),
        p95ResponseTime: durations[p95Index] || 0,
        p99ResponseTime: durations[p99Index] || 0,
        operationsPerSecond: Math.round(operationsPerSecond * 100) / 100,
        errorRate: Math.round(errorRate * 10000) / 100,
        lastUpdated: now
      };
    }

    return result;
  }

  /**
   * Clear old metrics to free memory
   */
  cleanupOldMetrics(olderThanMs: number = 3600000): number { // 1 hour default
    const cutoffTime = Date.now() - olderThanMs;
    const oldCount = this.metrics.length;
    this.metrics = this.metrics.filter(m => m.timestamp >= cutoffTime);
    const removedCount = oldCount - this.metrics.length;

    if (removedCount > 0) {
      logger.debug(`Cleaned up ${removedCount} old performance metrics`);
    }

    return removedCount;
  }

  /**
   * Export metrics for external monitoring systems
   */
  exportMetrics(): {
    summary: PerformanceStats;
    byOperation: Record<string, PerformanceStats>;
    recentErrors: DatabaseOperationMetrics[];
  } {
    const summary = this.getPerformanceStats();
    const byOperation = this.getOperationMetrics();

    // Get recent errors (last 100)
    const recentErrors = this.metrics
      .filter(m => !m.success)
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, 100);

    return {
      summary,
      byOperation,
      recentErrors
    };
  }
}

/**
 * Database health checker
 */
export class DatabaseHealthChecker {
  private lastHealthCheck = 0;
  private healthCheckInterval = 30000; // 30 seconds

  /**
   * Perform a health check on the database
   */
  async performHealthCheck(
    testOperation: () => Promise<any>
  ): Promise<DatabaseHealthMetrics> {
    const now = Date.now();

    // Prevent too frequent health checks
    if (now - this.lastHealthCheck < this.healthCheckInterval) {
      return this.getCachedHealthMetrics();
    }

    this.lastHealthCheck = now;

    let connectionStatus: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
    let activeConnections = 0;
    let totalConnections = 1; // SQLite has 1 connection
    let connectionPoolUtilization = 0;
    let memoryUsage = 0;

    try {
      // Perform a simple test operation
      const startTime = Date.now();
      await testOperation();
      const responseTime = Date.now() - startTime;

      if (responseTime > 5000) { // 5 seconds
        connectionStatus = 'degraded';
      }

      activeConnections = 1;
      memoryUsage = process.memoryUsage().heapUsed;

    } catch (error) {
      connectionStatus = 'unhealthy';
      logger.error('Database health check failed:', error instanceof Error ? error : new Error(String(error)));
    }

    const metrics: DatabaseHealthMetrics = {
      connectionStatus,
      activeConnections,
      totalConnections,
      connectionPoolUtilization,
      memoryUsage,
      lastHealthCheck: now
    };

    this.cacheHealthMetrics(metrics);
    return metrics;
  }

  private cachedMetrics?: DatabaseHealthMetrics;

  private cacheHealthMetrics(metrics: DatabaseHealthMetrics): void {
    this.cachedMetrics = metrics;
  }

  private getCachedHealthMetrics(): DatabaseHealthMetrics {
    if (!this.cachedMetrics) {
      // Return default healthy metrics if no cache
      return {
        connectionStatus: 'healthy',
        activeConnections: 1,
        totalConnections: 1,
        connectionPoolUtilization: 0,
        memoryUsage: 0,
        lastHealthCheck: Date.now()
      };
    }
    return this.cachedMetrics;
  }
}

/**
 * Combined database monitoring system
 */
export class DatabaseMonitor {
  private performanceMonitor: DatabasePerformanceMonitor;
  private healthChecker: DatabaseHealthChecker;
  private monitoringEnabled: boolean;

  constructor(monitoringEnabled: boolean = true) {
    this.performanceMonitor = new DatabasePerformanceMonitor();
    this.healthChecker = new DatabaseHealthChecker();
    this.monitoringEnabled = monitoringEnabled;
  }

  /**
   * Record a database operation with timing
   */
  async recordOperation<T>(
    operation: string,
    operationFn: () => Promise<T>,
    recordCount?: number
  ): Promise<T> {
    if (!this.monitoringEnabled) {
      return operationFn();
    }

    const startTime = Date.now();
    let success = false;
    let error: string | undefined;

    try {
      const result = await operationFn();
      success = true;
      return result;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      throw e;
    } finally {
      const duration = Date.now() - startTime;
      this.performanceMonitor.recordOperation(operation, duration, success, error, recordCount);
    }
  }

  /**
   * Perform health check
   */
  async performHealthCheck(testOperation: () => Promise<any>): Promise<DatabaseHealthMetrics> {
    return this.healthChecker.performHealthCheck(testOperation);
  }

  /**
   * Get performance statistics
   */
  getPerformanceStats(): PerformanceStats {
    return this.performanceMonitor.getPerformanceStats();
  }

  /**
   * Get detailed metrics
   */
  getDetailedMetrics() {
    return this.performanceMonitor.exportMetrics();
  }

  /**
   * Clean up old metrics
   */
  cleanupOldMetrics(olderThanMs?: number): number {
    return this.performanceMonitor.cleanupOldMetrics(olderThanMs);
  }

  /**
   * Enable/disable monitoring
   */
  setMonitoringEnabled(enabled: boolean): void {
    this.monitoringEnabled = enabled;
  }
}

// Global database monitor instance
export const databaseMonitor = new DatabaseMonitor(
  process.env.NODE_ENV === 'production' || process.env.ENABLE_DATABASE_MONITORING === 'true'
);