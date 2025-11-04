import { logger } from './logger';

export enum CircuitState {
  CLOSED = 'CLOSED',     // Normal operation
  OPEN = 'OPEN',         // Failing, reject all calls
  HALF_OPEN = 'HALF_OPEN' // Testing if service recovered
}

export interface CircuitBreakerConfig {
  failureThreshold: number;     // Number of failures before opening circuit
  recoveryTimeout: number;      // Time in ms before trying half-open
  monitoringPeriod: number;     // Time window for failure counting in ms
  successThreshold: number;     // Number of successes needed in half-open to close
}

export interface CircuitBreakerMetrics {
  state: CircuitState;
  failures: number;
  successes: number;
  lastFailureTime?: number;
  lastSuccessTime?: number;
  totalRequests: number;
  totalFailures: number;
  totalSuccesses: number;
}

/**
 * Circuit Breaker pattern implementation for graceful database backend degradation
 */
export class DatabaseCircuitBreaker {
  private config: CircuitBreakerConfig;
  private state: CircuitState = CircuitState.CLOSED;
  private failures: number = 0;
  private successes: number = 0;
  private lastFailureTime?: number;
  private lastSuccessTime?: number;
  private nextAttemptTime?: number;

  // Metrics tracking
  private totalRequests: number = 0;
  private totalFailures: number = 0;
  private totalSuccesses: number = 0;

  constructor(config: Partial<CircuitBreakerConfig> = {}) {
    this.config = {
      failureThreshold: 5,
      recoveryTimeout: 60000, // 1 minute
      monitoringPeriod: 300000, // 5 minutes
      successThreshold: 3,
      ...config
    };
  }

  /**
   * Execute a database operation with circuit breaker protection
   */
  async execute<T>(operation: () => Promise<T>): Promise<T> {
    this.totalRequests++;

    // Check if circuit should open due to timeout
    this.checkTimeout();

    if (this.state === CircuitState.OPEN) {
      if (Date.now() < (this.nextAttemptTime || 0)) {
        throw new Error('Circuit breaker is OPEN - database operations temporarily disabled');
      } else {
        // Time to try half-open
        this.state = CircuitState.HALF_OPEN;
        this.successes = 0;
        logger.info('Circuit breaker transitioning to HALF_OPEN state');
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  /**
   * Handle successful operation
   */
  private onSuccess(): void {
    this.totalSuccesses++;
    this.lastSuccessTime = Date.now();

    if (this.state === CircuitState.HALF_OPEN) {
      this.successes++;
      if (this.successes >= this.config.successThreshold) {
        this.closeCircuit();
      }
    } else if (this.state === CircuitState.CLOSED) {
      // Reset failure count on success in closed state
      this.failures = 0;
    }
  }

  /**
   * Handle failed operation
   */
  private onFailure(): void {
    this.totalFailures++;
    this.failures++;
    this.lastFailureTime = Date.now();

    // Check if we should open the circuit
    if (this.state === CircuitState.CLOSED && this.failures >= this.config.failureThreshold) {
      this.openCircuit();
    } else if (this.state === CircuitState.HALF_OPEN) {
      // Failure in half-open means service still not ready
      this.openCircuit();
    }
  }

  /**
   * Open the circuit breaker
   */
  private openCircuit(): void {
    this.state = CircuitState.OPEN;
    this.nextAttemptTime = Date.now() + this.config.recoveryTimeout;
    logger.warn(`Circuit breaker OPENED - database operations disabled for ${this.config.recoveryTimeout}ms`);
  }

  /**
   * Close the circuit breaker
   */
  private closeCircuit(): void {
    this.state = CircuitState.CLOSED;
    this.failures = 0;
    this.successes = 0;
    this.nextAttemptTime = undefined;
    logger.info('Circuit breaker CLOSED - database operations restored');
  }

  /**
   * Check if recovery timeout has passed
   */
  private checkTimeout(): void {
    if (this.state === CircuitState.OPEN && this.nextAttemptTime && Date.now() >= this.nextAttemptTime) {
      this.state = CircuitState.HALF_OPEN;
      this.successes = 0;
      logger.info('Circuit breaker transitioning to HALF_OPEN state after timeout');
    }
  }

  /**
   * Get current circuit breaker metrics
   */
  getMetrics(): CircuitBreakerMetrics {
    return {
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      lastFailureTime: this.lastFailureTime,
      lastSuccessTime: this.lastSuccessTime,
      totalRequests: this.totalRequests,
      totalFailures: this.totalFailures,
      totalSuccesses: this.totalSuccesses
    };
  }

  /**
   * Manually reset the circuit breaker
   */
  reset(): void {
    this.state = CircuitState.CLOSED;
    this.failures = 0;
    this.successes = 0;
    this.nextAttemptTime = undefined;
    logger.info('Circuit breaker manually reset');
  }

  /**
   * Force circuit breaker to open (for testing/emergency)
   */
  forceOpen(): void {
    this.state = CircuitState.OPEN;
    this.nextAttemptTime = Date.now() + this.config.recoveryTimeout;
    logger.warn('Circuit breaker forcibly opened');
  }

  /**
   * Check if circuit breaker allows operations
   */
  isAvailable(): boolean {
    this.checkTimeout();
    return this.state !== CircuitState.OPEN;
  }

  /**
   * Get current state
   */
  getState(): CircuitState {
    return this.state;
  }
}

/**
 * Database-specific circuit breaker with enhanced error handling
 */
export class DatabaseCircuitBreakerManager {
  private primaryBreaker: DatabaseCircuitBreaker;
  private fallbackBreaker: DatabaseCircuitBreaker;

  constructor() {
    this.primaryBreaker = new DatabaseCircuitBreaker({
      failureThreshold: 3,      // Fail after 3 consecutive errors
      recoveryTimeout: 30000,   // Wait 30 seconds before retry
      monitoringPeriod: 300000, // 5 minute monitoring window
      successThreshold: 2       // Need 2 successes to close
    });

    this.fallbackBreaker = new DatabaseCircuitBreaker({
      failureThreshold: 10,     // More tolerant for fallback
      recoveryTimeout: 60000,   // Longer recovery time
      monitoringPeriod: 600000, // 10 minute window
      successThreshold: 5       // Need more successes for fallback
    });
  }

  /**
   * Execute primary database operation with circuit breaker
   */
  async executePrimary<T>(operation: () => Promise<T>): Promise<T> {
    return this.primaryBreaker.execute(operation);
  }

  /**
   * Execute fallback database operation with circuit breaker
   */
  async executeFallback<T>(operation: () => Promise<T>): Promise<T> {
    return this.fallbackBreaker.execute(operation);
  }

  /**
   * Execute operation with primary/fallback logic
   */
  async executeWithFallback<T>(
    primaryOperation: () => Promise<T>,
    fallbackOperation: () => Promise<T>
  ): Promise<T> {
    try {
      return await this.executePrimary(primaryOperation);
    } catch (primaryError) {
      logger.warn('Primary database operation failed, attempting fallback:', primaryError instanceof Error ? primaryError.message : String(primaryError));

      try {
        return await this.executeFallback(fallbackOperation);
      } catch (fallbackError) {
        logger.error('Both primary and fallback database operations failed');
        throw new Error('Database operations unavailable - both primary and fallback systems are failing');
      }
    }
  }

  /**
   * Get metrics for both circuit breakers
   */
  getMetrics() {
    return {
      primary: this.primaryBreaker.getMetrics(),
      fallback: this.fallbackBreaker.getMetrics()
    };
  }

  /**
   * Check if primary database is available
   */
  isPrimaryAvailable(): boolean {
    return this.primaryBreaker.isAvailable();
  }

  /**
   * Check if fallback database is available
   */
  isFallbackAvailable(): boolean {
    return this.fallbackBreaker.isAvailable();
  }

  /**
   * Reset both circuit breakers
   */
  reset(): void {
    this.primaryBreaker.reset();
    this.fallbackBreaker.reset();
    logger.info('All circuit breakers reset');
  }
}

// Global circuit breaker instance
export const databaseCircuitBreaker = new DatabaseCircuitBreakerManager();