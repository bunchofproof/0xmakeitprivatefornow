#!/bin/bash

# ZK Discord Verifier - Monitoring Setup Script
# Usage: ./deploy/monitoring.sh [action]

set -e

ACTION=${1:-setup}
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "📊 ZK Discord Verifier Monitoring Setup"
echo "Action: $ACTION"
echo "Project Root: $PROJECT_ROOT"

case $ACTION in
    "setup")
        echo "🔧 Setting up monitoring and health checks..."
        setup_monitoring
        ;;
    "check")
        echo "🔍 Checking system health..."
        check_system_health
        ;;
    "logs")
        echo "📋 Collecting system logs..."
        collect_logs
        ;;
    "cleanup")
        echo "🧹 Cleaning up old logs..."
        cleanup_logs
        ;;
    *)
        echo "❌ Unknown action: $ACTION"
        echo "Available actions: setup, check, logs, cleanup"
        exit 1
        ;;
esac

setup_monitoring() {
    echo "📊 Setting up monitoring infrastructure..."

    # Create monitoring directory
    mkdir -p "$PROJECT_ROOT/monitoring"

    # Create health check script
    cat > "$PROJECT_ROOT/monitoring/health-check.sh" << 'EOF'
#!/bin/bash
# Health check script for ZK Discord Verifier

set -e

echo "🔍 ZK Discord Verifier Health Check"
echo "Timestamp: $(date)"
echo

# Check Docker services
echo "🐳 Checking Docker services..."
if docker-compose -f docker-compose.prod.yml ps -q | grep -q .; then
    echo "✅ Docker services are running"
else
    echo "❌ No Docker services running"
    exit 1
fi

# Check individual service health
services=("postgres" "redis" "backend" "bot" "web" "nginx")
for service in "${services[@]}"; do
    echo -n "🔍 Checking $service... "

    case $service in
        "postgres")
            if docker-compose -f docker-compose.prod.yml exec -T postgres pg_isready -U zkuser > /dev/null 2>&1; then
                echo "✅ Healthy"
            else
                echo "❌ Unhealthy"
            fi
            ;;
        "redis")
            if docker-compose -f docker-compose.prod.yml exec -T redis redis-cli ping | grep -q PONG; then
                echo "✅ Healthy"
            else
                echo "❌ Unhealthy"
            fi
            ;;
        "backend")
            if curl -f -s http://localhost:3001/health > /dev/null 2>&1; then
                echo "✅ Healthy"
            else
                echo "❌ Unhealthy"
            fi
            ;;
        "web")
            if curl -f -s http://localhost:3000 > /dev/null 2>&1; then
                echo "✅ Healthy"
            else
                echo "❌ Unhealthy"
            fi
            ;;
        "nginx")
            if curl -f -s -k https://localhost > /dev/null 2>&1; then
                echo "✅ Healthy"
            else
                echo "❌ Unhealthy"
            fi
            ;;
        "bot")
            # Bot health check - just verify container is running
            if docker-compose -f docker-compose.prod.yml ps bot | grep -q "Up"; then
                echo "✅ Running"
            else
                echo "❌ Not running"
            fi
            ;;
    esac
done

echo
echo "📈 System Resource Usage:"
echo "CPU: $(uptime | awk -F'load average:' '{ print $2 }')"
echo "Memory: $(free -h | awk 'NR==2{printf "%.1f%% (Used: %s/%s)", $3*100/$2, $3, $2 }')"
echo "Disk: $(df -h / | awk 'NR==2{print $5 " used"}')"

echo
echo "🔗 Service Endpoints:"
echo "Web Interface: https://localhost"
echo "API Health: https://localhost/api/health"
echo "Database: postgresql://localhost:5432"

echo
echo "✅ Health check completed"
EOF

    # Create log aggregation script
    cat > "$PROJECT_ROOT/monitoring/log-aggregator.sh" << 'EOF'
#!/bin/bash
# Log aggregation script for ZK Discord Verifier

set -e

LOG_DIR="$PROJECT_ROOT/monitoring/logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo "📋 Collecting logs from all services..."

# Collect logs from Docker containers
docker-compose -f docker-compose.prod.yml logs --tail=1000 > "$LOG_DIR/docker_logs_$TIMESTAMP.log" 2>&1

# Collect system logs
echo "=== System Information ===" > "$LOG_DIR/system_info_$TIMESTAMP.log"
echo "Timestamp: $(date)" >> "$LOG_DIR/system_info_$TIMESTAMP.log"
echo "Uptime: $(uptime)" >> "$LOG_DIR/system_info_$TIMESTAMP.log"
echo "CPU: $(lscpu | grep 'Model name')" >> "$LOG_DIR/system_info_$TIMESTAMP.log"
echo "Memory: $(free -h)" >> "$LOG_DIR/system_info_$TIMESTAMP.log"
echo "Disk: $(df -h)" >> "$LOG_DIR/system_info_$TIMESTAMP.log"

# Collect Nginx logs
if docker-compose -f docker-compose.prod.yml ps nginx | grep -q "Up"; then
    docker-compose -f docker-compose.prod.yml exec nginx cat /var/log/nginx/access.log > "$LOG_DIR/nginx_access_$TIMESTAMP.log" 2>/dev/null || true
    docker-compose -f docker-compose.prod.yml exec nginx cat /var/log/nginx/error.log > "$LOG_DIR/nginx_error_$TIMESTAMP.log" 2>/dev/null || true
fi

# Compress old logs (older than 7 days)
find "$LOG_DIR" -name "*.log" -type f -mtime +7 -exec gzip {} \; 2>/dev/null || true

echo "✅ Log collection completed"
echo "Logs saved to: $LOG_DIR"
EOF

    # Make scripts executable
    chmod +x "$PROJECT_ROOT/monitoring/health-check.sh"
    chmod +x "$PROJECT_ROOT/monitoring/log-aggregator.sh"

    echo "✅ Monitoring setup completed!"
    echo "📍 Scripts created in: $PROJECT_ROOT/monitoring/"
    echo "   - health-check.sh: Comprehensive health monitoring"
    echo "   - log-aggregator.sh: Centralized log collection"
}

check_system_health() {
    echo "🔍 Performing comprehensive system health check..."

    # Run health check script if it exists
    if [[ -f "$PROJECT_ROOT/monitoring/health-check.sh" ]]; then
        bash "$PROJECT_ROOT/monitoring/health-check.sh"
    else
        echo "❌ Health check script not found. Run 'setup' first."
        exit 1
    fi
}

collect_logs() {
    echo "📋 Collecting system logs..."

    # Run log aggregator script if it exists
    if [[ -f "$PROJECT_ROOT/monitoring/log-aggregator.sh" ]]; then
        bash "$PROJECT_ROOT/monitoring/log-aggregator.sh"
    else
        echo "❌ Log aggregator script not found. Run 'setup' first."
        exit 1
    fi
}

cleanup_logs() {
    echo "🧹 Cleaning up old logs..."

    # Clean Docker logs
    docker system prune -f

    # Clean old monitoring logs (older than 30 days)
    if [[ -d "$PROJECT_ROOT/monitoring/logs" ]]; then
        find "$PROJECT_ROOT/monitoring/logs" -name "*.log" -type f -mtime +30 -delete
        find "$PROJECT_ROOT/monitoring/logs" -name "*.gz" -type f -mtime +90 -delete
        echo "✅ Old monitoring logs cleaned up"
    fi

    # Clean application logs (older than 7 days)
    find "$PROJECT_ROOT" -name "*.log" -type f -mtime +7 -delete 2>/dev/null || true

    echo "✅ Log cleanup completed"
}

# Help function
show_help() {
    echo "ZK Discord Verifier Monitoring Script"
    echo ""
    echo "Usage: $0 [action]"
    echo ""
    echo "Actions:"
    echo "   setup     Set up monitoring infrastructure (default)"
    echo "   check     Perform comprehensive health check"
    echo "   logs      Collect logs from all services"
    echo "   cleanup   Clean up old logs and Docker system"
    echo ""
    echo "Examples:"
    echo "   $0 setup      # Set up monitoring"
    echo "   $0 check      # Check system health"
    echo "   $0 logs       # Collect all logs"
}

# Show help if requested
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    show_help
    exit 0
fi

echo "🎉 Monitoring script completed!"