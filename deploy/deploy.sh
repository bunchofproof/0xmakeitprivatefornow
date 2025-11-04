#!/bin/bash

# ZK Discord Verifier - Automated Deployment Script
# Usage: ./deploy/deploy.sh [environment] [action]

set -e

ENVIRONMENT=${1:-production}
ACTION=${2:-deploy}
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="docker-compose.${ENVIRONMENT}.yml"

echo "🚀 ZK Discord Verifier Deployment Script"
echo "Environment: $ENVIRONMENT"
echo "Action: $ACTION"
echo "Project Root: $PROJECT_ROOT"

# Validate environment
if [[ ! -f "$PROJECT_ROOT/$COMPOSE_FILE" ]]; then
    echo "❌ Error: Compose file for environment '$ENVIRONMENT' not found: $COMPOSE_FILE"
    exit 1
fi

# Validate required files exist
required_files=("$PROJECT_ROOT/.env.$ENVIRONMENT" "$PROJECT_ROOT/nginx/ssl/cert.pem" "$PROJECT_ROOT/nginx/ssl/key.pem")
for file in "${required_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "❌ Error: Required file not found: $file"
        echo "Please ensure all required configuration files are present."
        exit 1
    fi
done

case $ACTION in
    "deploy")
        echo "📦 Starting deployment..."
        deploy
        ;;
    "update")
        echo "🔄 Updating existing deployment..."
        update_deployment
        ;;
    "rollback")
        echo "⏪ Rolling back deployment..."
        rollback_deployment
        ;;
    "stop")
        echo "🛑 Stopping deployment..."
        stop_deployment
        ;;
    "status")
        echo "📊 Checking deployment status..."
        check_status
        ;;
    "logs")
        echo "📋 Showing deployment logs..."
        show_logs
        ;;
    *)
        echo "❌ Unknown action: $ACTION"
        echo "Available actions: deploy, update, rollback, stop, status, logs"
        exit 1
        ;;
esac

deploy() {
    echo "🔨 Building and starting services..."

    # Stop existing deployment
    if docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" ps -q | grep -q .; then
        echo "Stopping existing deployment..."
        docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" down
    fi

    # Build and start services
    docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" up --build -d

    # Wait for services to be healthy
    echo "⏳ Waiting for services to be ready..."
    sleep 30

    # Check service health
    check_service_health

    echo "✅ Deployment completed successfully!"
    echo "🔗 Services available at:"
    echo "   Web: https://your-domain.com"
    echo "   API: https://your-domain.com/api/"
}

update_deployment() {
    echo "🔄 Pulling latest changes and updating..."

    # Pull latest images
    docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" pull

    # Update services one by one to minimize downtime
    docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" up --build -d web
    sleep 10

    docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" up --build -d backend
    sleep 10

    docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" up --build -d bot
    sleep 10

    echo "✅ Update completed!"
}

rollback_deployment() {
    echo "⏪ Rolling back to previous version..."
    # This would typically use git tags or Docker image tags for rollback
    echo "❌ Rollback not implemented - requires git tag strategy"
    exit 1
}

stop_deployment() {
    echo "🛑 Stopping all services..."
    docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" down
    echo "✅ All services stopped."
}

check_status() {
    echo "📊 Service Status:"
    docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" ps

    echo -e "\n🔍 Health Checks:"
    check_service_health
}

check_service_health() {
    local unhealthy_services=()

    # Check backend health
    if curl -f -s http://localhost:3001/health > /dev/null 2>&1; then
        echo "✅ Backend: Healthy"
    else
        echo "❌ Backend: Unhealthy"
        unhealthy_services+=("backend")
    fi

    # Check web health
    if curl -f -s http://localhost:3000 > /dev/null 2>&1; then
        echo "✅ Web: Healthy"
    else
        echo "❌ Web: Unhealthy"
        unhealthy_services+=("web")
    fi

    # Check database
    if docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" exec -T postgres pg_isready -U zkuser > /dev/null 2>&1; then
        echo "✅ Database: Healthy"
    else
        echo "❌ Database: Unhealthy"
        unhealthy_services+=("postgres")
    fi

    # Check Redis
    if docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" exec -T redis redis-cli ping | grep -q PONG; then
        echo "✅ Redis: Healthy"
    else
        echo "❌ Redis: Unhealthy"
        unhealthy_services+=("redis")
    fi

    if [[ ${#unhealthy_services[@]} -gt 0 ]]; then
        echo -e "\n❌ Found ${#unhealthy_services[@]} unhealthy services: ${unhealthy_services[*]}"
        return 1
    fi

    return 0
}

show_logs() {
    echo "📋 Recent logs (last 50 lines):"
    docker-compose -f "$PROJECT_ROOT/$COMPOSE_FILE" logs --tail=50 -f
}

# SSL Certificate management functions
generate_self_signed_ssl() {
    echo "🔐 Generating self-signed SSL certificate..."
    mkdir -p "$PROJECT_ROOT/nginx/ssl"

    openssl req -x509 -newkey rsa:4096 -keyout "$PROJECT_ROOT/nginx/ssl/key.pem" \
        -out "$PROJECT_ROOT/nginx/ssl/cert.pem" -days 365 -nodes \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

    echo "✅ SSL certificate generated."
}

setup_production_ssl() {
    echo "🔐 Setting up production SSL certificate..."
    echo "Please place your SSL certificate files in the following locations:"
    echo "   Certificate: $PROJECT_ROOT/nginx/ssl/cert.pem"
    echo "   Private Key: $PROJECT_ROOT/nginx/ssl/key.pem"
    echo ""
    echo "For Let's Encrypt certificates, consider using certbot:"
    echo "   sudo certbot certonly --standalone -d your-domain.com"
    echo "   sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem $PROJECT_ROOT/nginx/ssl/cert.pem"
    echo "   sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem $PROJECT_ROOT/nginx/ssl/key.pem"
}

# Help function
show_help() {
    echo "ZK Discord Verifier Deployment Script"
    echo ""
    echo "Usage: $0 [environment] [action]"
    echo ""
    echo "Environments:"
    echo "   production    Production deployment (default)"
    echo "   development   Local development deployment"
    echo ""
    echo "Actions:"
    echo "   deploy       Build and start all services (default)"
    echo "   update       Update existing deployment"
    echo "   stop         Stop all services"
    echo "   status       Check deployment status"
    echo "   logs         Show deployment logs"
    echo "   rollback     Rollback to previous version"
    echo ""
    echo "Examples:"
    echo "   $0 production deploy      # Deploy to production"
    echo "   $0 development status     # Check development status"
    echo "   $0 production update      # Update production deployment"
}

# Show help if requested
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    show_help
    exit 0
fi

echo "🎉 Deployment script completed!"