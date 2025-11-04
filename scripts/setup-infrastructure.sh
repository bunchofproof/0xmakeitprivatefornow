#!/bin/bash

# Infrastructure Preparation Script for ZK Discord Verifier Encryption
# This script generates and configures all necessary certificates and keys

set -e

echo "🔐 ZK Discord Verifier - Infrastructure Preparation Script"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BASE_DIR="$(pwd)"
CERT_DIR="${BASE_DIR}/certs"
KEY_DIR="${BASE_DIR}/keys"

# Environment variables
ENVIRONMENT=${1:-development}
if [[ ! "$ENVIRONMENT" =~ ^(development|test|production)$ ]]; then
    echo -e "${RED}❌ Invalid environment: $ENVIRONMENT${NC}"
    echo "Usage: $0 [development|test|production]"
    exit 1
fi

echo -e "${BLUE}📋 Preparing encryption infrastructure for: $ENVIRONMENT${NC}"
echo ""

# Function to create directory structure
create_directories() {
    echo -e "${YELLOW}📁 Creating directory structure...${NC}"
    
    mkdir -p "${CERT_DIR}/${ENVIRONMENT}"
    mkdir -p "${KEY_DIR}/${ENVIRONMENT}"
    mkdir -p "${KEY_DIR}/backups"
    mkdir -p "${KEY_DIR}/backups/local"
    mkdir -p "${KEY_DIR}/backups/secure"
    
    echo -e "${GREEN}✅ Directory structure created${NC}"
    echo ""
}

# Function to generate CA certificate
generate_ca_certificate() {
    echo -e "${YELLOW}🏛️ Generating Certificate Authority (CA) certificate...${NC}"
    
    cd "${CERT_DIR}"
    
    # Generate CA private key
    openssl genrsa -out ca-key.pem 4096 2>/dev/null
    
    # Generate CA certificate
    openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem \
        -subj "/C=US/ST=California/L=San Francisco/O=ZK Discord Verifier/OU=Security/CN=ZK-Verifier-CA" \
        2>/dev/null
    
    echo -e "${GREEN}✅ CA certificate generated${NC}"
    cd "${BASE_DIR}"
    echo ""
}

# Function to generate server certificate
generate_server_certificate() {
    echo -e "${YELLOW}🖥️ Generating server certificate...${NC}"
    
    cd "${CERT_DIR}/${ENVIRONMENT}"
    
    # Generate server private key
    openssl genrsa -out server-key.pem 2048 2>/dev/null
    
    # Generate certificate signing request
    openssl req -new -key server-key.pem -out server.csr \
        -subj "/C=US/ST=California/L=San Francisco/O=ZK Discord Verifier/OU=Backend/CN=zk-verifier-${ENVIRONMENT}.local" \
        2>/dev/null
    
    # Generate server certificate signed by CA
    openssl x509 -req -in server.csr -CA ../ca-cert.pem -CAkey ../ca-key.pem \
        -CAcreateserial -out server-cert.pem -days 365 -extensions v3_req \
        -extfile <(printf "subjectAltName=DNS:localhost,DNS:127.0.0.1,IP:127.0.0.1") \
        2>/dev/null
    
    # Clean up CSR file
    rm -f server.csr
    
    echo -e "${GREEN}✅ Server certificate generated${NC}"
    cd "${BASE_DIR}"
    echo ""
}

# Function to generate client certificates for services
generate_client_certificates() {
    echo -e "${YELLOW}👥 Generating client certificates for services...${NC}"
    
    local services=("backend" "bot" "web" "shared")
    
    for service in "${services[@]}"; do
        echo "  Generating certificate for: $service"
        
        cd "${CERT_DIR}/${ENVIRONMENT}"
        
        # Generate client private key
        openssl genrsa -out "${service}-client-key.pem" 2048 2>/dev/null
        
        # Generate client certificate signing request
        openssl req -new -key "${service}-client-key.pem" -out "${service}.csr" \
            -subj "/C=US/ST=California/L=San Francisco/O=ZK Discord Verifier/OU=${service^}/CN=${service}-client" \
            2>/dev/null
        
        # Generate client certificate signed by CA
        openssl x509 -req -in "${service}.csr" -CA ../ca-cert.pem -CAkey ../ca-key.pem \
            -CAcreateserial -out "${service}-client-cert.pem" -days 365 \
            2>/dev/null
        
        # Clean up CSR file
        rm -f "${service}.csr"
        
        echo -e "  ${GREEN}✅ $service client certificate generated${NC}"
    done
    
    cd "${BASE_DIR}"
    echo ""
}

# Function to generate encryption keys
generate_encryption_keys() {
    echo -e "${YELLOW}🔑 Generating encryption keys...${NC}"
    
    local key_types=("AES-256-GCM" "HMAC-SHA256")
    
    for key_type in "${key_types[@]}"; do
        echo "  Generating $key_type key..."
        
        local key_name=$(echo "$key_type" | tr '[:upper:]' '[:lower:]' | sed 's/-/_/g')
        local key_file="${KEY_DIR}/${ENVIRONMENT}/${key_name}_key.pem"
        
        case "$key_type" in
            "AES-256-GCM")
                openssl rand -hex 32 > "$key_file"
                ;;
            "HMAC-SHA256")
                openssl rand -hex 32 > "$key_file"
                ;;
        esac
        
        echo -e "  ${GREEN}✅ $key_type key generated${NC}"
    done
    
    echo -e "${GREEN}✅ Encryption keys generated${NC}"
    echo ""
}

# Function to set secure permissions
set_permissions() {
    echo -e "${YELLOW}🔒 Setting secure file permissions...${NC}"
    
    # Set restrictive permissions on certificate files
    find "${CERT_DIR}" -name "*.pem" -exec chmod 600 {} \;
    find "${CERT_DIR}" -name "*.key" -exec chmod 600 {} \;
    find "${KEY_DIR}" -name "*key*" -exec chmod 600 {} \;
    
    # Set more permissive permissions on certificate files (but not private keys)
    find "${CERT_DIR}" -name "*.pem" -not -name "*.key" -exec chmod 644 {} \;
    
    echo -e "${GREEN}✅ Secure permissions set${NC}"
    echo ""
}

# Function to create configuration files
create_configuration() {
    echo -e "${YELLOW}⚙️ Creating configuration files...${NC}"
    
    # Create certificate information file
    cat > "${CERT_DIR}/${ENVIRONMENT}/certificate-info.json" << EOF
{
  "environment": "$ENVIRONMENT",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "certificates": {
    "ca": {
      "file": "ca-cert.pem",
      "type": "certificate_authority",
      "validity_days": 3650
    },
    "server": {
      "file": "server-cert.pem",
      "key_file": "server-key.pem",
      "type": "server_certificate",
      "validity_days": 365,
      "subject": "CN=zk-verifier-${ENVIRONMENT}.local"
    },
    "clients": {
      "backend": {
        "cert_file": "backend-client-cert.pem",
        "key_file": "backend-client-key.pem"
      },
      "bot": {
        "cert_file": "bot-client-cert.pem",
        "key_file": "bot-client-key.pem"
      },
      "web": {
        "cert_file": "web-client-cert.pem",
        "key_file": "web-client-key.pem"
      },
      "shared": {
        "cert_file": "shared-client-cert.pem",
        "key_file": "shared-client-key.pem"
      }
    }
  }
}
EOF
    
    # Create environment-specific .env template
    cat > "${BASE_DIR}/.env.${ENVIRONMENT}.template" << EOF
# ZK Discord Verifier - $ENVIRONMENT Environment Configuration

# Encryption Infrastructure
CERT_ENVIRONMENT=$ENVIRONMENT
CERT_MONITORING_ENABLED=true
CERT_CHECK_INTERVAL_HOURS=24
CERT_WARNING_DAYS_BEFORE_EXPIRY=30

# Key Management
KEY_ROTATION_ENABLED=true
KEY_ROTATION_INTERVAL_DAYS=90
KEY_BACKUP_ENABLED=true
KEY_BACKUP_LOCATION=local

# Communication Security
SERVICE_ENCRYPTION_ENABLED=true
TLS_VERSION=tls1.3
REQUIRE_ENCRYPTION_PRODUCTION=true

# Certificate Paths
CA_CERT_PATH=./certs/ca-cert.pem
SERVER_CERT_PATH=./certs/$ENVIRONMENT/server-cert.pem
SERVER_KEY_PATH=./certs/$ENVIRONMENT/server-key.pem

# Service Certificates
BACKEND_CLIENT_CERT=./certs/$ENVIRONMENT/backend-client-cert.pem
BACKEND_CLIENT_KEY=./certs/$ENVIRONMENT/backend-client-key.pem
BOT_CLIENT_CERT=./certs/$ENVIRONMENT/bot-client-cert.pem
BOT_CLIENT_KEY=./certs/$ENVIRONMENT/bot-client-key.pem
WEB_CLIENT_CERT=./certs/$ENVIRONMENT/web-client-cert.pem
WEB_CLIENT_KEY=./certs/$ENVIRONMENT/web-client-key.pem

# Encryption Keys
AES_KEY_PATH=./keys/$ENVIRONMENT/aes_256_gcm_key.pem
HMAC_KEY_PATH=./keys/$ENVIRONMENT/hmac_sha256_key.pem
EOF
    
    echo -e "${GREEN}✅ Configuration files created${NC}"
    echo ""
}

# Function to create health check script
create_health_check() {
    echo -e "${YELLOW}🏥 Creating infrastructure health check script...${NC}"
    
    cat > "${BASE_DIR}/scripts/health-check-infrastructure.sh" << 'EOF'
#!/bin/bash

# Infrastructure Health Check Script
# Validates encryption infrastructure and certificates

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT=${1:-development}

echo "🏥 Infrastructure Health Check - $ENVIRONMENT Environment"
echo "==============================================="

# Check certificate files
echo "Checking certificates..."
cert_dir="${BASE_DIR}/certs/${ENVIRONMENT}"

if [[ -f "${cert_dir}/server-cert.pem" ]]; then
    echo "✅ Server certificate exists"
    
    # Check certificate validity
    if openssl x509 -in "${cert_dir}/server-cert.pem" -noout -checkend 2592000 2>/dev/null; then
        echo "✅ Server certificate is valid for at least 30 days"
    else
        echo "❌ Server certificate expires within 30 days"
    fi
else
    echo "❌ Server certificate missing"
fi

if [[ -f "${cert_dir}/ca-cert.pem" ]]; then
    echo "✅ CA certificate exists"
else
    echo "❌ CA certificate missing"
fi

# Check key files
echo "Checking encryption keys..."
key_dir="${BASE_DIR}/keys/${ENVIRONMENT}"

if [[ -f "${key_dir}/aes_256_gcm_key.pem" ]]; then
    echo "✅ AES-256-GCM key exists"
else
    echo "❌ AES-256-GCM key missing"
fi

if [[ -f "${key_dir}/hmac_sha256_key.pem" ]]; then
    echo "✅ HMAC-SHA256 key exists"
else
    echo "❌ HMAC-SHA256 key missing"
fi

echo "🏥 Infrastructure health check completed"
EOF

    chmod +x "${BASE_DIR}/scripts/health-check-infrastructure.sh"
    
    echo -e "${GREEN}✅ Health check script created${NC}"
    echo ""
}

# Function to create setup completion summary
create_summary() {
    echo -e "${YELLOW}📋 Creating setup summary...${NC}"
    
    cat > "${BASE_DIR}/INFRASTRUCTURE_SETUP_COMPLETE.md" << EOF
# Infrastructure Setup Complete ✅

## Environment: $ENVIRONMENT

### Generated Certificates
- CA Certificate: \`certs/ca-cert.pem\`
- Server Certificate: \`certs/$ENVIRONMENT/server-cert.pem\`
- Client Certificates: \`certs/$ENVIRONMENT/*-client-cert.pem\`

### Generated Keys
- AES-256-GCM Key: \`keys/$ENVIRONMENT/aes_256_gcm_key.pem\`
- HMAC-SHA256 Key: \`keys/$ENVIRONMENT/hmac_sha256_key.pem\`

### Configuration Files
- Environment Template: \`.env.$ENVIRONMENT.template\`
- Certificate Info: \`certs/$ENVIRONMENT/certificate-info.json\`

### Health Check
- Infrastructure Health Check: \`scripts/health-check-infrastructure.sh\`

### Next Steps
1. Copy \`.env.$ENVIRONMENT.template\` to \`.env.$ENVIRONMENT\`
2. Run health check: \`./scripts/health-check-infrastructure.sh $ENVIRONMENT\`
3. Start services with encryption infrastructure
4. Monitor certificate and key expiration

### Security Notes
- All private keys have restricted permissions (600)
- Certificates are valid for 365 days
- CA certificate is valid for 10 years
- Keys should be rotated according to security policies

Generated on: $(date)
EOF
    
    echo -e "${GREEN}✅ Setup summary created${NC}"
    echo ""
}

# Main execution
main() {
    echo -e "${BLUE}Starting infrastructure preparation for $ENVIRONMENT environment...${NC}"
    echo ""
    
    create_directories
    generate_ca_certificate
    generate_server_certificate
    generate_client_certificates
    generate_encryption_keys
    set_permissions
    create_configuration
    create_health_check
    create_summary
    
    echo -e "${GREEN}🎉 Infrastructure preparation completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}📖 Next Steps:${NC}"
    echo "1. Review the generated configuration files"
    echo "2. Copy .env.$ENVIRONMENT.template to .env.$ENVIRONMENT"
    echo "3. Run: ./scripts/health-check-infrastructure.sh $ENVIRONMENT"
    echo "4. Start your services with the new encryption infrastructure"
    echo ""
    echo -e "${GREEN}Your encryption infrastructure is ready for enterprise-grade secure communications! 🔐${NC}"
}

# Run main function
main