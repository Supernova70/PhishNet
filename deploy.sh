#!/bin/bash
# =============================================================================
#  Phishing Guard V2 — One-Click Deployment Script for AWS EC2
# =============================================================================
#  Usage: chmod +x deploy.sh && ./deploy.sh
#
#  What this script does:
#    1. Installs Docker (if not already installed)
#    2. Validates environment configuration
#    3. Allocates swap space for low-RAM instances
#    4. Builds and starts all services
#    5. Verifies deployment health
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        Phishing Guard V2 — Production Deployment        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Install Docker ───────────────────────────────────────────────────
echo -e "${YELLOW}[1/6] Checking Docker installation...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker not found. Installing...${NC}"
    sudo apt-get update
    sudo apt-get install -y ca-certificates curl gnupg
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo usermod -aG docker $USER
    newgrp docker
    echo -e "${GREEN}Docker installed successfully.${NC}"
else
    echo -e "${GREEN}Docker is installed: $(docker --version)${NC}"
fi

# ── Step 2: Check Docker Compose ─────────────────────────────────────────────
echo -e "${YELLOW}[2/6] Checking Docker Compose...${NC}"
if ! docker compose version &> /dev/null; then
    echo -e "${RED}Docker Compose plugin not found. Installing...${NC}"
    sudo apt-get install -y docker-compose-plugin
fi
echo -e "${GREEN}Docker Compose: $(docker compose version --short)${NC}"

# ── Step 3: Validate .env configuration ──────────────────────────────────────
echo -e "${YELLOW}[3/6] Checking environment configuration...${NC}"
if [ ! -f .env.prod ]; then
    echo -e "${RED}ERROR: .env.prod file not found!${NC}"
    exit 1
fi
echo -e "${GREEN}.env.prod found.${NC}"

# ── Step 4: Validate required env vars ───────────────────────────────────────
echo -e "${YELLOW}[4/6] Validating configuration...${NC}"
source .env.prod 2>/dev/null || true

missing=()
[ -z "$DB_PASSWORD" ] && missing+=("DB_PASSWORD")
[ -z "$EMAIL_ADDRESS" ] && missing+=("EMAIL_ADDRESS")
[ -z "$EMAIL_PASSWORD" ] && missing+=("EMAIL_PASSWORD")

if [ ${#missing[@]} -gt 0 ]; then
    echo -e "${RED}ERROR: Missing required environment variables in .env.prod:${NC}"
    for var in "${missing[@]}"; do
        echo -e "${RED}  - $var${NC}"
    done
    echo ""
    echo -e "${YELLOW}Edit: nano .env.prod${NC}"
    exit 1
fi
echo -e "${GREEN}Configuration valid.${NC}"

# ── Step 5: Allocate swap (for t3.micro with 1GB RAM) ───────────────────────
echo -e "${YELLOW}[5/6] Checking swap space...${NC}"
if [ $(swapon --show | wc -l) -eq 0 ]; then
    echo -e "${YELLOW}No swap detected. Allocating 2GB swap...${NC}"
    sudo fallocate -l 2G /swapfile 2>/dev/null || sudo dd if=/dev/zero of=/swapfile bs=1M count=2048
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab > /dev/null
    echo -e "${GREEN}Swap allocated (2GB).${NC}"
else
    echo -e "${GREEN}Swap already configured.${NC}"
fi

# ── Step 6: Build and start services ─────────────────────────────────────────
echo -e "${YELLOW}[6/6] Building and starting services...${NC}"
echo ""

sg docker -c "docker compose -f docker-compose.prod.yml down 2>/dev/null || true"
sg docker -c "docker compose -f docker-compose.prod.yml up -d --build"

echo ""
echo -e "${BLUE}Waiting for services to start...${NC}"
sleep 15

# ── Verify deployment ────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                  Deployment Status                      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

sg docker -c "docker compose -f docker-compose.prod.yml ps"
echo ""

# Get public IP
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com 2>/dev/null || echo "UNAVAILABLE")

# Test health
echo -e "${YELLOW}Testing health endpoint...${NC}"
for i in {1..5}; do
    if curl -s http://localhost/api/health > /dev/null 2>&1; then
        echo -e "${GREEN}Backend is healthy!${NC}"
        echo ""
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║              DEPLOYMENT SUCCESSFUL!                     ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${BLUE}Web App:     http://${PUBLIC_IP}${NC}"
        echo -e "${BLUE}API Docs:    http://${PUBLIC_IP}/docs${NC}"
        echo -e "${BLUE}Health:      http://${PUBLIC_IP}/health${NC}"
        echo ""
        break
    fi
    echo -e "${YELLOW}  Attempt $i/5 — waiting 5s...${NC}"
    sleep 5
done

if ! curl -s http://localhost/api/health > /dev/null 2>&1; then
    echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║              DEPLOYMENT MAY HAVE ISSUES                 ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Check logs:${NC}"
    echo -e "${YELLOW}  sg docker -c \"docker compose -f docker-compose.prod.yml logs\"${NC}"
    echo ""
    echo -e "${YELLOW}Common fixes:${NC}"
    echo -e "${YELLOW}  1. Edit config:  nano .env.prod${NC}"
    echo -e "${YELLOW}  2. Rebuild:      sg docker -c \"docker compose -f docker-compose.prod.yml up -d --build\"${NC}"
    echo -e "${YELLOW}  3. Logs:         sg docker -c \"docker compose -f docker-compose.prod.yml logs -f backend\"${NC}"
fi

echo ""
echo -e "${GREEN}Done!${NC}"
