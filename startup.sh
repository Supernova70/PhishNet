#!/bin/bash
# =============================================================================
#  Phishing Guard — Startup Script
# =============================================================================
#  Run this after starting your EC2 instance to bring everything back online.
#  Your public IP changes each time — this script shows you the new one.
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         Phishing Guard — Starting Services              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Start Docker ─────────────────────────────────────────────────────
echo -e "${YELLOW}[1/3] Starting Docker...${NC}"
sudo systemctl start docker
sudo systemctl enable docker
echo -e "${GREEN}Docker is running.${NC}"

# ── Step 2: Start all containers ─────────────────────────────────────────────
echo -e "${YELLOW}[2/3] Starting all containers...${NC}"
cd /home/ubuntu/PhishNet
sg docker -c "docker compose -f docker-compose.prod.yml up -d"

echo ""
echo -e "${YELLOW}Waiting for services to initialize...${NC}"
sleep 15

# ── Step 3: Verify and show access info ──────────────────────────────────────
echo -e "${YELLOW}[3/3] Verifying deployment...${NC}"
echo ""

# Check containers
sg docker -c "docker compose -f docker-compose.prod.yml ps"
echo ""

# Get new public IP
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com 2>/dev/null || echo "UNAVAILABLE")

# Test health
if curl -s http://localhost/api/health > /dev/null 2>&1; then
    echo -e "${GREEN}Backend is healthy!${NC}"
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║               SERVICES ARE ONLINE                       ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Web App:     http://${PUBLIC_IP}${NC}"
    echo -e "${BLUE}API Docs:    http://${PUBLIC_IP}/docs${NC}"
    echo -e "${BLUE}Health:      http://${PUBLIC_IP}/health${NC}"
    echo ""
else
    echo -e "${RED}Backend may still be starting up. Wait 30s and try:${NC}"
    echo -e "${RED}  curl http://localhost/api/health${NC}"
    echo ""
    echo -e "${BLUE}Your public IP: ${PUBLIC_IP}${NC}"
    echo -e "${BLUE}Try: http://${PUBLIC_IP}${NC}"
fi
