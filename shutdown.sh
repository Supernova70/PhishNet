#!/bin/bash
# =============================================================================
#  Phishing Guard — Graceful Shutdown
# =============================================================================
#  Run this before stopping your EC2 instance to avoid data corruption.
# =============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Phishing Guard — Shutting down...${NC}"

sg docker -c "docker compose -f docker-compose.prod.yml down"

echo ""
echo -e "${GREEN}All containers stopped safely.${NC}"
echo -e "${GREEN}You can now stop your EC2 instance.${NC}"
