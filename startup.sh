#!/bin/bash
# =============================================================================
#  PhishNet — Startup Script
# =============================================================================
#  One-command bring-up of the production stack (nginx + FastAPI + PostgreSQL).
#  Run this after starting your EC2 instance (or after pulling new code —
#  images are rebuilt so the latest frontend/backend always deploy).
#
#  Usage:
#    ./startup.sh                 # build + start + health check + DuckDNS update
#    SKIP_DUCKDNS=1 ./startup.sh  # skip the DuckDNS IP update
#
#  The backend runs `alembic upgrade head` on every start (schema migrations),
#  and the frontend is rebuilt into the nginx static volume automatically.
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

cd "$(dirname "$0")"

DUCKDNS_TOKEN="1176b3e0-85a6-4696-8b65-0fbe191bb9c1"
DUCKDNS_DOMAIN="phishing-guard"
COMPOSE="docker compose -f docker-compose.prod.yml"
CERT_DIR="/etc/letsencrypt/live/${DUCKDNS_DOMAIN}.duckdns.org"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         PhishNet — Starting Services                     ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Start Docker ─────────────────────────────────────────────────────
echo -e "${YELLOW}[1/6] Starting Docker...${NC}"
sudo systemctl start docker
sudo systemctl enable docker
echo -e "${GREEN}Docker is running.${NC}"

# ── Step 2: Swap (small instances — needed before image builds) ──────────────
MEM_KB=$(awk '/MemTotal/{print $2}' /proc/meminfo)
if [ "$MEM_KB" -lt 4000000 ] && [ ! -s /swapfile ]; then
    echo -e "${YELLOW}[2/6] Low memory (<4G) — creating 2G swapfile...${NC}"
    sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile \
        && sudo mkswap /swapfile > /dev/null && sudo swapon /swapfile \
        && echo -e "${GREEN}Swap created.${NC}" || echo -e "${RED}Swap creation failed (continuing).${NC}"
else
    echo -e "${YELLOW}[2/6] Swap OK (not needed).${NC}"
fi

# ── Step 3: TLS certificate (nginx refuses to start without one) ────────────
echo -e "${YELLOW}[3/6] Checking TLS certificate...${NC}"
SELF_SIGNED=""
if [ ! -f "$CERT_DIR/fullchain.pem" ]; then
    echo -e "${YELLOW}No certificate at $CERT_DIR — generating a self-signed one (valid 365d).${NC}"
    sudo mkdir -p "$CERT_DIR"
    sudo openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
        -subj "/CN=${DUCKDNS_DOMAIN}.duckdns.org" \
        -addext "subjectAltName=DNS:${DUCKDNS_DOMAIN}.duckdns.org,DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    SELF_SIGNED="1"
    echo -e "${GREEN}Self-signed certificate created.${NC}"
else
    echo -e "${GREEN}Certificate found: $CERT_DIR/fullchain.pem${NC}"
fi

# ── Step 4: Build + start all containers ─────────────────────────────────────
echo -e "${YELLOW}[4/6] Building and starting containers (--build — deploys latest code)...${NC}"
sg docker -c "$COMPOSE up -d --build"

echo ""
echo -e "${YELLOW}Waiting for services to initialize...${NC}"

# ── Step 5: Wait for backend health + frontend build ────────────────────────
echo -e "${YELLOW}[5/6] Verifying deployment...${NC}"
HEALTHY=""
for i in $(seq 1 60); do
    if curl -sk --max-time 5 https://localhost/api/health 2>/dev/null | grep -q '"status":"ok"'; then
        HEALTHY="1"
        break
    fi
    sleep 3
done

# Frontend one-shot build: wait until it finishes (recreated only when code changed)
FC_ID=$(sg docker -c "$COMPOSE ps -q frontend-build" 2>/dev/null || true)
if [ -n "$FC_ID" ]; then
    FC_STATUS=$(docker inspect -f '{{.State.Status}}' "$FC_ID" 2>/dev/null || echo "unknown")
    if [ "$FC_STATUS" = "running" ]; then
        echo -e "${YELLOW}Frontend build in progress (waiting up to 5 min)...${NC}"
        for i in $(seq 1 60); do
            FC_STATUS=$(docker inspect -f '{{.State.Status}}' "$FC_ID" 2>/dev/null || echo "gone")
            [ "$FC_STATUS" != "running" ] && break
            sleep 5
        done
    fi
fi

sg docker -c "$COMPOSE ps"
echo ""

# ── Step 6: Update DuckDNS with current public IP ────────────────────────────
PUBLIC_IP=$(curl -s --max-time 10 http://checkip.amazonaws.com 2>/dev/null || echo "")
if [ "${SKIP_DUCKDNS:-0}" = "1" ]; then
    echo -e "${YELLOW}[6/6] DuckDNS update skipped (SKIP_DUCKDNS=1).${NC}"
else
    IP_PARAM=""
    [ -n "$PUBLIC_IP" ] && IP_PARAM="&ip=${PUBLIC_IP}"
    DUCK_RESPONSE=$(curl -s --max-time 10 \
        "https://www.duckdns.org/update?domains=${DUCKDNS_DOMAIN}&token=${DUCKDNS_TOKEN}${IP_PARAM}" \
        2>/dev/null || echo "ERROR")
    if [ "$DUCK_RESPONSE" = "OK" ]; then
        echo -e "${GREEN}[6/6] DuckDNS updated: ${DUCKDNS_DOMAIN}.duckdns.org → ${PUBLIC_IP}${NC}"
    else
        echo -e "${RED}[6/6] DuckDNS update failed (response: ${DUCK_RESPONSE})${NC}"
    fi
fi

echo ""

# ── Result ───────────────────────────────────────────────────────────────────
if [ -n "$HEALTHY" ]; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║               SERVICES ARE ONLINE                       ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Web App:     https://${DUCKDNS_DOMAIN}.duckdns.org${NC}"
    echo -e "${BLUE}API Docs:    https://${DUCKDNS_DOMAIN}.duckdns.org/docs${NC}"
    echo -e "${BLUE}Health:      https://${DUCKDNS_DOMAIN}.duckdns.org/api/health${NC}"
    echo -e "${BLUE}Local:       https://localhost${NC}"
    echo -e "${BLUE}Public IP:   ${PUBLIC_IP}${NC}"
    echo ""
    if [ -n "$SELF_SIGNED" ]; then
        echo -e "${YELLOW}NOTE: TLS uses a SELF-SIGNED certificate (browser will warn — accept once).${NC}"
        echo -e "${YELLOW}For a trusted Let's Encrypt cert, run (once DNS points here):${NC}"
        echo -e "${YELLOW}  $COMPOSE stop nginx${NC}"
        echo -e "${YELLOW}  sudo rm -rf $CERT_DIR${NC}"
        echo -e "${YELLOW}  sudo certbot certonly --standalone -d ${DUCKDNS_DOMAIN}.duckdns.org --agree-tos -m your@email.com${NC}"
        echo -e "${YELLOW}  $COMPOSE up -d${NC}"
        echo ""
    fi
else
    echo -e "${RED}Backend did not become healthy in 3 minutes. Debug with:${NC}"
    echo -e "${RED}  $COMPOSE logs -f backend${NC}"
    echo -e "${RED}  $COMPOSE logs -f nginx${NC}"
    echo ""
    echo -e "${BLUE}Your public IP: ${PUBLIC_IP}${NC}"
    echo -e "${BLUE}Try: https://${DUCKDNS_DOMAIN}.duckdns.org${NC}"
    echo ""
    exit 1
fi
