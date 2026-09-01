# AWS EC2 Deployment Guide — Phishing Guard V2

Complete step-by-step guide to deploy Phishing Guard on an AWS EC2 instance using the **Free Tier**.

---

## AWS Free Tier Limits (First 12 Months)

| Resource | Free Tier Allowance | Our Usage |
|----------|-------------------|-----------|
| **EC2 t3.micro** | 750 hours/month (1 instance 24/7) | ~730 hrs/month ✓ |
| **EBS gp3** | 30 GB | ~15 GB used ✓ |
| **Data Transfer** | 15 GB outbound/month | ~2 GB/month ✓ |
| **Elastic IP** | 1 static IP (while instance runs) | 1 ✓ |
| **Estimated monthly cost** | **$0** for first 12 months | — |

> **Budget note**: Your $120 will NOT be consumed during free tier. Save it for after the 12-month period or for any non-free-tier resources you might add later.

---

## Recommended Instance Type

| Instance | vCPU | RAM | Network | Free Tier | Best For |
|----------|------|-----|---------|-----------|----------|
| **t3.micro** ★ | 2 | 1 GB | Up to 5 Gbps burst | Yes | Our project (recommended) |
| t2.micro | 1 | 1 GB | Up to 1 Gbps burst | Yes | Fallback option |

**We use `t3.micro`** — it has 2 vCPUs which helps with concurrent scan processing and Docker builds.

---

## Prerequisites

Before starting, you need:

1. **AWS Account** with Free Tier — [aws.amazon.com](https://aws.amazon.com)
2. **SSH Key Pair** — created during EC2 launch (`.pem` file)
3. **Your email credentials** — Gmail App Password for IMAP access
4. **GitHub access** — to clone the repository

---

## Step 1: Launch EC2 Instance

### 1.1 Open EC2 Console
1. Go to [AWS Console → EC2](https://console.aws.amazon.com/ec2)
2. Select your region (e.g., **Mumbai ap-south-1** for India)
3. Click **Launch Instance**

### 1.2 Configure Instance

| Setting | Value |
|---------|-------|
| **Name** | `phishing-guard` |
| **AMI** | Ubuntu 24.04 LTS (Free Tier eligible) |
| **Instance type** | `t3.micro` |
| **Key pair** | Create new → name it `phishing-guard-key` → Download `.pem` file |

### 1.3 Network Settings (Security Group)

Click **Edit** on Network settings, then configure:

| Type | Protocol | Port | Source | Purpose |
|------|----------|------|--------|---------|
| SSH | TCP | 22 | **My IP** | SSH access (change to your IP) |
| HTTP | TCP | 80 | **0.0.0.0/0** | Web app access |
| HTTPS | TCP | 443 | **0.0.0.0/0** | Future SSL |

> **Security tip**: For SSH, always use "My IP" instead of "0.0.0.0/0". You can find your IP at [whatismyipaddress.com](https://whatismyipaddress.com).

### 1.4 Storage

| Setting | Value |
|---------|-------|
| **Size** | 30 GB (Free Tier max) |
| **Type** | gp3 |
| **Delete on termination** | Yes |

### 1.5 Launch

Click **Launch Instance**. Wait for the instance state to become **Running**.

---

## Step 2: Connect to Your Instance

### 2.1 Get Public IP
1. EC2 Console → Instances → Select `phishing-guard`
2. Copy the **Public IPv4 address** (e.g., `13.232.xx.xx`)

### 2.2 Set Key Permissions (Windows)
```powershell
# In PowerShell, navigate to where you saved the .pem file
icacls "phishing-guard-key.pem" /inheritance:r /grant:r "%USERNAME%:R"
```

### 2.3 SSH into Instance
```bash
# From PowerShell or terminal:
ssh -i "phishing-guard-key.pem" ubuntu@YOUR_PUBLIC_IP

# Accept fingerprint:
# Are you sure you want to continue connecting (yes/no)? yes
```

You should see: `ubuntu@ip-172-31-xx-xx:~$`

---

## Step 3: Install Docker & Docker Compose

Run these commands **one by one** on the EC2 instance:

```bash
# Update system packages
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add your user to docker group (avoids needing sudo for docker)
sudo usermod -aG docker $USER

# Apply group change (or log out and back in)
newgrp docker

# Verify Docker is working
docker --version
docker compose version
```

---

## Step 4: Clone the Repository

```bash
# Clone the project
git clone https://github.com/Supernova70/Minor-project.git
cd Minor-project

# Verify you're in the right directory
ls -la
# You should see: docker-compose.prod.yml, nginx.conf, Dockerfile, etc.
```

---

## Step 5: Configure Environment Variables

### 5.1 Create Production Environment File

```bash
# Copy the template
cp .env.prod .env
```

### 5.2 Edit the Environment File

```bash
nano .env
```

**Change these values** (use `Ctrl+W` to search, edit with arrow keys):

```bash
# 1. Set a STRONG database password (min 16 characters)
DB_PASSWORD=YourStr0ngP@ssw0rdHere2026

# 2. Set your email credentials
EMAIL_ADDRESS=your-email@gsfcuniversity.ac.in
EMAIL_PASSWORD=your-gmail-app-password

# 3. (Optional) Add VirusTotal API key
VIRUSTOTAL_API_KEYS=your-vt-api-key-here
```

**Save and exit**: `Ctrl+X` → `Y` → `Enter`

### 5.3 Verify the File

```bash
cat .env
```

Make sure `DB_PASSWORD` is set to something strong and unique.

---

## Step 6: Build & Start the Application

### 6.1 Make the Deploy Script Executable

```bash
chmod +x deploy.sh
```

### 6.2 Run the Deployment

```bash
./deploy.sh
```

This script will:
1. Stop any existing containers
2. Build the Docker images (backend + frontend)
3. Start all services (nginx, backend, PostgreSQL)
4. Run database migrations
5. Verify everything is healthy

**First build takes 5-10 minutes** (downloading Python/Node dependencies).

### 6.3 Manual Alternative (if deploy.sh doesn't work)

```bash
# Build and start everything
docker compose -f docker-compose.prod.yml up -d --build

# Check status
docker compose -f docker-compose.prod.yml ps

# View logs
docker compose -f docker-compose.prod.yml logs -f
```

---

## Step 7: Verify Deployment

### 7.1 Check All Containers Are Running

```bash
docker compose -f docker-compose.prod.yml ps
```

Expected output:
```
NAME           STATUS          PORTS
pg-nginx       Up              0.0.0.0:80->80/tcp
pg-backend     Up              8000/tcp
pg-db          Up (healthy)    5432/tcp
```

### 7.2 Test Backend Health

```bash
curl http://localhost/health
```

Expected: `{"status": "ok", "version": "2.0.0", ...}`

### 7.3 Access the Web App

Open your browser and go to:
```
http://YOUR_PUBLIC_IP
```

You should see the Phishing Guard dashboard.

### 7.4 Access Swagger API Docs

```
http://YOUR_PUBLIC_IP/docs
```

---

## Step 8: Import Sample Data (Optional)

If you want to load the sample `.eml` files for demo:

```bash
# Copy .eml files to the container
docker cp ".eml files/." pg-backend:/app/uploads/

# Run the ingest script
docker exec pg-backend python scripts/ingest_eml.py --force
```

---

## Stopping and Starting the EC2 Instance

To save costs, you can stop your EC2 instance when not in use. All data persists on the EBS volume.

### Before Stopping (Graceful Shutdown)

```bash
cd ~/PhishNet
./shutdown.sh
```

This stops all Docker containers safely. Then you can stop the instance from the AWS Console.

### After Starting the Instance Again

```bash
cd ~/PhishNet
./startup.sh
```

This will:
1. Start Docker
2. Start all containers
3. Print your **new public IP** with access URLs

> **Note:** Your public IP changes each time you stop/start. The startup script shows the new one. No code changes are needed — the frontend uses relative URLs (`/api/...`) through nginx, so it works with any IP.

### What Persists Across Stops/Starts

| Resource | Persists? |
|----------|-----------|
| Project files (`/home/ubuntu/PhishNet`) | Yes (EBS) |
| Docker images | Yes (EBS) |
| Database data | Yes (Docker volume on EBS) |
| Swap space | No (recreated by startup script) |
| Docker service | No (restarted by startup script) |

---

## Useful Commands

> **Note:** All `docker compose` commands below should be wrapped with `sg docker -c "..."` if you're not in a docker group session. The startup/shutdown scripts handle this automatically.

### View Logs
```bash
# All services
sg docker -c "docker compose -f docker-compose.prod.yml logs -f"

# Just backend
sg docker -c "docker compose -f docker-compose.prod.yml logs -f backend"

# Just nginx
sg docker -c "docker compose -f docker-compose.prod.yml logs -f nginx"

# Database
sg docker -c "docker compose -f docker-compose.prod.yml logs -f postgres"
```

### Restart Services
```bash
# Restart everything
sg docker -c "docker compose -f docker-compose.prod.yml restart"

# Restart just backend (after code changes)
sg docker -c "docker compose -f docker-compose.prod.yml restart backend"
```

### Stop Everything
```bash
sg docker -c "docker compose -f docker-compose.prod.yml down"
```

### Full Rebuild (after code updates)
```bash
sg docker -c "docker compose -f docker-compose.prod.yml down"
sg docker -c "docker compose -f docker-compose.prod.yml up -d --build"
```

### Enter a Container (debugging)
```bash
# Shell into backend
sg docker -c "docker exec -it pg-backend bash"

# Shell into database
sg docker -c "docker exec -it pg-db psql -U phishing_user -d phishing_guard"
```

### Check Disk Usage
```bash
df -h
sg docker -c "docker system df"
```

---

## Updating the Application

When you push new code to GitHub:

```bash
# On the EC2 instance:
cd Minor-project
git pull origin main

# Rebuild and restart
sg docker -c "docker compose -f docker-compose.prod.yml down"
sg docker -c "docker compose -f docker-compose.prod.yml up -d --build"
```

---

## Troubleshooting

### "Cannot connect to the Docker daemon"
```bash
sudo systemctl start docker
sudo systemctl enable docker
```

### "Permission denied while trying to connect to Docker"
```bash
# Use sg docker to run commands in the docker group
sg docker -c "docker compose -f docker-compose.prod.yml ps"
```

### "Port 80 already in use"
```bash
# Check what's using port 80
sudo lsof -i :80
# Kill it or change nginx port in docker-compose.prod.yml
```

### Backend container keeps restarting
```bash
# Check logs
sg docker -c "docker compose -f docker-compose.prod.yml logs backend"

# Common fix: run migrations manually
sg docker -c "docker exec pg-backend alembic upgrade head"
```

### Database connection errors
```bash
# Check if postgres is healthy
sg docker -c "docker compose -f docker-compose.prod.yml ps postgres"

# Reset database (WARNING: deletes all data)
sg docker -c "docker compose -f docker-compose.prod.yml down -v"
sg docker -c "docker compose -f docker-compose.prod.yml up -d --build"
```

### Out of memory on t3.micro
If the instance runs out of RAM:
```bash
# Add swap space (2GB)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

### Can't SSH after key change
```bash
# Re-set key permissions on Windows:
icacls "phishing-guard-key.pem" /inheritance:r /grant:r "%USERNAME%:R"
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        Internet                             │
│                           │                                 │
│                    ┌──────▼──────┐                          │
│                    │  Port 80    │                          │
│                    │   Nginx     │                          │
│                    │ (reverse    │                          │
│                    │   proxy)    │                          │
│                    └──────┬──────┘                          │
│              ┌────────────┼────────────┐                    │
│              │            │            │                     │
│    ┌─────────▼──┐  ┌──────▼──────┐  ┌─▼──────────┐        │
│    │  React SPA │  │  FastAPI    │  │  PostgreSQL │        │
│    │  (static)  │  │  Backend    │  │  Database   │        │
│    │  /usr/...  │  │  :8000      │  │  :5432      │        │
│    └────────────┘  └──────┬──────┘  └─────────────┘        │
│                           │                                 │
│                    ┌──────▼──────┐                          │
│                    │   Uploads   │                          │
│                    │   ML Model  │                          │
│                    │   YARA Rules│                          │
│                    └─────────────┘                          │
│                                                             │
│              ┌───────────────────────┐                      │
│              │   EC2 t3.micro        │                      │
│              │   Ubuntu 24.04 LTS    │                      │
│              │   2 vCPU, 1 GB RAM    │                      │
│              │   30 GB gp3 EBS       │                      │
│              └───────────────────────┘                      │
└─────────────────────────────────────────────────────────────┘
```

---

## Cost Breakdown (12-Month Free Tier)

| Month | EC2 (t3.micro) | EBS (30 GB) | Data Transfer | Total |
|-------|---------------|-------------|---------------|-------|
| 1-12 | $0 (free tier) | $0 (free tier) | $0 (free tier) | **$0** |
| 13+ | ~$7.50/mo | ~$2.40/mo | ~$0.90/mo | **~$10.80/mo** |

> After 12 months, you'll be charged standard rates. To avoid surprise bills, set up a **billing alert** in AWS Console → Billing → Budgets.

---

## Security Checklist

- [ ] SSH access restricted to "My IP" (not 0.0.0.0/0)
- [ ] Strong `DB_PASSWORD` set in `.env.prod`
- [ ] `.env.prod` file not committed to Git (it's in `.gitignore`)
- [ ] Email App Password used (not real Gmail password)
- [ ] No API keys committed to repository
- [ ] Instance has only ports 22, 80, 443 open

---

## Quick Reference

| Resource | Value |
|----------|-------|
| **Web App** | `http://YOUR_PUBLIC_IP` |
| **API Docs** | `http://YOUR_PUBLIC_IP/docs` |
| **Health Check** | `http://YOUR_PUBLIC_IP/health` |
| **SSH Command** | `ssh -i "phishing-guard-key.pem" ubuntu@YOUR_PUBLIC_IP` |
| **Docker Compose** | `sg docker -c "docker compose -f docker-compose.prod.yml ..."` |
| **Shutdown** | `./shutdown.sh` |
| **Startup** | `./startup.sh` |
| **Project Directory** | `/home/ubuntu/PhishNet` |
