# =============================================================================
#  Phishing Guard — Frontend Production Build
# =============================================================================
#  Multi-stage: build React app → copy dist to nginx
# =============================================================================

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies (cached layer)
COPY package.json package-lock.json* ./
RUN npm ci --prefer-offline

# Copy source and build
COPY . .
RUN npm run build

# Stage 2: Output — just the dist folder
FROM alpine:3.19
COPY --from=builder /app/dist /app/dist
CMD ["echo", "Build complete"]
