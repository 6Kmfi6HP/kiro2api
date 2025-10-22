# Deployment Guide

This guide covers deploying kiro2api in various environments.

## Table of Contents

- [Deployment Options](#deployment-options)
- [Environment Configuration](#environment-configuration)
- [Binary Deployment](#binary-deployment)
- [Docker Deployment](#docker-deployment)
- [Systemd Service](#systemd-service)
- [Security Considerations](#security-considerations)
- [Token Directory Persistence](#token-directory-persistence)
- [Monitoring and Logging](#monitoring-and-logging)
- [Backup and Recovery](#backup-and-recovery)
- [Scaling Considerations](#scaling-considerations)

## Deployment Options

kiro2api can be deployed in several ways:

1. **Standalone Binary** - Simple single-file deployment
2. **Docker Container** - Containerized deployment (Dockerfile not yet provided)
3. **Systemd Service** - Linux system service
4. **Manual Process** - Direct execution for development/testing

## Environment Configuration

### Required Environment Variables

```bash
# Required: Client authentication token (minimum 32 characters recommended)
KIRO_CLIENT_TOKEN=your-secure-random-password-here

# Optional: Server port (default: 8080)
PORT=8080

# Optional: Token storage directory (default: ./tokens)
KIRO_TOKENS_DIR=/path/to/tokens

# Optional: Authentication tokens (if not using dashboard)
KIRO_AUTH_TOKEN='[{"auth":"Social","refreshToken":"your_token"}]'
# OR
KIRO_AUTH_TOKEN=/path/to/auth_config.json
```

### Optional Environment Variables

```bash
# Logging configuration
LOG_LEVEL=info          # debug, info, warn, error
LOG_FORMAT=json         # json, text
LOG_FILE=/var/log/kiro2api.log

# Server configuration
GIN_MODE=release        # release, debug
```

## Binary Deployment

### 1. Download or Build Binary

```bash
# Build from source
go build -o kiro2api main.go

# Or download pre-built binary
# (if releases are available)
```

### 2. Create Configuration

```bash
# Create .env file
cat > .env <<EOF
KIRO_CLIENT_TOKEN=$(openssl rand -hex 32)
PORT=8080
LOG_LEVEL=info
LOG_FORMAT=json
EOF

# Create tokens directory
mkdir -p tokens
chmod 700 tokens
```

### 3. Run Service

```bash
# Direct execution
./kiro2api

# With custom port
./kiro2api 8080

# With environment file
source .env && ./kiro2api
```

## Docker Deployment

**Note:** Dockerfile is not yet provided. This section describes the recommended approach.

### Recommended Dockerfile

```dockerfile
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -ldflags="-s -w" -o kiro2api main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/kiro2api .
COPY --from=builder /app/.env.example .env.example

# Create tokens directory
RUN mkdir -p /root/tokens && chmod 700 /root/tokens

EXPOSE 8080
CMD ["./kiro2api"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  kiro2api:
    build: .
    ports:
      - "8080:8080"
    environment:
      - KIRO_CLIENT_TOKEN=${KIRO_CLIENT_TOKEN}
      - PORT=8080
      - LOG_LEVEL=info
      - LOG_FORMAT=json
    volumes:
      - ./tokens:/root/tokens
    restart: unless-stopped
```

### Running with Docker

```bash
# Build image
docker build -t kiro2api .

# Run container
docker run -d \
  --name kiro2api \
  -p 8080:8080 \
  -e KIRO_CLIENT_TOKEN="your-secure-token" \
  -v $(pwd)/tokens:/root/tokens \
  kiro2api

# View logs
docker logs -f kiro2api
```

## Systemd Service

### 1. Create Service File

```bash
sudo nano /etc/systemd/system/kiro2api.service
```

```ini
[Unit]
Description=Kiro2API Service
After=network.target

[Service]
Type=simple
User=kiro2api
Group=kiro2api
WorkingDirectory=/opt/kiro2api
EnvironmentFile=/opt/kiro2api/.env
ExecStart=/opt/kiro2api/kiro2api
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/kiro2api/tokens /var/log/kiro2api

[Install]
WantedBy=multi-user.target
```

### 2. Setup Service

```bash
# Create service user
sudo useradd -r -s /bin/false kiro2api

# Create directories
sudo mkdir -p /opt/kiro2api/tokens
sudo mkdir -p /var/log/kiro2api

# Copy binary and config
sudo cp kiro2api /opt/kiro2api/
sudo cp .env /opt/kiro2api/

# Set permissions
sudo chown -R kiro2api:kiro2api /opt/kiro2api
sudo chmod 700 /opt/kiro2api/tokens
sudo chmod 600 /opt/kiro2api/.env

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable kiro2api
sudo systemctl start kiro2api

# Check status
sudo systemctl status kiro2api
```

## Security Considerations

### 1. Client Token Security

- Use strong random tokens (minimum 32 characters)
- Never commit tokens to version control
- Rotate tokens regularly
- Use different tokens for different environments

```bash
# Generate secure token
openssl rand -hex 32
```

### 2. Token Directory Permissions

```bash
# Ensure tokens directory is secure
chmod 700 tokens
chown kiro2api:kiro2api tokens  # If using service user
```

### 3. Network Security

- Use HTTPS/TLS in production (reverse proxy recommended)
- Restrict access with firewall rules
- Use VPN or private network for sensitive deployments

### 4. Reverse Proxy Configuration

#### Nginx Example

```nginx
server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # For streaming responses
        proxy_buffering off;
        proxy_cache off;
    }

    # Dashboard access (optional: restrict by IP)
    location /dashboard {
        proxy_pass http://localhost:8080/dashboard;
        # allow 10.0.0.0/8;
        # deny all;
    }
}
```

## Token Directory Persistence

### Important Notes

- The `tokens/` directory contains all dashboard-managed authentication tokens
- This directory MUST be persisted across deployments
- Losing this directory means losing all dashboard-added tokens

### Backup Strategy

```bash
# Backup tokens directory
tar -czf tokens-backup-$(date +%Y%m%d).tar.gz tokens/

# Restore tokens directory
tar -xzf tokens-backup-20251022.tar.gz
```

### Docker Volume Persistence

```bash
# Create named volume
docker volume create kiro2api-tokens

# Run with named volume
docker run -d \
  --name kiro2api \
  -v kiro2api-tokens:/root/tokens \
  kiro2api
```

## Monitoring and Logging

### Log Configuration

```bash
# JSON logging for production
LOG_FORMAT=json
LOG_FILE=/var/log/kiro2api/app.log

# Text logging for development
LOG_FORMAT=text
LOG_LEVEL=debug
```

### Log Rotation

```bash
# Create logrotate configuration
sudo nano /etc/logrotate.d/kiro2api
```

```
/var/log/kiro2api/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 kiro2api kiro2api
    sharedscripts
    postrotate
        systemctl reload kiro2api > /dev/null 2>&1 || true
    endscript
}
```

### Health Checks

```bash
# Check service health
curl -H "Authorization: Bearer ${KIRO_CLIENT_TOKEN}" \
  http://localhost:8080/v1/models

# Check dashboard
curl http://localhost:8080/dashboard
```

## Backup and Recovery

### What to Backup

1. **Tokens Directory** - Contains all authentication tokens
2. **Environment Configuration** - `.env` file or environment variables
3. **Application Binary** - For version consistency

### Backup Script

```bash
#!/bin/bash
BACKUP_DIR="/backup/kiro2api"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup tokens
tar -czf "$BACKUP_DIR/tokens-$DATE.tar.gz" tokens/

# Backup config (without sensitive data)
cp .env.example "$BACKUP_DIR/env-template-$DATE"

# Keep only last 7 days
find "$BACKUP_DIR" -name "tokens-*.tar.gz" -mtime +7 -delete
```

### Recovery Procedure

```bash
# 1. Stop service
sudo systemctl stop kiro2api

# 2. Restore tokens
tar -xzf tokens-backup-20251022.tar.gz

# 3. Verify permissions
chmod 700 tokens
chown -R kiro2api:kiro2api tokens

# 4. Start service
sudo systemctl start kiro2api

# 5. Verify
curl http://localhost:8080/dashboard
```

## Scaling Considerations

### Single Instance Limitations

- Token pool is managed in-memory
- No built-in load balancing
- Suitable for small to medium deployments

### Horizontal Scaling (Future)

For high-availability deployments, consider:

1. **Shared Token Storage** - Use network filesystem or database
2. **Load Balancer** - Distribute requests across instances
3. **Session Affinity** - Sticky sessions for OAuth flows
4. **Health Checks** - Monitor instance health

### Vertical Scaling

- Increase memory for larger token pools
- Increase CPU for higher request throughput
- Monitor resource usage with tools like `htop`, `prometheus`

### Performance Tuning

```bash
# Increase file descriptor limits
ulimit -n 65536

# Adjust Go runtime
GOMAXPROCS=4 ./kiro2api
```

## Firewall Configuration

### UFW (Ubuntu)

```bash
# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow kiro2api port (if direct access needed)
sudo ufw allow 8080/tcp

# Enable firewall
sudo ufw enable
```

### iptables

```bash
# Allow kiro2api port
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u kiro2api -n 50 --no-pager

# Check permissions
ls -la /opt/kiro2api/tokens

# Check environment
sudo systemctl show kiro2api --property=Environment
```

### Dashboard Not Accessible

```bash
# Check if service is running
curl http://localhost:8080/dashboard

# Check firewall
sudo ufw status

# Check reverse proxy logs
sudo tail -f /var/log/nginx/error.log
```

### Token Loading Issues

```bash
# Check tokens directory
ls -la tokens/

# Check token file format
cat tokens/*.json | jq .

# Check logs for loading errors
grep "token" /var/log/kiro2api/app.log
```

## Production Checklist

- [ ] Strong `KIRO_CLIENT_TOKEN` configured (32+ characters)
- [ ] Tokens directory has correct permissions (700)
- [ ] HTTPS/TLS configured (reverse proxy)
- [ ] Firewall rules configured
- [ ] Log rotation configured
- [ ] Backup strategy implemented
- [ ] Monitoring/health checks configured
- [ ] Service auto-restart configured
- [ ] Documentation updated with deployment details
- [ ] Security audit completed

## Support

For issues or questions:
- Check the [Troubleshooting Guide](troubleshooting.md)
- Review logs in `/var/log/kiro2api/`
- Check GitHub issues
