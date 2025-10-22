# Migration Guide

This guide helps you migrate from environment variable-based token configuration to the web dashboard.

## Table of Contents

- [Overview](#overview)
- [Migration Strategies](#migration-strategies)
- [Step-by-Step Migration](#step-by-step-migration)
- [Using Both Methods Simultaneously](#using-both-methods-simultaneously)
- [Rollback Procedure](#rollback-procedure)
- [Common Migration Issues](#common-migration-issues)
- [Migration Checklist](#migration-checklist)

## Overview

### Before (Environment Variable Only)

```bash
# All tokens configured in environment variable
KIRO_AUTH_TOKEN='[
  {"auth":"Social","refreshToken":"token1"},
  {"auth":"IdC","refreshToken":"token2","clientId":"id","clientSecret":"secret"}
]'
```

### After (Dashboard Management)

```bash
# Optional: Keep existing tokens in environment
# OR use dashboard to add tokens via browser
# Tokens stored in tokens/ directory
```

### Key Changes

- `KIRO_AUTH_TOKEN` is now **optional** (was required)
- Service can start with zero tokens
- Tokens can be added via web dashboard
- Tokens persist in `tokens/` directory
- Environment variable takes priority over file-based tokens

## Migration Strategies

### Strategy 1: Gradual Migration (Recommended)

Keep existing environment configuration while adding new tokens via dashboard.

**Pros:**
- Zero downtime
- Easy rollback
- Test dashboard before full migration

**Cons:**
- Temporary dual configuration
- Need to track which tokens are where

### Strategy 2: Full Migration

Move all tokens from environment to dashboard.

**Pros:**
- Clean single source of truth
- Easier long-term management
- Better for remote deployments

**Cons:**
- Requires service restart
- More complex rollback

### Strategy 3: Hybrid Approach

Keep critical tokens in environment, manage additional tokens via dashboard.

**Pros:**
- Best of both worlds
- Critical tokens always available
- Flexibility for temporary tokens

**Cons:**
- Need to remember which tokens are where
- Slightly more complex configuration

## Step-by-Step Migration

### Phase 1: Preparation

#### 1. Backup Current Configuration

```bash
# Backup environment file
cp .env .env.backup

# Or backup environment variable
echo "$KIRO_AUTH_TOKEN" > kiro_auth_token.backup
```

#### 2. Verify Current Setup

```bash
# Check current tokens
curl -H "Authorization: Bearer ${KIRO_CLIENT_TOKEN}" \
  http://localhost:8080/api/tokens

# Note the number of tokens and their types
```

#### 3. Update to Latest Version

```bash
# Pull latest code
git pull origin main

# Rebuild
go build -o kiro2api main.go

# Or download latest binary
```

### Phase 2: Enable Dashboard

#### 1. Ensure Tokens Directory Exists

```bash
# Create tokens directory
mkdir -p tokens
chmod 700 tokens

# Set KIRO_TOKENS_DIR if using custom location
export KIRO_TOKENS_DIR=/path/to/tokens
```

#### 2. Restart Service

```bash
# If using systemd
sudo systemctl restart kiro2api

# If running directly
./kiro2api
```

#### 3. Verify Dashboard Access

```bash
# Check dashboard is accessible
curl http://localhost:8080/dashboard

# Should return HTML page
```

### Phase 3: Migrate Tokens

#### Option A: Keep Environment Tokens (Gradual)

```bash
# No changes needed to KIRO_AUTH_TOKEN
# Add new tokens via dashboard
# Old tokens continue working from environment
```

1. Open dashboard: `http://localhost:8080/dashboard`
2. Click "Add Token"
3. Select provider and complete OAuth flow
4. New token saved to `tokens/` directory
5. Old tokens still loaded from environment

#### Option B: Move to Dashboard (Full Migration)

```bash
# 1. Parse existing tokens
cat .env | grep KIRO_AUTH_TOKEN

# 2. For each token, add via dashboard:
#    - Open http://localhost:8080/dashboard
#    - Click "Add Token"
#    - Complete OAuth flow for each provider

# 3. Verify all tokens are in dashboard
ls -la tokens/

# 4. Remove KIRO_AUTH_TOKEN from environment
sed -i '/KIRO_AUTH_TOKEN/d' .env

# 5. Restart service
sudo systemctl restart kiro2api

# 6. Verify tokens loaded from files
curl http://localhost:8080/api/tokens
```

### Phase 4: Verification

#### 1. Check Token Count

```bash
# Should match previous count
curl -H "Authorization: Bearer ${KIRO_CLIENT_TOKEN}" \
  http://localhost:8080/api/tokens | jq '. | length'
```

#### 2. Test API Requests

```bash
# Test message endpoint
curl -X POST http://localhost:8080/v1/messages \
  -H "Authorization: Bearer ${KIRO_CLIENT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 100,
    "messages": [{"role": "user", "content": "test"}]
  }'
```

#### 3. Verify Token Refresh

```bash
# Check token status in dashboard
# Tokens should show "valid" status
```

## Using Both Methods Simultaneously

### Configuration Priority

1. **Environment Variable** (`KIRO_AUTH_TOKEN`) - Highest priority
2. **File-based Tokens** (`tokens/` directory) - Used only if env var not set

### Example: Hybrid Setup

```bash
# .env file - Critical production tokens
KIRO_AUTH_TOKEN='[
  {"auth":"Social","refreshToken":"production-token-1"},
  {"auth":"Social","refreshToken":"production-token-2"}
]'

# tokens/ directory - Additional/temporary tokens
# - development-token-1.json
# - testing-token-1.json
```

**Note:** If `KIRO_AUTH_TOKEN` is set, tokens from `tokens/` directory are **ignored**.

### When to Use Each Method

**Use Environment Variable for:**
- Critical production tokens
- Tokens that must always be available
- Automated deployments
- CI/CD pipelines

**Use Dashboard for:**
- Development/testing tokens
- Temporary tokens
- Remote deployments where env vars are hard to set
- Frequent token rotation

## Rollback Procedure

### If Migration Fails

#### 1. Restore Environment Configuration

```bash
# Restore backup
cp .env.backup .env

# Or restore environment variable
export KIRO_AUTH_TOKEN=$(cat kiro_auth_token.backup)
```

#### 2. Restart Service

```bash
sudo systemctl restart kiro2api
```

#### 3. Verify Rollback

```bash
# Check tokens loaded
curl -H "Authorization: Bearer ${KIRO_CLIENT_TOKEN}" \
  http://localhost:8080/api/tokens

# Test API
curl -X POST http://localhost:8080/v1/messages \
  -H "Authorization: Bearer ${KIRO_CLIENT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}'
```

### If Dashboard Tokens Not Loading

#### 1. Check Tokens Directory

```bash
# Verify directory exists
ls -la tokens/

# Check permissions
# Should be 700 (drwx------)
```

#### 2. Check Token Files

```bash
# Verify JSON format
cat tokens/*.json | jq .

# Check for errors
grep "token" /var/log/kiro2api/app.log
```

#### 3. Verify Environment

```bash
# Check KIRO_TOKENS_DIR
echo $KIRO_TOKENS_DIR

# Check KIRO_AUTH_TOKEN is not set (if using dashboard only)
echo $KIRO_AUTH_TOKEN
```

## Common Migration Issues

### Issue 1: Tokens Not Loading from Directory

**Symptoms:**
- Dashboard shows no tokens
- API requests fail with "no available tokens"

**Causes:**
- `KIRO_AUTH_TOKEN` environment variable is set (takes priority)
- Incorrect `KIRO_TOKENS_DIR` path
- Wrong file permissions

**Solutions:**
```bash
# Check if env var is set
env | grep KIRO_AUTH_TOKEN

# Unset if using dashboard only
unset KIRO_AUTH_TOKEN

# Verify tokens directory
ls -la $KIRO_TOKENS_DIR

# Fix permissions
chmod 700 tokens
```

### Issue 2: Duplicate Tokens

**Symptoms:**
- Same token appears twice in token pool
- Unexpected token count

**Cause:**
- Token exists in both environment and files (before fix)

**Solution:**
```bash
# Choose one source:
# Option 1: Use environment only
rm -rf tokens/*.json

# Option 2: Use dashboard only
unset KIRO_AUTH_TOKEN
# Remove from .env file
```

### Issue 3: Dashboard OAuth Callback Fails

**Symptoms:**
- OAuth flow starts but never completes
- "Callback timeout" error

**Causes:**
- Firewall blocking callback port
- Browser on different machine (remote deployment)

**Solutions:**
```bash
# For remote deployments, use manual callback
# See doc/remote-deployment.md

# Check firewall
sudo ufw status

# Allow callback ports (if needed)
sudo ufw allow 9090:9099/tcp
```

### Issue 4: Service Won't Start Without Tokens

**Symptoms:**
- Service fails to start
- Error: "未找到有效的token配置"

**Cause:**
- Using old version that requires tokens

**Solution:**
```bash
# Update to latest version
git pull origin main
go build -o kiro2api main.go

# Service should start with zero tokens
./kiro2api
```

### Issue 5: Token Files Corrupted

**Symptoms:**
- Tokens not loading
- JSON parse errors in logs

**Cause:**
- Manual editing of token files
- Incomplete file writes

**Solution:**
```bash
# Validate JSON
cat tokens/*.json | jq .

# Remove corrupted files
rm tokens/corrupted-token.json

# Re-add token via dashboard
```

## Migration Checklist

### Pre-Migration

- [ ] Backup current `.env` file
- [ ] Backup `KIRO_AUTH_TOKEN` value
- [ ] Document current token count and types
- [ ] Test current API functionality
- [ ] Update to latest kiro2api version
- [ ] Create `tokens/` directory with correct permissions

### During Migration

- [ ] Restart service with dashboard enabled
- [ ] Verify dashboard is accessible
- [ ] Add tokens via dashboard (if full migration)
- [ ] Verify token count matches previous
- [ ] Test API requests with new configuration
- [ ] Check logs for errors

### Post-Migration

- [ ] Remove `KIRO_AUTH_TOKEN` from environment (if full migration)
- [ ] Update deployment documentation
- [ ] Update backup procedures to include `tokens/` directory
- [ ] Train team on dashboard usage
- [ ] Monitor service for 24-48 hours
- [ ] Delete backup files (after confirming stability)

### Rollback Checklist (If Needed)

- [ ] Restore `.env.backup`
- [ ] Restart service
- [ ] Verify token count
- [ ] Test API functionality
- [ ] Document issues encountered
- [ ] Plan retry with fixes

## Best Practices

### 1. Gradual Migration

Start with non-critical tokens, verify functionality, then migrate critical tokens.

### 2. Keep Backups

Always maintain backups of both environment configuration and token files.

### 3. Test in Development First

Perform migration in development/staging environment before production.

### 4. Monitor After Migration

Watch logs and metrics for 24-48 hours after migration.

### 5. Document Your Setup

Keep clear documentation of which tokens are where and why.

## Migration Timeline

### Small Deployment (1-5 tokens)

- **Preparation:** 15 minutes
- **Migration:** 30 minutes
- **Verification:** 15 minutes
- **Total:** ~1 hour

### Medium Deployment (5-20 tokens)

- **Preparation:** 30 minutes
- **Migration:** 1-2 hours
- **Verification:** 30 minutes
- **Total:** ~2-3 hours

### Large Deployment (20+ tokens)

- **Preparation:** 1 hour
- **Migration:** 3-4 hours
- **Verification:** 1 hour
- **Total:** ~5-6 hours

## Support

If you encounter issues during migration:

1. Check the [Troubleshooting Guide](troubleshooting.md)
2. Review service logs
3. Consult the [Dashboard Guide](dashboard-guide.md)
4. Open a GitHub issue with:
   - Migration strategy used
   - Error messages
   - Log excerpts
   - Environment details

## Next Steps

After successful migration:

- Read the [Dashboard Guide](dashboard-guide.md) for daily usage
- Review [Remote Deployment Guide](remote-deployment.md) if applicable
- Set up monitoring and alerts
- Update team documentation
