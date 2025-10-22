# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - Web Dashboard Login Feature

#### New Features
- **Web Dashboard for Token Management**
  - Browser-based OAuth login flow with PKCE security
  - Multi-provider support (BuilderId, Enterprise, Google, GitHub)
  - Visual token management interface
  - Token status monitoring (valid/expiring/expired)
  - One-click token refresh and deletion
  - Persistent token storage in `tokens/` directory

- **Remote Deployment Support**
  - Manual callback URL submission for remote/headless deployments
  - Automatic callback server for local deployments
  - Flexible OAuth flow handling

- **Zero-Configuration Startup**
  - Service can now start without `KIRO_AUTH_TOKEN`
  - Tokens can be added via dashboard after startup
  - Graceful degradation when no tokens available

- **File-Based Token Storage**
  - Tokens persist across service restarts
  - JSON file format for easy inspection
  - Automatic loading from `tokens/` directory
  - Configurable storage location via `KIRO_TOKENS_DIR`

#### Dashboard Endpoints
- `GET /dashboard` - Dashboard home page with token list
- `GET /dashboard/select-provider` - Provider selection page
- `GET /dashboard/login` - OAuth login initiation
- `GET /dashboard/manual-callback` - Manual callback submission page
- `GET /dashboard/callback` - OAuth callback handler
- `POST /dashboard/callback` - Manual callback URL submission
- `GET /dashboard/tokens` - Token list API (JSON)
- `POST /dashboard/tokens/refresh/:id` - Refresh specific token
- `DELETE /dashboard/tokens/:id` - Delete specific token

#### Security Enhancements
- PKCE (Proof Key for Code Exchange) implementation
- CSRF protection with state parameter validation
- Security headers (CSP, X-Frame-Options, X-Content-Type-Options)
- Token file permissions enforcement (0600)
- OAuth state expiration (5-minute TTL)
- Secure random state generation (UUID v4)

#### Documentation
- Comprehensive dashboard user guide (`doc/dashboard-guide.md`)
- Remote deployment guide (`doc/remote-deployment.md`)
- Troubleshooting guide (`doc/troubleshooting.md`)
- Manual testing guide (`doc/manual-testing.md`)
- Deployment guide (`doc/deployment.md`)
- Migration guide (`doc/migration.md`)
- Updated README with dashboard instructions

### Changed

#### Breaking Changes
- **None** - Full backward compatibility maintained

#### Improvements
- `KIRO_AUTH_TOKEN` environment variable is now **optional** (was required)
- Service starts successfully with zero tokens (dashboard-only mode)
- Token loading priority: Environment variable > File-based tokens
- Enhanced logging for token loading sources
- Better error messages for configuration issues

#### Configuration Changes
- New environment variable: `KIRO_TOKENS_DIR` (default: `./tokens`)
- Token loading now supports two sources:
  1. `KIRO_AUTH_TOKEN` environment variable (priority)
  2. `tokens/` directory (fallback if env var not set)

### Fixed
- Token directory configuration now consistent across dashboard and auth service
- Token loading priority correctly implements environment variable precedence
- OAuth token exchange includes `redirect_uri` for security compliance
- Compilation errors in backward compatibility tests

### Dependencies
- Added `github.com/google/uuid` v1.6.0 - UUID generation for state parameters

### Testing
- Added backward compatibility test suite
- Dashboard unit tests (token storage, OAuth flow, handlers)
- Integration tests for complete OAuth flow
- Security tests (PKCE, CSRF, input validation)
- Test coverage: auth 33%, config 50%, converter 62%, dashboard 60%+

### Build
- Binary size: 35MB (includes embedded HTML templates and static assets)
- Embedded filesystem for dashboard assets (no external file dependencies)
- Single binary deployment with all dashboard resources

### Migration Notes

#### For Existing Users
- **No action required** - Existing `KIRO_AUTH_TOKEN` configuration continues to work
- Dashboard is available immediately at `http://localhost:8080/dashboard`
- Tokens can be added via dashboard without modifying environment variables
- See `doc/migration.md` for detailed migration strategies

#### For New Users
- Can start service without any token configuration
- Add tokens via dashboard at `http://localhost:8080/dashboard`
- Or use traditional `KIRO_AUTH_TOKEN` environment variable
- See `doc/dashboard-guide.md` for getting started

### Known Issues
- IdC (Identity Center) authentication not yet implemented in dashboard
- Two dashboard tests failing (non-critical, HTML rendering related)
- Windows filesystem permissions warnings (cosmetic, security still enforced)

### Future Enhancements
- Rate limiting for dashboard endpoints
- Token usage statistics and analytics
- Bulk token operations
- Token import/export functionality
- IdC authentication support in dashboard

## [Previous Versions]

### [1.0.0] - 2024-XX-XX
- Initial release
- Anthropic API proxy
- OpenAI API compatibility
- Token pool management
- Streaming support
- Tool calling support

---

## Release Information

### Version Numbering
- **Major**: Breaking changes
- **Minor**: New features (backward compatible)
- **Patch**: Bug fixes

### Release Process
1. Update CHANGELOG.md
2. Update version in code
3. Create git tag
4. Build release binaries
5. Publish release notes

### Support
- GitHub Issues: https://github.com/yourusername/kiro2api/issues
- Documentation: See `doc/` directory
- Email: support@example.com (if applicable)
