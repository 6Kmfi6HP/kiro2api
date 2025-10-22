# Manual Testing Checklist

This document provides a comprehensive manual testing checklist for the kiro2api Web Dashboard feature.

## Test Environment Setup

Before starting tests, ensure:
- [ ] kiro2api service is running
- [ ] Test environment is clean (no existing tokens in `tokens/` directory)
- [ ] Browser developer tools are open (F12)
- [ ] Log level is set to `debug` for detailed logging

```bash
# Clean test environment
rm -rf tokens/*

# Start service with debug logging
LOG_LEVEL=debug ./kiro2api
```

## 1. Local OAuth Flow Tests

### 1.1 Service Startup

- [ ] **Test**: Start service without `KIRO_AUTH_TOKEN` configured
  - **Expected**: Service starts successfully
  - **Expected**: Log shows "Dashboard available at http://localhost:8080/dashboard"
  - **Expected**: No errors in logs

- [ ] **Test**: Access dashboard at `http://localhost:8080/dashboard`
  - **Expected**: Dashboard page loads successfully
  - **Expected**: "Add Account" button is visible
  - **Expected**: No tokens are displayed (empty state)

### 1.2 Provider Selection

- [ ] **Test**: Click "Add Account" button
  - **Expected**: Provider selection page loads
  - **Expected**: All providers are listed (BuilderId, Enterprise, Google, GitHub)
  - **Expected**: Each provider has a description

- [ ] **Test**: Select "BuilderId" provider
  - **Expected**: Login page loads
  - **Expected**: "Login" button is visible
  - **Expected**: Provider name is displayed correctly

### 1.3 OAuth Login Flow - BuilderId

- [ ] **Test**: Click "Login" button for BuilderId
  - **Expected**: Authorization URL is generated
  - **Expected**: Browser opens authorization page (or URL is displayed)
  - **Expected**: Callback server starts (check logs)
  - **Expected**: Log shows "Callback server started redirect_uri=http://127.0.0.1:xxxxx/oauth/callback"

- [ ] **Test**: Complete OAuth authentication in browser
  - **Expected**: AWS Builder ID login page loads
  - **Expected**: Can enter credentials and authorize
  - **Expected**: Browser redirects to callback URL
  - **Expected**: Success message is displayed

- [ ] **Test**: Verify token is saved
  - **Expected**: Token file exists in `tokens/` directory
  - **Expected**: Token appears in dashboard
  - **Expected**: Token status is "valid"
  - **Expected**: Log shows "Token saved successfully"

- [ ] **Test**: Verify token file content
  ```bash
  cat tokens/*.json | jq .
  ```
  - **Expected**: JSON is valid
  - **Expected**: Contains `id`, `authMethod`, `provider`, `accessToken`, `refreshToken`
  - **Expected**: `expiresAt` is in the future
  - **Expected**: `createdAt` is current time

### 1.4 OAuth Login Flow - Google

- [ ] **Test**: Add Google account
  - **Expected**: Google OAuth flow works
  - **Expected**: Token is saved successfully
  - **Expected**: Token appears in dashboard

### 1.5 OAuth Login Flow - GitHub

- [ ] **Test**: Add GitHub account
  - **Expected**: GitHub OAuth flow works
  - **Expected**: Token is saved successfully
  - **Expected**: Token appears in dashboard

### 1.6 OAuth Login Flow - Enterprise

- [ ] **Test**: Add Enterprise account (if available)
  - **Expected**: Enterprise OAuth flow works
  - **Expected**: Can enter Start URL if required
  - **Expected**: Token is saved successfully
  - **Expected**: Token appears in dashboard

## 2. Remote OAuth Flow Tests

### 2.1 Manual Callback Initiation

- [ ] **Test**: Start OAuth flow for remote deployment
  - **Expected**: Authorization URL is generated
  - **Expected**: Can copy authorization URL
  - **Expected**: State is saved (check logs)

- [ ] **Test**: Open authorization URL in browser
  - **Expected**: AWS SSO login page loads
  - **Expected**: Can complete authentication
  - **Expected**: Browser redirects to `http://127.0.0.1:xxxxx/oauth/callback?code=...&state=...`
  - **Expected**: Browser shows connection error (expected for remote deployment)

### 2.2 Manual Callback Submission

- [ ] **Test**: Copy callback URL from browser
  - **Expected**: URL contains `code` parameter
  - **Expected**: URL contains `state` parameter
  - **Expected**: URL format is correct

- [ ] **Test**: Navigate to "Manual Callback" page
  - **Expected**: Manual callback form is displayed
  - **Expected**: Input field for callback URL is visible
  - **Expected**: Submit button is visible

- [ ] **Test**: Paste and submit callback URL
  - **Expected**: Form submission succeeds
  - **Expected**: Success message is displayed
  - **Expected**: Token is saved
  - **Expected**: Log shows "Token saved successfully"

- [ ] **Test**: Verify token in dashboard
  - **Expected**: Token appears in dashboard
  - **Expected**: Token status is "valid"
  - **Expected**: Token file exists in `tokens/` directory

### 2.3 Manual Callback Error Cases

- [ ] **Test**: Submit callback URL with missing `code` parameter
  - **Expected**: Error message: "Callback URL missing code or state parameter"
  - **Expected**: Token is not saved

- [ ] **Test**: Submit callback URL with missing `state` parameter
  - **Expected**: Error message: "Callback URL missing code or state parameter"
  - **Expected**: Token is not saved

- [ ] **Test**: Submit callback URL with invalid `state` parameter
  - **Expected**: Error message: "invalid state"
  - **Expected**: Token is not saved

- [ ] **Test**: Submit callback URL after 10 minutes (state expiration)
  - **Expected**: Error message: "invalid state"
  - **Expected**: Token is not saved

- [ ] **Test**: Submit same callback URL twice
  - **Expected**: Second submission fails
  - **Expected**: Error message: "Invalid authorization code" or similar
  - **Expected**: Only one token is saved

## 3. Token Management Tests

### 3.1 View Tokens

- [ ] **Test**: Dashboard displays all tokens
  - **Expected**: All saved tokens are listed
  - **Expected**: Each token shows: ID, Provider, Auth Method, Status, Expires At, Created At
  - **Expected**: Token status is calculated correctly (valid/expiring/expired)

- [ ] **Test**: Token status indicators
  - **Expected**: "valid" status for tokens expiring in >24 hours
  - **Expected**: "expiring" status for tokens expiring in <24 hours
  - **Expected**: "expired" status for tokens past expiration time

### 3.2 Refresh Token

- [ ] **Test**: Refresh a valid token
  - **Expected**: Refresh succeeds
  - **Expected**: Success message is displayed
  - **Expected**: `expiresAt` time is updated
  - **Expected**: Token file is updated
  - **Expected**: Log shows "Token refreshed successfully"

- [ ] **Test**: Refresh an expiring token
  - **Expected**: Refresh succeeds
  - **Expected**: Token status changes from "expiring" to "valid"
  - **Expected**: `expiresAt` time is extended

- [ ] **Test**: Refresh an expired token
  - **Expected**: Refresh may fail if refresh token is also expired
  - **Expected**: Appropriate error message is displayed
  - **Expected**: If refresh token is valid, token is refreshed successfully

- [ ] **Test**: Refresh token with invalid refresh token
  - **Expected**: Error message is displayed
  - **Expected**: Token is not updated
  - **Expected**: Log shows error details

### 3.3 Delete Token

- [ ] **Test**: Delete a token
  - **Expected**: Confirmation prompt is displayed (if implemented)
  - **Expected**: Token is removed from dashboard
  - **Expected**: Token file is deleted from `tokens/` directory
  - **Expected**: Log shows "Token deleted successfully"

- [ ] **Test**: Delete non-existent token
  - **Expected**: Error message: "Token not found"
  - **Expected**: No changes to other tokens

- [ ] **Test**: Delete token and verify API impact
  - **Expected**: After deletion, API requests using that token fail
  - **Expected**: Other tokens continue to work

### 3.4 Multiple Tokens

- [ ] **Test**: Add multiple tokens (3-5 tokens)
  - **Expected**: All tokens are saved successfully
  - **Expected**: All tokens appear in dashboard
  - **Expected**: Each token has unique ID

- [ ] **Test**: Refresh multiple tokens
  - **Expected**: Can refresh each token independently
  - **Expected**: Refreshing one token doesn't affect others

- [ ] **Test**: Delete one token from multiple
  - **Expected**: Only selected token is deleted
  - **Expected**: Other tokens remain intact

## 4. Error Scenario Tests

### 4.1 Network Errors

- [ ] **Test**: Start OAuth flow with network disconnected
  - **Expected**: Error message about network connectivity
  - **Expected**: Token is not saved
  - **Expected**: Log shows network error

- [ ] **Test**: Refresh token with network disconnected
  - **Expected**: Error message about network connectivity
  - **Expected**: Token is not updated

### 4.2 Invalid Provider

- [ ] **Test**: Manually navigate to `/dashboard/login?provider=InvalidProvider`
  - **Expected**: Error message: "Invalid provider"
  - **Expected**: Redirected to provider selection or error page

### 4.3 OAuth Errors

- [ ] **Test**: User denies OAuth authorization
  - **Expected**: Error is handled gracefully
  - **Expected**: No token is saved
  - **Expected**: User can retry

- [ ] **Test**: OAuth timeout (wait >5 minutes without completing)
  - **Expected**: Callback server times out
  - **Expected**: Error message is displayed
  - **Expected**: User can retry

### 4.4 File System Errors

- [ ] **Test**: Remove write permission from `tokens/` directory
  ```bash
  chmod 555 tokens/
  ```
  - **Expected**: Token save fails
  - **Expected**: Error message: "Failed to save token"
  - **Expected**: Log shows permission error

- [ ] **Test**: Fill disk space (if possible in test environment)
  - **Expected**: Token save fails
  - **Expected**: Error message about disk space
  - **Expected**: Service continues to run

- [ ] **Test**: Restore permissions and retry
  ```bash
  chmod 755 tokens/
  ```
  - **Expected**: Token save succeeds after permission fix

### 4.5 Concurrent Operations

- [ ] **Test**: Start two OAuth flows simultaneously
  - **Expected**: Both flows complete successfully
  - **Expected**: Two tokens are saved
  - **Expected**: No race conditions or conflicts

- [ ] **Test**: Refresh two tokens simultaneously
  - **Expected**: Both refreshes complete successfully
  - **Expected**: Both tokens are updated correctly

- [ ] **Test**: Delete token while refreshing it
  - **Expected**: One operation succeeds, other fails gracefully
  - **Expected**: No data corruption

## 5. Browser Compatibility Tests

### 5.1 Desktop Browsers

- [ ] **Test**: Chrome (latest version)
  - **Expected**: All features work correctly
  - **Expected**: UI renders properly
  - **Expected**: No console errors

- [ ] **Test**: Firefox (latest version)
  - **Expected**: All features work correctly
  - **Expected**: UI renders properly
  - **Expected**: No console errors

- [ ] **Test**: Safari (latest version, macOS)
  - **Expected**: All features work correctly
  - **Expected**: UI renders properly
  - **Expected**: No console errors

- [ ] **Test**: Edge (latest version)
  - **Expected**: All features work correctly
  - **Expected**: UI renders properly
  - **Expected**: No console errors

### 5.2 Mobile Browsers

- [ ] **Test**: Chrome for Android
  - **Expected**: Dashboard is accessible
  - **Expected**: UI is responsive
  - **Expected**: Basic functionality works

- [ ] **Test**: Safari for iOS
  - **Expected**: Dashboard is accessible
  - **Expected**: UI is responsive
  - **Expected**: Basic functionality works

### 5.3 Browser Features

- [ ] **Test**: Incognito/Private mode
  - **Expected**: Dashboard works in private mode
  - **Expected**: OAuth flow completes successfully

- [ ] **Test**: Browser back button
  - **Expected**: Navigation works correctly
  - **Expected**: No broken states

- [ ] **Test**: Browser refresh (F5)
  - **Expected**: Dashboard reloads correctly
  - **Expected**: Token list is updated

- [ ] **Test**: Multiple browser tabs
  - **Expected**: Can open dashboard in multiple tabs
  - **Expected**: Changes in one tab reflect in others after refresh

## 6. Accessibility Tests

### 6.1 Keyboard Navigation

- [ ] **Test**: Navigate dashboard using Tab key
  - **Expected**: Can focus all interactive elements
  - **Expected**: Focus order is logical
  - **Expected**: Focus indicators are visible

- [ ] **Test**: Activate buttons using Enter/Space
  - **Expected**: All buttons can be activated via keyboard
  - **Expected**: Same behavior as mouse click

- [ ] **Test**: Navigate forms using Tab and Shift+Tab
  - **Expected**: Can navigate form fields
  - **Expected**: Can submit forms using Enter

### 6.2 Screen Reader Compatibility

- [ ] **Test**: Use screen reader (NVDA, JAWS, or VoiceOver)
  - **Expected**: All text is readable
  - **Expected**: Button labels are descriptive
  - **Expected**: Form fields have labels
  - **Expected**: Error messages are announced

### 6.3 Visual Accessibility

- [ ] **Test**: Color contrast
  - **Expected**: Text has sufficient contrast ratio (WCAG AA)
  - **Expected**: Status indicators are distinguishable

- [ ] **Test**: Zoom to 200%
  - **Expected**: UI remains usable
  - **Expected**: No text overlap
  - **Expected**: No horizontal scrolling

## 7. Backward Compatibility Tests

### 7.1 Environment Variable Configuration

- [ ] **Test**: Start service with `KIRO_AUTH_TOKEN` set
  ```bash
  export KIRO_AUTH_TOKEN='[{"auth":"Social","refreshToken":"xxx"}]'
  ./kiro2api
  ```
  - **Expected**: Service starts successfully
  - **Expected**: Token from environment variable is loaded
  - **Expected**: Dashboard is still accessible

- [ ] **Test**: Start service without `KIRO_AUTH_TOKEN`
  ```bash
  unset KIRO_AUTH_TOKEN
  ./kiro2api
  ```
  - **Expected**: Service starts successfully
  - **Expected**: Loads tokens from `tokens/` directory
  - **Expected**: Dashboard is accessible

### 7.2 Token Loading Priority

- [ ] **Test**: Set `KIRO_AUTH_TOKEN` and have tokens in `tokens/` directory
  - **Expected**: Environment variable tokens are used first
  - **Expected**: File tokens are also loaded
  - **Expected**: All tokens are available for API requests

- [ ] **Test**: Remove `KIRO_AUTH_TOKEN` and restart
  - **Expected**: Service loads tokens from files only
  - **Expected**: All file tokens are available

### 7.3 Existing API Endpoints

- [ ] **Test**: `/v1/models` endpoint
  ```bash
  curl http://localhost:8080/v1/models
  ```
  - **Expected**: Returns model list
  - **Expected**: No changes in behavior

- [ ] **Test**: `/v1/messages` endpoint
  ```bash
  curl -X POST http://localhost:8080/v1/messages \
    -H "Authorization: Bearer 123456" \
    -H "Content-Type: application/json" \
    -d '{"model":"claude-sonnet-4-20250514","max_tokens":100,"messages":[{"role":"user","content":"test"}]}'
  ```
  - **Expected**: Returns response
  - **Expected**: Uses tokens from environment or files
  - **Expected**: No changes in behavior

- [ ] **Test**: `/v1/chat/completions` endpoint (OpenAI format)
  ```bash
  curl -X POST http://localhost:8080/v1/chat/completions \
    -H "Authorization: Bearer 123456" \
    -H "Content-Type: application/json" \
    -d '{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"test"}]}'
  ```
  - **Expected**: Returns response
  - **Expected**: No changes in behavior

### 7.4 Existing Auth Flow

- [ ] **Test**: API authentication with `KIRO_CLIENT_TOKEN`
  - **Expected**: Authentication works as before
  - **Expected**: No changes in auth middleware

- [ ] **Test**: Token refresh for environment variable tokens
  - **Expected**: Tokens are refreshed automatically
  - **Expected**: No changes in refresh logic

## 8. Security Tests

### 8.1 CSRF Protection

- [ ] **Test**: Submit callback with invalid state
  - **Expected**: Request is rejected
  - **Expected**: Error message: "invalid state"

- [ ] **Test**: Reuse state parameter
  - **Expected**: Second use is rejected
  - **Expected**: State is deleted after first use

### 8.2 PKCE Validation

- [ ] **Test**: Verify PKCE parameters are generated
  - **Expected**: Code verifier is random (43+ characters)
  - **Expected**: Code challenge is SHA256 hash of verifier
  - **Expected**: Code challenge method is "S256"

- [ ] **Test**: Token exchange includes code verifier
  - **Expected**: Code verifier is sent to token endpoint
  - **Expected**: Token exchange succeeds

### 8.3 Input Validation

- [ ] **Test**: Submit malformed callback URL
  - **Expected**: Error message about invalid URL format
  - **Expected**: No server crash

- [ ] **Test**: Submit callback URL with XSS payload
  ```
  http://127.0.0.1:12345/oauth/callback?code=<script>alert('xss')</script>&state=xxx
  ```
  - **Expected**: Payload is escaped/sanitized
  - **Expected**: No XSS execution

- [ ] **Test**: Submit extremely long callback URL (>10KB)
  - **Expected**: Request is rejected or truncated
  - **Expected**: No server crash

### 8.4 Security Headers

- [ ] **Test**: Check HTTP response headers
  ```bash
  curl -I http://localhost:8080/dashboard
  ```
  - **Expected**: Contains security headers (if implemented)
  - **Expected**: No sensitive information in headers

### 8.5 Token File Security

- [ ] **Test**: Check token file permissions
  ```bash
  ls -la tokens/
  ```
  - **Expected**: Files are readable only by owner (600)
  - **Expected**: Directory is accessible only by owner (700)

- [ ] **Test**: Verify sensitive data is not logged
  - **Expected**: Access tokens are not in logs
  - **Expected**: Refresh tokens are not in logs
  - **Expected**: Only token IDs are logged

## 9. Performance Tests

### 9.1 Load Time

- [ ] **Test**: Measure dashboard load time
  - **Expected**: Page loads in <2 seconds
  - **Expected**: No blocking resources

- [ ] **Test**: Measure API response time
  ```bash
  time curl http://localhost:8080/dashboard/tokens
  ```
  - **Expected**: Response in <500ms
  - **Expected**: Consistent response times

### 9.2 Scalability

- [ ] **Test**: Dashboard with 10 tokens
  - **Expected**: All tokens load quickly
  - **Expected**: UI remains responsive

- [ ] **Test**: Dashboard with 50 tokens
  - **Expected**: All tokens load (may be slower)
  - **Expected**: UI remains usable

- [ ] **Test**: Dashboard with 100 tokens
  - **Expected**: Consider pagination or optimization
  - **Expected**: No browser crash

## 10. Integration Tests

### 10.1 End-to-End Flow

- [ ] **Test**: Complete flow from start to API usage
  1. Start service without tokens
  2. Access dashboard
  3. Add account via OAuth
  4. Verify token in dashboard
  5. Make API request using the token
  6. Verify API request succeeds

- [ ] **Test**: Token lifecycle
  1. Add token via dashboard
  2. Use token for API requests
  3. Refresh token via dashboard
  4. Continue using token for API requests
  5. Delete token via dashboard
  6. Verify API requests fail

### 10.2 Service Restart

- [ ] **Test**: Restart service with tokens in directory
  - **Expected**: Service loads all tokens on startup
  - **Expected**: Tokens are available for API requests
  - **Expected**: Dashboard shows all tokens

- [ ] **Test**: Restart service during OAuth flow
  - **Expected**: OAuth flow fails gracefully
  - **Expected**: User can retry after restart

## Test Summary

After completing all tests, fill out this summary:

- **Total Tests**: ___
- **Passed**: ___
- **Failed**: ___
- **Skipped**: ___
- **Blockers**: ___

### Critical Issues Found

1.
2.
3.

### Non-Critical Issues Found

1.
2.
3.

### Recommendations

1.
2.
3.

## Sign-off

- **Tester Name**: _______________
- **Date**: _______________
- **Environment**: _______________
- **Version**: _______________
- **Approval**: [ ] Approved [ ] Rejected

---

**Note**: This checklist should be executed in a clean test environment. For production deployment, additional security and performance testing may be required.
