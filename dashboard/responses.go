package dashboard

import (
	"fmt"
	"html"
	"net/http"

	"github.com/gin-gonic/gin"
)

// JSONSuccess sends a JSON success response
func JSONSuccess(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    data,
	})
}

// JSONError sends a JSON error response
func JSONError(c *gin.Context, statusCode int, message string) {
	c.JSON(statusCode, gin.H{
		"success": false,
		"error":   message,
	})
}

// JSONValidationError sends a JSON validation error response
func JSONValidationError(c *gin.Context, errors map[string]string) {
	c.JSON(http.StatusBadRequest, gin.H{
		"success": false,
		"error":   "Validation failed",
		"errors":  errors,
	})
}

// RenderTemplate renders an HTML template with data
func RenderTemplate(c *gin.Context, templateName string, data interface{}) {
	c.HTML(http.StatusOK, templateName, data)
}

// RenderError renders an HTML error page
func RenderError(c *gin.Context, statusCode int, message string) {
	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Error - Kiro2API Dashboard</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Helvetica Neue', sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      background: linear-gradient(135deg, #f093fb 0%%, #f5576c 100%%);
      padding: 20px;
    }
    .container {
      background: white;
      padding: 3rem;
      border-radius: 1rem;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
      max-width: 500px;
      width: 100%%;
    }
    .error-icon {
      font-size: 4rem;
      margin-bottom: 1rem;
    }
    h1 {
      color: #2d3748;
      margin: 0 0 1rem 0;
      font-size: 1.75rem;
      font-weight: 600;
    }
    .error-message {
      background: #fff5f5;
      border: 1px solid #feb2b2;
      border-radius: 0.5rem;
      padding: 1rem;
      margin: 1.5rem 0;
      text-align: left;
    }
    .error-code {
      font-family: 'Courier New', monospace;
      color: #c53030;
      font-weight: bold;
      font-size: 0.875rem;
      margin-bottom: 0.5rem;
    }
    .error-description {
      color: #718096;
      font-size: 0.875rem;
      line-height: 1.5;
    }
    .actions {
      margin-top: 2rem;
      display: flex;
      gap: 1rem;
      justify-content: center;
    }
    .btn {
      padding: 0.75rem 1.5rem;
      border-radius: 0.5rem;
      text-decoration: none;
      font-weight: 500;
      transition: all 0.2s;
      border: none;
      cursor: pointer;
      font-size: 0.875rem;
    }
    .btn-primary {
      background: #667eea;
      color: white;
    }
    .btn-primary:hover {
      background: #5568d3;
    }
    .btn-secondary {
      background: #e2e8f0;
      color: #2d3748;
    }
    .btn-secondary:hover {
      background: #cbd5e0;
    }
    @media (max-width: 640px) {
      .container {
        padding: 2rem;
      }
      .actions {
        flex-direction: column;
      }
      .btn {
        width: 100%%;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="error-icon">❌</div>
    <h1>Error</h1>
    <div class="error-message">
      <div class="error-code">HTTP %d</div>
      <div class="error-description">%s</div>
    </div>
    <div class="actions">
      <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
      <button onclick="window.history.back()" class="btn btn-secondary">Go Back</button>
    </div>
  </div>
</body>
</html>`, statusCode, html.EscapeString(message))

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(statusCode, htmlContent)
}

// RenderSuccess renders an HTML success page
func RenderSuccess(c *gin.Context, message string) {
	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Success - Kiro2API Dashboard</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Helvetica Neue', sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
      padding: 20px;
    }
    .container {
      background: white;
      padding: 3rem;
      border-radius: 1rem;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
      max-width: 500px;
      width: 100%%;
    }
    .success-icon {
      font-size: 4rem;
      margin-bottom: 1rem;
      animation: bounce 0.5s ease-in-out;
    }
    @keyframes bounce {
      0%%, 100%% { transform: translateY(0); }
      50%% { transform: translateY(-20px); }
    }
    h1 {
      color: #2d3748;
      margin: 0 0 1rem 0;
      font-size: 1.75rem;
      font-weight: 600;
    }
    .success-message {
      color: #718096;
      font-size: 1rem;
      line-height: 1.6;
      margin-bottom: 2rem;
    }
    .actions {
      margin-top: 2rem;
      display: flex;
      gap: 1rem;
      justify-content: center;
    }
    .btn {
      padding: 0.75rem 1.5rem;
      border-radius: 0.5rem;
      text-decoration: none;
      font-weight: 500;
      transition: all 0.2s;
      border: none;
      cursor: pointer;
      font-size: 0.875rem;
    }
    .btn-primary {
      background: #667eea;
      color: white;
    }
    .btn-primary:hover {
      background: #5568d3;
    }
    .close-hint {
      margin-top: 1.5rem;
      padding-top: 1.5rem;
      border-top: 1px solid #e2e8f0;
      font-size: 0.875rem;
      color: #a0aec0;
    }
    @media (max-width: 640px) {
      .container {
        padding: 2rem;
      }
      .actions {
        flex-direction: column;
      }
      .btn {
        width: 100%%;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="success-icon">✅</div>
    <h1>Success!</h1>
    <div class="success-message">%s</div>
    <div class="actions">
      <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
    </div>
    <div class="close-hint">This window will close automatically in 3 seconds...</div>
  </div>
  <script>
    setTimeout(() => {
      window.location.href = '/dashboard';
    }, 3000);
  </script>
</body>
</html>`, html.EscapeString(message))

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, htmlContent)
}

// Error types for consistent error handling
var (
	ErrInvalidProvider = fmt.Errorf("invalid provider")
	ErrInvalidState    = fmt.Errorf("invalid state")
	ErrTokenNotFound   = fmt.Errorf("token not found")
	ErrTokenExpired    = fmt.Errorf("token expired")
	ErrOAuthFailed     = fmt.Errorf("OAuth flow failed")
)

// SecurityHeaders adds security headers to responses
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Content Security Policy
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'")

		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// XSS Protection
		c.Header("X-XSS-Protection", "1; mode=block")

		// Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		c.Next()
	}
}

// RateLimitMiddleware provides basic rate limiting for OAuth endpoints
// This is a simple implementation - for production, use a proper rate limiter
func RateLimitMiddleware() gin.HandlerFunc {
	// TODO: Implement proper rate limiting with token bucket or similar
	// For now, just pass through
	return func(c *gin.Context) {
		c.Next()
	}
}
