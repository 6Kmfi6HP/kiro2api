package dashboard

import (
	"context"
	"fmt"
	"html"
	"net"
	"net/http"
	"sync"
	"time"
)

// CallbackServer handles OAuth callback requests
type CallbackServer struct {
	server      *http.Server
	listener    net.Listener
	redirectURI string
	hostname    string
	strategy    string // "random" or "predefined"
	ports       []int  // For predefined strategy

	// Callback handling
	callbackChan chan *CallbackResult
	errorChan    chan error
	once         sync.Once
	timeout      time.Duration
}

// CallbackResult holds OAuth callback data
type CallbackResult struct {
	Code  string
	State string
}

// CallbackServerOptions configures the callback server
type CallbackServerOptions struct {
	Strategy string   // "random" or "predefined"
	Ports    []int    // Required for "predefined" strategy
	Hostname string   // "127.0.0.1" or "localhost"
	Timeout  time.Duration
}

// NewCallbackServer creates a new OAuth callback server
func NewCallbackServer(opts CallbackServerOptions) *CallbackServer {
	if opts.Strategy == "" {
		opts.Strategy = "random"
	}
	if opts.Hostname == "" {
		opts.Hostname = "127.0.0.1"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Minute // 2 minutes default
	}

	return &CallbackServer{
		hostname:     opts.Hostname,
		strategy:     opts.Strategy,
		ports:        opts.Ports,
		callbackChan: make(chan *CallbackResult, 1),
		errorChan:    make(chan error, 1),
		timeout:      opts.Timeout,
	}
}

// Start starts the callback server
// Returns the redirect URI with actual port
func (s *CallbackServer) Start() (string, error) {
	if s.strategy == "predefined" {
		return s.startWithPredefinedPorts()
	}
	return s.startWithRandomPort()
}

// startWithRandomPort starts server on random port (port 0)
// Used for IdC authentication
func (s *CallbackServer) startWithRandomPort() (string, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", s.hostname))
	if err != nil {
		return "", fmt.Errorf("failed to start server: %w", err)
	}

	s.listener = listener
	addr := listener.Addr().(*net.TCPAddr)
	s.redirectURI = fmt.Sprintf("http://%s:%d/oauth/callback", s.hostname, addr.Port)

	// Create HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", s.handleCallback)
	s.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start server in background
	go func() {
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.errorChan <- fmt.Errorf("server error: %w", err)
		}
	}()

	return s.redirectURI, nil
}

// startWithPredefinedPorts tries each port in order
// Used for Social authentication
func (s *CallbackServer) startWithPredefinedPorts() (string, error) {
	if len(s.ports) == 0 {
		return "", fmt.Errorf("predefined port strategy requires non-empty ports array")
	}

	var lastErr error
	for _, port := range s.ports {
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.hostname, port))
		if err != nil {
			lastErr = err
			continue
		}

		// Success - use this port
		s.listener = listener
		addr := listener.Addr().(*net.TCPAddr)
		s.redirectURI = fmt.Sprintf("http://%s:%d/oauth/callback", s.hostname, addr.Port)

		// Create HTTP server
		mux := http.NewServeMux()
		mux.HandleFunc("/oauth/callback", s.handleCallback)
		s.server = &http.Server{
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}

		// Start server in background
		go func() {
			if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
				s.errorChan <- fmt.Errorf("server error: %w", err)
			}
		}()

		return s.redirectURI, nil
	}

	return "", fmt.Errorf("failed to start server on any predefined port: %w", lastErr)
}

// WaitForCallback waits for OAuth callback with timeout
func (s *CallbackServer) WaitForCallback() (*CallbackResult, error) {
	select {
	case result := <-s.callbackChan:
		return result, nil
	case err := <-s.errorChan:
		return nil, err
	case <-time.After(s.timeout):
		return nil, fmt.Errorf("OAuth callback timeout (%v)", s.timeout)
	}
}

// handleCallback processes OAuth callback requests
func (s *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Only accept GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()

	// Check for OAuth errors
	if errCode := query.Get("error"); errCode != "" {
		errDesc := query.Get("error_description")
		if errDesc == "" {
			errDesc = "Unknown error"
		}
		s.sendErrorResponse(w, errCode, errDesc)
		s.once.Do(func() {
			s.errorChan <- fmt.Errorf("OAuth error: %s - %s", errCode, errDesc)
		})
		return
	}

	// Extract code and state
	code := query.Get("code")
	state := query.Get("state")

	if code == "" || state == "" {
		s.sendValidationErrorResponse(w, "Missing code or state parameter")
		s.once.Do(func() {
			s.errorChan <- fmt.Errorf("OAuth callback missing authorization code or state")
		})
		return
	}

	// Send success response
	s.sendSuccessResponse(w)

	// Send result to channel (only once)
	s.once.Do(func() {
		s.callbackChan <- &CallbackResult{
			Code:  code,
			State: state,
		}
	})
}

// sendSuccessResponse sends HTML success page
func (s *CallbackServer) sendSuccessResponse(w http.ResponseWriter) {
	htmlContent := `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Authentication Successful</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .container {
      background: white;
      padding: 3rem;
      border-radius: 1rem;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
      max-width: 400px;
    }
    .success-icon {
      font-size: 4rem;
      margin-bottom: 1rem;
    }
    h1 {
      color: #2d3748;
      margin: 0 0 1rem 0;
      font-size: 1.5rem;
    }
    p {
      color: #718096;
      margin: 0;
      line-height: 1.6;
    }
    .close-hint {
      margin-top: 1.5rem;
      padding-top: 1.5rem;
      border-top: 1px solid #e2e8f0;
      font-size: 0.875rem;
      color: #a0aec0;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="success-icon">✅</div>
    <h1>Authentication Successful!</h1>
    <p>You have successfully authenticated.</p>
    <p>You can now close this window and return to the CLI.</p>
    <div class="close-hint">This window will close automatically in 3 seconds...</div>
  </div>
  <script>
    setTimeout(() => window.close(), 3000);
  </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(htmlContent))
}

// sendErrorResponse sends HTML error page
func (s *CallbackServer) sendErrorResponse(w http.ResponseWriter, errCode, errDesc string) {
	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Authentication Failed</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: linear-gradient(135deg, #f093fb 0%%, #f5576c 100%%);
    }
    .container {
      background: white;
      padding: 3rem;
      border-radius: 1rem;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
      max-width: 400px;
    }
    .error-icon {
      font-size: 4rem;
      margin-bottom: 1rem;
    }
    h1 {
      color: #2d3748;
      margin: 0 0 1rem 0;
      font-size: 1.5rem;
    }
    .error-details {
      background: #fff5f5;
      border: 1px solid #feb2b2;
      border-radius: 0.5rem;
      padding: 1rem;
      margin: 1rem 0;
      text-align: left;
    }
    .error-code {
      font-family: monospace;
      color: #c53030;
      font-weight: bold;
    }
    .error-description {
      color: #718096;
      margin-top: 0.5rem;
      font-size: 0.875rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="error-icon">❌</div>
    <h1>Authentication Failed</h1>
    <div class="error-details">
      <div class="error-code">%s</div>
      <div class="error-description">%s</div>
    </div>
    <p>Please try again or contact support if the problem persists.</p>
  </div>
</body>
</html>`, html.EscapeString(errCode), html.EscapeString(errDesc))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(htmlContent))
}

// sendValidationErrorResponse sends validation error page
func (s *CallbackServer) sendValidationErrorResponse(w http.ResponseWriter, message string) {
	s.sendErrorResponse(w, "invalid_request", message)
}

// Stop gracefully stops the server
func (s *CallbackServer) Stop() error {
	if s.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx)
}
