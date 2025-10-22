// ===== Navigation Toggle (Mobile) =====
document.addEventListener('DOMContentLoaded', function() {
  const navToggle = document.getElementById('navToggle');
  const nav = document.getElementById('nav');

  if (navToggle && nav) {
    navToggle.addEventListener('click', function() {
      nav.classList.toggle('active');
    });

    // Close nav when clicking outside
    document.addEventListener('click', function(event) {
      if (!nav.contains(event.target) && !navToggle.contains(event.target)) {
        nav.classList.remove('active');
      }
    });
  }
});

// ===== Provider Selection =====
function selectProvider(provider) {
  showLoading();

  // Directly initiate OAuth flow via API
  fetch(`/dashboard/api/login?provider=${provider}`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json'
    }
  })
  .then(response => response.json())
  .then(data => {
    hideLoading();

    if (data.success) {
      // Show authentication modal instead of opening popup directly
      showAuthModal(provider, data.data.authUrl, data.data.state);
    } else {
      alert(data.error || 'Failed to initiate login. Please try again.');
    }
  })
  .catch(error => {
    hideLoading();
    console.error('Login error:', error);
    alert('Failed to initiate login. Please try again.');
  });
}

function showEnterpriseForm() {
  const form = document.getElementById('enterpriseForm');
  if (form) {
    form.style.display = 'block';
    form.scrollIntoView({ behavior: 'smooth' });
  }
}

function hideEnterpriseForm() {
  const form = document.getElementById('enterpriseForm');
  if (form) {
    form.style.display = 'none';
  }
}

function submitEnterpriseForm(event) {
  event.preventDefault();
  const startUrl = document.getElementById('startUrl').value;
  showLoading();

  // Directly initiate OAuth flow via API
  fetch(`/dashboard/api/login?provider=Enterprise&startUrl=${encodeURIComponent(startUrl)}`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json'
    }
  })
  .then(response => response.json())
  .then(data => {
    hideLoading();

    if (data.success) {
      // Show authentication modal instead of opening popup directly
      showAuthModal('Enterprise SSO', data.data.authUrl, data.data.state);
      // Hide the enterprise form
      hideEnterpriseForm();
    } else {
      alert(data.error || 'Failed to initiate login. Please try again.');
    }
  })
  .catch(error => {
    hideLoading();
    console.error('Login error:', error);
    alert('Failed to initiate login. Please try again.');
  });
}

// ===== Authentication Modal =====
function showAuthModal(provider, authUrl, state) {
  // Store OAuth state for later use
  window.currentOAuthState = { provider, authUrl, state };

  // Update modal title
  const modalTitle = document.getElementById('authModalTitle');
  if (modalTitle) {
    modalTitle.textContent = `Authenticate with ${provider}`;
  }

  // Clear previous error/success messages
  const modalError = document.getElementById('modalError');
  const modalSuccess = document.getElementById('modalSuccess');
  if (modalError) modalError.style.display = 'none';
  if (modalSuccess) modalSuccess.style.display = 'none';

  // Clear callback input
  const callbackInput = document.getElementById('callbackUrlInput');
  if (callbackInput) callbackInput.value = '';

  // Show modal
  const modal = document.getElementById('authModal');
  if (modal) {
    modal.classList.add('active');
    // Focus on first button for accessibility
    setTimeout(() => {
      const firstButton = modal.querySelector('.action-buttons button');
      if (firstButton) firstButton.focus();
    }, 100);
  }
}

function closeAuthModal() {
  const modal = document.getElementById('authModal');
  if (modal) {
    modal.classList.remove('active');
  }
  // Clean up OAuth state
  window.currentOAuthState = null;
}

function copyAuthUrl() {
  if (!window.currentOAuthState || !window.currentOAuthState.authUrl) {
    showModalError('No authentication URL available');
    return;
  }

  navigator.clipboard.writeText(window.currentOAuthState.authUrl)
    .then(() => {
      showModalSuccess('Login link copied to clipboard!');
      // Change button text temporarily
      const btn = event.target.closest('button');
      if (btn) {
        const originalHTML = btn.innerHTML;
        btn.innerHTML = '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg> Copied!';
        setTimeout(() => {
          btn.innerHTML = originalHTML;
        }, 2000);
      }
    })
    .catch(err => {
      console.error('Failed to copy:', err);
      showModalError('Failed to copy to clipboard. Please copy the URL manually.');
    });
}

function openAuthWindow() {
  if (!window.currentOAuthState || !window.currentOAuthState.authUrl) {
    showModalError('No authentication URL available');
    return;
  }

  // Open authorization URL in new window
  window.open(window.currentOAuthState.authUrl, '_blank', 'width=600,height=700');

  // Show success message
  showModalSuccess('Authentication window opened. Complete the sign-in process, then paste the callback URL below or wait for automatic redirect.');

  // Keep modal open for manual callback option
  // Start polling for automatic callback completion
  if (window.currentOAuthState.state) {
    pollForCompletion(window.currentOAuthState.state);
  }
}

function submitManualCallback() {
  const callbackInput = document.getElementById('callbackUrlInput');
  if (!callbackInput) return;

  const callbackUrl = callbackInput.value.trim();

  // Validate URL
  try {
    const url = new URL(callbackUrl);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    if (!code || !state) {
      showModalError('Invalid callback URL. Missing code or state parameter.');
      return;
    }
  } catch (e) {
    showModalError('Invalid URL format. Please paste the complete callback URL.');
    return;
  }

  // Disable submit button
  const submitBtn = event.target;
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<div class="spinner" style="width: 18px; height: 18px; border-width: 2px;"></div> Processing...';
  }

  showLoading();

  // Submit to backend
  fetch('/dashboard/callback', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify({ callbackUrl: callbackUrl })
  })
  .then(response => response.json())
  .then(data => {
    hideLoading();

    if (data.success) {
      showModalSuccess(data.data.message || 'Authentication successful!');
      setTimeout(() => {
        closeAuthModal();
        window.location.href = '/dashboard';
      }, 1500);
    } else {
      showModalError(data.error || 'Failed to process callback');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Submit Callback';
      }
    }
  })
  .catch(error => {
    hideLoading();
    console.error('Callback error:', error);
    showModalError('Network error. Please try again.');
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Submit Callback';
    }
  });
}

function showModalError(message) {
  const modalError = document.getElementById('modalError');
  const modalSuccess = document.getElementById('modalSuccess');

  if (modalSuccess) modalSuccess.style.display = 'none';

  if (modalError) {
    modalError.textContent = message;
    modalError.style.display = 'block';
    modalError.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

function showModalSuccess(message) {
  const modalError = document.getElementById('modalError');
  const modalSuccess = document.getElementById('modalSuccess');

  if (modalError) modalError.style.display = 'none';

  if (modalSuccess) {
    modalSuccess.textContent = message;
    modalSuccess.style.display = 'block';
    modalSuccess.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

// ===== Login Flow =====
function initiateLogin() {
  const loginBtn = document.getElementById('loginBtn');
  const oauthStatus = document.getElementById('oauthStatus');

  if (loginBtn) {
    loginBtn.disabled = true;
    loginBtn.innerHTML = '<div class="spinner" style="width: 18px; height: 18px; border-width: 2px;"></div> Initiating...';
  }

  // Get provider from page data
  const provider = window.provider || new URLSearchParams(window.location.search).get('provider');

  // Call backend to initiate OAuth flow
  fetch(`/dashboard/api/login?provider=${provider}`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json'
    }
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      // Show OAuth status
      if (oauthStatus) {
        oauthStatus.style.display = 'flex';
      }

      // Display callback info
      const callbackInfo = document.getElementById('callbackInfo');
      const callbackUrl = document.getElementById('callbackUrl');
      if (callbackInfo && callbackUrl && data.data.redirectUri) {
        callbackUrl.textContent = data.data.authUrl;
        callbackInfo.style.display = 'block';
      }

      // Open authorization URL in new window
      const authWindow = window.open(data.data.authUrl, '_blank', 'width=600,height=700');

      // Poll for completion
      pollForCompletion(data.data.state);
    } else {
      showError(data.error || 'Failed to initiate login');
      if (loginBtn) {
        loginBtn.disabled = false;
        loginBtn.innerHTML = `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M13.8 12H3"/></svg> Sign In with ${provider}`;
      }
    }
  })
  .catch(error => {
    console.error('Login error:', error);
    showError('Failed to initiate login. Please try again.');
    if (loginBtn) {
      loginBtn.disabled = false;
      loginBtn.innerHTML = `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M13.8 12H3"/></svg> Sign In with ${provider}`;
    }
  });
}

function pollForCompletion(state) {
  const statusMessage = document.getElementById('statusMessage');
  let attempts = 0;
  const maxAttempts = 24; // 2 minutes (5 seconds interval)

  const interval = setInterval(() => {
    attempts++;

    // Check if token was saved by checking token list
    fetch('/dashboard/tokens', {
      method: 'GET',
      headers: {
        'Accept': 'application/json'
      }
    })
    .then(response => response.json())
    .then(data => {
      if (data.success && data.data.tokens && data.data.tokens.length > 0) {
        // Token found, redirect to dashboard
        clearInterval(interval);
        if (statusMessage) {
          statusMessage.textContent = 'Authentication successful! Redirecting...';
        }
        setTimeout(() => {
          window.location.href = '/dashboard';
        }, 1000);
      } else if (attempts >= maxAttempts) {
        // Timeout
        clearInterval(interval);
        if (statusMessage) {
          statusMessage.textContent = 'Authentication timed out. Please try again or use manual callback.';
        }
      }
    })
    .catch(error => {
      console.error('Poll error:', error);
      if (attempts >= maxAttempts) {
        clearInterval(interval);
      }
    });
  }, 5000); // Poll every 5 seconds
}

function cancelLogin() {
  window.location.href = '/dashboard';
}

function copyCallbackUrl() {
  const callbackUrl = document.getElementById('callbackUrl');
  if (callbackUrl) {
    navigator.clipboard.writeText(callbackUrl.textContent)
      .then(() => {
        // Show success feedback
        const btn = event.target.closest('.btn-copy');
        if (btn) {
          const originalHTML = btn.innerHTML;
          btn.innerHTML = '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>';
          setTimeout(() => {
            btn.innerHTML = originalHTML;
          }, 2000);
        }
      })
      .catch(err => {
        console.error('Failed to copy:', err);
        alert('Failed to copy to clipboard');
      });
  }
}

// ===== Manual Callback Submission =====
function submitCallback(event) {
  event.preventDefault();

  const form = event.target;
  const callbackUrl = document.getElementById('callbackUrl').value.trim();
  const submitBtn = document.getElementById('submitBtn');
  const resultMessage = document.getElementById('resultMessage');

  // Validate URL
  try {
    const url = new URL(callbackUrl);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    if (!code || !state) {
      showResultMessage('error', 'Invalid callback URL. Missing code or state parameter.');
      return;
    }
  } catch (e) {
    showResultMessage('error', 'Invalid URL format. Please paste the complete callback URL.');
    return;
  }

  // Disable submit button
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<div class="spinner" style="width: 18px; height: 18px; border-width: 2px;"></div> Processing...';
  }

  showLoading();

  // Submit to backend
  fetch('/dashboard/callback', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify({ callbackUrl: callbackUrl })
  })
  .then(response => response.json())
  .then(data => {
    hideLoading();

    if (data.success) {
      showResultMessage('success', data.data.message || 'Authentication successful!');
      setTimeout(() => {
        window.location.href = '/dashboard';
      }, 2000);
    } else {
      showResultMessage('error', data.error || 'Failed to process callback');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Submit Callback';
      }
    }
  })
  .catch(error => {
    hideLoading();
    console.error('Callback error:', error);
    showResultMessage('error', 'Network error. Please try again.');
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Submit Callback';
    }
  });
}

function showResultMessage(type, message) {
  const resultMessage = document.getElementById('resultMessage');
  if (resultMessage) {
    resultMessage.className = `result-message ${type}`;
    resultMessage.textContent = message;
    resultMessage.style.display = 'block';
    resultMessage.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

// ===== Token Management =====
function refreshToken(tokenId) {
  if (!confirm('Refresh this token?')) {
    return;
  }

  showLoading();

  fetch(`/dashboard/tokens/refresh/${tokenId}`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json'
    }
  })
  .then(response => response.json())
  .then(data => {
    hideLoading();

    if (data.success) {
      // Reload page to show updated token
      window.location.reload();
    } else {
      showError(data.error || 'Failed to refresh token');
    }
  })
  .catch(error => {
    hideLoading();
    console.error('Refresh error:', error);
    showError('Network error. Please try again.');
  });
}

let deleteTokenId = null;

function deleteToken(tokenId) {
  deleteTokenId = tokenId;
  const modal = document.getElementById('deleteModal');
  if (modal) {
    modal.classList.add('active');

    // Set up confirm button
    const confirmBtn = document.getElementById('confirmDeleteBtn');
    if (confirmBtn) {
      confirmBtn.onclick = confirmDelete;
    }
  }
}

function closeDeleteModal() {
  const modal = document.getElementById('deleteModal');
  if (modal) {
    modal.classList.remove('active');
  }
  deleteTokenId = null;
}

function confirmDelete() {
  if (!deleteTokenId) {
    return;
  }

  closeDeleteModal();
  showLoading();

  fetch(`/dashboard/tokens/${deleteTokenId}`, {
    method: 'DELETE',
    headers: {
      'Accept': 'application/json'
    }
  })
  .then(response => response.json())
  .then(data => {
    hideLoading();

    if (data.success) {
      // Remove token from DOM
      const tokenItem = document.querySelector(`[data-token-id="${deleteTokenId}"]`);
      if (tokenItem) {
        tokenItem.style.transition = 'opacity 0.3s, transform 0.3s';
        tokenItem.style.opacity = '0';
        tokenItem.style.transform = 'translateX(-20px)';
        setTimeout(() => {
          tokenItem.remove();

          // Check if no tokens left
          const tokenList = document.querySelector('.token-list');
          if (tokenList && tokenList.children.length === 0) {
            window.location.reload();
          }
        }, 300);
      }
    } else {
      showError(data.error || 'Failed to delete token');
    }
  })
  .catch(error => {
    hideLoading();
    console.error('Delete error:', error);
    showError('Network error. Please try again.');
  });

  deleteTokenId = null;
}

// Close modal when clicking outside
document.addEventListener('click', function(event) {
  const modal = document.getElementById('deleteModal');
  if (modal && event.target === modal) {
    closeDeleteModal();
  }
});

// ===== Loading Overlay =====
function showLoading() {
  const overlay = document.getElementById('loadingOverlay');
  if (overlay) {
    overlay.classList.add('active');
  }
}

function hideLoading() {
  const overlay = document.getElementById('loadingOverlay');
  if (overlay) {
    overlay.classList.remove('active');
  }
}

// ===== Error Display =====
function showError(message) {
  alert(message); // Simple alert for now, can be enhanced with a toast notification
}

// ===== Form Submission with Loading State =====
document.addEventListener('DOMContentLoaded', function() {
  const forms = document.querySelectorAll('form');

  forms.forEach(form => {
    // Skip forms that have custom submit handlers
    if (form.onsubmit) {
      return;
    }

    form.addEventListener('submit', function() {
      // Add loading class to form
      form.classList.add('is-submitting');

      // Disable submit buttons
      const submitButtons = form.querySelectorAll('button[type="submit"]');
      submitButtons.forEach(btn => {
        btn.disabled = true;
      });
    });
  });
});

// ===== Auto-format dates =====
document.addEventListener('DOMContentLoaded', function() {
  const timeElements = document.querySelectorAll('time[datetime]');

  timeElements.forEach(timeEl => {
    const datetime = timeEl.getAttribute('datetime');
    if (datetime) {
      try {
        const date = new Date(datetime);
        const now = new Date();
        const diffMs = date - now;
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

        let formatted;
        if (diffDays < 0) {
          formatted = 'Expired';
        } else if (diffDays === 0) {
          formatted = 'Today';
        } else if (diffDays === 1) {
          formatted = 'Tomorrow';
        } else if (diffDays < 7) {
          formatted = `${diffDays} days`;
        } else {
          formatted = date.toLocaleDateString();
        }

        timeEl.textContent = formatted;
        timeEl.title = date.toLocaleString();
      } catch (e) {
        console.error('Failed to format date:', e);
      }
    }
  });
});

// ===== Keyboard Navigation =====
document.addEventListener('keydown', function(event) {
  // Escape key closes modals
  if (event.key === 'Escape') {
    // Check auth modal first
    const authModal = document.getElementById('authModal');
    if (authModal && authModal.classList.contains('active')) {
      closeAuthModal();
      return;
    }

    const modal = document.getElementById('deleteModal');
    if (modal && modal.classList.contains('active')) {
      closeDeleteModal();
      return;
    }

    const oauthStatus = document.getElementById('oauthStatus');
    if (oauthStatus && oauthStatus.style.display !== 'none') {
      cancelLogin();
    }
  }

  // Enter key in callback input submits the form
  if (event.key === 'Enter') {
    const callbackInput = document.getElementById('callbackUrlInput');
    if (callbackInput && document.activeElement === callbackInput) {
      event.preventDefault();
      submitManualCallback();
    }
  }
});
