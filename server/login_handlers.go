package server

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"kiro2api/logger"
	"kiro2api/weblogin"
)

// LoginHandlers 登录相关处理器
type LoginHandlers struct {
	loginHandler *weblogin.LoginHandler
}

// NewLoginHandlers 创建登录处理器
func NewLoginHandlers(loginHandler *weblogin.LoginHandler) *LoginHandlers {
	return &LoginHandlers{
		loginHandler: loginHandler,
	}
}

// StartLogin 启动登录流程
// POST /api/login/start
func (h *LoginHandlers) StartLogin(c *gin.Context) {
	var req weblogin.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
			"details": err.Error(),
		})
		return
	}

	logger.Info("Starting login flow", "provider", req.Provider, "accountName", req.AccountName)

	resp, err := h.loginHandler.StartLogin(&req)
	if err != nil {
		logger.Error("Failed to start login", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to start login",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// WaitForLogin 等待登录完成
// GET /api/login/wait/:sessionId
func (h *LoginHandlers) WaitForLogin(c *gin.Context) {
	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Session ID is required",
		})
		return
	}

	logger.Debug("Waiting for login completion", "sessionId", sessionID)

	// 设置 5 分钟超时
	tokenData, err := h.loginHandler.WaitForLogin(sessionID, 5*time.Minute)
	if err != nil {
		logger.Error("Login failed", "sessionId", sessionID, "error", err)
		c.JSON(http.StatusRequestTimeout, gin.H{
			"error": "Login failed or timeout",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token": gin.H{
			"provider":    tokenData.Provider,
			"authMethod":  tokenData.AuthMethod,
			"accountName": tokenData.AccountName,
			"expiresAt":   tokenData.ExpiresAt,
			"createdAt":   tokenData.CreatedAt,
		},
	})
}

// HandleManualCallback 处理手动回调
// POST /api/login/manual-callback
func (h *LoginHandlers) HandleManualCallback(c *gin.Context) {
	var req weblogin.ManualCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
			"details": err.Error(),
		})
		return
	}

	logger.Info("Processing manual callback", "sessionId", req.SessionID)

	tokenData, err := h.loginHandler.HandleManualCallback(&req)
	if err != nil {
		logger.Error("Failed to process manual callback", "sessionId", req.SessionID, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to process callback",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Callback processed successfully",
		"token": gin.H{
			"provider":    tokenData.Provider,
			"authMethod":  tokenData.AuthMethod,
			"accountName": tokenData.AccountName,
			"expiresAt":   tokenData.ExpiresAt,
			"createdAt":   tokenData.CreatedAt,
		},
	})
}

// ListTokens 列出所有 token
// GET /api/login/tokens
func (h *LoginHandlers) ListTokens(c *gin.Context) {
	tokens, err := h.loginHandler.ListTokens()
	if err != nil {
		logger.Error("Failed to list tokens", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list tokens",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tokens": tokens,
		"count":  len(tokens),
	})
}

// RefreshToken 刷新 token
// POST /api/login/tokens/:filename/refresh
func (h *LoginHandlers) RefreshToken(c *gin.Context) {
	filename := c.Param("filename")
	if filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Filename is required",
		})
		return
	}

	logger.Info("Refreshing token", "filename", filename)

	tokenData, err := h.loginHandler.RefreshToken(filename)
	if err != nil {
		logger.Error("Failed to refresh token", "filename", filename, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to refresh token",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Token refreshed successfully",
		"token": gin.H{
			"provider":    tokenData.Provider,
			"authMethod":  tokenData.AuthMethod,
			"accountName": tokenData.AccountName,
			"expiresAt":   tokenData.ExpiresAt,
			"refreshedAt": tokenData.RefreshedAt,
		},
	})
}

// DeleteToken 删除 token
// DELETE /api/login/tokens/:filename
func (h *LoginHandlers) DeleteToken(c *gin.Context) {
	filename := c.Param("filename")
	if filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Filename is required",
		})
		return
	}

	logger.Info("Deleting token", "filename", filename)

	if err := h.loginHandler.DeleteToken(filename); err != nil {
		logger.Error("Failed to delete token", "filename", filename, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to delete token",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Token deleted successfully",
	})
}

// RegisterLoginRoutes 注册登录相关路由
func RegisterLoginRoutes(router *gin.Engine, loginHandler *weblogin.LoginHandler) {
	handlers := NewLoginHandlers(loginHandler)

	api := router.Group("/api/login")
	{
		api.POST("/start", handlers.StartLogin)
		api.GET("/wait/:sessionId", handlers.WaitForLogin)
		api.POST("/manual-callback", handlers.HandleManualCallback)
		api.GET("/tokens", handlers.ListTokens)
		api.POST("/tokens/:filename/refresh", handlers.RefreshToken)
		api.DELETE("/tokens/:filename", handlers.DeleteToken)
	}

	logger.Info("Login routes registered")
}
