package server

import (
	"net/http"

	"kiro2api/auth"

	"github.com/gin-gonic/gin"
)

// HandleHealth 健康检查端点
// 返回token池的健康状态
func HandleHealth(authService *auth.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if authService == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":            "unhealthy",
				"error":             "auth service not initialized",
				"total_tokens":      0,
				"available_tokens":  0,
				"last_refresh_time": "never",
			})
			return
		}

		// 获取健康状态
		status := authService.GetHealthStatus()

		// 根据状态返回不同的HTTP状态码
		statusCode := http.StatusOK
		if status.Status == "unhealthy" {
			statusCode = http.StatusServiceUnavailable
		} else if status.Status == "degraded" {
			statusCode = http.StatusOK // degraded仍返回200，但状态字段标明
		}

		c.JSON(statusCode, status)
	}
}
