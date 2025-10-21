package weblogin

import "time"

// LoginProvider 登录提供商类型
type LoginProvider string

const (
	ProviderGoogle   LoginProvider = "Google"
	ProviderGithub   LoginProvider = "Github"
	ProviderBuilderId LoginProvider = "BuilderId"
	ProviderEnterprise LoginProvider = "Enterprise"
	ProviderInternal LoginProvider = "Internal"
)

// AuthMethod 认证方法
type AuthMethod string

const (
	AuthMethodSocial AuthMethod = "Social"
	AuthMethodIdC    AuthMethod = "IdC"
)

// TokenData Token 数据结构
type TokenData struct {
	// 通用字段
	AccessToken  string        `json:"accessToken"`
	RefreshToken string        `json:"refreshToken"`
	TokenType    string        `json:"tokenType"`
	ExpiresIn    int           `json:"expiresIn"`
	ExpiresAt    time.Time     `json:"expiresAt"`
	Provider     LoginProvider `json:"provider"`
	AuthMethod   AuthMethod    `json:"authMethod"`
	AccountName  string        `json:"accountName,omitempty"`

	// IdC 特定字段
	Region               string `json:"region,omitempty"`
	ClientID             string `json:"clientId,omitempty"`
	ClientSecret         string `json:"clientSecret,omitempty"`
	ClientIDHash         string `json:"clientIdHash,omitempty"`
	ClientSecretExpiresAt time.Time `json:"clientSecretExpiresAt,omitempty"`
	StartURL             string `json:"startUrl,omitempty"`

	// Social 特定字段
	ProfileArn string `json:"profileArn,omitempty"`
	IDToken    string `json:"idToken,omitempty"`

	// 元数据
	CreatedAt  time.Time `json:"createdAt"`
	RefreshedAt *time.Time `json:"refreshedAt,omitempty"`
	SavedAt    time.Time `json:"savedAt"`
	Version    string    `json:"version"`
}

// LoginRequest 登录请求
type LoginRequest struct {
	Provider    LoginProvider `json:"provider" binding:"required"`
	Region      string        `json:"region,omitempty"`
	StartURL    string        `json:"startUrl,omitempty"`
	AccountName string        `json:"accountName,omitempty"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	SessionID    string `json:"sessionId"`
	AuthURL      string `json:"authUrl"`
	RedirectURI  string `json:"redirectUri"`
	Message      string `json:"message"`
	IsLocalhost  bool   `json:"isLocalhost"`
}

// ManualCallbackRequest 手动回调请求
type ManualCallbackRequest struct {
	SessionID   string `json:"sessionId" binding:"required"`
	CallbackURL string `json:"callbackUrl" binding:"required"`
}

// TokenListItem Token 列表项
type TokenListItem struct {
	ID          string        `json:"id"`
	Filename    string        `json:"filename"`
	Provider    LoginProvider `json:"provider"`
	AuthMethod  AuthMethod    `json:"authMethod"`
	AccountName string        `json:"accountName,omitempty"`
	CreatedAt   time.Time     `json:"createdAt"`
	ExpiresAt   time.Time     `json:"expiresAt"`
	IsExpired   bool          `json:"isExpired"`
	Status      string        `json:"status"`
}

// LoginSession 登录会话
type LoginSession struct {
	SessionID     string
	Provider      LoginProvider
	Region        string
	StartURL      string
	AccountName   string
	CodeVerifier  string
	CodeChallenge string
	State         string
	RedirectURI   string
	CreatedAt     time.Time
	ResultChan    chan *TokenData
	ErrorChan     chan error
}
