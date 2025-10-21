# Web Login 功能说明

## 概述

Web Login 功能允许用户通过网页界面登录 Kiro 账号，自动保存 token 到本地文件系统，实现持久化存储和自动加载。

## 核心特性

- **网页登录界面** - 美观易用的登录控制面板
- **持久化存储** - Token 自动保存到本地 JSON 文件
- **自动加载** - 启动时自动加载已保存的 token 到认证系统
- **Token 管理** - 支持查看、刷新、删除已保存的 token
- **远程部署支持** - 支持手动提交回调 URL，适用于远程部署场景
- **社交登录** - 支持 Google 和 GitHub 账号登录

## 配置

### 环境变量

在 `.env` 文件中添加以下配置：

```bash
# 启用 Web Login 功能
ENABLE_WEB_LOGIN=true

# OAuth 回调服务器端口（默认: 8081）
WEB_LOGIN_CALLBACK_PORT=8081

# OAuth 回调服务器主机名（默认: 127.0.0.1）
# 如果部署在远程服务器，可以设置为服务器的公网 IP 或域名
WEB_LOGIN_HOSTNAME=127.0.0.1

# Token 保存目录（默认: ./tokens）
WEB_LOGIN_TOKEN_DIR=./tokens
```

### 目录结构

启用后会自动创建以下目录：

```
kiro2api/
├── tokens/                          # Token 保存目录
│   ├── token-google-social-account1-1234567890.json
│   ├── token-github-social-account2-1234567891.json
│   └── ...
└── web/
    └── login.html                   # 登录管理页面
```

## 使用方法

### 1. 本地部署（推荐）

1. 启动 kiro2api：
   ```bash
   ENABLE_WEB_LOGIN=true ./kiro2api
   ```

2. 打开浏览器访问：`http://localhost:8080/login`

3. 在登录页面：
   - 选择 Provider（Google 或 GitHub）
   - 输入账户名称（可选，用于识别）
   - 点击 "Start Login"

4. 系统会自动打开浏览器完成 OAuth 登录流程

5. 登录成功后，Token 会自动保存到 `./tokens` 目录

6. 刷新页面查看已保存的 Token 列表

### 2. 远程部署

当 kiro2api 部署在远程服务器时：

1. 访问：`http://your-server-ip:8080/login`

2. 点击 "Start Login" 后，复制显示的授权 URL

3. 在浏览器中打开授权 URL 完成登录

4. 登录成功后，浏览器会跳转到回调 URL（格式：`http://127.0.0.1:8081/oauth/callback?code=xxx&state=xxx`）

5. 复制完整的回调 URL

6. 在登录页面的 "Remote Deployment Mode" 区域粘贴回调 URL

7. 点击 "Submit Callback" 完成登录

## API 接口

### POST /api/login/start

启动登录流程

**请求体：**
```json
{
  "provider": "Google",
  "accountName": "my-account"
}
```

**响应：**
```json
{
  "sessionId": "abc123...",
  "authUrl": "https://prod.us-east-1.auth.desktop.kiro.dev/login?...",
  "redirectUri": "http://127.0.0.1:8081/oauth/callback",
  "message": "Please open the auth URL in your browser to complete login",
  "isLocalhost": true
}
```

### GET /api/login/wait/:sessionId

等待登录完成（用于本地部署，自动轮询）

### POST /api/login/manual-callback

手动提交回调 URL（用于远程部署）

**请求体：**
```json
{
  "sessionId": "abc123...",
  "callbackUrl": "http://127.0.0.1:8081/oauth/callback?code=xxx&state=xxx"
}
```

### GET /api/login/tokens

列出所有已保存的 token

**响应：**
```json
{
  "tokens": [
    {
      "id": "abc123...",
      "filename": "token-google-social-account1-1234567890.json",
      "provider": "Google",
      "authMethod": "Social",
      "accountName": "account1",
      "createdAt": "2025-10-21T12:00:00Z",
      "expiresAt": "2025-10-21T13:00:00Z",
      "isExpired": false,
      "status": "valid"
    }
  ],
  "count": 1
}
```

### POST /api/login/tokens/:filename/refresh

刷新指定 token

### DELETE /api/login/tokens/:filename

删除指定 token

## Token 文件格式

保存的 Token 文件格式（JSON）：

```json
{
  "accessToken": "xxx",
  "refreshToken": "xxx",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "expiresAt": "2025-10-21T13:00:00Z",
  "provider": "Google",
  "authMethod": "Social",
  "accountName": "my-account",
  "profileArn": "arn:aws:...",
  "idToken": "xxx",
  "createdAt": "2025-10-21T12:00:00Z",
  "savedAt": "2025-10-21T12:00:00Z",
  "version": "1.0"
}
```

## 自动加载机制

启动 kiro2api 时，系统会自动：

1. 扫描 `WEB_LOGIN_TOKEN_DIR` 目录
2. 加载所有未过期的 Token
3. 将 Token 添加到 auth service 的 Token 池
4. 记录加载的 Token 数量

日志示例：
```
INFO Loaded saved tokens to auth service count=3
```

## 安全考虑

1. **Token 文件权限** - Token 文件使用 0600 权限（仅所有者可读写）
2. **本地存储** - Token 文件存储在本地文件系统，不会上传到云端
3. **PKCE 保护** - 使用 PKCE (RFC 7636) 防止授权码拦截攻击
4. **State 验证** - 使用随机 State 参数防止 CSRF 攻击
5. **HTTPS** - Kiro Auth Service 使用 HTTPS 加密通信

## 故障排除

### 问题 1：OAuth 回调服务器启动失败

**原因**：端口已被占用

**解决**：修改 `WEB_LOGIN_CALLBACK_PORT` 环境变量，使用其他端口

### 问题 2：登录超时

**原因**：5 分钟内未完成登录

**解决**：重新启动登录流程

### 问题 3：Token 未自动加载

**原因**：Token 文件格式错误或已过期

**解决**：
1. 检查 Token 文件格式是否正确
2. 查看日志中的错误信息
3. 删除错误的 Token 文件，重新登录

### 问题 4：远程部署无法回调

**原因**：回调 URL 使用 127.0.0.1，无法从公网访问

**解决**：使用 "Manual Callback" 功能，手动复制回调 URL 提交

## 开发参考

### 目录结构

```
weblogin/
├── types.go           # 类型定义
├── token_manager.go   # Token 管理器
├── auth_client.go     # Kiro Auth Service 客户端
├── oauth_server.go    # OAuth 回调服务器
└── login_handler.go   # 登录流程处理器

server/
└── login_handlers.go  # HTTP 路由处理器

web/
└── login.html         # 登录管理页面
```

### 核心流程

1. **启动登录**
   - 生成 PKCE 参数（code_verifier, code_challenge）
   - 生成随机 State 参数
   - 创建登录会话
   - 构造授权 URL
   - 返回给前端

2. **用户授权**
   - 用户在浏览器中打开授权 URL
   - 完成 OAuth 登录
   - Kiro Auth Service 回调到本地服务器

3. **Token 交换**
   - OAuth 服务器接收回调
   - 验证 State 参数
   - 使用授权码和 code_verifier 交换 Token
   - 保存 Token 到文件

4. **自动加载**
   - 启动时扫描 Token 目录
   - 加载未过期的 Token
   - 添加到 auth service

## 参考项目

本功能基于以下项目的实现：

- [kiro-batch-login](https://github.com/6Kmfi6HP/kiro-batch-login) - Kiro 批量登录 CLI

## 许可证

MIT License
