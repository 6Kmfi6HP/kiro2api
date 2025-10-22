# Dashboard 使用指南

本指南将帮助您快速上手 kiro2api Web Dashboard，轻松管理 Kiro 认证 Token。

## 目录

- [快速开始](#快速开始)
- [认证提供商选择](#认证提供商选择)
- [OAuth 登录流程](#oauth-登录流程)
- [Token 管理](#token-管理)
- [常见问题](#常见问题)

## 快速开始

### 1. 启动服务

无需预先配置 `KIRO_AUTH_TOKEN`，直接启动 kiro2api：

```bash
# 本地运行
./kiro2api

# 或使用 Docker
docker run -d -p 8080:8080 \
  -v $(pwd)/tokens:/app/tokens \
  -e KIRO_CLIENT_TOKEN=123456 \
  ghcr.io/caidaoli/kiro2api:latest
```

服务启动后，您会看到类似以下的日志：

```
INFO  Server starting on :8080
INFO  Dashboard available at http://localhost:8080/dashboard
```

### 2. 访问 Dashboard

在浏览器中打开：

```
http://localhost:8080/dashboard
```

您将看到 Dashboard 主页，显示：
- 当前已保存的所有 Token
- 每个 Token 的状态（valid/expiring/expired）
- 添加新账号的按钮

### 3. 添加第一个账号

1. 点击页面上的 **"Add Account"** 按钮
2. 选择您的认证提供商（详见下一节）
3. 点击 **"Login"** 开始 OAuth 流程
4. 在弹出的浏览器窗口中完成认证
5. 认证成功后，Token 自动保存

## 认证提供商选择

kiro2api 支持多种认证提供商，每种提供商适用于不同的使用场景。

### BuilderId（推荐）

**适用场景**：个人开发者，使用 AWS Builder ID 账号

**特点**：
- 最简单的认证方式
- 无需企业账号
- 支持 Google、GitHub 等社交账号登录

**使用步骤**：
1. 在 Dashboard 中选择 "BuilderId"
2. 点击 "Login"
3. 在浏览器中使用您的 AWS Builder ID 登录
4. 授权后自动完成

### Enterprise

**适用场景**：企业用户，使用企业 AWS 账号

**特点**：
- 需要企业 AWS 账号
- 支持 SSO 单点登录
- 更高的使用配额

**使用步骤**：
1. 在 Dashboard 中选择 "Enterprise"
2. 输入您的企业 Start URL（如果需要）
3. 点击 "Login"
4. 在浏览器中使用企业凭证登录
5. 授权后自动完成

### Google

**适用场景**：使用 Google 账号登录 AWS

**特点**：
- 使用 Google 账号作为身份提供商
- 适合已经使用 Google Workspace 的团队

**使用步骤**：
1. 在 Dashboard 中选择 "Google"
2. 点击 "Login"
3. 在浏览器中使用 Google 账号登录
4. 授权后自动完成

### GitHub

**适用场景**：使用 GitHub 账号登录 AWS

**特点**：
- 使用 GitHub 账号作为身份提供商
- 适合开源项目和开发者

**使用步骤**：
1. 在 Dashboard 中选择 "GitHub"
2. 点击 "Login"
3. 在浏览器中使用 GitHub 账号登录
4. 授权后自动完成

## OAuth 登录流程

### 本地部署（自动回调）

当 kiro2api 运行在本地时，OAuth 回调会自动处理：

1. **点击 Login**
   - Dashboard 生成授权 URL
   - 自动在浏览器中打开授权页面

2. **完成认证**
   - 在浏览器中输入您的凭证
   - 授权 kiro2api 访问您的账号

3. **自动回调**
   - 浏览器重定向到 `http://127.0.0.1:<port>/oauth/callback`
   - kiro2api 自动接收回调
   - Token 自动保存到 `tokens/` 目录

4. **完成**
   - 浏览器显示成功消息
   - 返回 Dashboard 查看新添加的 Token

### 远程部署（手动回调）

当 kiro2api 部署在远程服务器时，需要使用手动回调模式。详见 [远程部署指南](./remote-deployment.md)。

## Token 管理

### 查看 Token 状态

Dashboard 主页显示所有已保存的 Token，每个 Token 包含以下信息：

- **ID**：Token 的唯一标识符
- **Provider**：认证提供商（BuilderId、Enterprise 等）
- **Auth Method**：认证方式（Social 或 IdC）
- **Status**：Token 状态
  - `valid`：Token 有效，距离过期还有超过 24 小时
  - `expiring`：Token 即将过期（24 小时内）
  - `expired`：Token 已过期
- **Expires At**：Token 过期时间
- **Created At**：Token 创建时间

### 刷新 Token

当 Token 即将过期或已过期时，您可以手动刷新：

1. 在 Dashboard 中找到需要刷新的 Token
2. 点击该 Token 旁边的 **"Refresh"** 按钮
3. 系统自动使用 Refresh Token 获取新的 Access Token
4. 刷新成功后，Expires At 时间会更新

**注意**：
- 刷新操作不需要重新登录
- 如果 Refresh Token 也已过期，刷新会失败，需要重新登录
- 刷新后的 Token 会自动保存到文件

### 删除 Token

如果您不再需要某个 Token，可以删除它：

1. 在 Dashboard 中找到需要删除的 Token
2. 点击该 Token 旁边的 **"Delete"** 按钮
3. 确认删除操作
4. Token 文件会从 `tokens/` 目录中删除

**注意**：
- 删除操作不可恢复
- 删除后，如果需要使用该账号，需要重新登录
- 如果该 Token 正在被 API 使用，删除后 API 请求会失败

### Token 文件存储

所有通过 Dashboard 保存的 Token 都存储在 `tokens/` 目录中：

```
tokens/
├── 550e8400-e29b-41d4-a716-446655440000.json
├── 6ba7b810-9dad-11d1-80b4-00c04fd430c8.json
└── ...
```

每个文件包含一个 Token 的完整信息：

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "authMethod": "Social",
  "provider": "BuilderId",
  "accessToken": "eyJraWQiOiJrZXktM...",
  "refreshToken": "arn:aws:sso:us-east-1:999999999999:token/refresh/...",
  "profileArn": "arn:aws:iam::999999999999:user/...",
  "expiresAt": "2025-10-23T10:00:00Z",
  "createdAt": "2025-10-22T10:00:00Z",
  "metadata": {}
}
```

**环境变量配置**：

您可以通过 `KIRO_TOKENS_DIR` 环境变量自定义 Token 存储目录：

```bash
export KIRO_TOKENS_DIR=/path/to/custom/tokens
./kiro2api
```

## 常见问题

### Q: Dashboard 无法访问？

**A**: 检查以下几点：
1. 确认服务已启动：`curl http://localhost:8080/v1/models`
2. 检查端口是否被占用：`netstat -an | grep 8080`
3. 检查防火墙设置
4. 查看服务日志：`LOG_LEVEL=debug ./kiro2api`

### Q: OAuth 登录失败？

**A**: 可能的原因：
1. **网络问题**：检查是否能访问 AWS SSO 服务
2. **浏览器问题**：尝试使用无痕模式或其他浏览器
3. **回调端口被占用**：kiro2api 会自动尝试其他端口
4. **State 参数过期**：State 参数有效期为 10 分钟，超时后需要重新开始

### Q: Token 刷新失败？

**A**: 可能的原因：
1. **Refresh Token 已过期**：需要重新登录
2. **网络问题**：检查网络连接
3. **认证服务问题**：AWS SSO 服务可能暂时不可用

解决方法：
- 删除失败的 Token
- 重新通过 Dashboard 登录

### Q: 如何在远程服务器上使用 Dashboard？

**A**: 请参考 [远程部署指南](./remote-deployment.md)，使用手动回调模式。

### Q: Dashboard 和环境变量配置可以同时使用吗？

**A**: 可以。Token 加载优先级：
1. 环境变量 `KIRO_AUTH_TOKEN`（如果设置）
2. Token 文件目录 `KIRO_TOKENS_DIR`（默认 `./tokens`）

如果设置了 `KIRO_AUTH_TOKEN`，Dashboard 保存的 Token 仍然会存储到文件，但 API 会优先使用环境变量中的配置。

### Q: 如何备份 Token？

**A**: 直接备份 `tokens/` 目录：

```bash
# 备份
cp -r tokens/ tokens_backup/

# 恢复
cp -r tokens_backup/* tokens/
```

### Q: Token 文件可以手动编辑吗？

**A**: 可以，但不推荐。Token 文件是标准的 JSON 格式，您可以手动编辑，但需要确保：
1. JSON 格式正确
2. 所有必需字段都存在
3. 时间格式为 RFC3339（`2025-10-22T10:00:00Z`）

建议通过 Dashboard 管理 Token，避免手动编辑导致的错误。

### Q: 如何查看 Dashboard 日志？

**A**: 启用 debug 日志：

```bash
LOG_LEVEL=debug ./kiro2api
```

Dashboard 相关的日志会包含 `[dashboard]` 标签。

## 下一步

- [远程部署指南](./remote-deployment.md) - 了解如何在远程服务器上使用 Dashboard
- [故障排除](./troubleshooting.md) - 解决常见问题
- [手动测试清单](./manual-testing.md) - 完整的功能测试步骤
