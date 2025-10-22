# 远程部署指南

本指南介绍如何在远程服务器上部署 kiro2api 并使用 Web Dashboard 进行 Token 管理。

## 目录

- [问题背景](#问题背景)
- [解决方案](#解决方案)
- [部署步骤](#部署步骤)
- [手动回调流程](#手动回调流程)
- [网络配置](#网络配置)
- [安全考虑](#安全考虑)
- [故障排除](#故障排除)

## 问题背景

### 为什么需要手动回调？

当 kiro2api 部署在远程服务器时，OAuth 回调 URL 通常是 `http://127.0.0.1:<port>/oauth/callback`。这个 URL 指向本地回环地址，浏览器无法将回调请求发送到远程服务器。

**示例场景**：

```
用户浏览器 (本地)
    ↓
AWS SSO 认证服务器
    ↓
回调 URL: http://127.0.0.1:12345/oauth/callback
    ↓
❌ 无法到达远程服务器上的 kiro2api
```

### 传统解决方案的问题

1. **修改回调 URL 为公网地址**
   - 需要配置域名和 SSL 证书
   - 需要开放公网端口
   - 安全风险较高

2. **使用 SSH 隧道**
   - 配置复杂
   - 需要额外的工具
   - 不适合非技术用户

### kiro2api 的解决方案

kiro2api 提供了**手动回调模式**，让您可以：
1. 在本地浏览器中完成 OAuth 认证
2. 复制浏览器地址栏中的回调 URL
3. 通过 Dashboard 提交回调 URL
4. Token 安全地保存到远程服务器

## 解决方案

### 手动回调模式工作原理

```
1. 用户在 Dashboard 中点击 "Login"
   ↓
2. Dashboard 生成授权 URL 和 State
   ↓
3. 用户在浏览器中完成认证
   ↓
4. 浏览器重定向到 http://127.0.0.1:<port>/oauth/callback?code=xxx&state=xxx
   ↓
5. 用户复制完整的回调 URL
   ↓
6. 用户在 Dashboard 中点击 "Manual Callback"
   ↓
7. 粘贴回调 URL 并提交
   ↓
8. kiro2api 验证 State 并交换 Token
   ↓
9. Token 保存到远程服务器的 tokens/ 目录
```

### 优势

- **无需公网暴露**：不需要开放额外的端口
- **安全可靠**：State 参数防止 CSRF 攻击
- **简单易用**：只需复制粘贴 URL
- **适用所有场景**：VPS、云服务器、容器化部署

## 部署步骤

### 1. 在远程服务器上部署 kiro2api

#### 使用 Docker（推荐）

```bash
# 创建 Token 存储目录
mkdir -p /opt/kiro2api/tokens

# 启动服务
docker run -d \
  --name kiro2api \
  -p 8080:8080 \
  -v /opt/kiro2api/tokens:/app/tokens \
  -e KIRO_CLIENT_TOKEN=your-secure-token \
  -e LOG_LEVEL=info \
  ghcr.io/caidaoli/kiro2api:latest

# 检查服务状态
docker logs kiro2api
```

#### 使用二进制文件

```bash
# 上传二进制文件到服务器
scp kiro2api user@remote-server:/opt/kiro2api/

# SSH 登录到服务器
ssh user@remote-server

# 创建 Token 存储目录
mkdir -p /opt/kiro2api/tokens

# 配置环境变量
cat > /opt/kiro2api/.env << EOF
PORT=8080
KIRO_CLIENT_TOKEN=your-secure-token
KIRO_TOKENS_DIR=/opt/kiro2api/tokens
LOG_LEVEL=info
GIN_MODE=release
EOF

# 启动服务
cd /opt/kiro2api
./kiro2api
```

#### 使用 systemd（生产环境推荐）

```bash
# 创建 systemd 服务文件
sudo cat > /etc/systemd/system/kiro2api.service << EOF
[Unit]
Description=kiro2api Service
After=network.target

[Service]
Type=simple
User=kiro2api
WorkingDirectory=/opt/kiro2api
EnvironmentFile=/opt/kiro2api/.env
ExecStart=/opt/kiro2api/kiro2api
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

# 重新加载 systemd
sudo systemctl daemon-reload

# 启动服务
sudo systemctl start kiro2api

# 设置开机自启
sudo systemctl enable kiro2api

# 查看状态
sudo systemctl status kiro2api
```

### 2. 配置反向代理（可选但推荐）

#### Nginx

```nginx
server {
    listen 80;
    server_name your-domain.com;

    # 重定向到 HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Dashboard
    location /dashboard {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # API
    location /v1 {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 流式响应支持
        proxy_buffering off;
        proxy_cache off;
        proxy_http_version 1.1;
        chunked_transfer_encoding on;
    }
}
```

#### Caddy

```caddy
your-domain.com {
    reverse_proxy /dashboard* 127.0.0.1:8080
    reverse_proxy /v1* 127.0.0.1:8080 {
        flush_interval -1
    }
}
```

### 3. 配置防火墙

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

## 手动回调流程

### 详细步骤

#### 1. 访问 Dashboard

在本地浏览器中打开：

```
https://your-domain.com/dashboard
```

或者如果没有配置域名：

```
http://your-server-ip:8080/dashboard
```

#### 2. 开始 OAuth 流程

1. 点击 **"Add Account"** 按钮
2. 选择认证提供商（例如 BuilderId）
3. 点击 **"Login"** 按钮
4. Dashboard 会显示授权 URL

#### 3. 完成认证

1. 复制授权 URL
2. 在新的浏览器标签页中打开该 URL
3. 使用您的 AWS 凭证登录
4. 授权 kiro2api 访问您的账号

#### 4. 复制回调 URL

认证成功后，浏览器会尝试重定向到类似以下的 URL：

```
http://127.0.0.1:12345/oauth/callback?code=eyJraWQiOiJrZXktM...&state=550e8400-e29b-41d4-a716-446655440000
```

**重要**：
- 不要关闭这个浏览器标签页
- 复制地址栏中的**完整 URL**
- 确保包含 `code` 和 `state` 参数

#### 5. 提交手动回调

1. 返回 Dashboard 标签页
2. 点击 **"Manual Callback"** 按钮
3. 在输入框中粘贴完整的回调 URL
4. 点击 **"Submit"** 按钮

#### 6. 验证成功

如果一切正常，您会看到：
- 成功消息："Authentication successful! Token has been saved."
- Dashboard 主页显示新添加的 Token
- Token 状态为 "valid"

### 常见错误

#### 错误 1：State 参数无效

```json
{
  "error": "invalid state"
}
```

**原因**：
- State 参数已过期（有效期 10 分钟）
- State 参数不匹配

**解决方法**：
- 重新开始 OAuth 流程
- 确保在 10 分钟内完成整个流程

#### 错误 2：Code 参数缺失

```json
{
  "error": "Callback URL missing code or state parameter"
}
```

**原因**：
- 复制的 URL 不完整
- URL 被浏览器截断

**解决方法**：
- 确保复制完整的 URL
- 检查 URL 中是否包含 `?code=` 和 `&state=`

#### 错误 3：Token 交换失败

```json
{
  "error": "Failed to exchange code for token"
}
```

**原因**：
- Authorization Code 已被使用
- Authorization Code 已过期
- 网络问题

**解决方法**：
- 重新开始 OAuth 流程
- 检查服务器网络连接
- 查看服务器日志：`docker logs kiro2api`

## 网络配置

### 端口要求

| 端口 | 用途 | 是否必需 | 说明 |
|------|------|----------|------|
| 8080 | kiro2api 服务 | 是 | 可通过 `PORT` 环境变量修改 |
| 80 | HTTP（反向代理） | 可选 | 推荐配置 |
| 443 | HTTPS（反向代理） | 可选 | 推荐配置 |

### 防火墙规则

**最小权限原则**：

```bash
# 仅允许必要的端口
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

**如果不使用反向代理**：

```bash
sudo ufw allow 8080/tcp  # kiro2api 直接访问
```

### 云服务商安全组

#### AWS EC2

```
入站规则：
- 类型：HTTP，协议：TCP，端口：80，来源：0.0.0.0/0
- 类型：HTTPS，协议：TCP，端口：443，来源：0.0.0.0/0
- 类型：自定义TCP，协议：TCP，端口：8080，来源：0.0.0.0/0（可选）

出站规则：
- 类型：所有流量，协议：所有，端口：所有，目标：0.0.0.0/0
```

#### 阿里云 ECS

```
入方向：
- 协议类型：TCP，端口范围：80/80，授权对象：0.0.0.0/0
- 协议类型：TCP，端口范围：443/443，授权对象：0.0.0.0/0
- 协议类型：TCP，端口范围：8080/8080，授权对象：0.0.0.0/0（可选）

出方向：
- 协议类型：全部，端口范围：-1/-1，授权对象：0.0.0.0/0
```

## 安全考虑

### 1. HTTPS 加密

**强烈推荐**在生产环境中使用 HTTPS：

```bash
# 使用 Let's Encrypt 免费证书
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

### 2. 访问控制

#### 限制 Dashboard 访问

```nginx
# Nginx: 仅允许特定 IP 访问 Dashboard
location /dashboard {
    allow 1.2.3.4;      # 您的 IP
    allow 5.6.7.0/24;   # 您的网络
    deny all;

    proxy_pass http://127.0.0.1:8080;
}
```

#### 使用 HTTP Basic Auth

```nginx
# 生成密码文件
sudo htpasswd -c /etc/nginx/.htpasswd admin

# Nginx 配置
location /dashboard {
    auth_basic "Dashboard Access";
    auth_basic_user_file /etc/nginx/.htpasswd;

    proxy_pass http://127.0.0.1:8080;
}
```

### 3. Token 文件保护

```bash
# 设置正确的文件权限
chmod 700 /opt/kiro2api/tokens
chmod 600 /opt/kiro2api/tokens/*.json

# 设置正确的所有者
chown -R kiro2api:kiro2api /opt/kiro2api/tokens
```

### 4. 日志审计

```bash
# 启用详细日志
LOG_LEVEL=info
LOG_FORMAT=json
LOG_FILE=/var/log/kiro2api/access.log

# 定期检查日志
tail -f /var/log/kiro2api/access.log | grep dashboard
```

### 5. 定期备份

```bash
# 创建备份脚本
cat > /opt/kiro2api/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/kiro2api/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/tokens_$DATE.tar.gz" -C /opt/kiro2api tokens/

# 保留最近 7 天的备份
find "$BACKUP_DIR" -name "tokens_*.tar.gz" -mtime +7 -delete
EOF

chmod +x /opt/kiro2api/backup.sh

# 添加到 crontab（每天凌晨 2 点备份）
echo "0 2 * * * /opt/kiro2api/backup.sh" | crontab -
```

## 故障排除

### 问题 1：无法访问 Dashboard

**症状**：浏览器显示 "无法连接到服务器"

**排查步骤**：

```bash
# 1. 检查服务是否运行
sudo systemctl status kiro2api
# 或
docker ps | grep kiro2api

# 2. 检查端口是否监听
sudo netstat -tlnp | grep 8080

# 3. 检查防火墙
sudo ufw status
sudo iptables -L -n

# 4. 检查日志
sudo journalctl -u kiro2api -f
# 或
docker logs -f kiro2api
```

### 问题 2：手动回调失败

**症状**：提交回调 URL 后显示错误

**排查步骤**：

```bash
# 1. 检查 State 是否有效
# 查看日志中的 State 相关信息
docker logs kiro2api | grep state

# 2. 检查网络连接
# 确保服务器可以访问 AWS SSO
curl -I https://oidc.us-east-1.amazonaws.com

# 3. 检查 Token 目录权限
ls -la /opt/kiro2api/tokens

# 4. 启用 debug 日志
# 修改 .env 文件
LOG_LEVEL=debug
# 重启服务
sudo systemctl restart kiro2api
```

### 问题 3：Token 保存失败

**症状**：认证成功但 Token 未保存

**排查步骤**：

```bash
# 1. 检查磁盘空间
df -h

# 2. 检查目录权限
ls -la /opt/kiro2api/tokens

# 3. 检查 SELinux（CentOS/RHEL）
getenforce
# 如果是 Enforcing，临时禁用测试
sudo setenforce 0

# 4. 查看详细错误
docker logs kiro2api | grep "Failed to save token"
```

### 问题 4：反向代理配置问题

**症状**：通过域名访问 Dashboard 出现 502 错误

**排查步骤**：

```bash
# 1. 检查 Nginx 配置
sudo nginx -t

# 2. 检查 Nginx 日志
sudo tail -f /var/log/nginx/error.log

# 3. 检查 kiro2api 是否监听正确的地址
sudo netstat -tlnp | grep 8080

# 4. 测试直接访问
curl http://127.0.0.1:8080/v1/models
```

## 最佳实践

### 1. 使用域名和 HTTPS

```bash
# 配置域名
your-domain.com → 服务器 IP

# 配置 SSL 证书
sudo certbot --nginx -d your-domain.com

# 访问 Dashboard
https://your-domain.com/dashboard
```

### 2. 配置监控和告警

```bash
# 使用 systemd 监控服务状态
sudo systemctl enable kiro2api

# 配置邮件告警
sudo apt install mailutils
echo "kiro2api service failed" | mail -s "Alert" admin@example.com
```

### 3. 定期更新

```bash
# 拉取最新镜像
docker pull ghcr.io/caidaoli/kiro2api:latest

# 重启服务
docker stop kiro2api
docker rm kiro2api
docker run -d ... # 使用新镜像启动
```

### 4. 文档化部署

创建部署文档，记录：
- 服务器信息（IP、域名、端口）
- 配置文件位置
- 备份策略
- 应急联系人

## 下一步

- [Dashboard 使用指南](./dashboard-guide.md) - 了解 Dashboard 的详细功能
- [故障排除](./troubleshooting.md) - 解决常见问题
- [手动测试清单](./manual-testing.md) - 完整的功能测试步骤
