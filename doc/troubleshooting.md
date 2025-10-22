# 故障排除指南

本指南帮助您诊断和解决 kiro2api Web Dashboard 的常见问题。

## 目录

- [Dashboard 访问问题](#dashboard-访问问题)
- [OAuth 登录问题](#oauth-登录问题)
- [Token 管理问题](#token-管理问题)
- [网络连接问题](#网络连接问题)
- [浏览器兼容性问题](#浏览器兼容性问题)
- [性能问题](#性能问题)
- [日志分析](#日志分析)

## Dashboard 访问问题

### 问题：无法访问 Dashboard

**症状**：
- 浏览器显示 "无法连接到服务器"
- 或显示 "ERR_CONNECTION_REFUSED"

**可能原因**：
1. kiro2api 服务未启动
2. 端口被占用或防火墙阻止
3. 配置的端口不正确

**解决步骤**：

```bash
# 1. 检查服务是否运行
# 本地部署
ps aux | grep kiro2api

# Docker 部署
docker ps | grep kiro2api

# systemd 部署
sudo systemctl status kiro2api

# 2. 检查端口监听
sudo netstat -tlnp | grep 8080
# 或
sudo ss -tlnp | grep 8080

# 3. 测试 API 端点
curl http://localhost:8080/v1/models

# 4. 检查防火墙
sudo ufw status
sudo iptables -L -n | grep 8080

# 5. 查看服务日志
# Docker
docker logs kiro2api

# systemd
sudo journalctl -u kiro2api -f

# 本地运行
LOG_LEVEL=debug ./kiro2api
```

**解决方案**：

如果服务未运行：
```bash
# 启动服务
./kiro2api

# 或 Docker
docker start kiro2api

# 或 systemd
sudo systemctl start kiro2api
```

如果端口被占用：
```bash
# 查找占用端口的进程
sudo lsof -i :8080

# 终止进程或更改 kiro2api 端口
export PORT=8081
./kiro2api
```

如果防火墙阻止：
```bash
# UFW
sudo ufw allow 8080/tcp

# firewalld
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

### 问题：Dashboard 页面显示空白

**症状**：
- Dashboard 页面加载但内容为空
- 浏览器控制台显示 JavaScript 错误

**可能原因**：
1. 静态资源加载失败
2. 模板文件缺失
3. 浏览器缓存问题

**解决步骤**：

```bash
# 1. 检查静态资源
curl http://localhost:8080/dashboard/static/style.css

# 2. 清除浏览器缓存
# Chrome: Ctrl+Shift+Delete
# Firefox: Ctrl+Shift+Delete
# Safari: Cmd+Option+E

# 3. 使用无痕模式测试
# Chrome: Ctrl+Shift+N
# Firefox: Ctrl+Shift+P

# 4. 检查浏览器控制台
# F12 → Console 标签页
# 查看是否有错误信息

# 5. 检查服务日志
docker logs kiro2api | grep "Failed to load"
```

**解决方案**：

如果静态资源缺失：
```bash
# 重新构建或重新下载
go build -o kiro2api main.go

# 或拉取最新 Docker 镜像
docker pull ghcr.io/caidaoli/kiro2api:latest
```

### 问题：Dashboard 显示 404 错误

**症状**：
- 访问 `/dashboard` 显示 "404 Not Found"

**可能原因**：
1. 路由配置错误
2. 版本过旧，不支持 Dashboard

**解决步骤**：

```bash
# 1. 检查版本
./kiro2api --version

# 2. 测试其他端点
curl http://localhost:8080/v1/models

# 3. 检查路由配置
# 查看日志中的路由注册信息
docker logs kiro2api | grep "dashboard"
```

**解决方案**：

更新到最新版本：
```bash
# 拉取最新代码
git pull origin main
go build -o kiro2api main.go

# 或使用最新 Docker 镜像
docker pull ghcr.io/caidaoli/kiro2api:latest
```

## OAuth 登录问题

### 问题：OAuth 登录失败

**症状**：
- 点击 "Login" 后无响应
- 或显示 "Failed to build authorization URL"

**可能原因**：
1. 网络连接问题
2. 认证服务不可用
3. 配置错误

**解决步骤**：

```bash
# 1. 测试网络连接
curl -I https://oidc.us-east-1.amazonaws.com

# 2. 检查 DNS 解析
nslookup oidc.us-east-1.amazonaws.com

# 3. 启用 debug 日志
LOG_LEVEL=debug ./kiro2api

# 4. 查看详细错误
docker logs kiro2api | grep "Failed to build"
```

**解决方案**：

如果网络问题：
```bash
# 检查代理设置
echo $HTTP_PROXY
echo $HTTPS_PROXY

# 如果需要代理
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080
./kiro2api
```

如果认证服务不可用：
- 等待服务恢复
- 尝试其他认证提供商

### 问题：回调服务器启动失败

**症状**：
- 日志显示 "Failed to start callback server"
- 或 "Address already in use"

**可能原因**：
1. 回调端口被占用
2. 权限不足

**解决步骤**：

```bash
# 1. 检查端口占用
sudo netstat -tlnp | grep 127.0.0.1

# 2. 查找占用端口的进程
sudo lsof -i :12345

# 3. 检查日志
docker logs kiro2api | grep "callback server"
```

**解决方案**：

kiro2api 会自动尝试其他端口，如果持续失败：
```bash
# 终止占用端口的进程
sudo kill -9 <PID>

# 或重启服务
sudo systemctl restart kiro2api
```

### 问题：State 参数无效

**症状**：
- 手动回调时显示 "invalid state"

**可能原因**：
1. State 参数已过期（超过 10 分钟）
2. State 参数不匹配
3. 服务重启导致 State 丢失

**解决步骤**：

```bash
# 1. 检查时间差
# 确保从点击 Login 到提交回调不超过 10 分钟

# 2. 检查日志
docker logs kiro2api | grep "state"

# 3. 确认 State 参数
# 检查回调 URL 中的 state 参数是否完整
```

**解决方案**：

重新开始 OAuth 流程：
1. 返回 Dashboard
2. 点击 "Add Account"
3. 重新选择提供商并登录
4. 在 10 分钟内完成整个流程

### 问题：Authorization Code 无效

**症状**：
- 显示 "Failed to exchange code for token"
- 或 "Invalid authorization code"

**可能原因**：
1. Authorization Code 已被使用
2. Authorization Code 已过期
3. Code Verifier 不匹配

**解决步骤**：

```bash
# 1. 检查日志
docker logs kiro2api | grep "exchange code"

# 2. 确认 Code 参数
# 检查回调 URL 中的 code 参数是否完整

# 3. 检查网络连接
curl -I https://oidc.us-east-1.amazonaws.com
```

**解决方案**：

Authorization Code 只能使用一次，需要重新获取：
1. 重新开始 OAuth 流程
2. 获取新的 Authorization Code
3. 立即提交回调（不要重复提交）

## Token 管理问题

### 问题：Token 刷新失败

**症状**：
- 点击 "Refresh" 后显示错误
- 或 "Failed to refresh token"

**可能原因**：
1. Refresh Token 已过期
2. 网络连接问题
3. 认证服务不可用

**解决步骤**：

```bash
# 1. 检查 Token 状态
# 在 Dashboard 中查看 Token 的 Expires At 时间

# 2. 检查日志
docker logs kiro2api | grep "refresh token"

# 3. 测试网络连接
curl -I https://oidc.us-east-1.amazonaws.com

# 4. 手动测试刷新
curl -X POST http://localhost:8080/dashboard/tokens/refresh/<token-id> \
  -H "Content-Type: application/json"
```

**解决方案**：

如果 Refresh Token 过期：
1. 删除该 Token
2. 重新通过 Dashboard 登录

如果网络问题：
- 检查网络连接
- 稍后重试

### 问题：Token 删除失败

**症状**：
- 点击 "Delete" 后显示错误
- 或 "Token not found"

**可能原因**：
1. Token 文件已被删除
2. 文件权限问题
3. Token ID 不匹配

**解决步骤**：

```bash
# 1. 检查 Token 文件
ls -la /opt/kiro2api/tokens/

# 2. 检查文件权限
ls -l /opt/kiro2api/tokens/<token-id>.json

# 3. 检查日志
docker logs kiro2api | grep "delete token"

# 4. 手动删除
rm /opt/kiro2api/tokens/<token-id>.json
```

**解决方案**：

如果文件权限问题：
```bash
# 修复权限
sudo chown -R kiro2api:kiro2api /opt/kiro2api/tokens
sudo chmod 700 /opt/kiro2api/tokens
sudo chmod 600 /opt/kiro2api/tokens/*.json
```

如果文件已删除：
- 刷新 Dashboard 页面
- Token 应该自动从列表中消失

### 问题：Token 保存失败

**症状**：
- 认证成功但 Token 未出现在 Dashboard
- 或 "Failed to save token"

**可能原因**：
1. 磁盘空间不足
2. 目录权限问题
3. 文件系统只读

**解决步骤**：

```bash
# 1. 检查磁盘空间
df -h

# 2. 检查目录权限
ls -la /opt/kiro2api/tokens/

# 3. 测试写入
touch /opt/kiro2api/tokens/test.txt
rm /opt/kiro2api/tokens/test.txt

# 4. 检查文件系统
mount | grep /opt/kiro2api

# 5. 检查日志
docker logs kiro2api | grep "save token"
```

**解决方案**：

如果磁盘空间不足：
```bash
# 清理磁盘空间
sudo apt clean
sudo journalctl --vacuum-time=7d
```

如果权限问题：
```bash
# 修复权限
sudo chown -R kiro2api:kiro2api /opt/kiro2api/tokens
sudo chmod 700 /opt/kiro2api/tokens
```

如果文件系统只读：
```bash
# 重新挂载为读写
sudo mount -o remount,rw /opt/kiro2api
```

## 网络连接问题

### 问题：无法连接到 AWS SSO

**症状**：
- OAuth 登录超时
- 或 "Connection timed out"

**可能原因**：
1. 网络不通
2. DNS 解析失败
3. 防火墙阻止
4. 代理配置错误

**解决步骤**：

```bash
# 1. 测试网络连接
ping oidc.us-east-1.amazonaws.com

# 2. 测试 HTTPS 连接
curl -v https://oidc.us-east-1.amazonaws.com

# 3. 检查 DNS 解析
nslookup oidc.us-east-1.amazonaws.com
dig oidc.us-east-1.amazonaws.com

# 4. 检查路由
traceroute oidc.us-east-1.amazonaws.com

# 5. 检查代理设置
echo $HTTP_PROXY
echo $HTTPS_PROXY
echo $NO_PROXY
```

**解决方案**：

如果 DNS 问题：
```bash
# 使用公共 DNS
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf
```

如果需要代理：
```bash
# 配置代理
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080
export NO_PROXY=localhost,127.0.0.1

# 重启服务
sudo systemctl restart kiro2api
```

如果防火墙阻止：
```bash
# 允许出站 HTTPS 连接
sudo ufw allow out 443/tcp
```

### 问题：SSL 证书验证失败

**症状**：
- 显示 "SSL certificate problem"
- 或 "x509: certificate signed by unknown authority"

**可能原因**：
1. 系统证书过期
2. 企业代理使用自签名证书
3. 时间不同步

**解决步骤**：

```bash
# 1. 检查系统时间
date
timedatectl status

# 2. 更新 CA 证书
sudo apt update
sudo apt install ca-certificates
sudo update-ca-certificates

# 3. 测试 SSL 连接
openssl s_client -connect oidc.us-east-1.amazonaws.com:443

# 4. 检查证书有效期
echo | openssl s_client -connect oidc.us-east-1.amazonaws.com:443 2>/dev/null | openssl x509 -noout -dates
```

**解决方案**：

如果时间不同步：
```bash
# 同步时间
sudo ntpdate pool.ntp.org
# 或
sudo timedatectl set-ntp true
```

如果企业代理问题：
```bash
# 导入企业 CA 证书
sudo cp enterprise-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

## 浏览器兼容性问题

### 问题：Dashboard 在某些浏览器中无法正常工作

**症状**：
- 按钮无响应
- 页面布局错乱
- JavaScript 错误

**支持的浏览器**：
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

**解决步骤**：

```bash
# 1. 检查浏览器版本
# Chrome: chrome://version
# Firefox: about:support
# Safari: Safari → About Safari

# 2. 清除浏览器缓存
# Chrome: Ctrl+Shift+Delete
# Firefox: Ctrl+Shift+Delete
# Safari: Cmd+Option+E

# 3. 禁用浏览器扩展
# 使用无痕模式测试

# 4. 检查浏览器控制台
# F12 → Console 标签页
```

**解决方案**：

更新浏览器到最新版本：
- Chrome: chrome://settings/help
- Firefox: about:preferences#general
- Safari: App Store → Updates

如果问题持续：
- 尝试其他浏览器
- 报告问题到 GitHub Issues

### 问题：移动浏览器兼容性

**症状**：
- 移动设备上 Dashboard 显示异常

**支持的移动浏览器**：
- iOS Safari 14+
- Chrome for Android 90+

**解决方案**：

Dashboard 主要为桌面浏览器设计，建议：
1. 使用桌面浏览器访问
2. 或使用移动浏览器的"桌面模式"

## 性能问题

### 问题：Dashboard 加载缓慢

**症状**：
- Dashboard 页面加载时间超过 5 秒

**可能原因**：
1. Token 文件过多
2. 服务器资源不足
3. 网络延迟

**解决步骤**：

```bash
# 1. 检查 Token 文件数量
ls -1 /opt/kiro2api/tokens/*.json | wc -l

# 2. 检查服务器资源
top
htop
free -h
df -h

# 3. 检查网络延迟
ping localhost
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8080/dashboard

# 4. 检查日志
docker logs kiro2api | grep "slow"
```

**解决方案**：

如果 Token 文件过多：
```bash
# 删除过期的 Token
# 在 Dashboard 中手动删除
# 或使用脚本清理
find /opt/kiro2api/tokens -name "*.json" -mtime +30 -delete
```

如果资源不足：
```bash
# 增加服务器资源
# 或优化配置
GIN_MODE=release
LOG_LEVEL=warn
```

### 问题：API 请求超时

**症状**：
- Dashboard 操作超时
- 或 "Request timeout"

**可能原因**：
1. 网络延迟
2. 认证服务响应慢
3. 服务器负载高

**解决步骤**：

```bash
# 1. 测试 API 响应时间
time curl http://localhost:8080/v1/models

# 2. 检查服务器负载
uptime
top

# 3. 检查网络延迟
ping oidc.us-east-1.amazonaws.com

# 4. 检查日志
docker logs kiro2api | grep "timeout"
```

**解决方案**：

增加超时时间（如果需要）：
```bash
# 配置环境变量
export REQUEST_TIMEOUT=60s
./kiro2api
```

## 日志分析

### 启用详细日志

```bash
# 设置日志级别
export LOG_LEVEL=debug
export LOG_FORMAT=json
./kiro2api
```

### 常见日志消息

#### 成功消息

```
INFO  Dashboard available at http://localhost:8080/dashboard
INFO  Callback server started redirect_uri=http://127.0.0.1:12345/oauth/callback
INFO  Token saved successfully token_id=550e8400-e29b-41d4-a716-446655440000
INFO  Token refreshed successfully token_id=550e8400-e29b-41d4-a716-446655440000
INFO  Token deleted successfully token_id=550e8400-e29b-41d4-a716-446655440000
```

#### 错误消息

```
ERROR Failed to load tokens error="open tokens: no such file or directory"
ERROR Invalid provider provider=InvalidProvider error="provider not found"
ERROR Failed to generate PKCE error="crypto/rand: read failed"
ERROR Failed to start callback server error="listen tcp :12345: bind: address already in use"
ERROR Failed to save state error="state store full"
ERROR Invalid state error="state not found"
ERROR Failed to exchange code for token error="invalid authorization code"
ERROR Failed to save token error="permission denied"
ERROR Token not found token_id=invalid-id error="file not found"
ERROR Failed to refresh token token_id=550e8400 error="refresh token expired"
ERROR Failed to delete token token_id=550e8400 error="permission denied"
```

### 日志过滤

```bash
# 仅查看 Dashboard 相关日志
docker logs kiro2api 2>&1 | grep dashboard

# 仅查看错误日志
docker logs kiro2api 2>&1 | grep ERROR

# 实时查看日志
docker logs -f kiro2api

# 查看最近 100 行日志
docker logs --tail 100 kiro2api

# 查看特定时间范围的日志
docker logs --since 2025-10-22T10:00:00 --until 2025-10-22T11:00:00 kiro2api
```

## 获取帮助

如果以上方法都无法解决您的问题，请：

1. **查看文档**
   - [Dashboard 使用指南](./dashboard-guide.md)
   - [远程部署指南](./remote-deployment.md)

2. **搜索已知问题**
   - GitHub Issues: https://github.com/your-repo/kiro2api/issues

3. **提交问题报告**
   - 包含详细的错误信息
   - 附上相关日志
   - 说明复现步骤
   - 提供环境信息（操作系统、浏览器版本等）

4. **社区支持**
   - 加入讨论组
   - 查看 FAQ

## 诊断信息收集

提交问题时，请提供以下信息：

```bash
# 1. 版本信息
./kiro2api --version

# 2. 系统信息
uname -a
cat /etc/os-release

# 3. 服务状态
sudo systemctl status kiro2api
docker ps -a | grep kiro2api

# 4. 网络信息
sudo netstat -tlnp | grep 8080
curl -I http://localhost:8080/v1/models

# 5. 日志信息
docker logs --tail 200 kiro2api > kiro2api.log

# 6. 配置信息（隐藏敏感信息）
cat .env | grep -v TOKEN | grep -v SECRET

# 7. Token 文件信息
ls -la /opt/kiro2api/tokens/
```

将以上信息打包并附在问题报告中。
