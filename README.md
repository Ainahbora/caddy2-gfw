# Caddy2-GFW

Caddy2-GFW 是一个用于 Caddy 服务器的 HTTP 请求过滤模块，用于检测和拦截恶意请求。

## 功能特点

- 支持多种规则类型：
  - IP地址/网段规则
  - URL路径规则
  - User-Agent规则
- 规则文件自动刷新
- 可配置的黑名单TTL
- 自动清理过期黑名单
- 支持规则文件注释
- 线程安全的规则匹配

## 安装

```bash
# 使用 xcaddy 构建
xcaddy build --with github.com/ysicing/caddy2-gfw
```

## 配置示例

### Caddyfile 配置

```caddyfile
# 全局配置
{
    # 启用自动HTTPS
    auto_https disable_redirects
    # 设置日志级别
    log {
        level INFO
    }
}

# 示例站点配置
:80 {
    # 启用GFW模块
    gfw {
        # 规则文件路径
        block_rule_file /etc/caddy/rules.txt
        # 黑名单IP的TTL时间
        ttl 24h
        # 直接配置的规则（可选）
        block_rule ip:192.168.1.1
        block_rule url:/admin
        block_rule ua:curl
    }

    # 反向代理配置
    reverse_proxy localhost:8080
}
```

### 规则文件格式

规则文件支持以下格式：

```text
# IP规则
ip:192.168.1.1
ip:10.0.0.0/24

# URL规则
url:/admin
url:/wp-login.php

# User-Agent规则
ua:curl
ua:wget
```

## 规则类型说明

1. IP规则
   - 支持单个IP地址：`ip:192.168.1.1`
   - 支持CIDR格式：`ip:10.0.0.0/24`

2. URL规则
   - 支持路径匹配：`url:/admin`
   - 支持文件匹配：`url:/wp-login.php`

3. User-Agent规则
   - 支持完整匹配：`ua:curl`
   - 支持部分匹配：`ua:python-requests`

## 配置选项

- `block_rule_file`: 规则文件路径
- `ttl`: 黑名单IP的TTL时间，默认为24小时
- `block_rule`: 直接在配置中添加规则

## 日志说明

模块会记录以下类型的日志：

1. 初始化日志
   - 规则文件加载状态
   - 配置参数信息

2. 请求处理日志
   - 黑名单IP拦截
   - 规则匹配拦截
   - 恶意请求检测

3. 维护日志
   - 规则文件更新
   - 黑名单清理

## 注意事项

1. 规则文件格式
   - 每行一条规则
   - 支持#开头的注释行
   - 支持空行
   - 规则格式必须正确

2. 性能考虑
   - 规则文件不宜过大
   - 建议定期清理过期规则
   - 合理设置TTL时间

3. 安全建议
   - 定期更新规则文件
   - 监控日志文件
   - 及时处理异常请求

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License
