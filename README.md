# Caddy GFW 扩展

这是一个Caddy v2的扩展模块，用于检测恶意请求，自动拦截不合法请求并返回403状态码，同时将恶意IP上报到指定API。

## 功能特性

- 自动检测恶意请求并拦截
- 将不合法请求的IP加入黑名单
- 支持自定义拦截规则（IP地址、URL路径和User-Agent）
- 支持自定义上报API地址
- 异步上报恶意IP信息
- 自动拦截直接使用IP访问80和443端口的请求（无域名）

## 规则类型说明

GFW模块支持三种类型的拦截规则：

1. **IP地址规则**：直接填写IP地址，如 `192.168.1.100`，将匹配来自该IP的请求
2. **URL路径规则**：以 `/` 开头的规则，如 `/admin`，将匹配请求路径等于或以该路径开头的请求
3. **User-Agent规则**：不符合上述两种格式的规则，如 `malicious-bot`，将匹配包含该字符串的User-Agent

## 安装

### 使用xcaddy构建

```bash
xcaddy build --with github.com/ysicing/caddy2-gfw
```

### 使用go install

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/ysicing/caddy2-gfw
```

## 配置

### Caddyfile 配置示例

```caddyfile
{
  order gfw before respond
}

example.com {
  gfw {
    report_url https://api.baidu.com/report
    
    # 方式一：直接在配置中添加规则
    block_rule "malicious-bot"  # User-Agent规则
    block_rule "bad-crawler"    # User-Agent规则
    block_rule "/admin"        # URL路径规则
    block_rule "192.168.1.100" # IP地址规则
    
    # 方式二：从文件加载规则（适合管理大量规则）
    block_rule_file /path/to/block.rule
    
    # 注意：模块会自动拦截直接使用IP访问的请求（无需额外配置）
  }
  respond "Hello, World!"
}
```

### JSON 配置示例

```json
{
  "apps": {
    "http": {
      "servers": {
        "example": {
          "listen": [":80"],
          "routes": [
            {
              "handle": [
                {
                  "handler": "gfw",
                  "report_url": "https://api.baidu.com/report",
                  "block_rules": [
                    "malicious-bot",  // User-Agent规则
                    "bad-crawler",    // User-Agent规则
                    "/admin",         // URL路径规则
                    "192.168.1.100"   // IP地址规则
                  ],
                  "block_rule_file": "/path/to/block.rule", // 从文件加载规则
                  "_comment": "模块会自动拦截直接使用IP访问的请求（无需额外配置）"
                },
                {
                  "handler": "static_response",
                  "body": "Hello, World!"
                }
              ]
            }
          ]
        }
      }
    }
  }
}
```

## 配置选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `report_url` | 恶意IP上报的API地址 | `https://api.baidu.com/report` |
| `block_rule` | 添加单条拦截规则，可以多次指定 | 无 |
| `block_rule_file` | 从文件加载拦截规则，每行一条规则 | 无 |

## 工作原理

1. 模块会检查每个HTTP请求的合法性
2. 自动检测并拦截直接使用IP地址访问80和443端口的请求（无域名访问）
3. 如果请求被判定为不合法，将返回403状态码
4. 同时将该IP加入黑名单，默认有效期为1小时
5. 异步将恶意IP信息上报到指定API

## 许可证

MIT
