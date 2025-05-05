# Caddy2-GFW

Caddy2-GFW 是一个基于 Caddy2 的 Web 应用防火墙模块，提供全面的安全防护功能。

## 功能特性

### 基础功能
- IP 黑名单管理
- 规则文件监控和自动重载
- 自定义 TTL 配置
- 灵活的规则配置
- 基本安全检测（始终启用）
  - IP 规则匹配
  - URL 规则匹配
  - User-Agent 规则匹配
  - 直接 IP 访问检测

### 额外安全防护（可选启用）
1. SQL 注入防护
   - 检测 SQL 命令注入
   - 检测 UNION 查询
   - 检测 DROP/INSERT/UPDATE 等危险操作
   - 检测布尔注入

2. XSS 防护
   - 检测 script 标签
   - 检测 javascript: 协议
   - 检测事件处理器
   - 检测数据 URI

3. CSRF 防护
   - 检查 Referer 头
   - 验证请求来源
   - 支持自定义域名白名单

4. SSRF 防护
   - 检测本地 IP 访问
   - 检测特殊协议
   - 检测文件访问

5. 命令注入防护
   - 检测系统命令
   - 检测管道操作
   - 检测重定向操作
   - 检测敏感文件访问

6. 代码注入防护
   - 检测危险函数调用
   - 检测代码执行
   - 检测文件包含

7. 文件包含防护
   - 检测目录遍历
   - 检测 PHP 伪协议
   - 检测远程文件包含

## 安装

```bash
go install github.com/ysicing/caddy2-gfw@latest
```

## 配置示例

### 基础配置
```caddyfile
{
    order gfw before respond
}

:80 {
    gfw {
        # 基本规则配置
        block_rule ip:1.2.3.4
        block_rule url:/admin
        block_rule ua:curl
        block_rule_file /path/to/rules.txt
        ttl 24h

        # 额外安全检测（默认关闭）
        enable_extra true
    }
}
```

### 规则文件格式
```
# 注释行
ip:1.2.3.4
url:/admin
ua:curl
```

## 安全特性说明

### 基本安全检测（始终启用）
- IP 规则匹配：根据配置的 IP 规则进行匹配
- URL 规则匹配：根据配置的 URL 规则进行匹配
- User-Agent 规则匹配：根据配置的 User-Agent 规则进行匹配
- 直接 IP 访问检测：检测是否直接使用 IP 访问（没有配置域名）

### 额外安全检测（可选启用）
#### SQL 注入防护
- 检测常见的 SQL 注入模式
- 支持检测分号后的 SQL 命令
- 支持检测 UNION 查询
- 支持检测布尔注入

#### XSS 防护
- 检测 script 标签和事件处理器
- 检测 javascript: 协议
- 检测数据 URI
- 检测表达式注入

#### CSRF 防护
- 验证请求来源
- 检查 Referer 头
- 支持自定义域名白名单
- 支持 POST 请求验证

#### SSRF 防护
- 检测本地 IP 访问
- 检测特殊协议（file://, gopher://, dict://）
- 检测文件访问
- 支持自定义 IP 白名单

#### 命令注入防护
- 检测系统命令（cat, ls, rm 等）
- 检测管道操作（|, &, ;）
- 检测重定向操作（>, <）
- 检测敏感文件访问

#### 代码注入防护
- 检测危险函数调用
- 检测代码执行
- 检测文件包含
- 支持自定义函数黑名单

#### 文件包含防护
- 检测目录遍历（../）
- 检测 PHP 伪协议
- 检测远程文件包含
- 支持自定义路径白名单

## 注意事项

1. 性能考虑
   - 规则文件不要过大
   - 定期清理过期黑名单
   - 合理设置 TTL

2. 安全建议
   - 定期更新规则
   - 监控攻击日志
   - 及时处理异常
   - 根据实际需求决定是否启用额外安全检测

3. 配置建议
   - 根据实际需求配置规则
   - 合理设置 TTL
   - 定期检查规则文件
   - 评估额外安全检测对性能的影响

## 贡献

欢迎提交 Issue 和 Pull Request。

## 许可证

MIT License

## Metrics 指标

本模块支持 Prometheus 监控，自动集成到 Caddy 的 `/metrics` 端点。主要指标如下：

- `caddy_gfw_requests_total{status}`：请求总数（按 allowed/blocked/blacklisted/too_many_requests 分类）
- `caddy_gfw_attack_detections_total{type}`：各类攻击检测次数
- `caddy_gfw_blacklist_size`：当前黑名单 IP 数量
- `caddy_gfw_rule_matches_total{type}`：规则命中次数
- `caddy_gfw_request_duration_seconds`：请求处理耗时直方图

**如何启用：**
Caddyfile 增加
```
:9180 {
    metrics
}
```
即可通过 `http://localhost:9180/metrics` 采集。

## 配置项说明

- `block_all`：控制规则命中时是否将 IP 加入黑名单，
  - `true`：规则命中后，IP 被拉黑，后续请求全部拦截。
  - `false`（默认）：规则命中只拦截本次请求，不拉黑 IP。

**示例：**
```
gfw {
    block_rule ip:1.2.3.4
    block_all true
}
```
