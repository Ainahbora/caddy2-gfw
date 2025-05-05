package gfw

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// 常量定义
const (
	// 默认配置
	defaultBlacklistTTL    = 24 * time.Hour
	defaultCleanupInterval = 5 * time.Minute

	// 安全检测相关常量
	sqlInjectionPatterns  = `(?i)(\b(select|insert|update|delete|drop|union|exec|where|from|into|load_file|outfile)\b.*\b(from|into|where|union|exec|load_file|outfile)\b|'.*'|".*"|\b(and|or)\b.*\b(1=1|2=2|true|false)\b|;.*\b(drop|delete|update|insert)\b|.*\bdrop\s+table\b)`
	xssPatterns           = `(?i)(<script|javascript:|on\w+\s*=|data:|vbscript:|expression\s*\(|eval\s*\(|alert\s*\()`
	csrfPatterns          = `(?i)(_csrf|csrf_token|xsrf_token)`
	ssrfPatterns          = `(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0|::1|file://|gopher://|dict://)`
	cmdInjectionPatterns  = `(?i)(\b(cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|php)\b.*\b(>|<|\||&|;)\b|\b(rm|del|remove)\s+(-rf?|/s|/q)\b|\b(cat|ls|rm|wget|curl)\b.*\b(/etc/passwd|/etc/shadow|/etc/hosts)\b|\bcat\s+/etc/passwd\b)`
	codeInjectionPatterns = `(?i)(\b(eval|exec|system|passthru|shell_exec|assert|preg_replace)\s*\(.*\)|\b(include|require|include_once|require_once)\s*\(.*\))`
	fileIncludePatterns   = `(?i)(\.\./|\.\.\\|\.\.\/|\.\.\\|\.\.\/\.\.\/|\.\.\\\.\.\\|\.\.\/\.\.\/\.\.\/|\.\.\\\.\.\\\.\.\\|php://|data://|phar://|zip://)`
)

// 错误定义
var (
	ErrInvalidConfig     = errors.New("invalid configuration")
	ErrRuleFileNotFound  = errors.New("rule file not found")
	ErrRuleFileReadError = errors.New("failed to read rule file")
)

func init() {
	caddy.RegisterModule(&GFW{})
	httpcaddyfile.RegisterHandlerDirective("gfw", parseCaddyfile)
}

// GFW 实现了一个Caddy HTTP处理器，用于检测恶意请求
type GFW struct {
	// 配置选项
	BlockRules    []string      `json:"block_rules,omitempty"`
	BlockRuleFile string        `json:"block_rule_file,omitempty"`
	TTL           time.Duration `json:"ttl,omitempty"`

	// 内部状态
	blackList   map[string]time.Time
	blackListMu sync.RWMutex
	logger      *zap.Logger
	ruleCache   *RuleCache
	stopChan    chan struct{}
	done        chan struct{} // 用于等待清理协程完成
	lastModTime time.Time     // 规则文件最后修改时间
}

// RuleCache 规则缓存
type RuleCache struct {
	mu     sync.RWMutex
	rules  map[string]struct{}
	ipSet  map[string]struct{}
	urlSet map[string]struct{}
	uaSet  map[string]struct{}
}

// NewRuleCache 创建新的规则缓存
func NewRuleCache() *RuleCache {
	return &RuleCache{
		rules:  make(map[string]struct{}),
		ipSet:  make(map[string]struct{}),
		urlSet: make(map[string]struct{}),
		uaSet:  make(map[string]struct{}),
	}
}

// AddRule 添加规则到缓存
func (rc *RuleCache) AddRule(rule string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.rules[rule] = struct{}{}

	// 根据规则类型添加到对应的集合
	if strings.HasPrefix(rule, "ip:") {
		rc.ipSet[rule[3:]] = struct{}{}
	} else if strings.HasPrefix(rule, "url:") {
		rc.urlSet[rule[4:]] = struct{}{}
	} else if strings.HasPrefix(rule, "ua:") {
		rc.uaSet[rule[3:]] = struct{}{}
	}
}

// MatchIP 检查IP是否匹配规则
func (rc *RuleCache) MatchIP(ip string) bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	_, exists := rc.ipSet[ip]
	return exists
}

// MatchURL 检查URL是否匹配规则
func (rc *RuleCache) MatchURL(url string) bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	_, exists := rc.urlSet[url]
	return exists
}

// MatchUserAgent 检查User-Agent是否匹配规则
func (rc *RuleCache) MatchUserAgent(ua string) bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	_, exists := rc.uaSet[ua]
	return exists
}

// GetAllRules 返回所有规则
func (rc *RuleCache) GetAllRules() map[string]struct{} {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	rules := make(map[string]struct{}, len(rc.rules))
	for rule := range rc.rules {
		rules[rule] = struct{}{}
	}
	return rules
}

// CaddyModule 返回Caddy模块信息
func (*GFW) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.gfw",
		New: func() caddy.Module { return new(GFW) },
	}
}

// Provision 实现caddy.Provisioner接口，设置模块初始化
func (g *GFW) Provision(ctx caddy.Context) error {
	g.logger = ctx.Logger()
	g.blackList = make(map[string]time.Time)
	g.stopChan = make(chan struct{})
	g.done = make(chan struct{})

	// 设置默认值
	if g.TTL == 0 {
		g.TTL = defaultBlacklistTTL
	}

	// 初始化规则缓存
	g.ruleCache = NewRuleCache()

	// 如果指定了规则文件，从文件中读取规则
	if g.BlockRuleFile != "" {
		if err := g.loadRulesFromFile(); err != nil {
			g.logger.Error("从文件加载规则失败",
				zap.Error(err),
				zap.String("file", g.BlockRuleFile))
			// 继续执行，不因为规则文件加载失败而中断服务
		}
		// 启动规则文件监控
		go g.watchRuleFile()
	}

	// 启动黑名单清理协程
	go g.cleanupBlacklist()

	g.logger.Info("GFW模块已初始化",
		zap.String("block_rule_file", g.BlockRuleFile),
		zap.Strings("block_rules", g.BlockRules),
		zap.Duration("ttl", g.TTL))

	return nil
}

// Cleanup 实现caddy.Cleaner接口，清理资源
func (g *GFW) Cleanup() error {
	close(g.stopChan)
	<-g.done // 等待清理协程完成
	return nil
}

// cleanupBlacklist 定期清理过期的黑名单记录
func (g *GFW) cleanupBlacklist() {
	defer close(g.done)
	ticker := time.NewTicker(defaultCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			g.cleanup()
		case <-g.stopChan:
			// 最后一次清理
			g.cleanup()
			return
		}
	}
}

// cleanup 清理过期的黑名单记录
func (g *GFW) cleanup() {
	g.blackListMu.Lock()
	defer g.blackListMu.Unlock()

	now := time.Now()
	expiredCount := 0
	expiredIPs := make([]string, 0)

	for ip, expireTime := range g.blackList {
		if now.After(expireTime) {
			expiredIPs = append(expiredIPs, ip)
			expiredCount++
		}
	}

	// 批量删除过期记录
	for _, ip := range expiredIPs {
		delete(g.blackList, ip)
	}

	if expiredCount > 0 {
		g.logger.Debug("清理过期黑名单记录",
			zap.Int("expired_count", expiredCount),
			zap.Int("remaining_count", len(g.blackList)),
			zap.Strings("expired_ips", expiredIPs))
	}
}

// Validate 实现caddy.Validator接口，验证配置
func (g *GFW) Validate() error {
	return nil
}

// ServeHTTP 实现caddyhttp.MiddlewareHandler接口，处理HTTP请求
func (g *GFW) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 获取客户端IP
	clientIP := r.RemoteAddr

	// 检查IP是否在黑名单中
	g.blackListMu.RLock()
	blacklistTime, isBlacklisted := g.blackList[clientIP]
	g.blackListMu.RUnlock()

	// 如果在黑名单中且未过期，直接返回403
	if isBlacklisted && time.Now().Before(blacklistTime) {
		g.logger.Info("拦截黑名单IP的请求",
			zap.String("ip", clientIP),
			zap.String("path", r.URL.Path))
		http.Error(w, "blocked by gfw", http.StatusForbidden)
		return nil
	}

	// 检查请求是否合法
	if !g.isRequestLegal(r) {
		// 将IP加入黑名单，使用配置的TTL
		g.blackListMu.Lock()
		g.blackList[clientIP] = time.Now().Add(g.TTL)
		g.blackListMu.Unlock()

		g.logger.Warn("检测到恶意请求",
			zap.String("ip", clientIP),
			zap.String("path", r.URL.Path),
			zap.String("user_agent", r.UserAgent()))

		// 返回403状态码
		http.Error(w, "blocked by gfw", http.StatusForbidden)
		return nil
	}

	// 请求合法，继续处理
	return next.ServeHTTP(w, r)
}

// isRequestLegal 检查请求是否合法
func (g *GFW) isRequestLegal(r *http.Request) bool {
	// 获取请求信息
	userAgent := r.UserAgent()
	requestPath := r.URL.Path
	clientIP := r.RemoteAddr

	// 使用规则缓存进行匹配
	if g.ruleCache != nil {
		if g.ruleCache.MatchIP(clientIP) {
			g.logger.Info("IP规则匹配", zap.String("client_ip", clientIP))
			return false
		}

		if g.ruleCache.MatchURL(requestPath) {
			g.logger.Info("URL路径规则匹配", zap.String("path", requestPath))
			return false
		}

		if g.ruleCache.MatchUserAgent(userAgent) {
			g.logger.Info("User-Agent规则匹配", zap.String("user_agent", userAgent))
			return false
		}
	}

	// 检查SQL注入
	if g.detectSQLInjection(r) {
		g.logger.Warn("检测到SQL注入攻击", zap.String("ip", clientIP))
		return false
	}

	// 检查XSS攻击
	if g.detectXSS(r) {
		g.logger.Warn("检测到XSS攻击", zap.String("ip", clientIP))
		return false
	}

	// 检查CSRF攻击
	if g.detectCSRF(r) {
		g.logger.Warn("检测到CSRF攻击", zap.String("ip", clientIP))
		return false
	}

	// 检查SSRF攻击
	if g.detectSSRF(r) {
		g.logger.Warn("检测到SSRF攻击", zap.String("ip", clientIP))
		return false
	}

	// 检查命令注入
	if g.detectCommandInjection(r) {
		g.logger.Warn("检测到命令注入攻击", zap.String("ip", clientIP))
		return false
	}

	// 检查代码注入
	if g.detectCodeInjection(r) {
		g.logger.Warn("检测到代码注入攻击", zap.String("ip", clientIP))
		return false
	}

	// 检查文件包含漏洞
	if g.detectFileInclude(r) {
		g.logger.Warn("检测到文件包含漏洞", zap.String("ip", clientIP))
		return false
	}

	// 检查是否直接使用IP访问80或443端口（没有配置域名）
	host := r.Host
	// 检查Host是否为IP地址格式（简单判断是否包含字母）
	isIP := true
	for _, c := range host {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			isIP = false
			break
		}
	}

	// 如果是直接使用IP访问，则认为请求不合法
	if isIP {
		return false
	}

	// 默认认为请求合法
	return true
}

// detectSQLInjection 检测SQL注入攻击
func (g *GFW) detectSQLInjection(r *http.Request) bool {
	// 检查URL参数
	for key, values := range r.URL.Query() {
		for _, value := range values {
			// 检查完整的参数值
			fullValue := key + "=" + value
			if strings.Contains(strings.ToLower(fullValue), "drop table") {
				return true
			}

			// 检查SQL注入模式
			if g.matchPattern(value, sqlInjectionPatterns) {
				return true
			}

			// 检查分号后的SQL命令
			if strings.Contains(value, ";") {
				// 处理形如 "id=1; DROP TABLE users" 的情况
				if strings.Contains(strings.ToLower(value), "drop table") {
					return true
				}
				// 处理其他SQL命令
				parts := strings.Split(value, ";")
				for _, part := range parts {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					// 检查DROP TABLE命令
					if strings.Contains(strings.ToLower(part), "drop table") {
						return true
					}
					// 检查其他SQL命令
					if g.matchPattern(part, `(?i)\b(drop|delete|update|insert)\b`) {
						return true
					}
				}
			}
			// 检查参数名
			if g.matchPattern(key, `(?i)\b(drop|delete|update|insert)\b`) {
				return true
			}
		}
	}

	// 检查POST数据
	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			for key, values := range r.PostForm {
				for _, value := range values {
					// 检查完整的参数值
					fullValue := key + "=" + value
					if strings.Contains(strings.ToLower(fullValue), "drop table") {
						return true
					}

					// 检查SQL注入模式
					if g.matchPattern(value, sqlInjectionPatterns) {
						return true
					}

					// 检查分号后的SQL命令
					if strings.Contains(value, ";") {
						// 处理形如 "id=1; DROP TABLE users" 的情况
						if strings.Contains(strings.ToLower(value), "drop table") {
							return true
						}
						// 处理其他SQL命令
						parts := strings.Split(value, ";")
						for _, part := range parts {
							part = strings.TrimSpace(part)
							if part == "" {
								continue
							}
							// 检查DROP TABLE命令
							if strings.Contains(strings.ToLower(part), "drop table") {
								return true
							}
							// 检查其他SQL命令
							if g.matchPattern(part, `(?i)\b(drop|delete|update|insert)\b`) {
								return true
							}
						}
					}
					// 检查参数名
					if g.matchPattern(key, `(?i)\b(drop|delete|update|insert)\b`) {
						return true
					}
				}
			}
		}
	}

	// 检查原始查询字符串
	rawQuery := r.URL.RawQuery
	if strings.Contains(strings.ToLower(rawQuery), "drop table") {
		return true
	}

	return false
}

// detectXSS 检测XSS攻击
func (g *GFW) detectXSS(r *http.Request) bool {
	// 检查URL参数
	for _, values := range r.URL.Query() {
		for _, value := range values {
			if g.matchPattern(value, xssPatterns) {
				return true
			}
		}
	}

	// 检查POST数据
	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			for _, values := range r.PostForm {
				for _, value := range values {
					if g.matchPattern(value, xssPatterns) {
						return true
					}
				}
			}
		}
	}

	return false
}

// detectCSRF 检测CSRF攻击
func (g *GFW) detectCSRF(r *http.Request) bool {
	// 只检查POST请求
	if r.Method != "POST" {
		return false
	}

	// 检查Referer头
	referer := r.Header.Get("Referer")
	if referer == "" {
		return true
	}

	// 检查Referer是否来自同一域名
	refererURL, err := url.Parse(referer)
	if err != nil {
		return true
	}

	// 检查主机名是否匹配
	if refererURL.Host != r.Host {
		return true
	}

	return false
}

// detectSSRF 检测SSRF攻击
func (g *GFW) detectSSRF(r *http.Request) bool {
	// 检查URL参数
	for _, values := range r.URL.Query() {
		for _, value := range values {
			if g.matchPattern(value, ssrfPatterns) {
				return true
			}
		}
	}

	// 检查POST数据
	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			for _, values := range r.PostForm {
				for _, value := range values {
					if g.matchPattern(value, ssrfPatterns) {
						return true
					}
				}
			}
		}
	}

	return false
}

// detectCommandInjection 检测命令注入攻击
func (g *GFW) detectCommandInjection(r *http.Request) bool {
	// 检查URL参数
	for _, values := range r.URL.Query() {
		for _, value := range values {
			// 检查命令注入模式
			if g.matchPattern(value, cmdInjectionPatterns) {
				return true
			}
			// 检查管道符号
			if strings.Contains(value, "|") || strings.Contains(value, "&") || strings.Contains(value, ";") {
				return true
			}
			// 检查重定向符号
			if strings.Contains(value, ">") || strings.Contains(value, "<") {
				return true
			}
			// 检查敏感文件路径
			if strings.Contains(value, "/etc/passwd") || strings.Contains(value, "/etc/shadow") ||
				strings.Contains(value, "/etc/hosts") {
				return true
			}
			// 检查系统命令
			if g.matchPattern(value, `(?i)\b(cat|ls|rm|wget|curl|bash|sh)\b`) {
				return true
			}
		}
	}

	// 检查POST数据
	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			for _, values := range r.PostForm {
				for _, value := range values {
					// 检查命令注入模式
					if g.matchPattern(value, cmdInjectionPatterns) {
						return true
					}
					// 检查管道符号
					if strings.Contains(value, "|") || strings.Contains(value, "&") || strings.Contains(value, ";") {
						return true
					}
					// 检查重定向符号
					if strings.Contains(value, ">") || strings.Contains(value, "<") {
						return true
					}
					// 检查敏感文件路径
					if strings.Contains(value, "/etc/passwd") || strings.Contains(value, "/etc/shadow") ||
						strings.Contains(value, "/etc/hosts") {
						return true
					}
					// 检查系统命令
					if g.matchPattern(value, `(?i)\b(cat|ls|rm|wget|curl|bash|sh)\b`) {
						return true
					}
				}
			}
		}
	}

	// 检查请求头
	for _, header := range r.Header {
		for _, value := range header {
			// 检查命令注入模式
			if g.matchPattern(value, cmdInjectionPatterns) {
				return true
			}
			// 检查管道符号
			if strings.Contains(value, "|") || strings.Contains(value, "&") || strings.Contains(value, ";") {
				return true
			}
			// 检查重定向符号
			if strings.Contains(value, ">") || strings.Contains(value, "<") {
				return true
			}
			// 检查敏感文件路径
			if strings.Contains(value, "/etc/passwd") || strings.Contains(value, "/etc/shadow") ||
				strings.Contains(value, "/etc/hosts") {
				return true
			}
			// 检查系统命令
			if g.matchPattern(value, `(?i)\b(cat|ls|rm|wget|curl|bash|sh)\b`) {
				return true
			}
		}
	}

	return false
}

// detectCodeInjection 检测代码注入攻击
func (g *GFW) detectCodeInjection(r *http.Request) bool {
	// 检查URL参数
	for _, values := range r.URL.Query() {
		for _, value := range values {
			if g.matchPattern(value, codeInjectionPatterns) {
				return true
			}
		}
	}

	// 检查POST数据
	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			for _, values := range r.PostForm {
				for _, value := range values {
					if g.matchPattern(value, codeInjectionPatterns) {
						return true
					}
				}
			}
		}
	}

	return false
}

// detectFileInclude 检测文件包含漏洞
func (g *GFW) detectFileInclude(r *http.Request) bool {
	// 检查URL参数
	for _, values := range r.URL.Query() {
		for _, value := range values {
			// 检查文件包含模式
			if g.matchPattern(value, fileIncludePatterns) {
				return true
			}
			// 检查PHP伪协议
			if strings.Contains(value, "php://") || strings.Contains(value, "data://") ||
				strings.Contains(value, "phar://") || strings.Contains(value, "zip://") {
				return true
			}
			// 检查目录遍历
			if strings.Contains(value, "../") || strings.Contains(value, "..\\") {
				return true
			}
		}
	}

	// 检查POST数据
	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			for _, values := range r.PostForm {
				for _, value := range values {
					// 检查文件包含模式
					if g.matchPattern(value, fileIncludePatterns) {
						return true
					}
					// 检查PHP伪协议
					if strings.Contains(value, "php://") || strings.Contains(value, "data://") ||
						strings.Contains(value, "phar://") || strings.Contains(value, "zip://") {
						return true
					}
					// 检查目录遍历
					if strings.Contains(value, "../") || strings.Contains(value, "..\\") {
						return true
					}
				}
			}
		}
	}

	// 检查请求头
	for _, header := range r.Header {
		for _, value := range header {
			// 检查文件包含模式
			if g.matchPattern(value, fileIncludePatterns) {
				return true
			}
			// 检查PHP伪协议
			if strings.Contains(value, "php://") || strings.Contains(value, "data://") ||
				strings.Contains(value, "phar://") || strings.Contains(value, "zip://") {
				return true
			}
			// 检查目录遍历
			if strings.Contains(value, "../") || strings.Contains(value, "..\\") {
				return true
			}
		}
	}

	return false
}

// matchPattern 使用正则表达式匹配模式
func (g *GFW) matchPattern(value, pattern string) bool {
	matched, err := regexp.MatchString(pattern, value)
	if err != nil {
		g.logger.Error("正则表达式匹配失败",
			zap.Error(err),
			zap.String("pattern", pattern))
		return false
	}
	return matched
}

// loadRulesFromFile 从文件中加载规则
func (g *GFW) loadRulesFromFile() error {
	// 获取文件信息
	fileInfo, err := os.Stat(g.BlockRuleFile)
	if err != nil {
		return fmt.Errorf("获取规则文件信息失败: %w", err)
	}

	// 更新最后修改时间
	g.lastModTime = fileInfo.ModTime()

	// 打开规则文件
	file, err := os.Open(g.BlockRuleFile)
	if err != nil {
		return fmt.Errorf("打开规则文件失败: %w", err)
	}
	defer file.Close()

	// 创建新的规则缓存
	newCache := NewRuleCache()

	// 逐行读取规则
	scanner := bufio.NewScanner(file)
	lineCount := 0
	ruleCount := 0

	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 添加到规则缓存
		newCache.AddRule(line)
		ruleCount++
	}

	// 检查是否有扫描错误
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取规则文件失败: %w", err)
	}

	// 更新规则缓存
	g.ruleCache = newCache

	// 更新内存中的规则列表
	g.BlockRules = make([]string, 0, ruleCount)
	for rule := range newCache.GetAllRules() {
		g.BlockRules = append(g.BlockRules, rule)
	}

	g.logger.Info("从文件加载规则成功",
		zap.String("file", g.BlockRuleFile),
		zap.Int("total_lines", lineCount),
		zap.Int("rules_loaded", ruleCount),
		zap.Time("last_modified", g.lastModTime))

	return nil
}

// checkAndReloadRules 检查并重新加载规则
func (g *GFW) checkAndReloadRules() error {
	// 获取文件信息
	fileInfo, err := os.Stat(g.BlockRuleFile)
	if err != nil {
		return fmt.Errorf("获取规则文件信息失败: %w", err)
	}

	// 检查文件是否被修改
	if fileInfo.ModTime().Equal(g.lastModTime) {
		return nil
	}

	// 重新加载规则
	if err := g.loadRulesFromFile(); err != nil {
		return fmt.Errorf("重新加载规则失败: %w", err)
	}

	g.logger.Info("规则文件已更新",
		zap.String("file", g.BlockRuleFile),
		zap.Time("last_modified", fileInfo.ModTime()))

	return nil
}

// watchRuleFile 监控规则文件变化
func (g *GFW) watchRuleFile() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := g.checkAndReloadRules(); err != nil {
				g.logger.Error("检查规则文件更新失败",
					zap.Error(err),
					zap.String("file", g.BlockRuleFile))
			}
		case <-g.stopChan:
			return
		}
	}
}

// parseCaddyfile 解析Caddyfile配置
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var g GFW

	for h.Next() {
		// 解析配置参数
		for h.NextBlock(0) {
			switch h.Val() {
			case "block_rule":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				g.BlockRules = append(g.BlockRules, h.Val())

			case "block_rule_file":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				g.BlockRuleFile = h.Val()

			case "ttl":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				duration, err := time.ParseDuration(h.Val())
				if err != nil {
					return nil, h.Errf("invalid ttl duration: %v", err)
				}
				g.TTL = duration

			default:
				return nil, h.Errf("unknown subdirective '%s'", h.Val())
			}
		}
	}

	return &g, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*GFW)(nil)
	_ caddy.Validator             = (*GFW)(nil)
	_ caddyhttp.MiddlewareHandler = (*GFW)(nil)
	_ caddyfile.Unmarshaler       = (*GFW)(nil)
)

// UnmarshalCaddyfile 实现 caddyfile.Unmarshaler
func (g *GFW) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "block_rule":
				if !d.NextArg() {
					return d.ArgErr()
				}
				g.BlockRules = append(g.BlockRules, d.Val())

			case "block_rule_file":
				if !d.NextArg() {
					return d.ArgErr()
				}
				g.BlockRuleFile = d.Val()

			case "ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				duration, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid ttl duration: %v", err)
				}
				g.TTL = duration

			default:
				return d.Errf("unknown subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}
