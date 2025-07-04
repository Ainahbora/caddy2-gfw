package gfw

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ysicing/caddy2-gfw/storage"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// 常量定义
const (
	// 默认配置
	defaultBlacklistTTL     = 24 * time.Hour
	defaultCleanupInterval  = 5 * time.Minute
	defaultMaxBlacklistSize = 100000
	defaultMaxConcurrent    = 1000

	// 安全检测相关常量
	sqlInjectionPatterns  = `(?i)(\b(select|insert|update|delete|drop|union|exec|where|from|into|load_file|outfile)\b.*\b(from|into|where|union|exec|load_file|outfile)\b|'.*'|".*"|\b(and|or)\b.*\b(1=1|2=2|true|false)\b|;.*\b(drop|delete|update|insert)\b|.*\bdrop\s+table\b)`
	xssPatterns           = `(?i)(<script|javascript:|on\w+\s*=|data:|vbscript:|expression\s*\(|eval\s*\(|alert\s*\()`
	csrfPatterns          = `(?i)(_csrf|csrf_token|xsrf_token)`
	ssrfPatterns          = `(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0|::1|file://|gopher://|dict://)`
	cmdInjectionPatterns  = `(?i)(\b(cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|php)\b.*\b(>|<|\||&|;)\b|\b(rm|del|remove)\s+(-rf?|/s|/q)\b|\b(cat|ls|rm|wget|curl)\b.*\b(/etc/passwd|/etc/shadow|/etc/hosts)\b|\bcat\s+/etc/passwd\b)`
	codeInjectionPatterns = `(?i)(\b(eval|exec|system|passthru|shell_exec|assert|preg_replace)\s*\(.*\)|\b(include|require|include_once|require_once)\s*\(.*\))`
	fileIncludePatterns   = `(?i)(\.\./|\.\.\\|\.\.\/|\.\.\\|\.\.\/\.\.\/|\.\.\\\.\.\\|\.\.\/\.\.\/\.\.\/|\.\.\\\.\.\\\.\.\\|php://|data://|phar://|zip://)`
)

// 预编译正则表达式
var (
	sqlInjectionRegex  = regexp.MustCompile(sqlInjectionPatterns)
	xssRegex           = regexp.MustCompile(xssPatterns)
	csrfRegex          = regexp.MustCompile(csrfPatterns)
	ssrfRegex          = regexp.MustCompile(ssrfPatterns)
	cmdInjectionRegex  = regexp.MustCompile(cmdInjectionPatterns)
	codeInjectionRegex = regexp.MustCompile(codeInjectionPatterns)
	fileIncludeRegex   = regexp.MustCompile(fileIncludePatterns)
)

// 错误定义
var (
	ErrInvalidConfig     = errors.New("invalid configuration")
	ErrRuleFileNotFound  = errors.New("rule file not found")
	ErrRuleFileReadError = errors.New("failed to read rule file")
)

// 定义严重攻击类型
var (
	severeAttackTypes = map[string]bool{
		"sql_injection":     true,
		"command_injection": true,
		"code_injection":    true,
		"ssrf":              true,
	}
)

// 全局 metrics 变量和 once
var (
	metricsOnce      sync.Once
	requestsTotal    *prometheus.CounterVec
	attackDetections *prometheus.CounterVec
	blacklistSize    prometheus.Gauge
	ruleMatches      *prometheus.CounterVec
	requestDuration  prometheus.Histogram
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
	TTL           caddy.Duration `json:"ttl,omitempty"`
	EnableExtra   bool          `json:"enable_extra,omitempty"` // 是否启用额外安全检测
	BlockAll      bool          `json:"block_all,omitempty"`    // 规则匹配时是否拦截所有请求

	// 内部状态
	blackList        map[string]time.Time
	blackListMu      sync.RWMutex
	logger           *zap.Logger
	ruleCache        *RuleCache
	stopChan         chan struct{}
	done             chan struct{}
	lastModTime      time.Time
	maxBlacklistSize int
	maxConcurrent    int
	semaphore        chan struct{}
	watcher          *fsnotify.Watcher
	storage          storage.Storage
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
// 	_, exists := rc.uaSet[ua]
// 	return exists
    for pattern := range rc.uaSet {
		if strings.Contains(strings.ToLower(ua), strings.ToLower(pattern)) {
			return true
		}
	}
	return false
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
	g.maxBlacklistSize = defaultMaxBlacklistSize
	g.maxConcurrent = defaultMaxConcurrent
	g.semaphore = make(chan struct{}, g.maxConcurrent)

	// 设置默认值
	if g.TTL == 0 {
		//g.TTL = defaultBlacklistTTL
		g.TTL = caddy.Duration(24 * time.Hour)
	}

	// 全局只注册一次 metrics
	metricsOnce.Do(func() {
		registry := ctx.GetMetricsRegistry()
		if registry == nil {
			return
		}
		const ns, sub = "caddy", "gfw"
		requestsTotal = promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "requests_total",
			Help:      "Total number of requests processed by GFW",
		}, []string{"status"})
		attackDetections = promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "attack_detections_total",
			Help:      "Total number of detected attacks by GFW",
		}, []string{"type"})
		blacklistSize = promauto.With(registry).NewGauge(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "blacklist_size",
			Help:      "Current number of IPs in GFW blacklist",
		})
		ruleMatches = promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "rule_matches_total",
			Help:      "Total number of rule matches by GFW",
		}, []string{"type"})
		requestDuration = promauto.With(registry).NewHistogram(prometheus.HistogramOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "request_duration_seconds",
			Help:      "Request processing duration by GFW in seconds",
			Buckets:   prometheus.DefBuckets,
		})
	})

	// 初始化存储
	storageDir := filepath.Join(caddy.AppDataDir(), "gfw")
	storage, err := storage.NewFileStorage(storageDir)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	g.storage = storage

	// 从存储加载黑名单
	if err := g.loadBlacklist(); err != nil {
		g.logger.Error("failed to load blacklist", zap.Error(err))
	}

	// 初始化规则缓存
	g.ruleCache = NewRuleCache()

	// 如果指定了规则文件，从文件中读取规则
	if g.BlockRuleFile != "" {
		if err := g.loadRulesFromFile(); err != nil {
			g.logger.Error("failed to load rules from file",
				zap.Error(err),
				zap.String("file", g.BlockRuleFile))
		}
		// 启动规则文件监控
		go g.watchRuleFile()
	}

	// 启动黑名单清理协程
	go g.cleanupBlacklist()

	g.logger.Info("GFW module initialized",
		zap.String("block_rule_file", g.BlockRuleFile),
		zap.Strings("block_rules", g.BlockRules),
// 		zap.Duration("ttl", g.TTL))
        zap.Duration("ttl", time.Duration(g.TTL)))
	return nil
}

// Cleanup 实现caddy.Cleaner接口，清理资源
func (g *GFW) Cleanup() error {
	close(g.stopChan)
	<-g.done // 等待清理协程完成
	if g.watcher != nil {
		if err := g.watcher.Close(); err != nil {
			g.logger.Error("failed to close file watcher", zap.Error(err))
		}
	}
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
	expiredIPs := make([]string, 0, 100) // 预分配容量

	// 批量收集过期IP
	for ip, expireTime := range g.blackList {
		if now.After(expireTime) {
			expiredIPs = append(expiredIPs, ip)
			expiredCount++
		}
	}

	// 批量删除
	for _, ip := range expiredIPs {
		delete(g.blackList, ip)
	}

	// 更新黑名单大小指标
	blacklistSize.Set(float64(len(g.blackList)))

	if expiredCount > 0 {
		g.logger.Debug("cleaned up expired blacklist entries",
			zap.Int("expired_count", expiredCount),
			zap.Int("remaining_count", len(g.blackList)),
			zap.Strings("expired_ips", expiredIPs))

		// 异步保存更新后的黑名单
		go func() {
			if err := g.saveBlacklist(); err != nil {
				g.logger.Error("failed to save blacklist", zap.Error(err))
			}
		}()
	}
}

// Validate 实现caddy.Validator接口，验证配置
func (g *GFW) Validate() error {
	return nil
}

// ServeHTTP 实现caddyhttp.MiddlewareHandler接口，处理HTTP请求
func (g *GFW) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 记录请求开始时间
	start := time.Now()
	defer func() {
		// 记录请求处理时间
		requestDuration.Observe(time.Since(start).Seconds())
	}()

	// 并发限制
	select {
	case g.semaphore <- struct{}{}:
		defer func() { <-g.semaphore }()
	default:
		requestsTotal.WithLabelValues("too_many_requests").Inc()
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return nil
	}

	// 获取客户端IP
// 	clientIP := r.RemoteAddr
    clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        clientIP = r.RemoteAddr
    }
	// 检查IP是否在黑名单中
	if g.isIPBlacklisted(clientIP) {
		requestsTotal.WithLabelValues("blacklisted").Inc()
		g.logger.Info("blocked request due to blacklisted IP",
			zap.String("ip", clientIP),
			zap.String("path", r.URL.Path))
		http.Error(w, "blocked by gfw", http.StatusForbidden)
		return nil
	}

	// 检查请求是否合法
	attackType, isLegal := g.isRequestLegal(r)
	if !isLegal {
		// 如果是规则匹配且配置为拦截所有请求，将IP加入黑名单
		if strings.HasSuffix(attackType, "_rule") && g.BlockAll {
			g.addToBlacklist(clientIP)
			g.logger.Warn("rule matched, IP added to blacklist",
				zap.String("ip", clientIP),
				zap.String("rule_type", attackType))
		}
		// 如果是额外安全检测，将IP加入黑名单
		if !strings.HasSuffix(attackType, "_rule") {
			g.addToBlacklist(clientIP)
			g.logger.Warn("detected attack, IP added to blacklist",
				zap.String("ip", clientIP),
				zap.String("attack_type", attackType))
		}

		requestsTotal.WithLabelValues("blocked").Inc()
		g.logger.Warn("detected malicious request",
			zap.String("ip", clientIP),
			zap.String("path", r.URL.Path),
			zap.String("user_agent", r.UserAgent()),
			zap.String("attack_type", attackType))

		// 返回403状态码
		http.Error(w, "blocked by gfw", http.StatusForbidden)
		return nil
	}

	// 请求合法，继续处理
	requestsTotal.WithLabelValues("allowed").Inc()
	return next.ServeHTTP(w, r)
}

// isIPBlacklisted 检查IP是否在黑名单中
func (g *GFW) isIPBlacklisted(ip string) bool {
	g.blackListMu.RLock()
	defer g.blackListMu.RUnlock()

	expireTime, exists := g.blackList[ip]
	if !exists {
		return false
	}

	return time.Now().Before(expireTime)
}

// addToBlacklist 将IP添加到黑名单
func (g *GFW) addToBlacklist(ip string) {
	g.blackListMu.Lock()
	defer g.blackListMu.Unlock()

	// 检查黑名单大小
	if len(g.blackList) >= g.maxBlacklistSize {
		// 清理最旧的记录
		g.cleanupOldest()
	}

	//g.blackList[ip] = time.Now().Add(g.TTL)
    g.blackList[ip] = time.Now().Add(time.Duration(g.TTL))
	// 异步保存黑名单
	go func() {
		if err := g.saveBlacklist(); err != nil {
			g.logger.Error("failed to save blacklist", zap.Error(err))
		}
	}()
}

// cleanupOldest 清理最旧的黑名单记录
func (g *GFW) cleanupOldest() {
	var oldestIP string
	var oldestTime time.Time

	// 找到最旧的记录
	for ip, expireTime := range g.blackList {
		if oldestIP == "" || expireTime.Before(oldestTime) {
			oldestIP = ip
			oldestTime = expireTime
		}
	}

	// 删除最旧的记录
	if oldestIP != "" {
		delete(g.blackList, oldestIP)
	}
}

// isRequestLegal 检查请求是否合法，返回攻击类型和是否合法
func (g *GFW) isRequestLegal(r *http.Request) (string, bool) {
	// 获取请求信息
	userAgent := r.UserAgent()
	requestPath := r.URL.Path
// 	clientIP := r.RemoteAddr
    clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        clientIP = r.RemoteAddr
    }
	// 使用规则缓存进行匹配（基本安全检测）
	if g.ruleCache != nil {
		if g.ruleCache.MatchIP(clientIP) {
			ruleMatches.WithLabelValues("ip").Inc()
			g.logger.Info("IP rule matched", zap.String("client_ip", clientIP))
			return "ip_rule", false
		}

		if g.ruleCache.MatchURL(requestPath) {
			ruleMatches.WithLabelValues("url").Inc()
			g.logger.Info("URL path rule matched", zap.String("path", requestPath))
			return "url_rule", false
		}

		if g.ruleCache.MatchUserAgent(userAgent) {
			ruleMatches.WithLabelValues("ua").Inc()
			g.logger.Info("User-Agent rule matched", zap.String("user_agent", userAgent))
			return "ua_rule", false
		}
	}

	// 如果额外安全检测被禁用，直接返回true
	if !g.EnableExtra {
		return "", true
	}

	// 检查SQL注入
	if g.detectSQLInjection(r) {
		attackDetections.WithLabelValues("sql_injection").Inc()
		g.logger.Warn("detected SQL injection attack", zap.String("ip", clientIP))
		return "sql_injection", false
	}

	// 检查XSS攻击
	if g.detectXSS(r) {
		attackDetections.WithLabelValues("xss").Inc()
		g.logger.Warn("detected XSS attack", zap.String("ip", clientIP))
		return "xss", false
	}

	// 检查CSRF攻击
	if g.detectCSRF(r) {
		attackDetections.WithLabelValues("csrf").Inc()
		g.logger.Warn("detected CSRF attack", zap.String("ip", clientIP))
		return "csrf", false
	}

	// 检查SSRF攻击
	if g.detectSSRF(r) {
		attackDetections.WithLabelValues("ssrf").Inc()
		g.logger.Warn("detected SSRF attack", zap.String("ip", clientIP))
		return "ssrf", false
	}

	// 检查命令注入
	if g.detectCommandInjection(r) {
		attackDetections.WithLabelValues("command_injection").Inc()
		g.logger.Warn("detected command injection attack", zap.String("ip", clientIP))
		return "command_injection", false
	}

	// 检查代码注入
	if g.detectCodeInjection(r) {
		attackDetections.WithLabelValues("code_injection").Inc()
		g.logger.Warn("detected code injection attack", zap.String("ip", clientIP))
		return "code_injection", false
	}

	// 检查文件包含漏洞
	if g.detectFileInclude(r) {
		attackDetections.WithLabelValues("file_include").Inc()
		g.logger.Warn("detected file inclusion vulnerability", zap.String("ip", clientIP))
		return "file_include", false
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
		attackDetections.WithLabelValues("direct_ip_access").Inc()
		return "direct_ip_access", false
	}

	// 默认认为请求合法
	return "", true
}

// detectSQLInjection 检测SQL注入攻击
func (g *GFW) detectSQLInjection(r *http.Request) bool {
	// 检查URL参数
	for key, values := range r.URL.Query() {
		for _, value := range values {
			// 检查完整的参数值
			fullValue := key + "=" + value
			lowerValue := strings.ToLower(fullValue)
			if strings.Contains(lowerValue, "drop table") {
				return true
			}

			// 检查SQL注入模式
			if sqlInjectionRegex.MatchString(value) {
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
					if sqlInjectionRegex.MatchString(part) {
						return true
					}
				}
			}
			// 检查参数名
			if sqlInjectionRegex.MatchString(key) {
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
					lowerValue := strings.ToLower(fullValue)
					if strings.Contains(lowerValue, "drop table") {
						return true
					}

					// 检查SQL注入模式
					if sqlInjectionRegex.MatchString(value) {
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
							if sqlInjectionRegex.MatchString(part) {
								return true
							}
						}
					}
					// 检查参数名
					if sqlInjectionRegex.MatchString(key) {
						return true
					}
				}
			}
		}
	}

	// 检查原始查询字符串
	rawQuery := r.URL.RawQuery
	return strings.Contains(strings.ToLower(rawQuery), "drop table")
}

// detectXSS 检测XSS攻击
func (g *GFW) detectXSS(r *http.Request) bool {
	// 检查URL参数
	for _, values := range r.URL.Query() {
		for _, value := range values {
			if xssRegex.MatchString(value) {
				return true
			}
		}
	}

	// 检查POST数据
	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			for _, values := range r.PostForm {
				for _, value := range values {
					if xssRegex.MatchString(value) {
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

	// 检查CSRF token
	if csrfRegex.MatchString(referer) {
		return true
	}

	return false
}

// detectSSRF 检测SSRF攻击
func (g *GFW) detectSSRF(r *http.Request) bool {
	// 检查URL参数
	for _, values := range r.URL.Query() {
		for _, value := range values {
			if ssrfRegex.MatchString(value) {
				return true
			}
		}
	}

	// 检查POST数据
	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			for _, values := range r.PostForm {
				for _, value := range values {
					if ssrfRegex.MatchString(value) {
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
			if cmdInjectionRegex.MatchString(value) {
			    // g.logger.Error("检查命令注入模式", zap.String("value", value))
				return true
			}
			// 检查管道符号
			if strings.Contains(value, "|") || strings.Contains(value, "&") || strings.Contains(value, ";") {
			    // g.logger.Error("检查管道符号", zap.String("value", value))
				return true
			}
			// 检查重定向符号
			if strings.Contains(value, ">") || strings.Contains(value, "<") {
			    // g.logger.Error("检查重定向符号", zap.String("value", value))
				return true
			}
			// 检查敏感文件路径
			if strings.Contains(value, "/etc/passwd") || strings.Contains(value, "/etc/shadow") ||
				strings.Contains(value, "/etc/hosts") {
				// g.logger.Error("检查敏感文件路径", zap.String("value", value))
				return true
			}
			// 检查系统命令
			if cmdInjectionRegex.MatchString(value) {
			    // g.logger.Error("检查系统命令", zap.String("value", value))
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
					if cmdInjectionRegex.MatchString(value) {
					    // g.logger.Error("POST 检查命令注入模式", zap.String("value", value))
						return true
					}
					// 检查管道符号
					if strings.Contains(value, "|") || strings.Contains(value, "&") || strings.Contains(value, ";") {
					    // g.logger.Error("POST 检查管道符号", zap.String("value", value))
						return true
					}
					// 检查重定向符号
					if strings.Contains(value, ">") || strings.Contains(value, "<") {
					    // g.logger.Error("POST 检查重定向符号", zap.String("value", value))
						return true
					}
					// 检查敏感文件路径
					if strings.Contains(value, "/etc/passwd") || strings.Contains(value, "/etc/shadow") ||
						strings.Contains(value, "/etc/hosts") {
						// g.logger.Error("POST 检查敏感文件路径", zap.String("value", value))
						return true
					}
					// 检查系统命令
					if cmdInjectionRegex.MatchString(value) {
					    // g.logger.Error("POST 检查系统命令", zap.String("value", value))
						return true
					}
				}
			}
		}
	}
    return false
	// 检查请求头
	for _, header := range r.Header {
		for _, value := range header {
			// 检查命令注入模式
			if cmdInjectionRegex.MatchString(value) {
			    g.logger.Error("header 检查命令注入模式", zap.String("value", value))
				return true
			}
			// 检查管道符号
			if strings.Contains(value, "|") || strings.Contains(value, "&") || strings.Contains(value, ";") {
			    g.logger.Error("header 检查管道符号", zap.String("value", value))
				return true
			}
			// 检查重定向符号
			if strings.Contains(value, ">") || strings.Contains(value, "<") {
			    g.logger.Error("header 检查重定向符号", zap.String("value", value))
				return true
			}
			// 检查敏感文件路径
			if strings.Contains(value, "/etc/passwd") || strings.Contains(value, "/etc/shadow") ||
				strings.Contains(value, "/etc/hosts") {
				g.logger.Error("header 检查敏感文件路径", zap.String("value", value))
				return true
			}
			// 检查系统命令
			if cmdInjectionRegex.MatchString(value) {
			    g.logger.Error("header 检查系统命令", zap.String("value", value))
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
			if codeInjectionRegex.MatchString(value) {
				return true
			}
		}
	}

	// 检查POST数据
	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			for _, values := range r.PostForm {
				for _, value := range values {
					if codeInjectionRegex.MatchString(value) {
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
			if fileIncludeRegex.MatchString(value) {
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
					if fileIncludeRegex.MatchString(value) {
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
			if fileIncludeRegex.MatchString(value) {
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

// watchRuleFile 监控规则文件变化
func (g *GFW) watchRuleFile() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		g.logger.Error("failed to create file watcher", zap.Error(err))
		return
	}
	g.watcher = watcher

	// 获取规则文件所在目录
	ruleDir := filepath.Dir(g.BlockRuleFile)
	ruleFile := filepath.Base(g.BlockRuleFile)

	// 监控目录而不是单个文件
	if err := watcher.Add(ruleDir); err != nil {
		g.logger.Error("failed to add directory to watcher",
			zap.Error(err),
			zap.String("directory", ruleDir))
		return
	}

	go func() {
		defer watcher.Close()
		for {
			select {
			case event := <-watcher.Events:
				// 只处理目标文件的事件
				if filepath.Base(event.Name) == ruleFile {
					switch {
					case event.Op&fsnotify.Write == fsnotify.Write:
						// 添加延迟，等待文件写入完成
						time.Sleep(100 * time.Millisecond)
						if err := g.loadRulesFromFile(); err != nil {
							g.logger.Error("failed to reload rules",
								zap.Error(err),
								zap.String("file", g.BlockRuleFile))
						}
					case event.Op&fsnotify.Remove == fsnotify.Remove:
						// 文件被删除，尝试重新添加监控
						time.Sleep(100 * time.Millisecond)
						if err := watcher.Add(ruleDir); err != nil {
							g.logger.Error("failed to re-add directory to watcher",
								zap.Error(err),
								zap.String("directory", ruleDir))
						}
					}
				}
			case err := <-watcher.Errors:
				if err != nil {
					g.logger.Error("file watcher error",
						zap.Error(err),
						zap.String("directory", ruleDir))
					// 尝试重新添加监控
					time.Sleep(1 * time.Second)
					if err := watcher.Add(ruleDir); err != nil {
						g.logger.Error("failed to re-add directory to watcher",
							zap.Error(err),
							zap.String("directory", ruleDir))
					}
				}
			case <-g.stopChan:
				return
			}
		}
	}()

	g.logger.Info("file watcher started",
		zap.String("directory", ruleDir),
		zap.String("file", ruleFile))
}

// loadRulesFromFile 从文件中加载规则
func (g *GFW) loadRulesFromFile() error {
	// 获取文件信息
	fileInfo, err := os.Stat(g.BlockRuleFile)
	if err != nil {
		return fmt.Errorf("failed to get rule file info: %w", err)
	}

	// 更新最后修改时间
	g.lastModTime = fileInfo.ModTime()

	// 打开规则文件
	file, err := os.Open(g.BlockRuleFile)
	if err != nil {
		return fmt.Errorf("failed to open rule file: %w", err)
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
		return fmt.Errorf("failed to read rule file: %w", err)
	}

	// 更新规则缓存
	g.ruleCache = newCache

	// 更新内存中的规则列表
	g.BlockRules = make([]string, 0, ruleCount)
	for rule := range newCache.GetAllRules() {
		g.BlockRules = append(g.BlockRules, rule)
	}

	g.logger.Info("rules loaded from file",
		zap.String("file", g.BlockRuleFile),
		zap.Int("total_lines", lineCount),
		zap.Int("rules_loaded", ruleCount),
		zap.Time("last_modified", g.lastModTime))

	return nil
}

// parseCaddyfile 解析Caddyfile配置
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var g GFW
	g.EnableExtra = false // 默认禁用额外安全检测
	g.BlockAll = false    // 默认只拦截单次请求

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
// 				duration, err := time.ParseDuration(h.Val())
                duration, err := caddy.ParseDuration(h.Val())
				if err != nil {
					return nil, h.Errf("invalid ttl duration: %v", err)
				}
// 				g.TTL = duration
                g.TTL = caddy.Duration(duration)
			case "enable_extra":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				enable, err := strconv.ParseBool(h.Val())
				if err != nil {
					return nil, h.Errf("invalid enable_extra value: %v", err)
				}
				g.EnableExtra = enable

			case "block_all":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				blockAll, err := strconv.ParseBool(h.Val())
				if err != nil {
					return nil, h.Errf("invalid block_all value: %v", err)
				}
				g.BlockAll = blockAll

			default:
				return nil, h.Errf("unknown subdirective '%s'", h.Val())
			}
		}
	}

	return &g, nil
}

// UnmarshalCaddyfile 实现 caddyfile.Unmarshaler
func (g *GFW) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	g.EnableExtra = false // 默认禁用额外安全检测
	g.BlockAll = false    // 默认只拦截单次请求

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
// 				duration, err := time.ParseDuration(d.Val())
				duration, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid ttl duration: %v", err)
				}
// 				g.TTL = duration
                g.TTL = caddy.Duration(duration)

			case "enable_extra":
				if !d.NextArg() {
					return d.ArgErr()
				}
				enable, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("invalid enable_extra value: %v", err)
				}
				g.EnableExtra = enable

			case "block_all":
				if !d.NextArg() {
					return d.ArgErr()
				}
				blockAll, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("invalid block_all value: %v", err)
				}
				g.BlockAll = blockAll

			default:
				return d.Errf("unknown subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// loadBlacklist 从存储加载黑名单
func (g *GFW) loadBlacklist() error {
	data, err := g.storage.Load("blacklist.json")
	if err != nil {
		return fmt.Errorf("failed to read blacklist: %w", err)
	}

	if len(data) == 0 {
		return nil
	}

	var blacklist map[string]string
	if err := json.Unmarshal(data, &blacklist); err != nil {
		return fmt.Errorf("failed to parse blacklist: %w", err)
	}

	g.blackListMu.Lock()
	defer g.blackListMu.Unlock()

	now := time.Now()
	for ip, expireStr := range blacklist {
		expireTime, err := time.Parse(time.RFC3339, expireStr)
		if err != nil {
			g.logger.Warn("failed to parse expiration time",
				zap.Error(err),
				zap.String("ip", ip),
				zap.String("expire_time", expireStr))
			continue
		}

		// 只加载未过期的记录
		if now.Before(expireTime) {
			g.blackList[ip] = expireTime
		}
	}

	return nil
}

// saveBlacklist 保存黑名单到存储
func (g *GFW) saveBlacklist() error {
	g.blackListMu.RLock()
	defer g.blackListMu.RUnlock()

	blacklist := make(map[string]string)
	for ip, expireTime := range g.blackList {
		blacklist[ip] = expireTime.Format(time.RFC3339)
	}

	data, err := json.Marshal(blacklist)
	if err != nil {
		return fmt.Errorf("failed to serialize blacklist: %w", err)
	}

	if err := g.storage.Store("blacklist.json", data); err != nil {
		return fmt.Errorf("failed to save blacklist: %w", err)
	}

	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*GFW)(nil)
	_ caddy.Validator             = (*GFW)(nil)
	_ caddyhttp.MiddlewareHandler = (*GFW)(nil)
	_ caddyfile.Unmarshaler       = (*GFW)(nil)
)
