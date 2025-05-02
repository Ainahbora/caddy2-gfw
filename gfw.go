// Package gfw 提供Caddy的HTTP请求过滤扩展，用于检测恶意请求
package gfw

import (
	"errors"
	"net/http"
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
	defaultBlacklistTTL    = 1 * time.Hour
	defaultCleanupInterval = 5 * time.Minute

	// 错误信息
	errInvalidConfig     = "invalid configuration"
	errRuleFileNotFound  = "rule file not found"
	errRuleFileReadError = "failed to read rule file"
)

// 错误定义
var (
	ErrInvalidConfig     = errors.New(errInvalidConfig)
	ErrRuleFileNotFound  = errors.New(errRuleFileNotFound)
	ErrRuleFileReadError = errors.New(errRuleFileReadError)
)

func init() {
	caddy.RegisterModule(&GFW{})
	httpcaddyfile.RegisterHandlerDirective("gfw", parseCaddyfile)
}

// GFW 实现了一个Caddy HTTP处理器，用于检测恶意请求
type GFW struct {
	// 配置选项
	BlockRules    []string `json:"block_rules,omitempty"`
	BlockRuleFile string   `json:"block_rule_file,omitempty"`

	// 内部状态
	blackList   map[string]time.Time
	blackListMu sync.RWMutex
	logger      *zap.Logger
	ruleCache   *RuleCache
	stopChan    chan struct{}
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
	}

	// 启动黑名单清理协程
	go g.cleanupBlacklist()

	g.logger.Info("GFW模块已初始化",
		zap.String("block_rule_file", g.BlockRuleFile),
		zap.Strings("block_rules", g.BlockRules))

	return nil
}

// cleanupBlacklist 定期清理过期的黑名单记录
func (g *GFW) cleanupBlacklist() {
	ticker := time.NewTicker(defaultCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			g.cleanup()
		case <-g.stopChan:
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

	for ip, expireTime := range g.blackList {
		if now.After(expireTime) {
			delete(g.blackList, ip)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		g.logger.Debug("清理过期黑名单记录",
			zap.Int("expired_count", expiredCount),
			zap.Int("remaining_count", len(g.blackList)))
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
		w.WriteHeader(http.StatusForbidden)
		return nil
	}

	// 检查请求是否合法
	if !g.isRequestLegal(r) {
		// 将IP加入黑名单，有效期1小时
		g.blackListMu.Lock()
		g.blackList[clientIP] = time.Now().Add(defaultBlacklistTTL)
		g.blackListMu.Unlock()

		g.logger.Warn("检测到恶意请求",
			zap.String("ip", clientIP),
			zap.String("path", r.URL.Path),
			zap.String("user_agent", r.UserAgent()))

		// 返回403状态码
		w.WriteHeader(http.StatusForbidden)
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

			default:
				return d.Errf("unknown subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}
