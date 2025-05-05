package gfw

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

func init() {
	// 测试环境初始化全局 metrics
	registry := prometheus.NewRegistry()
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
}

func TestGFW_Provision(t *testing.T) {
	g := &GFW{}
	ctx := caddy.Context{}

	err := g.Provision(ctx)
	if err != nil {
		t.Errorf("Provision failed: %v", err)
	}

	if g.blackList == nil {
		t.Error("blackList not initialized")
	}
	if g.stopChan == nil {
		t.Error("stopChan not initialized")
	}
	if g.done == nil {
		t.Error("done not initialized")
	}
	if g.ruleCache == nil {
		t.Error("ruleCache not initialized")
	}
}

func TestGFW_SQLInjection(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected bool
	}{
		{
			name:     "SQL注入测试1",
			query:    "id=1' OR '1'='1",
			expected: true,
		},
		{
			name:     "SQL注入测试2",
			query:    "id=1 UNION SELECT * FROM users",
			expected: true,
		},
		{
			name:     "SQL注入测试3",
			query:    "id=1; DROP TABLE users",
			expected: true,
		},
		{
			name:     "正常查询",
			query:    "id=123",
			expected: false,
		},
	}

	g := setupGFW(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.URL.RawQuery = tt.query
			if g.detectSQLInjection(req) != tt.expected {
				t.Errorf("SQL注入检测失败: %s", tt.query)
			}
		})
	}
}

func TestGFW_XSS(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected bool
	}{
		{
			name:     "XSS测试1",
			query:    "q=<script>alert(1)</script>",
			expected: true,
		},
		{
			name:     "XSS测试2",
			query:    "q=javascript:alert(1)",
			expected: true,
		},
		{
			name:     "XSS测试3",
			query:    "q=onclick=alert(1)",
			expected: true,
		},
		{
			name:     "正常输入",
			query:    "q=hello",
			expected: false,
		},
	}

	g := setupGFW(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.URL.RawQuery = tt.query
			if g.detectXSS(req) != tt.expected {
				t.Errorf("XSS检测失败: %s", tt.query)
			}
		})
	}
}

func TestGFW_CSRF(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		referer  string
		host     string
		expected bool
	}{
		{
			name:     "CSRF测试1 - 无Referer",
			method:   "POST",
			referer:  "",
			host:     "example.com",
			expected: true,
		},
		{
			name:     "CSRF测试2 - 不同域名",
			method:   "POST",
			referer:  "https://evil.com",
			host:     "example.com",
			expected: true,
		},
		{
			name:     "正常请求",
			method:   "POST",
			referer:  "https://example.com",
			host:     "example.com",
			expected: false,
		},
	}

	g := setupGFW(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", nil)
			req.Host = tt.host
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			if g.detectCSRF(req) != tt.expected {
				t.Errorf("CSRF检测失败: %s", tt.name)
			}
		})
	}
}

func TestGFW_SSRF(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected bool
	}{
		{
			name:     "SSRF测试1",
			query:    "url=http://127.0.0.1",
			expected: true,
		},
		{
			name:     "SSRF测试2",
			query:    "url=file:///etc/passwd",
			expected: true,
		},
		{
			name:     "SSRF测试3",
			query:    "url=gopher://127.0.0.1:25",
			expected: true,
		},
		{
			name:     "正常URL",
			query:    "url=https://example.com",
			expected: false,
		},
	}

	g := setupGFW(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.URL.RawQuery = tt.query
			if g.detectSSRF(req) != tt.expected {
				t.Errorf("SSRF检测失败: %s", tt.query)
			}
		})
	}
}

func TestGFW_CommandInjection(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected bool
	}{
		{
			name:     "命令注入测试1",
			query:    "cmd=cat /etc/passwd",
			expected: true,
		},
		{
			name:     "命令注入测试2",
			query:    "cmd=ls -la | grep root",
			expected: true,
		},
		{
			name:     "命令注入测试3",
			query:    "cmd=rm -rf /",
			expected: true,
		},
		{
			name:     "正常命令",
			query:    "cmd=echo hello",
			expected: false,
		},
	}

	g := setupGFW(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.URL.RawQuery = tt.query
			if g.detectCommandInjection(req) != tt.expected {
				t.Errorf("命令注入检测失败: %s", tt.query)
			}
		})
	}
}

func TestGFW_CodeInjection(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected bool
	}{
		{
			name:     "代码注入测试1",
			query:    "code=eval('alert(1)')",
			expected: true,
		},
		{
			name:     "代码注入测试2",
			query:    "code=system('ls')",
			expected: true,
		},
		{
			name:     "代码注入测试3",
			query:    "code=exec('rm -rf /')",
			expected: true,
		},
		{
			name:     "正常代码",
			query:    "code=console.log('hello')",
			expected: false,
		},
	}

	g := setupGFW(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.URL.RawQuery = tt.query
			if g.detectCodeInjection(req) != tt.expected {
				t.Errorf("代码注入检测失败: %s", tt.query)
			}
		})
	}
}

func TestGFW_FileInclude(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected bool
	}{
		{
			name:     "文件包含测试1",
			query:    "file=../../../etc/passwd",
			expected: true,
		},
		{
			name:     "文件包含测试2",
			query:    "include=php://input",
			expected: true,
		},
		{
			name:     "文件包含测试3",
			query:    "require=../../../config.php",
			expected: true,
		},
		{
			name:     "正常文件",
			query:    "file=index.html",
			expected: false,
		},
	}

	g := setupGFW(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.URL.RawQuery = tt.query
			if g.detectFileInclude(req) != tt.expected {
				t.Errorf("文件包含检测失败: %s", tt.query)
			}
		})
	}
}

func TestGFW_ServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		query          string
		expectedStatus int
		remoteAddr     string
	}{
		{
			name:           "正常请求",
			query:          "",
			expectedStatus: http.StatusOK,
			remoteAddr:     "192.0.2.10:1234",
		},
		{
			name:           "SQL注入请求",
			query:          "id=1' OR '1'='1",
			expectedStatus: http.StatusForbidden,
			remoteAddr:     "192.0.2.11:1234",
		},
		{
			name:           "XSS请求",
			query:          "q=<script>alert(1)</script>",
			expectedStatus: http.StatusForbidden,
			remoteAddr:     "192.0.2.12:1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := setupGFW(t)
			g.EnableExtra = true // 启用额外安全检测

			req := httptest.NewRequest("GET", "/", nil)
			req.URL.RawQuery = tt.query
			req.RemoteAddr = tt.remoteAddr
			recorder := httptest.NewRecorder()
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return nil
			})

			err := g.ServeHTTP(recorder, req, next)
			if err != nil {
				t.Errorf("ServeHTTP failed: %v", err)
			}

			if recorder.Code != tt.expectedStatus {
				t.Errorf("期望状态码 %d, 实际状态码 %d", tt.expectedStatus, recorder.Code)
			}
		})
	}
}

func TestGFW_Blacklist(t *testing.T) {
	g := setupGFW(t)

	// 测试添加IP到黑名单
	ip := "192.168.1.1"
	g.blackListMu.Lock()
	g.blackList[ip] = time.Now().Add(g.TTL)
	g.blackListMu.Unlock()

	// 测试黑名单IP的请求
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ip
	recorder := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	err := g.ServeHTTP(recorder, req, next)
	if err != nil {
		t.Errorf("ServeHTTP failed: %v", err)
	}

	if recorder.Code != http.StatusForbidden {
		t.Errorf("期望状态码 %d, 实际状态码 %d", http.StatusForbidden, recorder.Code)
	}
}

func TestGFW_ExtraSecurity(t *testing.T) {
	tests := []struct {
		name           string
		enableExtra    bool
		request        *http.Request
		expectedResult bool
	}{
		{
			name:        "额外安全检测关闭 - SQL注入",
			enableExtra: false,
			request: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.URL.RawQuery = "id=1' OR '1'='1"
				return req
			}(),
			expectedResult: true, // 请求应该通过，因为额外安全检测被禁用
		},
		{
			name:        "额外安全检测开启 - SQL注入",
			enableExtra: true,
			request: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.URL.RawQuery = "id=1' OR '1'='1"
				return req
			}(),
			expectedResult: false, // 请求应该被拒绝，因为检测到SQL注入
		},
		{
			name:        "额外安全检测关闭 - XSS",
			enableExtra: false,
			request: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.URL.RawQuery = "q=<script>alert(1)</script>"
				return req
			}(),
			expectedResult: true, // 请求应该通过，因为额外安全检测被禁用
		},
		{
			name:        "额外安全检测开启 - XSS",
			enableExtra: true,
			request: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.URL.RawQuery = "q=<script>alert(1)</script>"
				return req
			}(),
			expectedResult: false, // 请求应该被拒绝，因为检测到XSS
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := setupGFW(t)
			g.EnableExtra = tt.enableExtra
			_, result := g.isRequestLegal(tt.request)
			if result != tt.expectedResult {
				t.Errorf("额外安全检测测试失败: %s, 期望结果: %v, 实际结果: %v", tt.name, tt.expectedResult, result)
			}
		})
	}
}

func TestGFW_BlockAllBehavior(t *testing.T) {
	g := setupGFW(t)
	g.BlockAll = true
	g.BlockRules = []string{"ip:192.0.2.1"}
	g.ruleCache = NewRuleCache()
	g.ruleCache.AddRule("ip:192.0.2.1")

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1"
	recorder := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	// 第一次命中规则，应该被拉黑
	_ = g.ServeHTTP(recorder, req, next)
	if !g.isIPBlacklisted("192.0.2.1") {
		t.Errorf("BlockAll=true 时，命中规则后 IP 应该被拉黑")
	}

	// 第二次请求，应该直接被拦截
	recorder2 := httptest.NewRecorder()
	_ = g.ServeHTTP(recorder2, req, next)
	if recorder2.Code != http.StatusForbidden {
		t.Errorf("BlockAll=true 时，黑名单 IP 应该被拦截")
	}
}

func TestGFW_BlockAllFalseBehavior(t *testing.T) {
	g := setupGFW(t)
	g.BlockAll = false
	g.BlockRules = []string{"ip:192.0.2.2"}
	g.ruleCache = NewRuleCache()
	g.ruleCache.AddRule("ip:192.0.2.2")

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.2"
	recorder := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	// 命中规则，只拦截本次，不拉黑
	_ = g.ServeHTTP(recorder, req, next)
	if g.isIPBlacklisted("192.0.2.2") {
		t.Errorf("BlockAll=false 时，命中规则后 IP 不应被拉黑")
	}
}

// 可选：metrics 相关断言（示例，实际可根据需要完善）
func TestGFW_Metrics(t *testing.T) {
	before := requestsTotal.WithLabelValues("allowed").Collect
	g := setupGFW(t)
	g.BlockAll = false
	g.BlockRules = []string{"ip:192.0.2.3"}
	g.ruleCache = NewRuleCache()
	g.ruleCache.AddRule("ip:192.0.2.3")

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.3"
	recorder := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})
	_ = g.ServeHTTP(recorder, req, next)
	// 这里只做示例，实际可用 prometheus/testutil 断言指标递增
	_ = before // 防止未使用
}

func setupGFW(t *testing.T) *GFW {
	g := &GFW{
		TTL: defaultBlacklistTTL,
	}
	ctx := caddy.Context{}
	err := g.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	return g
}
