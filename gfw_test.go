package gfw

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

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
	}{
		{
			name:           "正常请求",
			query:          "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "SQL注入请求",
			query:          "id=1' OR '1'='1",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "XSS请求",
			query:          "q=<script>alert(1)</script>",
			expectedStatus: http.StatusForbidden,
		},
	}

	g := setupGFW(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.URL.RawQuery = tt.query
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
