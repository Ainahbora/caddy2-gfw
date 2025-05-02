package gfw

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
)

func TestGFW_ServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		gfw            *GFW
		request        *http.Request
		expectedStatus int
		setup          func(*GFW, *http.Request)
	}{
		{
			name: "正常请求",
			gfw: &GFW{
				BlockRules: []string{"1.1.1.1"},
			},
			request:        httptest.NewRequest("GET", "https://example.com", nil),
			expectedStatus: http.StatusOK,
		},
		{
			name: "黑名单IP请求",
			gfw: &GFW{
				BlockRules: []string{"1.1.1.1"},
			},
			request:        httptest.NewRequest("GET", "https://example.com", nil),
			expectedStatus: http.StatusForbidden,
			setup: func(g *GFW, r *http.Request) {
				g.blackList = map[string]time.Time{
					"127.0.0.1": time.Now().Add(time.Hour),
				}
			},
		},
		{
			name: "匹配IP规则",
			gfw: &GFW{
				BlockRules: []string{"127.0.0.1"},
			},
			request:        httptest.NewRequest("GET", "https://example.com", nil),
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "匹配URL规则",
			gfw: &GFW{
				BlockRules: []string{"/api/v1"},
			},
			request:        httptest.NewRequest("GET", "https://example.com/api/v1/users", nil),
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "匹配User-Agent规则",
			gfw: &GFW{
				BlockRules: []string{"curl"},
			},
			request:        httptest.NewRequest("GET", "https://example.com", nil),
			expectedStatus: http.StatusForbidden,
			setup: func(g *GFW, r *http.Request) {
				r.Header.Set("User-Agent", "curl/7.64.1")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 设置请求的RemoteAddr
			tt.request.RemoteAddr = "127.0.0.1:12345"

			// 执行setup函数
			if tt.setup != nil {
				tt.setup(tt.gfw, tt.request)
			}

			// 创建响应记录器
			recorder := httptest.NewRecorder()

			// 创建下一个处理器
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusOK)
				return nil
			})

			// 调用ServeHTTP
			err := tt.gfw.ServeHTTP(recorder, tt.request, next)

			// 验证结果
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, recorder.Code)
		})
	}
}

func TestGFW_Provision(t *testing.T) {
	tests := []struct {
		name    string
		gfw     *GFW
		wantErr bool
	}{
		{
			name: "正常配置",
			gfw: &GFW{
				BlockRules: []string{"1.1.1.1", "/api/v1"},
			},
			wantErr: false,
		},
		{
			name:    "空配置",
			gfw:     &GFW{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.gfw.Provision(caddy.Context{})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tt.gfw.logger)
				assert.NotNil(t, tt.gfw.blackList)
				assert.NotNil(t, tt.gfw.stopChan)
				assert.NotNil(t, tt.gfw.ruleCache)
			}
		})
	}
}

func TestGFW_Validate(t *testing.T) {
	tests := []struct {
		name    string
		gfw     *GFW
		wantErr bool
	}{
		{
			name: "有效配置",
			gfw: &GFW{
				BlockRules: []string{"1.1.1.1"},
			},
			wantErr: false,
		},
		{
			name:    "空配置",
			gfw:     &GFW{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.gfw.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGFW_Cleanup(t *testing.T) {
	gfw := &GFW{
		blackList: make(map[string]time.Time),
	}

	// 添加一些测试数据
	now := time.Now()
	gfw.blackList["1.1.1.1"] = now.Add(-time.Hour) // 已过期
	gfw.blackList["2.2.2.2"] = now.Add(time.Hour)  // 未过期

	// 执行清理
	gfw.cleanup()

	// 验证结果
	assert.NotContains(t, gfw.blackList, "1.1.1.1")
	assert.Contains(t, gfw.blackList, "2.2.2.2")
}

func TestRuleCache(t *testing.T) {
	cache := NewRuleCache()

	// 测试添加规则
	cache.AddRule("1.1.1.1")
	cache.AddRule("/api/v1")
	cache.AddRule("curl")

	// 测试IP匹配
	assert.True(t, cache.MatchIP("1.1.1.1"))
	assert.False(t, cache.MatchIP("2.2.2.2"))

	// 测试URL匹配
	assert.True(t, cache.MatchURL("/api/v1/users"))
	assert.False(t, cache.MatchURL("/api/v2"))

	// 测试User-Agent匹配
	assert.True(t, cache.MatchUserAgent("curl/7.64.1"))
	assert.False(t, cache.MatchUserAgent("Mozilla/5.0"))
}
