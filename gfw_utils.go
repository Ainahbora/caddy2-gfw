package gfw

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Trie 前缀树结构，用于高效匹配URL路径规则
type Trie struct {
	root     *TrieNode
	mu       sync.RWMutex
	isLoaded bool
}

// TrieNode 前缀树节点
type TrieNode struct {
	children map[string]*TrieNode
	isEnd    bool
}

// NewTrie 创建新的前缀树
func NewTrie() *Trie {
	return &Trie{
		root: &TrieNode{
			children: make(map[string]*TrieNode),
			isEnd:    false,
		},
		isLoaded: false,
	}
}

// Insert 向前缀树中插入一个路径
func (t *Trie) Insert(path string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	parts := strings.Split(strings.Trim(path, "/"), "/")
	current := t.root

	for _, part := range parts {
		if part == "" {
			continue
		}
		if _, exists := current.children[part]; !exists {
			current.children[part] = &TrieNode{
				children: make(map[string]*TrieNode),
				isEnd:    false,
			}
		}
		current = current.children[part]
	}

	current.isEnd = true
}

// Search 在前缀树中搜索路径，支持前缀匹配
func (t *Trie) Search(path string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	parts := strings.Split(strings.Trim(path, "/"), "/")
	current := t.root

	// 空路径特殊处理
	if len(parts) == 1 && parts[0] == "" {
		return current.isEnd
	}

	for i, part := range parts {
		if part == "" {
			continue
		}

		// 检查当前节点是否是终点（前缀匹配）
		if current.isEnd {
			return true
		}

		if _, exists := current.children[part]; !exists {
			return false
		}

		current = current.children[part]

		// 如果是最后一个部分，检查是否是终点
		if i == len(parts)-1 && current.isEnd {
			return true
		}
	}

	return false
}

// RuleCache 规则缓存结构
type RuleCache struct {
	ipRules      map[string]bool // IP规则集合
	urlTrie      *Trie           // URL路径规则前缀树
	uaRules      map[string]bool // User-Agent规则集合
	lastModified time.Time       // 规则文件最后修改时间
	mu           sync.RWMutex    // 读写锁
}

// NewRuleCache 创建新的规则缓存
func NewRuleCache() *RuleCache {
	return &RuleCache{
		ipRules:      make(map[string]bool),
		urlTrie:      NewTrie(),
		uaRules:      make(map[string]bool),
		lastModified: time.Time{},
	}
}

// AddRule 添加规则到缓存
func (rc *RuleCache) AddRule(rule string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// 根据规则类型分别处理
	if isIPAddressFormat(rule) {
		rc.ipRules[rule] = true
	} else if strings.HasPrefix(rule, "/") {
		rc.urlTrie.Insert(rule)
	} else {
		rc.uaRules[rule] = true
	}
}

// MatchIP 检查IP是否匹配规则
func (rc *RuleCache) MatchIP(ip string) bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	for rule := range rc.ipRules {
		if strings.Contains(ip, rule) {
			return true
		}
	}
	return false
}

// MatchURL 检查URL路径是否匹配规则
func (rc *RuleCache) MatchURL(path string) bool {
	return rc.urlTrie.Search(path)
}

// MatchUserAgent 检查User-Agent是否匹配规则
func (rc *RuleCache) MatchUserAgent(ua string) bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	for rule := range rc.uaRules {
		if strings.Contains(ua, rule) {
			return true
		}
	}
	return false
}

// loadRulesFromFile 从文件中加载拦截规则，支持热更新
func (g *GFW) loadRulesFromFile() error {
	// 检查文件是否存在
	fileInfo, err := os.Stat(g.BlockRuleFile)
	if err != nil {
		return err
	}

	// 检查文件是否被修改
	if g.ruleCache != nil && fileInfo.ModTime().Equal(g.ruleCache.lastModified) {
		// 文件未修改，使用缓存
		g.logger.Debug("规则文件未修改，使用缓存",
			zap.String("file", g.BlockRuleFile),
			zap.Time("last_modified", g.ruleCache.lastModified))
		return nil
	}

	// 打开规则文件
	file, err := os.Open(g.BlockRuleFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// 创建新的规则缓存
	newCache := NewRuleCache()
	newCache.lastModified = fileInfo.ModTime()

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
		return err
	}

	// 更新规则缓存
	g.ruleCache = newCache

	// 更新内存中的规则列表（兼容旧代码）
	g.BlockRules = append(g.BlockRules, getBlockRulesFromCache(newCache)...)

	g.logger.Info("从文件加载规则成功",
		zap.String("file", g.BlockRuleFile),
		zap.Int("total_lines", lineCount),
		zap.Int("rules_loaded", ruleCount),
		zap.Time("last_modified", newCache.lastModified))

	return nil
}

// getBlockRulesFromCache 从缓存中获取所有规则
func getBlockRulesFromCache(cache *RuleCache) []string {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	rules := make([]string, 0)

	// 添加IP规则
	for rule := range cache.ipRules {
		rules = append(rules, rule)
	}

	// 添加UA规则
	for rule := range cache.uaRules {
		rules = append(rules, rule)
	}

	// URL规则需要特殊处理，这里简化处理
	// 实际实现中可能需要遍历前缀树

	return rules
}

// isIPAddressFormat 检查字符串是否为IP地址格式
func isIPAddressFormat(s string) bool {
	// 简单检查是否包含数字和点，且不包含字母
	hasDigit := false
	hasDot := false
	hasLetter := false

	for _, c := range s {
		if c >= '0' && c <= '9' {
			hasDigit = true
		} else if c == '.' {
			hasDot = true
		} else if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
			break
		}
	}

	// 如果包含数字和点，且不包含字母，则可能是IP地址
	return hasDigit && hasDot && !hasLetter
}

// CheckRuleFileUpdate 检查规则文件是否有更新并重新加载
// 可以由定时任务调用此函数实现热更新
func (g *GFW) CheckRuleFileUpdate() error {
	if g.BlockRuleFile == "" {
		return nil
	}
	return g.loadRulesFromFile()
}
