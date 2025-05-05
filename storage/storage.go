package storage

import (
	"fmt"
	"os"
	"path/filepath"
)

// Storage 定义存储接口
type Storage interface {
	Load(key string) ([]byte, error)
	Store(key string, data []byte) error
}

// FileStorage 实现基于文件的存储
type FileStorage struct {
	baseDir string
}

// NewFileStorage 创建新的文件存储实例
func NewFileStorage(baseDir string) (*FileStorage, error) {
	// 确保目录存在
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}
	return &FileStorage{baseDir: baseDir}, nil
}

// Load 从文件加载数据
func (fs *FileStorage) Load(key string) ([]byte, error) {
	path := filepath.Join(fs.baseDir, key)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return data, nil
}

// Store 将数据存储到文件
func (fs *FileStorage) Store(key string, data []byte) error {
	path := filepath.Join(fs.baseDir, key)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}
