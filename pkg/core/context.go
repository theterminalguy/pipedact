package core

import (
	"path/filepath"
	"strings"
)

// FileContext contains file metadata, raw text, and split lines for scanning.
type FileContext struct {
	FilePath     string
	RelativePath string
	Extension    string
	Content      string
	Lines        []string
}

// NewFileContext constructs a FileContext from path and content.
func NewFileContext(absPath, relPath, content string) *FileContext {
	ext := strings.ToLower(filepath.Ext(absPath))
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	return &FileContext{
		FilePath:     absPath,
		RelativePath: relPath,
		Extension:    ext,
		Content:      normalized,
		Lines:        lines,
	}
}
