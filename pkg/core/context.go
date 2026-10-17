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
	CodeLines    []string
	IsComment    []bool
}

// NewFileContext constructs a FileContext from path and content, stripping comments for code analysis.
func NewFileContext(absPath, relPath, content string) *FileContext {
	ext := strings.ToLower(filepath.Ext(absPath))
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")

	codeLines := make([]string, len(lines))
	isComment := make([]bool, len(lines))

	inBlockComment := false
	inDocstring := ""

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Python triple quotes docstring handling
		if ext == ".py" {
			if inDocstring != "" {
				if strings.Contains(line, inDocstring) {
					inDocstring = ""
				}
				codeLines[i] = ""
				isComment[i] = true
				continue
			} else if strings.HasPrefix(trimmed, `"""`) {
				if strings.Count(trimmed, `"""`) == 1 {
					inDocstring = `"""`
				}
				codeLines[i] = ""
				isComment[i] = true
				continue
			} else if strings.HasPrefix(trimmed, `'''`) {
				if strings.Count(trimmed, `'''`) == 1 {
					inDocstring = `'''`
				}
				codeLines[i] = ""
				isComment[i] = true
				continue
			} else if strings.HasPrefix(trimmed, "#") {
				codeLines[i] = ""
				isComment[i] = true
				continue
			}

			// Strip inline # comment if present (outside quotes)
			if idx := strings.Index(line, "#"); idx != -1 {
				codeLines[i] = line[:idx]
			} else {
				codeLines[i] = line
			}
			continue
		}

		// JS/TS/Go/Prisma comment handling
		if inBlockComment {
			if idx := strings.Index(line, "*/"); idx != -1 {
				inBlockComment = false
				codeLines[i] = strings.Repeat(" ", idx+2) + line[idx+2:]
				isComment[i] = strings.TrimSpace(codeLines[i]) == ""
			} else {
				codeLines[i] = ""
				isComment[i] = true
			}
			continue
		}

		if strings.HasPrefix(trimmed, "//") {
			codeLines[i] = ""
			isComment[i] = true
			continue
		}

		if strings.HasPrefix(trimmed, "/*") {
			if idx := strings.Index(line, "*/"); idx != -1 {
				// Single line block comment
				codeLines[i] = line[idx+2:]
				isComment[i] = strings.TrimSpace(codeLines[i]) == ""
			} else {
				inBlockComment = true
				codeLines[i] = ""
				isComment[i] = true
			}
			continue
		}

		// Inline comments
		curLine := line
		if idx := strings.Index(line, "//"); idx != -1 {
			curLine = line[:idx]
		}
		if idx := strings.Index(curLine, "/*"); idx != -1 {
			if endIdx := strings.Index(curLine, "*/"); endIdx != -1 && endIdx > idx {
				curLine = curLine[:idx] + strings.Repeat(" ", endIdx-idx+2) + curLine[endIdx+2:]
			} else {
				inBlockComment = true
				curLine = curLine[:idx]
			}
		}

		codeLines[i] = curLine
		isComment[i] = strings.TrimSpace(curLine) == "" && trimmed != ""
	}

	return &FileContext{
		FilePath:     absPath,
		RelativePath: relPath,
		Extension:    ext,
		Content:      normalized,
		Lines:        lines,
		CodeLines:    codeLines,
		IsComment:    isComment,
	}
}

// GetCodeLine returns the comment-stripped content of line at index.
func (fc *FileContext) GetCodeLine(idx int) string {
	if idx >= 0 && idx < len(fc.CodeLines) {
		return fc.CodeLines[idx]
	}
	return ""
}

// IsCommentLine returns true if line at index is empty or solely a comment.
func (fc *FileContext) IsCommentLine(idx int) bool {
	if idx >= 0 && idx < len(fc.IsComment) {
		return fc.IsComment[idx]
	}
	return false
}
