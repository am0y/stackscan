package scan

import (
	"os"
	"path/filepath"
	"strings"
)

type FileInfo struct {
	Path string
	Name string
	Dir  string
	Ext  string
	Size int64
}

var ignoreDirs = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true, "__pycache__": true,
	".next": true, "dist": true, "build": true, ".cache": true, "target": true,
	".gradle": true, ".idea": true, ".vscode": true, "coverage": true,
	"venv": true, ".venv": true, "env": true, ".tox": true, "bower_components": true,
}

func Walk(root string) ([]FileInfo, error) {
	var files []FileInfo

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			if ignoreDirs[info.Name()] || strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		files = append(files, FileInfo{
			Path: rel,
			Name: info.Name(),
			Dir:  filepath.Dir(rel),
			Ext:  strings.TrimPrefix(filepath.Ext(info.Name()), "."),
			Size: info.Size(),
		})

		return nil
	})

	return files, err
}

func HasFile(files []FileInfo, name string) bool {
	for _, f := range files {
		if f.Name == name && f.Dir == "." {
			return true
		}
	}
	return false
}

func HasFileAnywhere(files []FileInfo, name string) bool {
	for _, f := range files {
		if f.Name == name {
			return true
		}
	}
	return false
}

func HasExt(files []FileInfo, ext string) bool {
	for _, f := range files {
		if f.Ext == ext {
			return true
		}
	}
	return false
}

func CountExt(files []FileInfo, ext string) int {
	n := 0
	for _, f := range files {
		if f.Ext == ext {
			n++
		}
	}
	return n
}

func ReadFileHead(root, relPath string, maxBytes int) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, relPath))
	if err != nil {
		return "", err
	}
	if len(data) > maxBytes {
		data = data[:maxBytes]
	}
	return string(data), nil
}
