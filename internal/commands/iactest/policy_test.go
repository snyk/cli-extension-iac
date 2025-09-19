package iactest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestGetPolicyFile(t *testing.T) {
	logger := zerolog.Nop()
	t.Run("Policy file exists in root dir", func(t *testing.T) {
		rootDir := t.TempDir()
		policyFile := ".snyk"
		createTestFiles(t, rootDir, []string{policyFile})

		result := GetPolicyFile("", rootDir, &logger)
		assert.Equal(t, filepath.Join(rootDir, policyFile), result)
	})

	t.Run("Policy file exists in --policy-path", func(t *testing.T) {
		rootDir := t.TempDir()
		policyPath := filepath.Join(rootDir, "customDir")
		policyFile := ".snyk"
		createTestFiles(t, policyPath, []string{policyFile})

		result := GetPolicyFile(policyPath, rootDir, &logger)
		assert.Equal(t, filepath.Join(policyPath, policyFile), result)
	})

	t.Run("Wrong --policy-path fallback to root dir", func(t *testing.T) {
		rootDir := t.TempDir()
		policyPath := "wrongPath"
		policyFile := ".snyk"
		createTestFiles(t, rootDir, []string{policyFile})

		result := GetPolicyFile(policyPath, rootDir, &logger)
		assert.Equal(t, filepath.Join(rootDir, policyFile), result)
	})

	t.Run("Policy file not found", func(t *testing.T) {
		rootDir := t.TempDir()

		result := GetPolicyFile("", rootDir, &logger)
		assert.Empty(t, result)
	})
}

func createTestFiles(t *testing.T, baseDir string, files []string) {
	t.Helper()
	for _, file := range files {
		fullPath := filepath.Join(baseDir, file)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create directories: %v", err)
		}
		f, err := os.Create(fullPath)
		if err != nil {
			t.Fatalf("failed to create file %s: %v", fullPath, err)
		}
		_ = f.Close()
	}
}
