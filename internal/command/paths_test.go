package command

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizePaths(t *testing.T) {
	tests := []struct {
		name   string
		cwd    string
		input  string
		output string
	}{
		{
			name:   "original cwd original path",
			cwd:    filepath.Join("testdata", "symlinks", "original"),
			input:  filepath.Join("testdata", "symlinks", "original"),
			output: ".",
		},
		{
			name:   "original cwd linked path",
			cwd:    filepath.Join("testdata", "symlinks", "original"),
			input:  filepath.Join("testdata", "symlinks", "linked"),
			output: filepath.Join("..", "linked"),
		},
		{
			name:   "linked cwd linked path",
			cwd:    filepath.Join("testdata", "symlinks", "linked"),
			input:  filepath.Join("testdata", "symlinks", "linked"),
			output: ".",
		},
		{
			name:   "linked cwd original path",
			cwd:    filepath.Join("testdata", "symlinks", "linked"),
			input:  filepath.Join("testdata", "symlinks", "original"),
			output: filepath.Join("..", "original"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, err := filepath.Abs(test.input)
			if err != nil {
				t.Fatal(err)
			}

			cwd, err := filepath.Abs(test.cwd)
			if err != nil {
				t.Fatal(err)
			}

			withCurrentWorkingDirectory(t, cwd)
			withEnvironmentVariable(t, "PWD", cwd)

			paths, err := normalizePaths([]string{input})
			if err != nil {
				t.Fatal(err)
			}

			if v := paths[0]; v != test.output {
				t.Fatalf("unexpcted path: want %v, expected %v", test.output, v)
			}
		})
	}
}

func withCurrentWorkingDirectory(t *testing.T, cwd string) {
	t.Helper()

	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := os.Chdir(prev); err != nil {
			t.Fatal(err)
		}
	})

	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
}

func withEnvironmentVariable(t *testing.T, name, value string) {
	prev := os.Getenv("PWD")

	t.Cleanup(func() {
		if err := os.Setenv(name, prev); err != nil {
			t.Fatal(err)
		}
	})

	if err := os.Setenv(name, value); err != nil {
		t.Fatal(err)
	}
}
