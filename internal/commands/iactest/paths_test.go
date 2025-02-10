package iactest

import (
	"reflect"
	"testing"
)

func TestDetermineInputPaths(t *testing.T) {
	tests := []struct {
		name string
		args []string
		cwd  string
		want []string
	}{
		{
			name: "no arguments",
			args: []string{},
			cwd:  "/current/directory",
			want: []string{"/current/directory"},
		},
		{
			name: "only commands",
			args: []string{"iac", "test"},
			cwd:  "/current/directory",
			want: []string{"/current/directory"},
		},
		{
			name: "commands and flags",
			args: []string{"iac", "test", "-flag"},
			cwd:  "/current/directory",
			want: []string{"/current/directory"},
		},
		{
			name: "commands, flags and paths",
			args: []string{"iac", "test", "-flag", "/path/one", "/path/two"},
			cwd:  "/current/directory",
			want: []string{"/path/one", "/path/two"},
		},
		{
			name: "only paths",
			args: []string{"/path/one", "/path/two"},
			cwd:  "/current/directory",
			want: []string{"/path/one", "/path/two"},
		},
		{
			name: "mixed arguments",
			args: []string{"iac", "/path/one", "-flag", "/path/two"},
			cwd:  "/current/directory",
			want: []string{"/path/one", "/path/two"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetermineInputPaths(tt.args, tt.cwd); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DetermineInputPaths() = %v, want %v", got, tt.want)
			}
		})
	}
}
