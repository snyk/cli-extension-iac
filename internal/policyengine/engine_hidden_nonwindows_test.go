//go:build !windows

package engine_test

import "testing"

// hideDotEntries is a no-op on non-Windows platforms.
func hideDotEntries(t *testing.T, root string) {}
