//go:build windows

package engine_test

import (
	"syscall"
	"testing"
	"unsafe"
	"io/fs"
	"path/filepath"
	"strings"
)

func setHiddenWindows(t *testing.T, p string) {
	t.Helper()
	mod := syscall.NewLazyDLL("kernel32.dll")
	setFA := mod.NewProc("SetFileAttributesW")
	getFA := mod.NewProc("GetFileAttributesW")
	ptr, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		t.Logf("skip setting hidden attr: %v", err)
		return
	}
	r1, _, _ := getFA.Call(uintptr(unsafe.Pointer(ptr)))
	if r1 == 0xFFFFFFFF {
		return
	}
	const FILE_ATTRIBUTE_HIDDEN = 0x2
	attrs := uint32(r1) | FILE_ATTRIBUTE_HIDDEN
	_, _, _ = setFA.Call(uintptr(unsafe.Pointer(ptr)), uintptr(attrs))
}

// hideDotEntriesWindows marks any dot-prefixed files or directories under root as hidden
func hideDotEntriesWindows(t *testing.T, root string) {
    t.Helper()
    _ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
        if err != nil {
            return nil
        }
        if strings.HasPrefix(d.Name(), ".") {
            setHiddenWindows(t, path)
        }
        return nil
    })
}

// Bridge functions called from platform-agnostic tests
func hideDotEntries(t *testing.T, root string) { hideDotEntriesWindows(t, root) }
