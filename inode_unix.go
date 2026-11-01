// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package main

import (
	"os"
	"syscall"
)

// inodeOf is the file's inode, which changes when a certificate renewer
// replaces the file by renaming a new one over it.
func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino) //nolint:unconvert // uint32 on some platforms
	}
	return 0
}
