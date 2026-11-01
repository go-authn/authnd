// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package main

import "os"

// inodeOf: no inode here; size and modification time stand in.
func inodeOf(os.FileInfo) uint64 { return 0 }
