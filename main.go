// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "authnd:", err)
		os.Exit(1)
	}
}
