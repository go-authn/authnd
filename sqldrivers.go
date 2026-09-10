// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosql

package main

// The database drivers this binary can use.
//
// They are imported HERE, by the program, and not by
// go-authn/directory/hcldir: a driver is a choice a deployment makes, and a
// library has no business making it -- PostgreSQL alone has three. `-tags
// nosql` leaves all of them out along with the `users "sql"` block.
//
// This file was missing for the first hour of this program's life, and
// nothing said so until a configuration named a database: the library's
// message ("this binary registered no \"sqlite\" driver: import one") is what
// found it. Hence the test next door, which asks the BINARY what it can open
// rather than trusting that somebody remembered.
import (
	_ "github.com/go-sql-driver/mysql" // mysql
	_ "github.com/jackc/pgx/v5/stdlib" // postgres
	_ "modernc.org/sqlite"             // sqlite, in pure Go: no cgo
)
