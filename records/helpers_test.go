// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package records

import (
	"encoding/hex"
	"sort"
	"strings"
	"testing"
)

// hx decodes hex with spaces.
func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// recordMap indexes records by name.
func recordMap(rs []Record) map[string]Record {
	m := map[string]Record{}
	for _, r := range rs {
		m[r.Name()] = r
	}
	return m
}

// keysOf lists a record map's names, sorted.
func keysOf(m map[string]Record) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
