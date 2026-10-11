// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wired_test

import (
	"encoding/hex"
	"math"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func near(v any, want float64) bool {
	f, ok := v.(float64)
	return ok && math.Abs(f-want) < 1e-6
}
