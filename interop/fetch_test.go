// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// source is a third-party repository pinned to a release tag and the
// commit that tag named when the tests were written.
type source struct {
	name   string // also the suffix of the SIGMA_MBUS_INTEROP_<NAME> override
	url    string
	tag    string
	commit string
}

var (
	wmbusmeters = source{"WMBUSMETERS", "https://github.com/wmbusmeters/wmbusmeters", "3.0.0", "ac4f295369a48ef51cb835e6920b62cbee743bd6"}
	libmbus     = source{"LIBMBUS", "https://github.com/rscada/libmbus", "0.10.3", "d617bd2bf654fc1b0d291a340672727440853142"}
)

// checkout returns a directory holding s at its pinned commit. The tests
// run only with SIGMA_MBUS_INTEROP=1; they clone the tag into a temporary
// directory (skipping when git or the network is missing) unless
// SIGMA_MBUS_INTEROP_<NAME> names an existing checkout. Either way the
// checkout must be at the pinned commit. The files are read as data only:
// nothing from the checkout is built or run.
func checkout(t *testing.T, s source) string {
	t.Helper()
	if os.Getenv("SIGMA_MBUS_INTEROP") != "1" {
		t.Skip("fetches third-party test data; set SIGMA_MBUS_INTEROP=1 to run")
	}
	dir := os.Getenv("SIGMA_MBUS_INTEROP_" + s.name)
	if dir == "" {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skip("git is not on PATH")
		}
		dir = filepath.Join(t.TempDir(), strings.ToLower(s.name))
		out, err := exec.Command("git", "clone", "--quiet", "--depth", "1", "--branch", s.tag, s.url, dir).CombinedOutput()
		if err != nil {
			t.Skipf("cannot clone %s %s (offline?): %v %s", s.url, s.tag, err, out)
		}
	}
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("%s: not a git checkout: %v", dir, err)
	}
	if got := strings.TrimSpace(string(out)); got != s.commit {
		t.Fatalf("%s is at %s, the tests are pinned to %s (tag %s)", dir, got, s.commit, s.tag)
	}
	return dir
}
