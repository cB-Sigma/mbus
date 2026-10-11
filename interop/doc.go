// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop holds tests only: it decodes the published test data of
// two independent M-Bus implementations with github.com/cB-Sigma/mbus
// and compares the results with what those projects expect.
//
//   - libmbus (BSD-3-Clause), tag 0.10.3: every RSP_UD frame of
//     test/test-frames is decoded with package wired and compared, header
//     and record by record, with libmbus's normalised XML output.
//   - wmbusmeters (GPL-3.0-or-later), tag 3.0.0: the telegrams of its
//     driver tests (tests/generated_tests.xmq and the "// Test:" blocks of
//     its C++ drivers) and of its simulation files are decoded with
//     package wireless, with the AES keys the tests give, and the meter
//     identity, medium and common values are compared with the JSON
//     wmbusmeters prints for them.
//
// No data of either project is kept in this repository: the tests clone
// the pinned tag at run time, check the commit, read the files as data and
// skip when offline. They run only with SIGMA_MBUS_INTEROP=1; an existing
// checkout can be named with SIGMA_MBUS_INTEROP_LIBMBUS or
// SIGMA_MBUS_INTEROP_WMBUSMETERS. The module is not part of the
// published library and nothing imports it.
package interop
