// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The one place C++ code includes libvfio-user.
//
// libvfio-user's public headers are C11: its pci_caps/*.h headers use
// _Static_assert, which is not a C++ keyword. Map it to static_assert for
// the duration of the include only, so the library's own layout checks
// still run under C++ instead of being silently dropped.

#include <cstddef>

#include <linux/pci_regs.h>
#include <syslog.h>

#ifdef _Static_assert
#error "_Static_assert is already defined; libvfio_user.hpp cannot shim it safely"
#endif
#define _Static_assert static_assert  // NOLINT(bugprone-reserved-identifier)

extern "C" {
#include <libvfio-user.h>
}

#undef _Static_assert
