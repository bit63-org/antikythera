# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Sanitizer builds for tests and local runs: cmake -DAK_SANITIZE=ON
if(AK_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

# libFuzzer needs coverage instrumentation in the code under test, not only in
# the fuzz target: without it the fuzzer sees no new edges inside the
# libraries and never gets past the first header check. fuzzer-no-link adds
# the instrumentation without libFuzzer's main(); fuzz/CMakeLists.txt links
# the fuzz targets themselves with -fsanitize=fuzzer.
if(AK_FUZZ)
  add_compile_options(-fsanitize=fuzzer-no-link)
endif()
