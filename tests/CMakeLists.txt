# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# Boost.Test, as in kythira: one executable per test file, each defining its
# own BOOST_TEST_MODULE. vcpkg supplies a static Boost.Test; a system build
# may be shared, which needs BOOST_TEST_DYN_LINK.
find_package(Boost REQUIRED COMPONENTS unit_test_framework)
# The TLS tests build a throwaway PKI with OpenSSL (tls_test_support.hpp).
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

set(_ak_boost_test_dyn OFF)
get_target_property(_ak_bt_type Boost::unit_test_framework TYPE)
if(_ak_bt_type STREQUAL "SHARED_LIBRARY")
  set(_ak_boost_test_dyn ON)
else()
  foreach(_prop IMPORTED_LOCATION IMPORTED_LOCATION_RELEASE IMPORTED_LOCATION_NOCONFIG)
    get_target_property(_ak_bt_loc Boost::unit_test_framework ${_prop})
    if(_ak_bt_loc MATCHES "\\.so")
      set(_ak_boost_test_dyn ON)
    endif()
  endforeach()
endif()

function(ak_add_test name)
  cmake_parse_arguments(ARG "" "" "SOURCES;LIBS" ${ARGN})
  add_executable(${name} ${ARG_SOURCES})
  target_link_libraries(${name} PRIVATE ${ARG_LIBS} Boost::unit_test_framework ak::warnings)
  if(_ak_boost_test_dyn)
    target_compile_definitions(${name} PRIVATE BOOST_TEST_DYN_LINK)
  endif()
  add_test(NAME ${name} COMMAND ${name} --log_level=test_suite)
  set_tests_properties(${name} PROPERTIES TIMEOUT 60)
endfunction()

ak_add_test(wire_test         SOURCES wire_test.cpp         LIBS ak::common)
ak_add_test(geneve_test       SOURCES geneve_test.cpp       LIBS ak::oar_net)
ak_add_test(vtep_policy_test  SOURCES vtep_policy_test.cpp  LIBS ak::oar_net)
ak_add_test(mapping_table_test SOURCES mapping_table_test.cpp LIBS ak::oar_net)
ak_add_test(xts_cipher_test   SOURCES xts_cipher_test.cpp   LIBS ak::oar_blk)
ak_add_test(key_slot_test     SOURCES key_slot_test.cpp     LIBS ak::oar_blk)
ak_add_test(request_parser_test     SOURCES request_parser_test.cpp     LIBS ak::oar_blk)
ak_add_test(virtio_blk_function_test SOURCES virtio_blk_function_test.cpp LIBS ak::oar_blk)
ak_add_test(file_backend_test        SOURCES file_backend_test.cpp        LIBS ak::oar_blk)
ak_add_test(mailbox_test      SOURCES mailbox_test.cpp      LIBS ak::helm)
ak_add_test(device_pool_test  SOURCES device_pool_test.cpp  LIBS ak::helm)
ak_add_test(audit_log_test    SOURCES audit_log_test.cpp    LIBS ak::helm)
ak_add_test(command_router_test SOURCES command_router_test.cpp LIBS ak::helm)
ak_add_test(power_sequencer_test SOURCES power_sequencer_test.cpp LIBS ak::helm)
ak_add_test(mailbox_bodies_test SOURCES mailbox_bodies_test.cpp LIBS ak::helm)
ak_add_test(mctp_test         SOURCES mctp_test.cpp         LIBS ak::helm)
ak_add_test(signature_verifier_test SOURCES signature_verifier_test.cpp LIBS ak::hull)
ak_add_test(command_auth_test       SOURCES command_auth_test.cpp       LIBS ak::hull)
ak_add_test(cpu_topology_test       SOURCES cpu_topology_test.cpp       LIBS ak::hull)
ak_add_test(resource_allocator_test SOURCES resource_allocator_test.cpp LIBS ak::hull)
ak_add_test(proto_envelope_test   SOURCES proto_envelope_test.cpp   LIBS ak::proto ak::helm)
ak_add_test(proto_map_update_test SOURCES proto_map_update_test.cpp LIBS ak::proto)
ak_add_test(proto_report_test     SOURCES proto_report_test.cpp     LIBS ak::proto ak::helm)
ak_add_test(proto_link_test       SOURCES proto_link_test.cpp       LIBS ak::proto)
ak_add_test(proto_vectors_test    SOURCES proto_vectors_test.cpp    LIBS ak::proto ak::hull)
ak_add_test(controller_session_test SOURCES controller_session_test.cpp LIBS ak::helm)
ak_add_test(controller_link_test    SOURCES controller_link_test.cpp    LIBS ak::helm OpenSSL::Crypto)
ak_add_test(harbor_controller_test SOURCES harbor_controller_test.cpp LIBS ak::harbor_controller ak::hull OpenSSL::Crypto)
ak_add_test(key_store_test     SOURCES key_store_test.cpp     LIBS ak::helm)
ak_add_test(virtqueue_test    SOURCES virtqueue_test.cpp    LIBS ak::oar_virtio)
ak_add_test(virtio_pci_test   SOURCES virtio_pci_test.cpp   LIBS ak::oar_virtio)
ak_add_test(oar_protocol_test SOURCES oar_protocol_test.cpp LIBS ak::helm ak::proto)
ak_add_test(oar_link_test     SOURCES oar_link_test.cpp     LIBS ak::helm)
ak_add_test(virtio_function_test SOURCES virtio_function_test.cpp LIBS ak::oar_virtio)
ak_add_test(virtio_net_test   SOURCES virtio_net_test.cpp   LIBS ak::oar_net)

# Python tests for the tooling around the C++ tree (the hull kernel config
# checker). Skipped, not failed, when no interpreter is found.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  add_test(NAME kernel_config_test
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/kernel_config_test.py -v)
  set_tests_properties(kernel_config_test PROPERTIES TIMEOUT 60)
endif()

# Kernel Geneve interop (oar-net task 4): the codec against the Linux geneve
# driver in two network namespaces. Needs root, so an ordinary ctest run
# reports it skipped (exit 77); CI runs the script under sudo.
add_executable(geneve_interop_peer geneve_interop_peer.cpp)
target_link_libraries(geneve_interop_peer PRIVATE ak::oar_net ak::warnings)
add_test(NAME geneve_interop
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/geneve_interop.sh $<TARGET_FILE:geneve_interop_peer>)
set_tests_properties(geneve_interop PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)
