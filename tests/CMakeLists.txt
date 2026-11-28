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
  cmake_parse_arguments(ARG "" "" "SOURCES;LIBS;ARGS" ${ARGN})
  add_executable(${name} ${ARG_SOURCES})
  target_link_libraries(${name} PRIVATE ${ARG_LIBS} Boost::unit_test_framework ak::warnings)
  if(_ak_boost_test_dyn)
    target_compile_definitions(${name} PRIVATE BOOST_TEST_DYN_LINK)
  endif()
  add_test(NAME ${name} COMMAND ${name} --log_level=test_suite ${ARG_ARGS})
  set_tests_properties(${name} PROPERTIES TIMEOUT 60)
endfunction()

ak_add_test(wire_test         SOURCES wire_test.cpp         LIBS ak::common)
ak_add_test(geneve_test       SOURCES geneve_test.cpp       LIBS ak::oar_net)
ak_add_test(vtep_policy_test  SOURCES vtep_policy_test.cpp  LIBS ak::oar_net)
ak_add_test(mapping_table_test SOURCES mapping_table_test.cpp LIBS ak::oar_net)
ak_add_test(neighbor_test     SOURCES neighbor_test.cpp     LIBS ak::oar_net)
ak_add_test(packet_test       SOURCES packet_test.cpp       LIBS ak::oar_net)
ak_add_test(igmp_test         SOURCES igmp_test.cpp         LIBS ak::oar_net)
ak_add_test(dhcp4_test        SOURCES dhcp4_test.cpp        LIBS ak::oar_net)
ak_add_test(dhcp6_test        SOURCES dhcp6_test.cpp        LIBS ak::oar_net)
ak_add_test(vswitch_test      SOURCES vswitch_test.cpp      LIBS ak::oar_net)
ak_add_test(route_trie_test   SOURCES route_trie_test.cpp   LIBS ak::oar_net)
ak_add_test(oam_test          SOURCES oam_test.cpp          LIBS ak::oar_net)
ak_add_test(vtep_test         SOURCES vtep_test.cpp         LIBS ak::oar_net)
ak_add_test(mtu_test          SOURCES mtu_test.cpp          LIBS ak::oar_net)
ak_add_test(wireguard_test    SOURCES wireguard_test.cpp    LIBS ak::oar_net)
ak_add_test(tunnel_test       SOURCES tunnel_test.cpp       LIBS ak::oar_net)
ak_add_test(tunnel_peers_test SOURCES tunnel_peers_test.cpp LIBS ak::oar_net)
ak_add_test(metadata_store_test SOURCES metadata_store_test.cpp LIBS ak::oar_net ak::hull)
ak_add_test(metadata_http_test SOURCES metadata_http_test.cpp LIBS ak::oar_net)
ak_add_test(metadata_nat_test SOURCES metadata_nat_test.cpp LIBS ak::oar_net)
ak_add_test(xts_cipher_test   SOURCES xts_cipher_test.cpp   LIBS ak::oar_blk)
ak_add_test(key_slot_test     SOURCES key_slot_test.cpp     LIBS ak::oar_blk)
ak_add_test(request_parser_test     SOURCES request_parser_test.cpp     LIBS ak::oar_blk)
ak_add_test(virtio_blk_function_test SOURCES virtio_blk_function_test.cpp LIBS ak::oar_blk)
ak_add_test(virtio_blk_async_test    SOURCES virtio_blk_async_test.cpp    LIBS ak::oar_blk)
ak_add_test(file_backend_test        SOURCES file_backend_test.cpp        LIBS ak::oar_blk)
ak_add_test(net_role_test            SOURCES net_role_test.cpp            LIBS ak::oar_net_role ak::hull)
ak_add_test(blk_role_test            SOURCES blk_role_test.cpp            LIBS ak::oar_blk_role ak::hold_server)
ak_add_test(image_manifest_test      SOURCES image_manifest_test.cpp      LIBS ak::objstore)
ak_add_test(image_volume_test        SOURCES image_volume_test.cpp        LIBS ak::oar_blk_image)
ak_add_test(image_pack_test          SOURCES image_pack_test.cpp          LIBS ak::oar_blk_image)
ak_add_test(sigv4_test               SOURCES sigv4_test.cpp               LIBS ak::objstore_s3)
ak_add_test(http_response_test       SOURCES http_response_test.cpp       LIBS ak::objstore_s3)
ak_add_test(s3_object_store_test     SOURCES s3_object_store_test.cpp     LIBS ak::objstore_s3 ak::oar_blk_image)
ak_add_test(image_store_config_test  SOURCES image_store_config_test.cpp  LIBS ak::objstore_s3)
ak_add_test(mailbox_test      SOURCES mailbox_test.cpp      LIBS ak::helm)
ak_add_test(mailbox_device_test SOURCES mailbox_device_test.cpp LIBS ak::helm)
ak_add_test(device_pool_test  SOURCES device_pool_test.cpp  LIBS ak::helm)
ak_add_test(audit_log_test    SOURCES audit_log_test.cpp    LIBS ak::helm)
ak_add_test(command_router_test SOURCES command_router_test.cpp LIBS ak::helm)
ak_add_test(power_sequencer_test SOURCES power_sequencer_test.cpp LIBS ak::helm)
ak_add_test(helm_daemon_test SOURCES helm_daemon_test.cpp LIBS ak::helm ak::harbor_controller ak::hull OpenSSL::Crypto)
ak_add_test(helm_config_test SOURCES helm_config_test.cpp LIBS ak::helm)
ak_add_test(mailbox_bodies_test SOURCES mailbox_bodies_test.cpp LIBS ak::helm)
ak_add_test(mctp_test         SOURCES mctp_test.cpp         LIBS ak::helm)
ak_add_test(signature_verifier_test SOURCES signature_verifier_test.cpp LIBS ak::hull)
ak_add_test(command_auth_test       SOURCES command_auth_test.cpp       LIBS ak::hull)
ak_add_test(mailbox_client_test     SOURCES mailbox_client_test.cpp     LIBS ak::hull)
ak_add_test(vfio_mailbox_test       SOURCES vfio_mailbox_test.cpp       LIBS ak::hull)
ak_add_test(cpu_topology_test       SOURCES cpu_topology_test.cpp       LIBS ak::hull)
ak_add_test(resource_allocator_test SOURCES resource_allocator_test.cpp LIBS ak::hull)

# The jail (hull task 7): jail_test starts jail_probe inside real jails.
# Without user namespaces or Landlock the spawn cases log "skipped" and
# pass; CI also runs the binary under sudo for the privileged path and the
# cgroup placement case.
add_executable(jail_probe jail_probe.cpp)
target_link_libraries(jail_probe PRIVATE ak::warnings)
# The probe runs under Landlock with no /proc access, where the ASan
# runtime cannot start (it reads /proc/self/maps), so it is never
# sanitized or coverage-instrumented; what it checks is the jail, not itself.
if(AK_SANITIZE OR AK_FUZZ)
  target_compile_options(jail_probe PRIVATE -fno-sanitize=all)
  target_link_options(jail_probe PRIVATE -fno-sanitize=all)
endif()
ak_add_test(jail_test SOURCES jail_test.cpp LIBS ak::hull
            ARGS -- $<TARGET_FILE:jail_probe>)

# The VM supervisor (hull task 8): the VMM API client and its parsers, the
# supervisor with fakes, and the real launcher starting fake_vmm (a stand-in
# for cloud-hypervisor) inside real jails.
ak_add_test(vmm_api_test      SOURCES vmm_api_test.cpp      LIBS ak::hull)
ak_add_test(vm_supervisor_test SOURCES vm_supervisor_test.cpp LIBS ak::hull)
# hull-init and the agent's setup (task 3): host_setup_test runs hull-init
# over a fake sysfs tree; capabilities_test drops in a forked child.
ak_add_test(host_setup_test   SOURCES host_setup_test.cpp   LIBS ak::hull)
target_compile_definitions(host_setup_test PRIVATE HULL_INIT_PATH="$<TARGET_FILE:hull-init>")
add_dependencies(host_setup_test hull-init)
ak_add_test(capabilities_test SOURCES capabilities_test.cpp LIBS ak::hull)
add_executable(fake_vmm fake_vmm.cpp)
target_link_libraries(fake_vmm PRIVATE ak::warnings)
if(AK_SANITIZE OR AK_FUZZ)
  # Like jail_probe: it runs under Landlock without /proc/self/maps.
  target_compile_options(fake_vmm PRIVATE -fno-sanitize=all)
  target_link_options(fake_vmm PRIVATE -fno-sanitize=all)
endif()
ak_add_test(vmm_launcher_test SOURCES vmm_launcher_test.cpp LIBS ak::hull
            ARGS -- $<TARGET_FILE:fake_vmm>)
ak_add_test(proto_envelope_test   SOURCES proto_envelope_test.cpp   LIBS ak::proto ak::helm)
ak_add_test(proto_map_update_test SOURCES proto_map_update_test.cpp LIBS ak::proto)
ak_add_test(proto_ec2_id_test     SOURCES proto_ec2_id_test.cpp     LIBS ak::proto)
ak_add_test(proto_report_test     SOURCES proto_report_test.cpp     LIBS ak::proto ak::helm)
ak_add_test(proto_link_test       SOURCES proto_link_test.cpp       LIBS ak::proto)
ak_add_test(proto_volume_test     SOURCES proto_volume_test.cpp     LIBS ak::proto)
ak_add_test(hold_master_test      SOURCES hold_master_test.cpp      LIBS ak::hold_master)
ak_add_test(hold_store_test       SOURCES hold_store_test.cpp       LIBS ak::hold_store)
# The crash suite replays every step of several workloads: under the
# sanitizers it takes about a minute even before the simulation entries
# share the runner's four CPUs with it.
set_tests_properties(hold_store_test PROPERTIES TIMEOUT 180)
ak_add_test(hold_server_test      SOURCES hold_server_test.cpp      LIBS ak::hold_server)
ak_add_test(hold_replication_test SOURCES hold_replication_test.cpp LIBS ak::hold_server)
ak_add_test(hold_role_test        SOURCES hold_role_test.cpp        LIBS ak::hold_role)
ak_add_test(khold_role_test       SOURCES khold_role_test.cpp       LIBS ak::khold_role)
ak_add_test(khold_launch_test     SOURCES khold_launch_test.cpp     LIBS ak::khold_role)
# The simulation (block-volume-service task 9): a short seed sweep in every
# run, and a long one under `ctest -C Nightly -L nightly`.
ak_add_test(hold_sim_test SOURCES hold_sim_test.cpp
            LIBS ak::hold_server ak::hold_master ak::oar_blk_volume
            ARGS --run_test=!long_sweep,movement,multi_attach)
# Under the sanitizers on a 4-CPU runner, sharing it with the other
# entries, the base sweep takes about 90 s and the movement suite about
# 60 s; each case keeps its own 30 s limit against a hang, so these are
# only ceilings for a slow runner.
set_tests_properties(hold_sim_test PROPERTIES TIMEOUT 180)
# Tasks 17-18's suites as entries of their own.
foreach(_suite movement multi_attach)
  add_test(NAME hold_sim_${_suite}
           COMMAND hold_sim_test --log_level=test_suite --run_test=${_suite})
  set_tests_properties(hold_sim_${_suite} PROPERTIES TIMEOUT 180)
endforeach()
add_test(NAME hold_sim_nightly COMMAND hold_sim_test --run_test=long_sweep CONFIGURATIONS Nightly)
set_tests_properties(hold_sim_nightly PROPERTIES LABELS nightly TIMEOUT 7200)
ak_add_test(hold_node_test        SOURCES hold_node_test.cpp        LIBS ak::hold_server OpenSSL::Crypto)
ak_add_test(initiator_test        SOURCES initiator_test.cpp        LIBS ak::oar_blk_volume ak::hold_server)
ak_add_test(khold_initiator_test  SOURCES khold_initiator_test.cpp  LIBS ak::oar_blk_volume)
ak_add_test(network_volume_test   SOURCES network_volume_test.cpp   LIBS ak::oar_blk_volume ak::hold_role OpenSSL::Crypto)
ak_add_test(volume_copier_test    SOURCES volume_copier_test.cpp    LIBS ak::oar_blk)
ak_add_test(hydrating_backend_test SOURCES hydrating_backend_test.cpp LIBS ak::oar_blk_image ak::oar_blk_volume ak::hold_server)
ak_add_test(khold_volume_test     SOURCES khold_volume_test.cpp     LIBS ak::oar_blk_volume OpenSSL::Crypto)
ak_add_test(role_identity_test    SOURCES role_identity_test.cpp    LIBS ak::tls OpenSSL::Crypto)
ak_add_test(proto_hold_wire_test  SOURCES proto_hold_wire_test.cpp  LIBS ak::proto)
ak_add_test(proto_hold_wire_v2_test SOURCES proto_hold_wire_v2_test.cpp LIBS ak::proto)
ak_add_test(proto_volume_layout_test SOURCES proto_volume_layout_test.cpp LIBS ak::proto)
ak_add_test(crc32c_test           SOURCES crc32c_test.cpp           LIBS ak::common)
ak_add_test(proto_group_policy_test SOURCES proto_group_policy_test.cpp LIBS ak::proto ak::helm ak::hull)
ak_add_test(proto_vpc_config_test SOURCES proto_vpc_config_test.cpp LIBS ak::proto ak::hull)
ak_add_test(proto_group_members_test SOURCES proto_group_members_test.cpp LIBS ak::proto ak::hull)
ak_add_test(proto_instance_metadata_test SOURCES proto_instance_metadata_test.cpp LIBS ak::proto ak::hull)
ak_add_test(group_usage_test SOURCES group_usage_test.cpp LIBS ak::helm)
ak_add_test(proto_tunnel_peers_test SOURCES proto_tunnel_peers_test.cpp LIBS ak::proto)
ak_add_test(proto_cold_start_test SOURCES proto_cold_start_test.cpp LIBS ak::proto ak::helm ak::hull)
ak_add_test(proto_vectors_test    SOURCES proto_vectors_test.cpp    LIBS ak::proto ak::hull)
ak_add_test(controller_session_test SOURCES controller_session_test.cpp LIBS ak::helm)
ak_add_test(controller_link_test    SOURCES controller_link_test.cpp    LIBS ak::helm OpenSSL::Crypto)
ak_add_test(harbor_controller_test SOURCES harbor_controller_test.cpp LIBS ak::harbor_controller ak::hull OpenSSL::Crypto)
ak_add_test(key_store_test     SOURCES key_store_test.cpp     LIBS ak::helm)
ak_add_test(hpke_test          SOURCES hpke_test.cpp          LIBS ak::helm)
ak_add_test(virtqueue_test    SOURCES virtqueue_test.cpp    LIBS ak::oar_virtio)
ak_add_test(virtio_pci_test   SOURCES virtio_pci_test.cpp   LIBS ak::oar_virtio)
ak_add_test(oar_protocol_test SOURCES oar_protocol_test.cpp LIBS ak::helm ak::proto)
ak_add_test(oar_link_test     SOURCES oar_link_test.cpp     LIBS ak::helm)
ak_add_test(tunnel_keys_test  SOURCES tunnel_keys_test.cpp  LIBS ak::helm ak::oar_net ak::hull OpenSSL::Crypto)
ak_add_test(tunnel_keyring_test SOURCES tunnel_keyring_test.cpp LIBS ak::helm OpenSSL::Crypto)
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

# Kernel WireGuard interop (oar-net task 10): needs root, so it skips in an
# ordinary ctest run; CI runs tests/wireguard_interop.sh under sudo.
add_executable(wireguard_interop_peer wireguard_interop_peer.cpp)
target_link_libraries(wireguard_interop_peer PRIVATE ak::oar_net ak::warnings)
add_test(NAME wireguard_interop
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/wireguard_interop.sh $<TARGET_FILE:wireguard_interop_peer>)
set_tests_properties(wireguard_interop PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)

# vpc-subnets-routing task 8: frames per second through the VSwitch,
# switched versus routed, at the VpcConfig limits. ctest runs a few
# thousand frames per case for its delivery checks; the baseline in the
# spec comes from a Release build with the default count.
add_executable(vswitch_bench vswitch_bench.cpp)
target_link_libraries(vswitch_bench PRIVATE ak::oar_net ak::warnings)
add_test(NAME vswitch_bench COMMAND vswitch_bench --frames 20000)
set_tests_properties(vswitch_bench PROPERTIES TIMEOUT 120)

# vpc-subnets-routing task 7: two network roles with TAP-backed NICs in
# network namespaces, real guest stacks routed between subnets. Root
# only, so an ordinary ctest run skips it; CI runs tests/vpc_netns.sh
# under sudo.
add_executable(vpc_netns_role vpc_netns_role.cpp)
target_link_libraries(vpc_netns_role PRIVATE ak::oar_net_role ak::hull ak::warnings)
add_test(NAME vpc_netns
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/vpc_netns.sh $<TARGET_FILE:vpc_netns_role>)
set_tests_properties(vpc_netns PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)

# The guest's cooperative-detach helper, against a fake sysfs and procfs
# (block-volume-service task 13, Requirement 3.4).
add_test(NAME guest_eject_test
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/guest_eject_test.sh
                 ${PROJECT_SOURCE_DIR}/guest/ak-guest-eject)
set_tests_properties(guest_eject_test PROPERTIES TIMEOUT 60)

# harbor's sample ak-helm configuration must keep parsing.
add_test(NAME ak_helm_check
         COMMAND $<TARGET_FILE:ak-helm> --check ${PROJECT_SOURCE_DIR}/harbor/helm.conf.example)
set_tests_properties(ak_helm_check PROPERTIES TIMEOUT 30)

# helm's mailbox function over vfio-user (helm task 8): the probe serves it
# and harbor/mailbox_smoke.py drives it as a vfio-user client, no root or
# QEMU needed. Only where libvfio-user is built (CI builds without it).
if(AK_HAS_LIBVFIO_USER)
  find_package(Python3 COMPONENTS Interpreter)
  add_executable(mailbox_vfu_probe mailbox_vfu_probe.cpp)
  target_link_libraries(mailbox_vfu_probe PRIVATE ak::helm_vfu ak::warnings)
  if(Python3_Interpreter_FOUND)
    add_test(NAME mailbox_vfu_smoke
      COMMAND sh -c "sock=$(mktemp -u); \"$0\" \"$sock\" & probe=$!; if \"$1\" \"$2\" \"$sock\"; then wait $probe; else kill $probe; exit 1; fi"
              $<TARGET_FILE:mailbox_vfu_probe> ${Python3_EXECUTABLE}
              ${PROJECT_SOURCE_DIR}/harbor/mailbox_smoke.py)
    set_tests_properties(mailbox_vfu_smoke PROPERTIES TIMEOUT 60)
  endif()
endif()
