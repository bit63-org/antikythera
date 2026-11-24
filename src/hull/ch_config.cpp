// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/ch_config.hpp"

#include "hull/json.hpp"

namespace ak::hull {

auto vm_config_json(const Allocation& allocation, const BootPayload& payload) -> std::string {
    std::string j = "{\"cpus\":{\"boot_vcpus\":";
    j += std::to_string(allocation.vcpus);
    j += ",\"max_vcpus\":";
    j += std::to_string(allocation.vcpus);
    j += ",\"affinity\":[";
    for (std::size_t i = 0; i < allocation.vcpus && i < allocation.cpus.size(); ++i) {
        if (i != 0) {
            j += ',';
        }
        j += "{\"vcpu\":" + std::to_string(i) + ",\"host_cpus\":[" +
             std::to_string(allocation.cpus[i]) + "]}";
    }
    j += "]},\"memory\":{\"size\":";
    j += std::to_string(allocation.memory_bytes());
    j += ",\"hugepages\":true,\"hugepage_size\":";
    j += std::to_string(hugepage_bytes);
    j += ",\"shared\":false},\"payload\":{";
    if (!payload.firmware.empty()) {
        j += "\"firmware\":" + json::quote(payload.firmware.native());
    } else {
        j += "\"kernel\":" + json::quote(payload.kernel.native());
        if (!payload.cmdline.empty()) {
            j += ",\"cmdline\":" + json::quote(payload.cmdline);
        }
        if (!payload.initramfs.empty()) {
            j += ",\"initramfs\":" + json::quote(payload.initramfs.native());
        }
    }
    j += "},\"serial\":{\"mode\":\"Off\"},\"console\":{\"mode\":\"Off\"}}";
    return j;
}

auto ch_argv(const std::filesystem::path& binary, const std::filesystem::path& api_socket)
    -> std::vector<std::string> {
    return {binary.native(), "--api-socket", "path=" + api_socket.native(), "--seccomp", "true"};
}

auto device_id(const helm::mailbox::DeviceRef& ref) -> std::string {
    using helm::mailbox::DeviceType;
    const char* type = "unknown";
    switch (ref.type) {
        case DeviceType::nic_vf:
            type = "nic";
            break;
        case DeviceType::blk_fn:
            type = "blk";
            break;
        case DeviceType::gpu_whole:
            type = "gpu";
            break;
        case DeviceType::gpu_vf:
            type = "gpuvf";
            break;
    }
    return "ak-s" + std::to_string(ref.slot) + "-" + type + "-f" + std::to_string(ref.function);
}

}  // namespace ak::hull
