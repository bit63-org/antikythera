#!/usr/bin/env bash
# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0
#
# Runs as root inside L1. Builds the harbor phase 2 L2 guest from what L1
# already has, so nothing more is downloaded:
#
#   vmlinux          L1's own kernel, decompressed from /boot/vmlinuz:
#                    Cloud Hypervisor boots an uncompressed ELF through its
#                    PVH entry point, not a bzImage
#   initramfs.cpio.gz  static busybox, ak-guest-testdev, the vfio modules
#                    (decompressed, with their load order) and l2-init.sh
#                    as /init
#
# Usage: l2-image.sh OUTDIR GUEST_TESTDEV INIT

set -euo pipefail

out="${1:?usage: l2-image.sh OUTDIR GUEST_TESTDEV INIT}"
guest_testdev="${2:?usage: l2-image.sh OUTDIR GUEST_TESTDEV INIT}"
init="${3:?usage: l2-image.sh OUTDIR GUEST_TESTDEV INIT}"
kver="$(uname -r)"
busybox="/bin/busybox"

die() {
    printf 'l2-image: error: %s\n' "$*" >&2
    exit 1
}

[[ -x "${busybox}" ]] || die "${busybox} missing (apt install busybox-static)"
# ldd fails on a static binary; the initramfs has no libraries to offer.
if ldd "${busybox}" >/dev/null 2>&1; then
    die "${busybox} is dynamically linked (apt install busybox-static)"
fi
mkdir -p "${out}"

# --- vmlinux ------------------------------------------------------------
# The same search as the kernel's scripts/extract-vmlinux: find each
# compressor's magic in the bzImage, decompress from there, keep the first
# result that is an ELF file.
extract_vmlinux() {
    python3 - "$1" "$2" <<'PY'
import subprocess
import sys

image, dest = sys.argv[1], sys.argv[2]
data = open(image, "rb").read()
candidates = [
    (b"\x28\xb5\x2f\xfd", ["zstd", "-q", "-d", "-c"]),
    (b"\x1f\x8b\x08", ["gzip", "-q", "-d", "-c"]),
    (b"\xfd7zXZ\x00", ["xz", "-q", "-d", "-c"]),
    (b"\x02\x21\x4c\x18", ["lz4", "-q", "-d", "-c"]),
]
for magic, tool in candidates:
    pos = data.find(magic)
    while pos >= 0:
        try:
            out = subprocess.run(tool, input=data[pos:], capture_output=True).stdout
        except FileNotFoundError:
            break
        # Trailing garbage after the stream makes the tool fail, but the
        # decompressed kernel comes out first.
        if out.startswith(b"\x7fELF"):
            open(dest, "wb").write(out)
            sys.exit(0)
        pos = data.find(magic, pos + 1)
sys.exit(1)
PY
}
extract_vmlinux "/boot/vmlinuz-${kver}" "${out}/vmlinux" ||
    die "could not extract an ELF vmlinux from /boot/vmlinuz-${kver}"

# --- initramfs ------------------------------------------------------------
root="$(mktemp -d)"
trap 'rm -rf "${root}"' EXIT
mkdir -p "${root}"/{bin,dev,proc,sys,lib/modules}
cp "${busybox}" "${root}/bin/busybox"
install -m 0755 "${guest_testdev}" "${root}/bin/ak-guest-testdev"
install -m 0755 "${init}" "${root}/init"

# modprobe prints the insmod lines in dependency order; modules built into
# this kernel print as "builtin" and need nothing.
: >"${root}/modules.order"
while read -r verb path params; do
    [[ "${verb}" == "insmod" ]] || continue
    name="$(basename "${path}")"; name="${name%.zst}"; name="${name%.xz}"; name="${name%.gz}"
    # modprobe repeats a module that several others depend on.
    grep -q "^${name} " "${root}/modules.order" && continue
    case "${path}" in
        *.zst) zstd -q -d -c "${path}" >"${root}/lib/modules/${name}" ;;
        *.xz) xz -d -c "${path}" >"${root}/lib/modules/${name}" ;;
        *.gz) gzip -d -c "${path}" >"${root}/lib/modules/${name}" ;;
        *) cp "${path}" "${root}/lib/modules/${name}" ;;
    esac
    # vfio itself takes the no-IOMMU switch at load time.
    [[ "${name}" == "vfio.ko" ]] && params="${params} enable_unsafe_noiommu_mode=1"
    echo "${name} ${params}" >>"${root}/modules.order"
done < <(modprobe --show-depends vfio-pci)

(cd "${root}" && find . -print0 | cpio --null -o -H newc --quiet) | gzip -1 >"${out}/initramfs.cpio.gz"
echo "l2-image: ${out}/vmlinux and ${out}/initramfs.cpio.gz (kernel ${kver}, modules: $(cut -d' ' -f1 "${root}/modules.order" | tr '\n' ' '))"
