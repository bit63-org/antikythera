# Guest helpers

Optional files for a Linux guest running on antikythera.

## ak-guest-eject

Releases an antikythera disk when the host asks to detach it, as long as
nothing in the guest is using it (block-volume-service Requirement 3.4).

A detach of a volume under the controller's default `wait` policy does
not pull the disk out from under the guest. The host sets a flag in a
vendor-specific virtio PCI capability and waits. The guest releases the
disk through its normal removal path (`echo 1 >
/sys/bus/pci/devices/<bdf>/remove`), or the detach is reported `busy` and
the disk keeps working.

`ak-guest-eject` does that release for you, but only when the disk and
its partitions are not mounted, not held by LVM, MD or dm-crypt, not
active swap and not open by any process. Otherwise it logs the reason
once and leaves the disk alone: unmount it and the next poll releases it.

Install:

```sh
install -m 0755 ak-guest-eject /usr/local/sbin/
install -m 0644 ak-guest-eject.service /etc/systemd/system/
install -m 0644 90-ak-guest-eject.rules /etc/udev/rules.d/
systemctl daemon-reload && udevadm control --reload
systemctl enable --now ak-guest-eject.service   # optional: also from boot
```

`ak-guest-eject --dry-run` logs what it would release without releasing
anything. Without the helper, release a disk by hand with the sysfs
`remove` above once it is unmounted.
