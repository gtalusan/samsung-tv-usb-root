# Security / responsible use

This repository contains a working kernel exploit for one exact Samsung TV
firmware. Use it only on hardware you own or are explicitly authorized to test.

The `tv` profile is restricted to T-MSMDEUC 1500.9. It is not a generic Samsung
TV exploit. Wrong firmware addresses can hang or reboot the target.

Before testing:

* keep the official firmware recovery image available;
* verify the generated image checksum and destination block device;
* do not enable `--research-kmem` unless raw kernel access is intentional;
* understand that a failed p1 trigger can require a power cycle.

Do not submit device-private certificates, keys, serial numbers, live inventory,
or proprietary firmware/modules to this repository.

For security-sensitive contact, open a minimal GitHub issue requesting a private
channel; do not attach secrets or affected third-party data.
