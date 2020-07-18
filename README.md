# Post-Quantum WireGuard for Linux 3.10 - 5.5

This is a fork of the out-of-tree kernel module `wireguard-linux-compat` patched to support Post-Quantum Cryptography.
It embed the reference implementation of the KEM [CRYSTAL-Kyber](https://pq-crystals.org/kyber/), adapted for the Linux kernel, as well as a custom `Noise_Ik` protocol, largely inspired by [this paper](https://cryptojedi.org/crypto/#pqwireguard).

Please find the corresponding `wireguard-tools` fork [here](https://github.com/pete842/wireguard-tools/tree/kyber-integration).

WireGuard was merged into the Linux kernel for 5.6. This repository contains a backport of WireGuard for kernels 3.10 to 5.5, as an out of tree module.

**More information may be found at [WireGuard.com](https://www.wireguard.com/).**

## License

This project is released under the [GPLv2](COPYING).
