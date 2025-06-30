 <p align="center">
    <img src="docs/header.png" alt="defguard">
 </p>

**defguard_wireguard_rs** is a multi-platform Rust library providing a unified high-level API for managing WireGuard interfaces using native OS kernel and userspace WireGuard protocol implementations.
It can be used to create your own [WireGuard:tm:](https://www.wireguard.com/) VPN servers or clients for secure and private networking.

It was developed as part of [defguard](https://github.com/defguard/defguard) security platform and used in the [gateway/server](https://github.com/defguard/gateway) as well as [desktop client](https://github.com/defguard/client).

## Supported platforms

* Native OS Kernel: Linux, FreeBSD (and pfSense/OPNSense), NetBSD, Windows
* Userspace: Linux, macOS, FreeBSD, NetBSD

### Unique features

* **Peer routing** - see [WGApi](https://docs.rs/defguard_wireguard_rs/latest/defguard_wireguard_rs/struct.WGApi.html) docs.
* Configuring **DNS resolver** - see [WGApi](https://docs.rs/defguard_wireguard_rs/latest/defguard_wireguard_rs/struct.WGApi.html) docs.
  * On FreeBSD network interfaces are managed using **ioctl**.
  * On Linux, handle network routing using **netlink**.
  * **fwmark** handling

### Windows support
Please note that [WireGuard](https://www.wireguard.com/install/) needs to be installed on Windows with commands `wg` and `wireguard` available to be called from the command line.

### Note on `wireguard-go`
If you intend to use the userspace WireGuard implementation you should note that currently the library assumes
that the `wireguard-go` binary will be available at runtime. There are some sanity checks when instantiating the API,
but installing it is outside the scope of this project.

## Examples

* Client: https://github.com/DefGuard/wireguard-rs/blob/main/examples/client.rs
* Server: https://github.com/DefGuard/wireguard-rs/blob/main/examples/server.rs

## Documentation

See the [documentation](https://defguard.gitbook.io) for more information.

## Community and Support

Find us on Matrix: [#defguard:teonite.com](https://matrix.to/#/#defguard:teonite.com)

## Contribution

Please review the [Contributing guide](https://defguard.gitbook.io/defguard/for-developers/contributing) for information on how to get started contributing to the project. You might also find our [environment setup guide](https://defguard.gitbook.io/defguard/for-developers/dev-env-setup) handy.

# Built and sponsored by

<p align="center">
      <a href="https://teonite.com/services/rust/" target="_blank"><img src="https://drive.google.com/uc?export=view&id=1z0fxSsZztoaeVWxHw2MbPbuOHMe3OsqN" alt="build by teonite" /></a>
</p>

# Legal
WireGuard® is [registered trademarks](https://www.wireguard.com/trademark-policy/) of Jason A. Donenfeld.
