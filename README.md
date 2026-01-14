 <p align="center">
    <img src="docs/header.png" alt="defguard">
 </p>

**defguard_wireguard_rs** is a multi-platform Rust library providing a unified high-level API for managing WireGuard interfaces using native OS kernel and userspace WireGuard protocol implementations.
It can be used to create your own [WireGuard:tm:](https://www.wireguard.com/) VPN servers or clients for secure and private networking.

It was developed as part of [defguard](https://github.com/defguard/defguard) security platform and used in the [gateway/server](https://github.com/defguard/gateway) as well as [desktop client](https://github.com/defguard/client).

## Supported platforms

- Native OS Kernel: Linux, FreeBSD (and pfSense/OPNSense), NetBSD, Windows
- Userspace: Linux, macOS, FreeBSD, NetBSD

### Unique features

- **Peer routing** - see [WGApi](https://docs.rs/defguard_wireguard_rs/latest/defguard_wireguard_rs/struct.WGApi.html) docs.
- Configuring **DNS resolver** - see [WGApi](https://docs.rs/defguard_wireguard_rs/latest/defguard_wireguard_rs/struct.WGApi.html) docs.
  - On FreeBSD network interfaces are managed using **ioctl**.
  - On Linux, handle network routing using **netlink**.
  - **fwmark** handling

### Windows support

Please note that [WireGuard-NT](https://git.zx2c4.com/wireguard-nt/about/) [dll file](https://download.wireguard.com/wireguard-nt/) has to be placed under `resources-windows/binaries/wireguard.dll` path relative to your binary.

#### Windows development

For Windows development you'll need:

1. The `stable-x86_64-pc-windows-gnu` Rust toolchain. Use `rustup` to change the toolchain:

```
rustup install stable-x86_64-pc-windows-gnu
rustup default stable-x86_64-pc-windows-gnu
```

2. Install [MSYS2](https://www.msys2.org/)

3. Then run this in the MSYS2 terminal:

```
pacman -S --needed base-devel mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-nasm
```

4. Finally add msys to your PATH:

```
# cmd
set PATH=C:\msys64\ucrt64\bin;%PATH%
# power-shell
$env:PATH = "C:\msys64\ucrt64\bin;" + $env:PATH
```

More info can be found [here](https://stackoverflow.com/a/79640980).

## Examples

- Client: https://github.com/DefGuard/wireguard-rs/blob/main/examples/client.rs
- Server: https://github.com/DefGuard/wireguard-rs/blob/main/examples/server.rs

## Documentation

See the [documentation](https://defguard.gitbook.io) for more information.

## Community and Support

Reach out to our community via [GitHub Discussions](https://github.com/DefGuard/defguard/discussions/new/choose)

## Contribution

Please review the [Contributing guide](https://defguard.gitbook.io/defguard/for-developers/contributing) for information on how to get started contributing to the project. You might also find our [environment setup guide](https://defguard.gitbook.io/defguard/for-developers/dev-env-setup) handy.

# Legal

WireGuard® is [registered trademarks](https://www.wireguard.com/trademark-policy/) of Jason A. Donenfeld.
