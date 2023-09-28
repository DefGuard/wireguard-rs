 <p align="center">
    <img src="docs/header.png" alt="defguard">
 </p>

**wireguard-rs** is a Rust library providing a unified high-level API for managing WireGuard interfaces using native OS kernel and userspace WireGuard protocol implementations.
It can be used to create your own [WireGuard:tm:](https://www.wireguard.com/) VPN servers or clients for secure and private networking.

It was developed as part of [defguard](https://github.com/defguard/defguard) security platform and used in the [gateway/server](https://github.com/defguard/gateway) as well as [desktop client](https://github.com/defguard/client).

## Supported platforms

* Native OS Kernel
  - Linux
  - FreeBSD (and pfSense/OPNSense)
  - Windows (in development)
* Userspace using [wireguard-go](https://github.com/WireGuard/wireguard-go)
  - Linux
  - macOS
  - FreeBSD

## Examples

* Client: https://github.com/DefGuard/wireguard-rs/blob/main/examples/client.rs
* Server: https://github.com/DefGuard/wireguard-rs/blob/main/examples/server.rs

## Documentation

See the [documentation](https://defguard.gitbook.io) for more information.

## Community and Support

Find us on Matrix: [#defguard:teonite.com](https://matrix.to/#/#defguard:teonite.com)

## Contribution

Please review the [Contributing guide](https://defguard.gitbook.io/defguard/for-developers/contributing) for information on how to get started contributing to the project. You might also find our [environment setup guide](https://defguard.gitbook.io/defguard/for-developers/dev-env-setup) handy.

# Legal
WireGuard is [registered trademarks](https://www.wireguard.com/trademark-policy/) of Jason A. Donenfeld.
