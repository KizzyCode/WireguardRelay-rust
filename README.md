[![License BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![AppVeyor CI](https://ci.appveyor.com/api/projects/status/github/KizzyCode/WireguardRelay-rust?svg=true)](https://ci.appveyor.com/project/KizzyCode/WireguardRelay-rust)
[![docs.rs](https://docs.rs/wgproxy/badge.svg)](https://docs.rs/wgproxy)
[![crates.io](https://img.shields.io/crates/v/wgproxy.svg)](https://crates.io/crates/wgproxy)
[![Download numbers](https://img.shields.io/crates/d/wgproxy.svg)](https://crates.io/crates/wgproxy)
[![dependency status](https://deps.rs/crate/wgproxy/latest/status.svg)](https://deps.rs/crate/wgproxy)


# `wgproxy`
Welcome to `wgproxy` 🎉

`wgproxy` is a tiny layer-4-proxy to bridge WireGuard®-like traffic via a jump-host. This is e.g. useful to bridge from
IPv4-only networks to IPv6-only servers, or to route the traffic via specific gateways.

It basically works as a stateful NAT: A _valid_ WireGuard handshake message is used to allocate a NAT-mapping, which in
turn is used to forward/bridge packets between the client and the server.


## Example
```sh
# Export the necessary
export WGPROXY_SERVER="my-wireguard-server.invalid:51820"
export WGPROXY_PUBKEYS="<a csv list of the base64 server public keys>"
export WGPROXY_PORTS="51820-52000"
export WGPROXY_TIMEOUT="120"
export WGPROXY_LOGLEVEL="2"

# Start the proxy
wgproxy
```

## Microsoft  Windows Support
Microsoft Windows is **not** an officially supported target, and is not tested. While the application should compile,
networking under Windows works differently, and the integration test pipelines **did not pass**. Do not expect the
application to work reliably on Windows.
