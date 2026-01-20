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
# Export the necessary environment variables
export WGPROXY_SERVER="my-wireguard-server.invalid:51820"
export WGPROXY_PUBKEY="<the base64 server public key>"

# Configure optional environment variables
export WGPROXY_LISTEN="[::]:51820"
export WGPROXY_TIMEOUT="60"
export WGPROXY_LOGLEVEL="2"

# Start the proxy
wgproxy
```


## Security Model
`wgproxy` is an simple NAT, meaning that it does not decrypt the traffic or performs deep packet inspection beyond
validating the [handshake first message][1]. If the relay is public, this means that it is potentially susceptible to be
abused by rogue senders.

To prevent rogue packets from creating a new route, two criteria must be fulfilled:
1. Packets must either origin from an already well-known source/route, **or**
2. Packets must be a valid handshake first message for the configured server public key.

If these criteria are not fulfilled, the packet is dropped. If the packet is a valid handshake first message, a new
client-route will be registered to supersede the current route.

**This means that the main security model depends on an attacker not knowing the server public key.**
If an attacker knows the server public key, or has captured a valid handshake packet to replay, it can use that to
create new routes or hijack existing routes, rendering the relay unstable.

As WireGuard traffic is fully encrypted, it is not possible to perform a full traffic validation without decrypting the
traffic on the relay. This security model is a best-effort approach to limit the impact of rogue packets _without_ the
need to escrow private keys and decrypt private traffic in transit.

[1]: https://www.wireguard.com/protocol/#first-message-initiator-to-responder


## Microsoft Windows Support
Microsoft Windows is **not** an officially supported target, and is not tested. While the application should compile and
might work as expected, Windows networking has subtle differences and might cause weird errors.
