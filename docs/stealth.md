# Stealth transport

`stealth` is a TCP-based transport that hides what it is. It runs the whole TCP
engine — the control channel, the connection pool, port forwarding, sniffer —
unchanged, and wraps every tunnel connection in an encrypted, obfuscated layer
so a censor's deep packet inspection has nothing to match against.

It depends only on the Go standard library; there is no new third-party
dependency, so it builds exactly like the rest of Backhaul.

## When to use it

Use `stealth` when a plain `tcp`/`tcpmux` tunnel is being detected and blocked,
or when `wss` (TLS) is being fingerprinted. Unlike `tcp`, the token and all
tunnel traffic are encrypted; unlike `wss`, there is no TLS ClientHello to
fingerprint. The opening bytes of every connection are indistinguishable from
random and differ on every connection, so there is no per-token signature to
block.

Where DPI is not the problem, `tcp` is slightly faster (no per-record
encryption). On a real link the difference is invisible — the link, not the CPU,
is the bottleneck — and encryption is handled by AES-NI on any server CPU.

## How it works (brief)

- Each connection opens with an ephemeral X25519 key exchange. The shared secret
  is combined with the tunnel **token** through HKDF, so both ends derive the
  same keys only if both hold the token. Ephemeral keys give forward secrecy.
- The responder proves it holds the token with an AES-GCM tag the initiator
  verifies before the handshake completes, so a wrong token fails fast with a
  clear log line instead of hanging.
- The stream is an AES-256-GCM record layer. Records are padded by a random
  amount (inside the encryption) so their sizes leak nothing.
- An obfuscation layer keyed by the token masks the two-byte length prefixes and
  the handshake bytes with AES-CTR keystreams and pads the handshake, so the
  ephemeral key, the length framing and the message sizes are all uniform and
  carry no fixed fingerprint.

A peer without the token cannot derive the keys: its records do not
authenticate and the connection is dropped with nothing sent back, so a probe
finds a dead port.

## Configuration

`stealth` takes exactly the same keys as the `tcp` transport. Set
`transport = "stealth"` on **both** ends, with the **same token**. Both ends
must run a build that supports `stealth`.

Iran server (example):

```toml
[server]
bind_addr = "0.0.0.0:3080"
transport = "stealth"
token = "a-long-random-shared-secret"
ports = [
    "443=127.0.0.1:8443",
]
```

Kharej client (example):

```toml
[client]
remote_addr = "iran-server-ip:3080"
transport = "stealth"
token = "a-long-random-shared-secret"
connection_pool = 8
```

Notes:

- The token is the pre-shared key. Use a long, random value — not the default.
- All of the `tcp` transport's tuning keys apply unchanged: `nodelay`,
  `connection_pool`, `aggressive_pool`, `keepalive_period`, `mss`, `so_rcvbuf`,
  `so_sndbuf`, `sniffer`, `web_port`, `proxy_protocol`, port ranges, `accept_udp`.
- If a connection never establishes, check that **both** ends use
  `transport = "stealth"` with the **same token** and a build that supports it —
  a mismatch is logged as a rejected handshake.
