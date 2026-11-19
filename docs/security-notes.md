# Security notes (security-deps)

Follow-up to the security vetting of this fork (upstream master @669cb8ac6).
This file records what was changed, what remains, and the facts that need
maintainer attention. It is fork-only and upstreamable in pieces.

## Dependency state after the cleanup

`cargo audit` on this lock: 1 vulnerability, 35 hygiene warnings (was 9
vulnerabilities). Fixes applied on `security-deps` (or referenced forks):

| advisory / crate | resolution |
|---|---|
| users 0.2.2 (RUSTSEC-2020-0017) | replaced by uzers via fork (commit 07ff4d37a) |
| openssl/rustls/quinn/zstd/… | lock bumps (commit 846a98e6b) |
| time 0.1.45 (RUSTSEC-2020-0071, via fruitbasket) | fruitbasket dropped; the two Apple Event constants (`kInternetEventClass`/`kAEGetURL`, both `'GURL'` = `0x4755524c`) inlined in `src/platform/delegate.rs` |
| quick-xml 0.30/0.31/0.37.5 (RUSTSEC-2026-0194/0195) | three-parent fix: plist 1.6.1→1.10.4 (`cargo update` only, os-version allows `^1`), os-version 0.2.0→0.2.1, wayland-scanner 0.31.7→0.31.11 (`^0.41`), tauri-winrt-notification moved to a cfg(windows)-gated fork |
| libgit2-sys 0.14.2 (RUSTSEC-2024-0013, via keepawake→shadow-rs→git2) | fork `jer-gremlin/keepawake-rs` @51c5b10 drops the unused shadow-rs build dependency (build.rs only called `shadow_rs::new()`); shadow-rs 0.21 line is frozen at git2 ^0.16 and newer shadow-rs is semver-incompatible for keepawake |
| crypto-bigint 0.5.5 (RUSTSEC-2026-0387) | NOT fixed — see below |

Note on tauri-winrt-notification: every release after 0.1 depends on
windows ≥ 0.58, whose windows-future bindings reference
`windows_core::imp` symbols that exist only under `cfg(windows)` and fail
to compile on non-Windows hosts. Fork `jer-gremlin/tauri-winrt-notification`
@af54e69 gates the crate and its dependencies to Windows; identical source
on Windows. Upstreamable as a cross-compile fix.

## Remaining advisory: crypto-bigint (RUSTSEC-2026-0387)

Chain: hbb_common → webrtc (rustdesk-org fork, rev 49c89bd8) → webrtc-dtls
0.12 → p256/p384 0.13 → ecdsa → elliptic-curve → crypto-bigint 0.5.5.
Fix requires crypto-bigint ≥ 0.7.6, reachable only through the RustCrypto
ECDSA line majors. p256 0.14.0 has been published; webrtc-dtls has no
release consuming it yet (0.12.0 is latest). Exposure is the DTLS handshake
in WebRTC mode; practical risk in this protocol is low. Blocked until
rustdesk-org/webrtc (or webrtc-dtls) ships the bump; draft upstream issue
prepared. Nothing in this repo can resolve it semver-wise.

## Sodiumoxide (RUSTSEC-2021-0137, unmaintained) — proposed replacement map

Deprecated since 2021; ~24 files between src/ and libs/hbb_common. Survey:

- `base64::{encode, decode}` (~10 sites) → `base64` crate; `Variant::Original`
  == standard alphabet with padding, wire-identical.
- `crypto::secretbox` (~8 sites, incl. hbb_common stream framing) →
  `crypto_secretbox` (Xsalsa20-Poly1305). Wire caveat: libsodium emits
  `[mac(16) || ciphertext]`, RustCrypto convention appends the tag; call
  sites must arrange `[tag, ct]` to stay wire-compatible.
- `crypto::hash::sha256` (4 sites) → `sha2` crate, byte-identical.
- `crypto::sign` (2 sites) → `ed25519-dalek`. Wire caveat: libsodium's
  `sign::sign` returns `sig || message`; dalek signs detached, so the
  combined form must be reproduced at those call sites.
- `crypto::box_` (1 site) → `crypto_box` (HSalsa20 key derivation matches
  libsodium's `crypto_box_beforenm`); same mac-position caveat.
- `utils::memcmp` (1 site, trusted_devices) → `subtle::ConstantTimeEq`.
- `sodiumoxide::init()` (5 sites) → dropped; RustCrypto needs no init.

Needs maintainer sign-off (wire-format risk across peer protocols) and a
release-capable test pass; not done unilaterally in this fork.

## Code findings kept as accepted limits (need maintainer decisions)

- `custom_server.rs:41`: unsigned `--config`/`--filename` custom server
  bundles are accepted by design; unsigned distribution is the user's choice,
  but enabling upstream code-signing guidance would close it.
- `port_forward.rs:32`: `cmdkey /pass:<pw>` places the temporary account
  password on a command line, visible in process listings and WMI for the
  invocation lifetime. Candidate fix: short-lived scheduled task or
  PowerShell CredentialManager invocation writing via stdin-equivalent.
- Numeric 6-digit OTP (10^6) is bounded by the existing per-IP rate limits
  (6/min, 30 total) and login-failure rotation; entropy increase is a
  protocol change.
- At-rest secrets (`hbb_common::config::password_security::symmetric_crypt`)
  are keyed by the machine uid with a legacy zero-nonce mode. Anyone with
  the user's machine uid and file access decrypts stored options. Changing
  the derivation is an outward-compatibility break for existing installs.
- Handshake protocol level: version h1 exposes an offline dictionary of
  password hash prefixes; keyless deployments (no fixed key/server) fall
  back to plaintext exchange paths. Both are protocol-generation issues.

All items above are documentation-only so far; none block the fork's
primary use.
