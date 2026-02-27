# toloo

Rust implementation of the [Toloo Protocol v0.2](../toloo-docs/).
Targets **Relay conformance** — the highest level defined in
[`D-conformance.md`](../toloo-docs/D-conformance.md) §D.6.

```
toloo/      ← This: Rust relay + Tauri desktop app     ← you are here
toloo-docs/ ← Protocol specification (the contract)
toloo-js/   ← Browser JS client (client conformance, fallback)
```

---

## What this is

`toloo` is the reference implementation of the Toloo messaging protocol.
It contains everything needed to run a relay, host rooms, and exchange messages
— as a CLI daemon, as a library, or embedded in a native desktop app via Tauri.

The companion [`toloo-js`](../toloo-js/) is a pure-JS browser client that speaks
the same protocol over WebSocket and HTTP, intended as a fallback when the native
Tauri shell is not available (e.g. running from a web server or a browser extension).
Both implementations are faithful to the same spec and interoperate over the wire.

---

## Project layout

```
toloo-core/           Pure protocol — no IO, no async, no database
  src/
    types.rs          All wire types: Envelope, DatumBody, LocalNode, LocalRoom,
                        EndpointDescriptor, RelayConfig, RelayMetrics, …
    base64url.rs      RFC 4648 §5 encode/decode
    canonical.rs      RFC 8785 canonical JSON (for signing + datum_id)
    crypto.rs         Ed25519 sign/verify, X25519 ECDH, SHA-256, HKDF,
                        ChaCha20-Poly1305 AEAD
    envelope.rs       sign_envelope, verify_chain, maybe_commit, wrap_ack
    ids.rs            eid, datum_id, channel_of
    events.rs         typed event builders + content field validators
    pow.rs            Proof-of-Work compute + verify
    private.rs        private.message E2E encrypt/decrypt (ephemeral ECDH)
    rules.rs          room rule set parsing and evaluation
    vectors.rs        deterministic test vector computation [REF]

toloo-lib/            Stateful runtime — pool, transport, request handlers
  src/
    pool.rs           SQLite event store; membership reconstruction from
                        channel -2 events; channel queries
    transport/
      framing.rs      double-AEAD frame encode/decode for raw TCP streams
      skin.rs         x25519-v0.2 skin handshake (responder side)
      server.rs       TCP + WebSocket accept loop (tokio LocalSet); HTTP/HTTPS
                        endpoints with per-request x25519 ECDH
    requests/
      handlers.rs     All nine endpoint handlers: pool.exchange, room.send,
                        node.meta, room.create, room.update, room.join/leave/ban,
                        blob.fetch; room authority + auto-commit
    discovery.rs      toloo: URI and .toloo file encode/decode
  tests/
    vectors.rs        cross-implementation test vector assertions

toloo-cli/            Binary — headless relay and scripting
  src/
    main.rs           keygen, relay, create-room, import, send, sync, vectors

toloo-app/            Desktop app — Tauri v2
  src/
    index.html        Single-page app shell
    app.js            State, rooms, sync, relay hosting, import/export, context menus
    styles.css        Dark theme, RTL support, mobile-responsive layout
  src-tauri/src/
    lib.rs            All Tauri commands (identity, rooms, relay, discovery)
    main.rs           Tauri entry point

toloo-ffi/            Mobile bindings placeholder — uniffi (Android / iOS)
  src/
    lib.rs            Stub, not yet built out
```

Dependency chain:
```
toloo-core  ←  toloo-lib  ←  toloo-cli
                           ←  toloo-ffi
                           ←  toloo-app/src-tauri
```

---

## Platform support

### Desktop app (Tauri)

| Platform | Minimum version | Notes |
|---|---|---|
| Linux (any distro) | Kernel 4.x, glibc 2.17+ | `.AppImage` bundles its own WebKit — works on Arch, Fedora, NixOS, Ubuntu 16.04+, etc. `.deb` / `.rpm` depend on system WebKit. |
| Windows | Windows 10 (1803+) | Requires WebView2 runtime (pre-installed on Win11; auto-downloaded on Win10). x86_64 and ARM64 builds available. |
| Android | API 24 / Android 7.0+ | Tauri native build, full Rust backend. Per-ABI APKs: `aarch64` (ARM64, all modern phones) and `armv7` (32-bit ARM, older phones). |
| macOS | 10.15 Catalina+ | Build requires macOS runner — not in current CI. |
| iOS | 16+ | Build requires macOS + Xcode — not in current CI. |

### CLI (`toloo-cli`)

The CLI has no UI dependencies — pure Rust + bundled SQLite. It builds and runs
natively on Linux, Windows, and macOS with no system libraries required.

| Platform | Minimum | Binary | Notes |
|---|---|---|---|
| Linux x86_64 | Kernel 2.6.39 (Ubuntu 12.04+) | static musl | Zero system deps — copy and run on any distro |
| Windows x86_64 | Windows 10 | `.exe` (static CRT) | No MSVC redistributable required |
| Windows ARM64 | Windows 10 on ARM | `.exe` (static CRT) | Surface / Snapdragon |
| macOS x86_64 | 10.15 Catalina | binary | No Xcode needed — pure Rust, built on `macos-latest` |
| macOS ARM64 | 11.0 Big Sur | binary | Apple Silicon, no Xcode needed |

### Android legacy APK (WebView wrapper)

A second Android APK is built via plain Gradle, wrapping the web assets in a system
WebView. It has no Rust backend — it connects to external relays over WebSocket/HTTP.

| Minimum | Notes |
|---|---|
| API 21 / Android 5.0 (2014) | Uses system WebView. Features requiring the native backend (hosting a relay, key generation offline) are unavailable. Once `toloo-js` is complete this build will use those assets. |

---

## Building

### Prerequisites

All platforms need [Rust stable](https://rustup.rs) and the Tauri CLI:

```sh
cargo install tauri-cli --version "^2" --locked
```

### Library and CLI (any platform)

```sh
cargo build                    # dev build (all crates)
cargo build --release          # optimized
cargo test                     # all unit + integration tests
```

CLI — platform-specific static builds:

```sh
# Linux: fully static musl binary (runs on any Linux, kernel 2.6.39+)
rustup target add x86_64-unknown-linux-musl
sudo apt-get install -y musl-tools
cargo build -p toloo-cli --release --target x86_64-unknown-linux-musl

# Windows: static CRT — .exe runs on any Win10+ with no redistributables
# (run this from a Windows machine or windows-latest CI runner)
cargo build -p toloo-cli --release --target x86_64-pc-windows-msvc
# ARM64:
rustup target add aarch64-pc-windows-msvc
cargo build -p toloo-cli --release --target aarch64-pc-windows-msvc
# Set RUSTFLAGS for static CRT linkage:
set RUSTFLAGS=-C target-feature=+crt-static
```

### Desktop app — Linux

```sh
# Install system dependencies (Debian/Ubuntu)
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev patchelf rpm

cargo tauri dev   -p toloo-app          # hot-reload dev mode
cargo tauri build -p toloo-app          # produces .deb + .AppImage + .rpm
```

On Arch: `sudo pacman -S webkit2gtk-4.1 gtk3 libappindicator-gtk3 librsvg`

### Desktop app — Windows

```sh
# No extra dependencies — WebView2 is provided by Windows
cargo tauri dev   -p toloo-app
cargo tauri build -p toloo-app          # produces .msi + .exe (NSIS)

# ARM64 cross-compile (from any Windows machine)
rustup target add aarch64-pc-windows-msvc
cargo tauri build -p toloo-app --target aarch64-pc-windows-msvc
```

### Android (Tauri native, API 24+)

```sh
# 1. Install Android SDK + NDK (via Android Studio or command-line tools)
#    Set environment variables:
export ANDROID_HOME=$HOME/Android/Sdk
export NDK_HOME=$ANDROID_HOME/ndk/27.0.12077973

# 2. Install Java 17+
#    Arch: sudo pacman -S jdk17-openjdk
#    Ubuntu: sudo apt-get install -y openjdk-17-jdk

# 3. Add Rust Android targets
rustup target add \
  aarch64-linux-android \
  armv7-linux-androideabi \
  x86_64-linux-android \
  i686-linux-android

# 4. One-time project init (generates toloo-app/src-tauri/gen/android/)
cargo tauri android init -p toloo-app

# 5. Build APKs (one per ABI)
cargo tauri android build -p toloo-app --apk

# 6. Dev mode on a connected device or emulator
cargo tauri android dev -p toloo-app
```

Output: `toloo-app/src-tauri/gen/android/app/build/outputs/apk/`

### CLI

```sh
# Generate a node identity keypair
cargo run -p toloo-cli -- keygen

# Start a relay (default: all interfaces, port 17700)
cargo run -p toloo-cli -- relay

# Create a room and print its toloo:// invite URI
cargo run -p toloo-cli -- create-room --name "My Room"

# Decode any toloo:// URI or .toloo file (human-readable)
cargo run -p toloo-cli -- import <uri-or-file>

# Sign and submit a message to a relay
cargo run -p toloo-cli -- send --room <pub> --relay <ws-url>

# Fetch and display messages; optionally save to .toloo bundle
cargo run -p toloo-cli -- sync --relay <ws-url> --room <pub>

# Print deterministic test vectors for cross-implementation validation
cargo run -p toloo-cli -- vectors
```

### CI / automated releases

Pushing a tag (`v*`) triggers `.github/workflows/release.yml`, which builds all
targets in parallel and creates a GitHub Release:

| Job | Runner | Output |
|---|---|---|
| `build (linux-x86_64)` | ubuntu-latest | `.deb`, `.AppImage`, `.rpm` |
| `build (windows-x86_64)` | windows-latest | `.msi`, `.exe` (app installer) |
| `build (windows-aarch64)` | windows-latest | `.msi`, `.exe` (ARM64 app installer) |
| `build (android-tauri)` | ubuntu-latest | per-ABI `.apk` files (API 24+) |
| `build-cli (cli-linux-x86_64)` | ubuntu-latest | static musl binary |
| `build-cli (cli-windows-x86_64)` | windows-latest | `.exe` (static CRT) |
| `build-cli (cli-windows-aarch64)` | windows-latest | `.exe` ARM64 (static CRT) |
| `build-cli (cli-macos-x86_64)` | macos-latest | macOS binary (x86_64) |
| `build-cli (cli-macos-aarch64)` | macos-latest | macOS binary (Apple Silicon) |
| `build-android-legacy` | ubuntu-latest | WebView `.apk` (API 21+) |

APK signing is opt-in via repository secrets: `KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`,
`KEY_ALIAS`, `KEY_PASSWORD`.

---

## Execution model

### Native (Tauri)

The desktop app runs `toloo-lib` and `toloo-core` in-process via Tauri commands.
State (rooms, messages, identity) lives in memory and is persisted to
`localStorage` on the JS side. The relay runs in a dedicated OS thread with its
own single-threaded Tokio runtime and a `rusqlite`-backed pool.

```
┌─────────────────────────────────────┐
│  toloo-app (WebView)                │
│    app.js   ──invoke()──►  lib.rs   │
│    styles.css               │       │
│                         toloo-lib   │
│                         toloo-core  │
│                         rusqlite    │
│                         Tokio RT    │
└─────────────────────────────────────┘
```

A node can host its own relay in-app, generating a `toloo://` invite link that
others can import to reach it over LAN or the internet.

### Browser (toloo-js)

When running outside Tauri — in a browser, a web app, or a browser extension —
the same protocol is spoken by [`toloo-js`](../toloo-js/). It connects to an
external relay over `wss://` or `https://` (with optional `x25519-v0.2` skin
for app-layer encryption). All crypto is implemented in pure JS using the
WebCrypto API. There is no local relay in this mode; the browser is a pure client.

```
┌────────────────────┐       wss:// or https://      ┌──────────────┐
│  Browser           │ ──────────────────────────►   │  toloo       │
│    toloo.js        │  (x25519-v0.2 skin optional)  │  relay       │
│    WebCrypto       │ ◄──────────────────────────   │  (Rust)      │
└────────────────────┘                               └──────────────┘
```

---

## Transport endpoints

A relay can expose any combination of these endpoints (configured at startup):

| Proto | Skin | Browser | Description |
|-------|------|---------|-------------|
| `tcp` | — | No | Raw TCP, no TLS |
| `tcp` | `x25519-v0.2` | No | Raw TCP + app-layer ECDH encryption |
| `ws`  | — | Yes | WebSocket, no TLS |
| `wss` | — | Yes | WebSocket + TLS |
| `wss` | `x25519-v0.2` | Yes | WebSocket + TLS + app-layer encryption |
| `http` | — | Yes | HTTP long-poll |
| `https` | — | Yes | HTTP + TLS |
| `https` | `x25519-v0.2` | Yes | HTTP + TLS + per-request ECDH |

The `x25519-v0.2` skin provides end-to-end encryption between client and relay,
independent of TLS. It uses ephemeral X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305.

---

## Message lifecycle (3-depth envelope model)

Every room message goes through three envelope depths:

```
depth 1  ─── sender signs ───────────────────────►  relay receives
depth 2  ─── room key holder commits (d.t="commit", d.tc set) ──►  "✓ Sent"
depth 3  ─── sender wraps commit (d.t="ack") ────►  terminal; relays stop forwarding
```

UI states in the app:
- `⋯ Pending…` — trying to reach a relay
- `⏱ Waiting`  — depth-1 delivered, waiting for commit
- `✓ Sent`     — depth-2 commit received (room key holder signed)
- `✗ Failed`   — TTL expired with no commit

The commit can happen directly (relay holds the room key) or via a relay chain
(intermediate relays sign and forward until a key-holder commits).

---

## Spec reference

| File | Covers |
|------|--------|
| [`1-concepts.md`](../toloo-docs/1-concepts.md) | Mental model, terminology |
| [`2-data-model.md`](../toloo-docs/2-data-model.md) | Envelope format, canonical JSON, eid, datum_id |
| [`3-cryptography.md`](../toloo-docs/3-cryptography.md) | All algorithms and parameters |
| [`4-identity.md`](../toloo-docs/4-identity.md) | Node keypairs, node.meta, toloo: URI |
| [`5-rooms.md`](../toloo-docs/5-rooms.md) | Room keypairs, channels, membership, rules |
| [`6-events.md`](../toloo-docs/6-events.md) | All event types, content schemas, lifecycle |
| [`7-replication.md`](../toloo-docs/7-replication.md) | Pool model, commit flow, bisection sync |
| [`9-transport.md`](../toloo-docs/9-transport.md) | Carrier model, framing, x25519-v0.2 skin |
| [`10-endpoints.md`](../toloo-docs/10-endpoints.md) | All nine endpoint definitions |
| [`11-storage.md`](../toloo-docs/11-storage.md) | Retention, pruning, archival |
| [`12-discovery.md`](../toloo-docs/12-discovery.md) | Bootstrap, gossip, URI import |
| [`13-moderation.md`](../toloo-docs/13-moderation.md) | Local blocking, spam, PoW enforcement |
| [`A-registries.md`](../toloo-docs/A-registries.md) | Event types, field schemas, error codes, constants |
| [`B-wire-examples.md`](../toloo-docs/B-wire-examples.md) | Annotated wire traces |
| [`C-security-considerations.md`](../toloo-docs/C-security-considerations.md) | Threat model, crypto assumptions |
| [`D-conformance.md`](../toloo-docs/D-conformance.md) | MUST/SHOULD/MAY requirements, validation checklist |
| [`E-test-vectors.md`](../toloo-docs/E-test-vectors.md) | Deterministic test inputs and expected outputs |

---

## Future: mobile (toloo-ffi)

Native mobile support (Android / iOS) is planned via `toloo-ffi`, which will
expose `toloo-core` and `toloo-lib` through [uniffi](https://github.com/mozilla/uniffi-rs)
bindings consumable by Kotlin and Swift. This is not yet implemented — the
`toloo-ffi` crate is a placeholder. The current mobile story is Tauri (Android
and iOS builds are possible with `cargo tauri android/ios build` once the FFI
crate is ready).
