# AirFry

A native **Linux AirPlay screen-mirroring sender** for Apple TV — mirror your
desktop to an Apple TV with nothing installed on the TV. Written in Rust,
including an in-house port of the FairPlay SAP handshake (no Apple device or
proprietary binary shipped in this repo — see below).

> Status: **early**. The FairPlay crypto core is complete and validated;
> `airfry discover` finds receivers today. The pairing → RTSP → capture →
> mirror pipeline is being built in stages.

## Install (Arch Linux, one line)

```sh
curl -fsSL https://raw.githubusercontent.com/nored/airfry/master/install.sh | bash
```

This installs the build toolchain, clones the repo **with submodules**, builds
`airfry`, and installs it to `~/.local/bin/airfry`.

## Use

```sh
airfry discover        # find AirPlay receivers on your network
airfry version
```

More subcommands (`pair`, `mirror`) appear as the pipeline lands.

## How it's built

`airfry` is a Rust workspace:

- **`rust/fpemu`** — the FairPlay SAP interpreter, a faithful Rust port of
  doubletake's Go `fpemu`. Validated byte-for-byte against the Go engine's
  golden vectors (`cargo test`).
- **`rust/airfry`** — the sender: discovery, pairing, RTSP, capture, and the
  mirror stream.

### About the FairPlay blob — not shipped here

The FairPlay handshake needs an Apple-proprietary code snapshot. **This repo
does not contain it.** It is extracted at build time from the
[doubletake](https://github.com/omarroth/doubletake) submodule
(`third_party/doubletake`) by `rust/fpemu/build.rs`, and is `.gitignore`d so it
is never committed here.

## Credit

The AirPlay protocol implementation is ported from / based on
**[doubletake](https://github.com/omarroth/doubletake)** by **omarroth**,
included as a research-only git submodule. Huge thanks — this would not exist
without that work. AirFry is for research and personal/interoperability use.

## License

MIT (the AirFry code). doubletake and Apple's FairPlay code are under their own
terms; see `third_party/doubletake`.
