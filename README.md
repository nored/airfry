# AirFry

A native **Linux AirPlay screen-mirroring sender** for Apple TV — mirror your
desktop to an Apple TV with nothing installed on the TV. Written in Rust, with a
**native system-tray widget** (StatusNotifierItem — no main window, no Qt) whose
icon is white when idle and **turns blue while mirroring**, plus **underscan you
adjust by scrolling the tray icon**, and an in-house port of the FairPlay
handshake (Apple's proprietary blob is never shipped in this repo — see below).

## Install (Arch Linux, one line)

```sh
curl -fsSL https://raw.githubusercontent.com/nored/airfry/master/install.sh | bash
```

This installs the dependencies, clones the repo **with submodules**, builds a
proper pacman package, and installs `airfry` to `/usr/bin` (tracked by pacman;
remove with `pacman -R airfry`).

## Use

Launch **AirFry** from your app menu, or run `airfry`. It lives in the system
tray:

- **Open the tray menu** → it scans (only on open, never in the background) and
  lists AirPlay receivers. The last-seen list is cached, so the menu is
  populated instantly on launch; **Rescan** forces a fresh scan.
- **Click a receiver** → it pairs and starts mirroring this screen to it. The
  icon turns **blue** while mirroring. While streaming the menu shows **Stop**,
  **Mute/Unmute** and **Change display** instead of the device list.
- **Underscan** (in the tray, no window): **scroll the tray icon** up/down to
  shrink/grow the picture if it spills past the edges of your TV, or pick a step
  from the **Underscan** submenu. A text-art bar shows the current value. It
  persists and applies to the next mirror session.
- **Quit** stops mirroring and exits.

When nothing is streaming, AirFry does no background work — discovery only runs
while the menu is open and capture/encode only runs while mirroring.

On Wayland (GNOME/KDE) the first mirror triggers the system **ScreenCast
portal** to pick a display. Hardware H.264 encoding uses VA-API
(`gstreamer-vaapi` + `intel-media-driver` on Intel) when present, else software
x264.

### Command line (headless / scripting)

```sh
airfry discover                         # list receivers
airfry pair <host[:port]> [pin]         # connect + pair + FairPlay setup
airfry mirror <host[:port]> [--fit N] [--bitrate K] [--fps N]
airfry version
```

## How it's built

A Rust workspace:

- **`rust/fpemu`** — FairPlay SAP interpreter, a faithful Rust port of
  doubletake's Go `fpemu`, validated byte-for-byte against golden vectors.
- **`rust/airfry`** — the sender: mDNS discovery, HomeKit/transient pairing,
  PlayFair stream-key derivation (golden-tested), RTSP transport, the
  H.264/RTP mirror stream, GStreamer capture/encode, and the native
  StatusNotifierItem tray (via the vendored `third_party/ksni`, patched to
  surface the menu-open event so it scans only on open).

### About the FairPlay blob — not shipped here

The FairPlay handshake needs an Apple-proprietary code snapshot. **This repo
does not contain it.** It is extracted at build time from the
[doubletake](https://github.com/omarroth/doubletake) submodule by
`rust/fpemu/build.rs`, and is `.gitignore`d.

## Credit

The AirPlay protocol implementation is ported from / based on
**[doubletake](https://github.com/omarroth/doubletake)** by **omarroth**,
included as a research-only git submodule. AirFry is for research and
personal/interoperability use.

## License

MIT (the AirFry code). doubletake and Apple's FairPlay code are under their own
terms; see `third_party/doubletake`.
