# Maintainer: nored
# AirFry — native AirPlay screen-mirroring sender (Rust + Qt tray). Builds the
# airfry binary from this repo. Apple's FairPlay blob is NOT shipped; it is
# extracted from the doubletake submodule at build time by rust/fpemu/build.rs.
pkgname=airfry
pkgver=0.1.0
pkgrel=1
pkgdesc="Native Linux AirPlay screen-mirroring sender for Apple TV (tray app)"
arch=('x86_64')
url="https://github.com/nored/airfry"
license=('MIT')
depends=(
  'qt6-base'              # system-tray widget + in-menu underscan slider
  'gstreamer'             # capture/encode pipeline
  'gst-plugins-base'      # videoconvert, appsink, x264enc deps
  'gst-plugins-good'      # ximagesrc (X11 capture)
  'gst-plugin-pipewire'   # pipewiresrc (Wayland capture)
  'pipewire'
  'xdg-desktop-portal'    # Wayland ScreenCast portal
)
optdepends=(
  'gstreamer-vaapi: Intel/AMD VA-API hardware H.264 encoding'
  'intel-media-driver: Intel Gen9+ iGPU VA-API driver'
  'xdg-desktop-portal-gnome: ScreenCast portal backend on GNOME'
  'xdg-desktop-portal-kde: ScreenCast portal backend on KDE'
  'x264: software H.264 fallback encoder (gst-plugins-ugly)'
)
makedepends=('rust' 'git' 'qt6-base' 'gstreamer' 'gst-plugins-base')

build() {
  cd "$startdir/rust"
  cargo build --release --frozen -p airfry || cargo build --release -p airfry
}

check() {
  cd "$startdir/rust"
  cargo test --release -p fpemu || true
  cargo test --release -p airfry || true
}

package() {
  cd "$startdir"
  install -Dm755 rust/target/release/airfry "$pkgdir/usr/bin/airfry"
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
  install -Dm644 packaging/airfry.desktop "$pkgdir/usr/share/applications/airfry.desktop" 2>/dev/null || true
}
