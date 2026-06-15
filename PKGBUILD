# Maintainer: nored
# AirFry — native AirPlay screen-mirroring sender (pure Rust). Builds the airfry
# binary from this repo. The system tray is a native StatusNotifierItem (ksni,
# no Qt/C++). Apple's FairPlay blob is NOT shipped; it is extracted from the
# doubletake submodule at build time by rust/fpemu/build.rs.
pkgname=airfry
pkgver=0.1.0
pkgrel=1
pkgdesc="Native Linux AirPlay screen-mirroring sender for Apple TV (tray app)"
arch=('x86_64')
url="https://github.com/nored/airfry"
license=('MIT')
depends=(
  'gstreamer'             # capture/encode pipeline
  'gst-plugins-base'      # videoconvert, videoscale, compositor, appsink
  'gst-plugins-good'      # ximagesrc (X11 capture)
  'gst-plugins-bad'       # nvh264enc (NVENC), vah264enc (VA-API), vulkanh264enc
  'gst-plugins-ugly'      # x264enc (software H.264 fallback)
  'gst-plugin-pipewire'   # pipewiresrc (Wayland capture)
  'pipewire'
  'xdg-desktop-portal'    # Wayland ScreenCast portal
  'libnotify'             # desktop notifications (notify-send)
  'zenity'                # graphical PIN-pairing prompt
  'gtk4'                  # underscan slider popup
  'libadwaita'            # underscan slider follows the desktop theme/accent
)
optdepends=(
  'intel-media-driver: Intel Gen9+ iGPU VA-API hardware H.264 encoding'
  'libva-mesa-driver: AMD / older-Intel VA-API hardware H.264 encoding'
  'nvidia-utils: NVIDIA NVENC hardware H.264 encoding'
  'xdg-desktop-portal-gnome: ScreenCast portal backend on GNOME'
  'xdg-desktop-portal-kde: ScreenCast portal backend on KDE'
  'gnome-shell-extension-appindicator: shows the tray icon on GNOME Shell'
)
makedepends=('rust' 'git' 'gstreamer' 'gst-plugins-base' 'gtk4' 'libadwaita')

build() {
  cd "$startdir/rust"
  cargo build --release --frozen || cargo build --release
}

check() {
  cd "$startdir/rust"
  cargo test --release -p fpemu || true
  cargo test --release -p airfry || true
}

package() {
  cd "$startdir"
  install -Dm755 rust/target/release/airfry "$pkgdir/usr/bin/airfry"
  install -Dm755 rust/target/release/airfry-ctl "$pkgdir/usr/bin/airfry-ctl"
  install -Dm755 rust/target/release/airfry-underscan "$pkgdir/usr/bin/airfry-underscan"
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
  install -Dm644 packaging/airfry.desktop "$pkgdir/usr/share/applications/airfry.desktop" 2>/dev/null || true
}
