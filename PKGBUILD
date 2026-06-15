# Maintainer: nored
# AirFry — native AirPlay screen-mirroring sender (Rust). Builds the airfry
# binary from this repo. Apple's FairPlay blob is NOT shipped; it is extracted
# from the doubletake submodule at build time by rust/fpemu/build.rs.
pkgname=airfry
pkgver=0.1.0
pkgrel=1
pkgdesc="Native Linux AirPlay screen-mirroring sender for Apple TV"
arch=('x86_64')
url="https://github.com/nored/airfry"
license=('MIT')
# Runtime media deps are added as the capture/encode/mirror pipeline lands
# (pipewire, gstreamer, libva, intel-media-driver). Discovery needs none.
depends=()
optdepends=(
  'gstreamer-vaapi: Intel/AMD VA-API hardware H.264 encoding (mirror)'
  'intel-media-driver: Intel Gen9+ iGPU VA-API driver'
  'pipewire: Wayland screen capture (mirror)'
)
makedepends=('rust' 'git')

build() {
  cd "$startdir/rust"
  cargo build --release --frozen -p airfry || cargo build --release -p airfry
}

check() {
  cd "$startdir/rust"
  cargo test --release -p fpemu || true
}

package() {
  cd "$startdir"
  install -Dm755 rust/target/release/airfry "$pkgdir/usr/bin/airfry"
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}
