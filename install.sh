#!/usr/bin/env bash
# AirFry one-line installer for Arch Linux.
#   curl -fsSL https://raw.githubusercontent.com/nored/airfry/master/install.sh | bash
#
# Builds a proper pacman package and installs it system-wide (airfry lands in
# /usr/bin, which is on PATH, and is tracked by pacman so `pacman -R airfry`
# removes it cleanly). Apple's FairPlay blob is NOT shipped; it is extracted
# from the doubletake submodule at build time.
set -euo pipefail

REPO_URL="${AIRFRY_REPO:-https://github.com/nored/airfry.git}"
BUILD_DIR="${AIRFRY_BUILD:-${XDG_CACHE_HOME:-$HOME/.cache}/airfry/build}"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v pacman >/dev/null 2>&1 || die "this installer targets Arch Linux (pacman not found)."
[ "$(id -u)" -ne 0 ] || die "run as a normal user, not root (makepkg refuses root; it will sudo when needed)."

# install_pkgs: install a batch with --needed; if the batch fails (e.g. one name
# is unavailable on this box), retry each package individually so one missing
# optional package never aborts the whole install.
install_pkgs() {
  if sudo pacman -S --needed --noconfirm "$@"; then return 0; fi
  warn "batch install hit a snag — retrying packages individually…"
  local p
  for p in "$@"; do
    sudo pacman -S --needed --noconfirm "$p" || warn "skipped: $p (unavailable or conflicts here)"
  done
}

# --- 1. build tools -------------------------------------------------------
# base-devel: makepkg. rust: cargo. git: clone + submodules.
say "Installing build tools (base-devel, rust, git)…"
install_pkgs base-devel rust git

# --- 1b. runtime dependencies (install EVERYTHING that could be needed) ----
# Don't assume the machine's GPU or desktop — pull the full set so a fresh
# laptop just works. makepkg -si below also pulls the package's own depends;
# this is the superset. GStreamer incl. the bad/ugly plugins is where the
# NVENC / VA-API / Vulkan and x264 encoders actually live; PipeWire + the
# screen-share portal do Wayland capture; GTK4/libadwaita drive the underscan
# slider; libnotify/zenity handle notifications + the pairing PIN prompt.
say "Installing runtime dependencies (GStreamer, PipeWire, portal, GUI)…"
install_pkgs \
  gstreamer gst-plugins-base gst-plugins-good gst-plugins-bad gst-plugins-ugly \
  gst-plugin-pipewire pipewire \
  xdg-desktop-portal \
  gtk4 libadwaita libnotify zenity \
  libva

# Hardware-encode drivers + desktop integration — best-effort (depends on the
# GPU and desktop; missing ones are skipped, software x264 still works). Intel +
# AMD/mesa VA-API drivers; portal backends for GNOME and the generic GTK one;
# wireplumber for the PipeWire audio session; and the StatusNotifier tray host
# extension for GNOME Shell (KDE & others show tray icons natively).
say "Installing GPU drivers + desktop integration (best-effort)…"
install_pkgs \
  intel-media-driver libva-mesa-driver libva-utils \
  wireplumber \
  xdg-desktop-portal-gnome xdg-desktop-portal-gtk \
  gnome-shell-extension-appindicator

# --- 2. fetch -------------------------------------------------------------
if [ -d "$BUILD_DIR/.git" ]; then
  say "Updating checkout in $BUILD_DIR"
  git -C "$BUILD_DIR" pull --ff-only
  git -C "$BUILD_DIR" submodule update --init --recursive
else
  say "Cloning $REPO_URL -> $BUILD_DIR"
  rm -rf "$BUILD_DIR"
  mkdir -p "$(dirname "$BUILD_DIR")"
  git clone --recurse-submodules "$REPO_URL" "$BUILD_DIR"
fi

# --- 3. build + install the package --------------------------------------
say "Building and installing the airfry package (makepkg -si)…"
( cd "$BUILD_DIR" && makepkg -si --needed --noconfirm )

say "Installed: $(command -v airfry || echo /usr/bin/airfry)"
say "Done. Try:  airfry discover"
