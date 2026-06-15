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

# --- 1. build dependencies ------------------------------------------------
# base-devel: makepkg. rust: cargo. git: clone + submodules.
say "Installing build dependencies (base-devel, rust, git)…"
sudo pacman -S --needed --noconfirm base-devel rust git

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
