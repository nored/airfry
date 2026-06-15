#!/usr/bin/env bash
# AirFry one-line installer for Arch Linux.
#   curl -fsSL https://raw.githubusercontent.com/nored/airfry/master/install.sh | bash
#
# Installs the build toolchain, clones the repo with submodules, builds airfry,
# and installs it to ~/.local/bin/airfry. Apple's FairPlay blob is NOT shipped;
# it is extracted from the doubletake submodule at build time.
set -euo pipefail

REPO_URL="${AIRFRY_REPO:-https://github.com/nored/airfry.git}"
SRC_DIR="${AIRFRY_SRC:-$HOME/.local/share/airfry/src}"
BIN_DIR="${AIRFRY_BIN:-$HOME/.local/bin}"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v pacman >/dev/null 2>&1 || die "this installer targets Arch Linux (pacman not found)."

# --- 1. dependencies ------------------------------------------------------
# Build toolchain + git. (Capture/encode runtime deps are added as the mirror
# pipeline lands — pipewire, gstreamer, libva, intel-media-driver.)
DEPS=(git rust)
MISSING=()
for p in "${DEPS[@]}"; do
  pacman -Qq "$p" >/dev/null 2>&1 || MISSING+=("$p")
done
# `rust` may be provided by rustup instead of the pacman package.
if printf '%s\n' "${MISSING[@]:-}" | grep -qx rust && command -v cargo >/dev/null 2>&1; then
  MISSING=("${MISSING[@]/rust}")
fi
MISSING=("${MISSING[@]/#/}"); MISSING=($(printf '%s\n' "${MISSING[@]}" | sed '/^$/d')) || true
if [ "${#MISSING[@]}" -gt 0 ]; then
  say "Installing dependencies: ${MISSING[*]}"
  sudo pacman -S --needed --noconfirm "${MISSING[@]}"
else
  say "Build dependencies already present."
fi
command -v cargo >/dev/null 2>&1 || { [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"; }
command -v cargo >/dev/null 2>&1 || die "cargo not on PATH after install."

# --- 2. fetch -------------------------------------------------------------
if [ -d "$SRC_DIR/.git" ]; then
  say "Updating existing checkout in $SRC_DIR"
  git -C "$SRC_DIR" pull --ff-only
  git -C "$SRC_DIR" submodule update --init --recursive
else
  say "Cloning $REPO_URL -> $SRC_DIR"
  mkdir -p "$(dirname "$SRC_DIR")"
  git clone --recurse-submodules "$REPO_URL" "$SRC_DIR"
fi

# --- 3. build -------------------------------------------------------------
say "Building airfry (release)…"
( cd "$SRC_DIR/rust" && cargo build --release -p airfry )

# --- 4. install -----------------------------------------------------------
mkdir -p "$BIN_DIR"
install -m755 "$SRC_DIR/rust/target/release/airfry" "$BIN_DIR/airfry"
say "Installed: $BIN_DIR/airfry"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not on your PATH. Add:  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

say "Done. Try:  airfry discover"
