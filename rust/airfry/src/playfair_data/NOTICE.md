# PlayFair lookup tables

These `.bin` files are the fully-expanded PlayFair cipher lookup tables and
constants, derived from **doubletake** (https://github.com/omarroth/doubletake)
— specifically its `internal/airplay/playfair_tables_compact.go` — and embedded
here so `playfair.rs` does not need to reimplement the table-expansion logic.

They are doubletake's reverse-engineered representation, not Apple's signed
FairPlay binary (that binary is never committed to this repo; see
`rust/fpemu/build.rs`, which extracts it from the doubletake submodule at build
time). Credit: omarroth. See repo README / LICENSE.
