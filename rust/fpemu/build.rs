//! Build script: extract the FairPlay snapshot blob from the doubletake
//! submodule's `fpexchange_data.go` (the `snapshotData` byte array) into
//! `$OUT_DIR/fp_blob.bin`. The blob is Apple's proprietary FairPlay code, so
//! it is NEVER committed to this repo — it is regenerated from doubletake
//! (research-only submodule) at build time. See third_party/doubletake.

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let go = manifest.join("../../third_party/doubletake/internal/fpemu/fpexchange_data.go");
    println!("cargo:rerun-if-changed={}", go.display());

    let src = std::fs::read_to_string(&go).unwrap_or_else(|e| {
        panic!(
            "cannot read doubletake submodule at {}\n  ({})\n  Did you clone with --recurse-submodules? Try: git submodule update --init --recursive",
            go.display(),
            e
        )
    });

    const MARKER: &str = "var snapshotData = []byte{";
    let start = src
        .find(MARKER)
        .expect("snapshotData array not found in doubletake fpexchange_data.go")
        + MARKER.len();
    let rest = &src[start..];
    let end = rest
        .find("\n}")
        .expect("end of snapshotData array not found");
    let body = rest[..end].as_bytes();

    // Greedily parse `0xNN` (1-2 hex digit) tokens.
    let mut bytes: Vec<u8> = Vec::with_capacity(170_000);
    let mut i = 0usize;
    while i + 1 < body.len() {
        if body[i] == b'0' && (body[i + 1] | 0x20) == b'x' {
            let mut j = i + 2;
            let mut val: u32 = 0;
            let mut n = 0;
            while j < body.len() && n < 2 {
                match (body[j] as char).to_digit(16) {
                    Some(d) => {
                        val = val * 16 + d;
                        j += 1;
                        n += 1;
                    }
                    None => break,
                }
            }
            if n > 0 {
                bytes.push(val as u8);
            }
            i = j;
        } else {
            i += 1;
        }
    }

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("fp_blob.bin");
    std::fs::write(&out, &bytes).unwrap();
    println!(
        "cargo:warning=fp_blob.bin: extracted {} bytes from doubletake submodule",
        bytes.len()
    );
}
