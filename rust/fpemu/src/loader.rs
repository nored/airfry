//! Snapshot loader + public entry points — faithful port of
//! FPSAPExchangeStandalone / FPSAPExchangeM3 and the dedupFixups table.

use crate::decode::run;
use crate::{
    State, FP_BLOB, FP_CODE_BASE, FP_CODE_END, FP_ENTRY, FP_STACK_BASE, FP_STACK_SZ,
    FP_TRAMPOLINE_ADDR,
};

#[inline]
fn rd_u16(d: &[u8], p: usize) -> u16 {
    u16::from_le_bytes([d[p], d[p + 1]])
}
#[inline]
fn rd_u32(d: &[u8], p: usize) -> u32 {
    u32::from_le_bytes([d[p], d[p + 1], d[p + 2], d[p + 3]])
}
#[inline]
fn rd_u64(d: &[u8], p: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[p..p + 8]);
    u64::from_le_bytes(b)
}

/// The constant 144-byte FPLY-framed prefix of every m3 response.
static M3_PREFIX: [u8; 144] = [
    0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x98,
    0x03, 0x8f, 0x1a, 0x9c, 0x99, 0x1e, 0xa2, 0x2c, 0x51, 0x1e, 0x45, 0xba,
    0x97, 0xf1, 0xaf, 0x8d, 0xfb, 0x0f, 0x86, 0xf5, 0x50, 0xc5, 0x44, 0x86,
    0xfe, 0x6b, 0x3a, 0xb2, 0x33, 0xda, 0x43, 0x1e, 0xf8, 0xe5, 0xfc, 0x11,
    0x56, 0xdb, 0xa3, 0x21, 0xff, 0xfe, 0xab, 0xb1, 0xb3, 0x92, 0xb0, 0x9d,
    0x22, 0x7e, 0x88, 0xc7, 0x12, 0x20, 0x28, 0x66, 0xeb, 0x7b, 0xbf, 0x31,
    0x00, 0x15, 0xaa, 0x1d, 0x19, 0xa5, 0xdf, 0x36, 0xd5, 0xdf, 0xd8, 0xd3,
    0xca, 0x16, 0x39, 0xb3, 0x76, 0xea, 0xec, 0xe9, 0x46, 0xed, 0xfe, 0x8b,
    0x7a, 0x66, 0xcd, 0x30, 0x2d, 0x04, 0xaa, 0xc3, 0xc1, 0x25, 0x17, 0x14,
    0x01, 0x9b, 0xd5, 0xf2, 0xd4, 0x9b, 0x54, 0x3e, 0x11, 0xee, 0xd1, 0x64,
    0x62, 0x91, 0xec, 0x8e, 0xfd, 0x96, 0xb6, 0x91, 0x01, 0xb8, 0x49, 0xfd,
    0x93, 0xa0, 0x28, 0x60, 0xd1, 0xa0, 0xdf, 0xf5, 0xcd, 0x44, 0x14, 0xaa,];

/// Duplicate data regions zeroed in the snapshot, restored after page load.
/// (dst, src, n) — copy n bytes src -> dst.
static DEDUP_FIXUPS: &[(u64, u64, usize)] = &[
    (0x1b10a8020u64, 0x1b10a6820u64, 256usize),
    (0x1b10a9420u64, 0x1b10a8c20u64, 256usize),
    (0x1b10aac20u64, 0x1b10a5020u64, 256usize),
    (0x1b10ab820u64, 0x1b10a5420u64, 256usize),
    (0x1b10ac420u64, 0x1b10aa020u64, 256usize),
    (0x1b10b1980u64, 0x1b10b0d80u64, 128usize),
    (0x1b10b4180u64, 0x1b10b0d80u64, 128usize),
    (0x1b10b1080u64, 0x1b10af880u64, 128usize),
    (0x1b10a5180u64, 0x1b10a3980u64, 128usize),
    (0x1b10ac180u64, 0x1b10a3980u64, 128usize),
    (0x1b10a9980u64, 0x1b10a7980u64, 128usize),
    (0x1b10b7480u64, 0x1b10b4880u64, 128usize),
    (0x1b10b2980u64, 0x1b10b0980u64, 128usize),
    (0x1b10b5480u64, 0x1b10b3080u64, 128usize),
    (0x1b10b5d80u64, 0x1b10af980u64, 128usize),
    (0x1b10b7080u64, 0x1b10b3c80u64, 128usize),
    (0x1b10b2480u64, 0x1b10b1c80u64, 128usize),
    (0x1b10b6580u64, 0x1b10b2580u64, 128usize),
    (0x1b10a6980u64, 0x1b10a3d80u64, 128usize),
    (0x1b10a9580u64, 0x1b10a4580u64, 128usize),
    (0x1b10b5980u64, 0x1b10b5180u64, 128usize),
    (0x1b10b7180u64, 0x1b10b5180u64, 128usize),
    (0x1b10a8980u64, 0x1b10a7d80u64, 128usize),
    (0x1b10ab180u64, 0x1b10a7d80u64, 128usize),
    (0x1a12c6a80u64, 0x1a12c3140u64, 32usize),
    (0x1a12cdaa0u64, 0x1a12bfb80u64, 32usize),
    (0x1a12d0aa0u64, 0x1a12cf5e0u64, 32usize),
    (0x1a12d4460u64, 0x1a12cc1a0u64, 96usize),
    (0x1a12d4620u64, 0x1a12cc360u64, 32usize),
    (0x1a12d4680u64, 0x1a12cc3c0u64, 32usize),
    (0x1a12d46e0u64, 0x1a12cc420u64, 32usize),
    (0x1a12d4940u64, 0x1a12cc680u64, 32usize),
    (0x1a12d49a0u64, 0x1a12cc6e0u64, 32usize),
    (0x1a12d4a60u64, 0x1a12cc7a0u64, 32usize),
    (0x1a12d8660u64, 0x1a12cda40u64, 32usize),
    (0x1a12d86a0u64, 0x1a12cda80u64, 32usize),
    (0x1a12d86c0u64, 0x1a12c3140u64, 32usize),
    (0x1a130c180u64, 0x1a13075a0u64, 96usize),
    (0x1a13151a0u64, 0x1a13085c0u64, 32usize),
    (0x1b10a3180u64, 0x1b10a30a0u64, 32usize),
    (0x1b10a3320u64, 0x1b10a30a0u64, 32usize),
    (0x1b10a3560u64, 0x1b10a3480u64, 32usize),
    (0x1b10a36a0u64, 0x1b10a30a0u64, 32usize),
    (0x1b10a3780u64, 0x1b10a34e0u64, 32usize),
    (0x1b10a5120u64, 0x1b10a3920u64, 96usize),
    (0x1b10a5200u64, 0x1b10a3a00u64, 32usize),
    (0x1b10a6920u64, 0x1b10a3d20u64, 96usize),
    (0x1b10a6a00u64, 0x1b10a3e00u64, 32usize),
    (0x1b10a8920u64, 0x1b10a7d20u64, 96usize),
    (0x1b10a8a00u64, 0x1b10a7e00u64, 32usize),
    (0x1b10a9520u64, 0x1b10a4520u64, 96usize),
    (0x1b10a9600u64, 0x1b10a4600u64, 32usize),
    (0x1b10a9920u64, 0x1b10a7920u64, 96usize),
    (0x1b10a9a00u64, 0x1b10a7a00u64, 32usize),
    (0x1b10ab120u64, 0x1b10a7d20u64, 96usize),
    (0x1b10ab200u64, 0x1b10a7e00u64, 32usize),
    (0x1b10ac120u64, 0x1b10a3920u64, 96usize),
    (0x1b10ac200u64, 0x1b10a3a00u64, 32usize),
    (0x1b10b0360u64, 0x1b10afba0u64, 32usize),
    (0x1b10b03a0u64, 0x1b10afb60u64, 32usize),
    (0x1b10b03e0u64, 0x1b10afc20u64, 32usize),
    (0x1b10b0420u64, 0x1b10afbe0u64, 32usize),
    (0x1b10b1060u64, 0x1b10af860u64, 32usize),
    (0x1b10b1100u64, 0x1b10af900u64, 64usize),
    (0x1b10b1260u64, 0x1b10b06e0u64, 96usize),
    (0x1b10b12e0u64, 0x1b10b0660u64, 96usize),
    (0x1b10b1560u64, 0x1b10b09e0u64, 96usize),
    (0x1b10b15e0u64, 0x1b10b0960u64, 96usize),
    (0x1b10b1960u64, 0x1b10b0d60u64, 32usize),
    (0x1b10b1a00u64, 0x1b10b0e00u64, 64usize),
    (0x1b10b2460u64, 0x1b10b1c60u64, 32usize),
    (0x1b10b2500u64, 0x1b10b1d00u64, 64usize),
    (0x1b10b2960u64, 0x1b10b0960u64, 32usize),
    (0x1b10b2a00u64, 0x1b10b0a00u64, 64usize),
    (0x1b10b3060u64, 0x1b10b2ce0u64, 32usize),
    (0x1b10b3100u64, 0x1b10b2c80u64, 64usize),
    (0x1b10b3360u64, 0x1b10b0fa0u64, 32usize),
    (0x1b10b33a0u64, 0x1b10b0f60u64, 32usize),
    (0x1b10b33e0u64, 0x1b10b1020u64, 32usize),
    (0x1b10b3420u64, 0x1b10b0fe0u64, 32usize),
    (0x1b10b3660u64, 0x1b10afee0u64, 96usize),
    (0x1b10b36e0u64, 0x1b10afe60u64, 96usize),
    (0x1b10b3a60u64, 0x1b10b16a0u64, 32usize),
    (0x1b10b3aa0u64, 0x1b10b1660u64, 32usize),
    (0x1b10b3ae0u64, 0x1b10b1720u64, 32usize),
    (0x1b10b3b20u64, 0x1b10b16e0u64, 32usize),
    (0x1b10b4160u64, 0x1b10b0d60u64, 32usize),
    (0x1b10b4200u64, 0x1b10b0e00u64, 64usize),
    (0x1b10b4660u64, 0x1b10b02a0u64, 32usize),
    (0x1b10b46a0u64, 0x1b10b0260u64, 32usize),
    (0x1b10b46e0u64, 0x1b10b0320u64, 32usize),
    (0x1b10b4720u64, 0x1b10b02e0u64, 32usize),
    (0x1b10b5460u64, 0x1b10b2ce0u64, 32usize),
    (0x1b10b5500u64, 0x1b10b2c80u64, 64usize),
    (0x1b10b5560u64, 0x1b10b49a0u64, 32usize),
    (0x1b10b55a0u64, 0x1b10b4960u64, 32usize),
    (0x1b10b55e0u64, 0x1b10b4a20u64, 32usize),
    (0x1b10b5620u64, 0x1b10b49e0u64, 32usize),
    (0x1b10b5660u64, 0x1b10af2e0u64, 96usize),
    (0x1b10b56e0u64, 0x1b10af260u64, 96usize),
    (0x1b10b5960u64, 0x1b10b5160u64, 32usize),
    (0x1b10b5a00u64, 0x1b10b5200u64, 64usize),
    (0x1b10b5d60u64, 0x1b10af960u64, 32usize),
    (0x1b10b5e00u64, 0x1b10afa00u64, 64usize),
    (0x1b10b6060u64, 0x1b10b18e0u64, 96usize),
    (0x1b10b60e0u64, 0x1b10b1860u64, 96usize),
    (0x1b10b6460u64, 0x1b10b58e0u64, 96usize),
    (0x1b10b64e0u64, 0x1b10b5860u64, 96usize),
    (0x1b10b6560u64, 0x1b10b2560u64, 32usize),
    (0x1b10b6600u64, 0x1b10b2600u64, 64usize),
    (0x1b10b6660u64, 0x1b10b0ea0u64, 32usize),
    (0x1b10b66a0u64, 0x1b10b0e60u64, 32usize),
    (0x1b10b66e0u64, 0x1b10b0f20u64, 32usize),
    (0x1b10b6720u64, 0x1b10b0ee0u64, 32usize),
    (0x1b10b6760u64, 0x1b10b13e0u64, 96usize),
    (0x1b10b67e0u64, 0x1b10b1360u64, 96usize),
    (0x1b10b6960u64, 0x1b10af5a0u64, 32usize),
    (0x1b10b69a0u64, 0x1b10af560u64, 32usize),
    (0x1b10b69e0u64, 0x1b10af620u64, 32usize),
    (0x1b10b6a20u64, 0x1b10af5e0u64, 32usize),
    (0x1b10b6a60u64, 0x1b10afaa0u64, 32usize),
    (0x1b10b6aa0u64, 0x1b10afa60u64, 32usize),
    (0x1b10b6ae0u64, 0x1b10afb20u64, 32usize),
    (0x1b10b6b20u64, 0x1b10afae0u64, 32usize),
    (0x1b10b7060u64, 0x1b10b3c60u64, 32usize),
    (0x1b10b7100u64, 0x1b10b3d00u64, 64usize),
    (0x1b10b7160u64, 0x1b10b5160u64, 32usize),
    (0x1b10b7200u64, 0x1b10b5200u64, 64usize),
    (0x1b10b7260u64, 0x1b10af6a0u64, 32usize),
    (0x1b10b72a0u64, 0x1b10af660u64, 32usize),
    (0x1b10b72e0u64, 0x1b10af720u64, 32usize),
    (0x1b10b7320u64, 0x1b10af6e0u64, 32usize),
    (0x1b10b7460u64, 0x1b10b4860u64, 32usize),
    (0x1b10b7500u64, 0x1b10b4900u64, 64usize),
    (0x1b10b7760u64, 0x1b10b1c20u64, 32usize),
    (0x1b10b77a0u64, 0x1b10b1be0u64, 32usize),
    (0x1b10b77e0u64, 0x1b10b1ba0u64, 32usize),
    (0x1b10b7820u64, 0x1b10b1b60u64, 32usize),
];

/// FairPlay SAP exchange core: 128-byte payload -> 20-byte WB-AES hash.
pub fn fp_sap_exchange_standalone(payload: [u8; 128]) -> [u8; 20] {
    let data: &[u8] = FP_BLOB;
    let mut s = State::new();
    let mut pos = 0usize;

    let n_pages = rd_u32(data, pos);
    pos += 4;
    let heap_ptr = rd_u64(data, pos);
    pos += 8;
    let ctx = rd_u64(data, pos);
    pos += 8;

    // Named stubs.
    loop {
        let addr = rd_u64(data, pos);
        pos += 8;
        if addr == 0 {
            break;
        }
        let name_len = rd_u16(data, pos) as usize;
        pos += 2;
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).into_owned();
        pos += name_len;
        s.stubs.insert(addr, name);
    }

    // Sparse pages.
    for _ in 0..n_pages {
        let addr = rd_u64(data, pos);
        pos += 8;
        let n_spans = rd_u16(data, pos);
        pos += 2;
        s.mem.map_range(addr, 4096);
        if n_spans == 0xFFFF {
            s.mem.write_n(addr, &data[pos..pos + 4096]);
            pos += 4096;
        } else {
            for _ in 0..n_spans {
                let off = rd_u16(data, pos) as u64;
                pos += 2;
                let ln = rd_u16(data, pos) as usize;
                pos += 2;
                s.mem.write_n(addr + off, &data[pos..pos + ln]);
                pos += ln;
            }
        }
    }

    // Apply dedup fixups.
    for &(dst, src, n) in DEDUP_FIXUPS {
        let bytes = s.mem.read_n(src, n);
        s.mem.write_n(dst, &bytes);
    }

    // Trampoline: BLR X8 ; BRK #0.
    s.mem.map_range(FP_TRAMPOLINE_ADDR, 0x1000);
    s.mem.write32(FP_TRAMPOLINE_ADDR, 0xD63F0100);
    s.mem.write32(FP_TRAMPOLINE_ADDR + 4, 0xD4200000);

    // Misc region.
    s.mem.map_range(0x30000000, 0x1000);
    s.mem
        .write_n(0x30000000, &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
    s.mem.write32(0x30000800, 0xD4200000);

    // Build code instruction cache.
    s.mem.set_code_region(FP_CODE_BASE, FP_CODE_END);

    s.heap_ptr = heap_ptr;

    // FPSAPExchange(version=3, hwInfo, ctx, inBuf, inLen, &outBuf, &outLen, &rc)
    let hw_addr = s.heap_alloc(24);
    s.mem.write_n(hw_addr, &[0u8; 24]);

    let m2_header: [u8; 14] = [
        0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x82, 0x02, 0x03,
    ];
    let mut m2 = [0u8; 142];
    m2[..14].copy_from_slice(&m2_header);
    m2[14..].copy_from_slice(&payload);
    let in_addr = s.heap_alloc(142);
    s.mem.write_n(in_addr, &m2);

    let out_ptr_addr = s.heap_alloc(8);
    let out_len_addr = s.heap_alloc(4);
    let rc_addr = s.heap_alloc(4);
    s.mem.write64(out_ptr_addr, 0);
    s.mem.write32(out_len_addr, 0);
    s.mem.write32(rc_addr, 0);

    let sp = FP_STACK_BASE + FP_STACK_SZ - 0x100;
    s.cpu.sp = sp;
    s.cpu.x[0] = 3;
    s.cpu.x[1] = hw_addr;
    s.cpu.x[2] = ctx;
    s.cpu.x[3] = in_addr;
    s.cpu.x[4] = 142;
    s.cpu.x[5] = out_ptr_addr;
    s.cpu.x[6] = out_len_addr;
    s.cpu.x[7] = rc_addr;
    s.cpu.x[8] = FP_ENTRY;
    s.cpu.pc = FP_TRAMPOLINE_ADDR;

    let halt_pc = FP_TRAMPOLINE_ADDR + 4;
    if let Err(e) = run(&mut s, halt_pc) {
        panic!("FPSAPExchangeStandalone: {}", e);
    }

    let out_ptr = s.mem.read64(out_ptr_addr);
    let out_len = s.mem.read32(out_len_addr);
    let mut result = [0u8; 20];
    if out_len >= 164 && out_ptr != 0 {
        let out = s.mem.read_n(out_ptr, out_len as usize);
        result.copy_from_slice(&out[144..164]);
    }
    result
}

/// Full FPLY m2 (142+ bytes) -> m3 (164 bytes: 144-byte prefix + 20-byte hash).
pub fn fp_sap_exchange_m3(m2: &[u8]) -> Result<Vec<u8>, String> {
    if m2.len() < 142 {
        return Err(format!("m2 too short: {} bytes (need >= 142)", m2.len()));
    }
    let mut payload = [0u8; 128];
    payload.copy_from_slice(&m2[14..142]);
    let hash = fp_sap_exchange_standalone(payload);
    let mut m3 = vec![0u8; 164];
    m3[..144].copy_from_slice(&M3_PREFIX);
    m3[144..].copy_from_slice(&hash);
    Ok(m3)
}
