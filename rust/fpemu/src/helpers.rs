//! Arithmetic / bit-twiddling helpers — faithful port of the Go `fp*` helpers.

pub fn sign_extend(val: u64, bits: u32) -> u64 {
    if bits >= 64 {
        return val;
    }
    if val & (1u64 << (bits - 1)) != 0 {
        val | (!0u64 << bits)
    } else {
        val
    }
}

/// Returns (result, n, z, c, v).
pub fn add_with_carry64(x: u64, y: u64, carry: u64) -> (u64, bool, bool, bool, bool) {
    let result = x.wrapping_add(y).wrapping_add(carry);
    let n = (result >> 63) != 0;
    let z = result == 0;
    let c = if carry == 0 { result < x } else { result <= x };
    let v = (((x ^ result) & (y ^ result)) >> 63) != 0;
    (result, n, z, c, v)
}

pub fn add_with_carry32(x: u32, y: u32, carry: u32) -> (u32, bool, bool, bool, bool) {
    let s = x as u64 + y as u64 + carry as u64;
    let result = s as u32;
    let n = (result >> 31) != 0;
    let z = result == 0;
    let cc = s > 0xFFFF_FFFF;
    let v = (((x ^ result) & (y ^ result)) >> 31) != 0;
    (result, n, z, cc, v)
}

#[inline]
fn ones(n: u32) -> u64 {
    if n >= 64 {
        !0u64
    } else {
        (1u64 << n) - 1
    }
}

/// Returns (wmask, tmask).
pub fn decode_bit_masks(n_bit: u32, imms: u32, immr: u32, is64: bool) -> (u64, u64) {
    let combined = (n_bit << 6) | ((!imms) & 0x3F);
    let mut length = 0u32;
    for i in (1..=6u32).rev() {
        if combined & (1 << i) != 0 {
            length = i;
            break;
        }
    }
    let esize = 1u32 << length;
    let levels = esize - 1;
    let s = imms & levels;
    let r = immr & levels;
    let diff = s.wrapping_sub(r) & levels;

    let mut welem = ones(s + 1);
    if r != 0 {
        welem = (welem >> r) | (welem << (esize - r));
        welem &= ones(esize);
    }
    let telem = ones(diff + 1);

    let (mut wmask, mut tmask) = (0u64, 0u64);
    let mut i = 0u32;
    while i < 64 {
        wmask |= welem << i;
        tmask |= telem << i;
        i += esize;
    }
    if !is64 {
        wmask &= 0xFFFF_FFFF;
        tmask &= 0xFFFF_FFFF;
    }
    (wmask, tmask)
}

pub fn shift_val(mut val: u64, shift_type: u32, mut amount: u32, is64: bool) -> u64 {
    if amount == 0 {
        return val;
    }
    let bits = if is64 {
        64u32
    } else {
        val &= 0xFFFF_FFFF;
        32
    };
    amount &= bits - 1;
    if amount == 0 {
        return if is64 { val } else { val & 0xFFFF_FFFF };
    }
    match shift_type {
        0 => val <<= amount,
        1 => val >>= amount,
        2 => {
            if is64 {
                val = ((val as i64) >> amount) as u64;
            } else {
                val = (((val as u32) as i32) >> amount) as u32 as u64;
            }
        }
        3 => val = (val >> amount) | (val << (bits - amount)),
        _ => {}
    }
    if !is64 {
        val &= 0xFFFF_FFFF;
    }
    val
}

pub fn rev32(v: u32) -> u32 {
    (v >> 24) & 0xFF | (v >> 8) & 0xFF00 | (v << 8) & 0xFF0000 | (v << 24)
}
pub fn rev64(v: u64) -> u64 {
    (rev32(v as u32) as u64) << 32 | (rev32((v >> 32) as u32) as u64)
}
pub fn rbit64(mut v: u64) -> u64 {
    v = (v & 0x5555_5555_5555_5555) << 1 | (v & 0xAAAA_AAAA_AAAA_AAAA) >> 1;
    v = (v & 0x3333_3333_3333_3333) << 2 | (v & 0xCCCC_CCCC_CCCC_CCCC) >> 2;
    v = (v & 0x0F0F_0F0F_0F0F_0F0F) << 4 | (v & 0xF0F0_F0F0_F0F0_F0F0) >> 4;
    rev64(v)
}
pub fn rbit32(mut v: u32) -> u32 {
    v = (v & 0x5555_5555) << 1 | (v & 0xAAAA_AAAA) >> 1;
    v = (v & 0x3333_3333) << 2 | (v & 0xCCCC_CCCC) >> 2;
    v = (v & 0x0F0F_0F0F) << 4 | (v & 0xF0F0_F0F0) >> 4;
    rev32(v)
}
pub fn rev16_64(v: u64) -> u64 {
    ((v & 0xFF00_FF00_FF00_FF00) >> 8) | ((v & 0x00FF_00FF_00FF_00FF) << 8)
}
pub fn rev16_32(v: u32) -> u32 {
    ((v & 0xFF00_FF00) >> 8) | ((v & 0x00FF_00FF) << 8)
}

pub fn clz64(v: u64) -> u32 {
    v.leading_zeros()
}
pub fn clz32(v: u32) -> u32 {
    v.leading_zeros()
}

pub fn mulhi64(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) >> 64) as u64
}
pub fn smulhi64(a: u64, b: u64) -> u64 {
    (((a as i64 as i128) * (b as i64 as i128)) >> 64) as u64
}

pub fn vfp_expand_imm32(imm8: u32) -> u32 {
    let a = (imm8 >> 7) & 1;
    let b = (imm8 >> 6) & 1;
    let cdefgh = imm8 & 0x3F;
    let mut result = a << 31;
    if b != 0 {
        result |= 0x1F << 25;
    } else {
        result |= 1 << 30;
    }
    result |= cdefgh << 19;
    result
}
pub fn vfp_expand_imm64(imm8: u32) -> u64 {
    let a = ((imm8 >> 7) & 1) as u64;
    let b = ((imm8 >> 6) & 1) as u64;
    let cdefgh = (imm8 & 0x3F) as u64;
    let mut result = a << 63;
    if b != 0 {
        result |= 0xFFu64 << 54;
    } else {
        result |= 1u64 << 62;
    }
    result |= cdefgh << 48;
    result
}
