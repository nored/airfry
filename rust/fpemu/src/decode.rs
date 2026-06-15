//! ARM64 decode/execute — faithful port of fpRun/fpStep/fpExec* in the Go
//! interpreter. Functions mirror the Go names and structure exactly.

use crate::helpers::*;
use crate::{Cpu, Mem, State};

// --- Main execution loop -------------------------------------------------

pub fn run(s: &mut State, halt_pc: u64) -> Result<(), String> {
    let mut count: u64 = 0;
    while s.cpu.pc != halt_pc {
        let pc = s.cpu.pc;
        if let Some(name) = s.stubs.get(&pc).cloned() {
            s.handle_stub(&name)?;
            s.cpu.pc = s.cpu.x[30];
            count += 1;
            continue;
        }
        let inst = s.mem.fetch_inst(pc);
        if inst == 0 {
            let name = s.dyn_stub_classify(pc);
            s.stubs.insert(pc, name.to_string());
            s.handle_stub(name)?;
            s.cpu.pc = s.cpu.x[30];
            count += 1;
            continue;
        }
        if let Err(e) = step(s, inst) {
            return Err(format!("at PC=0x{:x} (inst #{}): {}", pc, count, e));
        }
        count += 1;
        if count > 100_000_000 {
            return Err(format!("exceeded 100M instructions at PC=0x{:x}", s.cpu.pc));
        }
    }
    Ok(())
}

pub fn step(s: &mut State, inst: u32) -> Result<(), String> {
    // BRK -> dynamic stub.
    if inst & 0xFFE0_001F == 0xD420_0000 {
        let name = s.dyn_stub_classify(s.cpu.pc);
        s.stubs.insert(s.cpu.pc, name.to_string());
        s.handle_stub(name)?;
        s.cpu.pc = s.cpu.x[30];
        return Ok(());
    }
    let op0 = (inst >> 25) & 0xF;
    if op0 >> 1 == 4 {
        return exec_dpimm(&mut s.cpu, inst);
    }
    if op0 >> 1 == 5 {
        return exec_branch(&mut s.cpu, &mut s.mem, inst);
    }
    if op0 & 5 == 4 {
        return exec_load_store(&mut s.cpu, &mut s.mem, inst);
    }
    if op0 & 7 == 5 {
        return exec_dpreg(&mut s.cpu, inst);
    }
    if op0 & 7 == 7 {
        return exec_simd(&mut s.cpu, &mut s.mem, inst);
    }
    Err(format!("unhandled op0={:04b} inst=0x{:08x}", op0, inst))
}

// ============================================================
// Data Processing — Immediate
// ============================================================

fn exec_dpimm(c: &mut Cpu, inst: u32) -> Result<(), String> {
    match (inst >> 23) & 0x7 {
        0 | 1 => exec_pcrel(c, inst),
        2 => exec_add_sub_imm(c, inst),
        4 => exec_log_imm(c, inst),
        5 => exec_move_wide(c, inst),
        6 => exec_bitfield(c, inst),
        7 => exec_extract(c, inst),
        op0 => Err(format!("unhandled DP-Imm op0={} inst=0x{:08x}", op0, inst)),
    }
}

fn exec_pcrel(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let rd = inst & 0x1F;
    let immhi = (inst >> 5) & 0x7FFFF;
    let immlo = (inst >> 29) & 0x3;
    let imm = sign_extend(((immhi << 2) | immlo) as u64, 21);
    if inst >> 31 != 0 {
        c.set_reg(rd, (c.pc & !0xFFF).wrapping_add(((imm as i64) << 12) as u64));
    } else {
        c.set_reg(rd, c.pc.wrapping_add(imm));
    }
    c.pc += 4;
    Ok(())
}

fn exec_add_sub_imm(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let op = (inst >> 30) & 1;
    let setf = (inst >> 29) & 1;
    let shift = (inst >> 22) & 3;
    let mut imm12 = ((inst >> 10) & 0xFFF) as u64;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let is64 = sf != 0;
    if shift == 1 {
        imm12 <<= 12;
    }
    let mut a = c.reg_sp(rn);
    if !is64 {
        a &= 0xFFFF_FFFF;
    }
    if setf != 0 {
        let (y, carry) = if op == 0 {
            (imm12, 0u64)
        } else if is64 {
            (!imm12, 1u64)
        } else {
            ((!(imm12 as u32)) as u64, 1u64)
        };
        let result;
        if is64 {
            let (r, n, z, cc, v) = add_with_carry64(a, y, carry);
            result = r;
            c.n = n;
            c.z = z;
            c.c = cc;
            c.v = v;
        } else {
            let (r32, n, z, cc, v) = add_with_carry32(a as u32, y as u32, carry as u32);
            result = r32 as u64;
            c.n = n;
            c.z = z;
            c.c = cc;
            c.v = v;
        }
        c.set_reg(rd, result);
    } else {
        let mut result = if op == 0 {
            a.wrapping_add(imm12)
        } else {
            a.wrapping_sub(imm12)
        };
        if !is64 {
            result &= 0xFFFF_FFFF;
        }
        c.set_reg_sp(rd, result);
    }
    c.pc += 4;
    Ok(())
}

fn exec_log_imm(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let opc = (inst >> 29) & 0x3;
    let n_bit = (inst >> 22) & 1;
    let immr = (inst >> 16) & 0x3F;
    let imms = (inst >> 10) & 0x3F;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let is64 = sf != 0;
    let (wmask, _) = decode_bit_masks(n_bit, imms, immr, is64);
    let mut a = c.reg(rn);
    if !is64 {
        a &= 0xFFFF_FFFF;
    }
    let mut result = match opc {
        0 | 3 => a & wmask,
        1 => a | wmask,
        2 => a ^ wmask,
        _ => 0,
    };
    if !is64 {
        result &= 0xFFFF_FFFF;
    }
    if opc == 3 {
        c.n = if is64 { result >> 63 != 0 } else { result >> 31 != 0 };
        c.z = result == 0;
        c.c = false;
        c.v = false;
        c.set_reg(rd, result);
    } else {
        c.set_reg_sp(rd, result);
    }
    c.pc += 4;
    Ok(())
}

fn exec_move_wide(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let opc = (inst >> 29) & 0x3;
    let hw = (inst >> 21) & 0x3;
    let imm16 = ((inst >> 5) & 0xFFFF) as u64;
    let rd = inst & 0x1F;
    let shift = hw * 16;
    match opc {
        0 => {
            let mut r = !(imm16 << shift);
            if sf == 0 {
                r &= 0xFFFF_FFFF;
            }
            c.set_reg(rd, r);
        }
        2 => c.set_reg(rd, imm16 << shift),
        3 => {
            let mask = 0xFFFFu64 << shift;
            c.set_reg(rd, (c.reg(rd) & !mask) | (imm16 << shift));
        }
        _ => return Err(format!("reserved move-wide opc={}", opc)),
    }
    c.pc += 4;
    Ok(())
}

fn exec_bitfield(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let opc = (inst >> 29) & 0x3;
    let n_bit = (inst >> 22) & 1;
    let immr = (inst >> 16) & 0x3F;
    let imms = (inst >> 10) & 0x3F;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let is64 = sf != 0;
    let (wmask, tmask) = decode_bit_masks(n_bit, imms, immr, is64);
    let datasize: u32 = if is64 { 64 } else { 32 };
    let mut src = c.reg(rn);
    if !is64 {
        src &= 0xFFFF_FFFF;
    }
    let r = immr;
    let rotated = if r == 0 {
        src
    } else {
        let mut x = (src >> r) | (src << (datasize - r));
        if !is64 {
            x &= 0xFFFF_FFFF;
        }
        x
    };
    match opc {
        0 => {
            // SBFM
            let bot = rotated & wmask;
            let mut top = 0u64;
            if (src >> imms) & 1 != 0 {
                top = !0u64;
                if !is64 {
                    top &= 0xFFFF_FFFF;
                }
            }
            let mut result = (top & !tmask) | (bot & tmask);
            if !is64 {
                result &= 0xFFFF_FFFF;
            }
            c.set_reg(rd, result);
        }
        1 => {
            // BFM
            let mut dst = c.reg(rd);
            if !is64 {
                dst &= 0xFFFF_FFFF;
            }
            let bot = (dst & !wmask) | (rotated & wmask);
            let mut result = (dst & !tmask) | (bot & tmask);
            if !is64 {
                result &= 0xFFFF_FFFF;
            }
            c.set_reg(rd, result);
        }
        2 => {
            // UBFM
            let mut result = (rotated & wmask) & tmask;
            if !is64 {
                result &= 0xFFFF_FFFF;
            }
            c.set_reg(rd, result);
        }
        _ => return Err(format!("reserved bitfield opc={}", opc)),
    }
    c.pc += 4;
    Ok(())
}

fn exec_extract(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let rm = (inst >> 16) & 0x1F;
    let imms = (inst >> 10) & 0x3F;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let is64 = sf != 0;
    let mut hi = c.reg(rn);
    let mut lo = c.reg(rm);
    let lsb = imms;
    let result = if is64 {
        if lsb == 0 {
            lo
        } else {
            (hi << (64 - lsb)) | (lo >> lsb)
        }
    } else {
        hi &= 0xFFFF_FFFF;
        lo &= 0xFFFF_FFFF;
        if lsb == 0 {
            lo
        } else {
            ((hi << (32 - lsb)) | (lo >> lsb)) & 0xFFFF_FFFF
        }
    };
    c.set_reg(rd, result);
    c.pc += 4;
    Ok(())
}

// ============================================================
// Data Processing — Register
// ============================================================

fn exec_dpreg(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let top5 = (inst >> 24) & 0x1F;
    match top5 {
        0x0A => exec_log_shift_reg(c, inst),
        0x0B => {
            if (inst >> 21) & 1 == 0 {
                exec_add_sub_shift_reg(c, inst)
            } else {
                exec_add_sub_ext_reg(c, inst)
            }
        }
        0x1A => exec_dp_11010(c, inst),
        0x1B => exec_dp_3src(c, inst),
        _ => Err(format!("unhandled DP-Reg top5=0x{:02x} inst=0x{:08x}", top5, inst)),
    }
}

fn exec_log_shift_reg(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let opc = (inst >> 29) & 0x3;
    let shift_type = (inst >> 22) & 0x3;
    let n_bit = (inst >> 21) & 1;
    let rm = (inst >> 16) & 0x1F;
    let imm6 = (inst >> 10) & 0x3F;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let is64 = sf != 0;
    let mut a = c.reg(rn);
    let mut b = shift_val(c.reg(rm), shift_type, imm6, is64);
    if n_bit != 0 {
        b = !b;
        if !is64 {
            b &= 0xFFFF_FFFF;
        }
    }
    if !is64 {
        a &= 0xFFFF_FFFF;
    }
    let mut result = match opc {
        0 | 3 => a & b,
        1 => a | b,
        2 => a ^ b,
        _ => 0,
    };
    if !is64 {
        result &= 0xFFFF_FFFF;
    }
    if opc == 3 {
        c.n = if is64 { (result >> 63) != 0 } else { (result >> 31) != 0 };
        c.z = result == 0;
        c.c = false;
        c.v = false;
    }
    c.set_reg(rd, result);
    c.pc += 4;
    Ok(())
}

fn exec_add_sub_shift_reg(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let op = (inst >> 30) & 1;
    let setf = (inst >> 29) & 1;
    let shift_type = (inst >> 22) & 0x3;
    let rm = (inst >> 16) & 0x1F;
    let imm6 = (inst >> 10) & 0x3F;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let is64 = sf != 0;
    let mut a = c.reg(rn);
    let mut b = shift_val(c.reg(rm), shift_type, imm6, is64);
    if !is64 {
        a &= 0xFFFF_FFFF;
        b &= 0xFFFF_FFFF;
    }
    let (y, carry) = if op == 0 {
        (b, 0u64)
    } else if is64 {
        (!b, 1u64)
    } else {
        ((!(b as u32)) as u64, 1u64)
    };
    if setf != 0 {
        let result;
        if is64 {
            let (r, n, z, cc, v) = add_with_carry64(a, y, carry);
            result = r;
            c.n = n;
            c.z = z;
            c.c = cc;
            c.v = v;
        } else {
            let (r32, n, z, cc, v) = add_with_carry32(a as u32, y as u32, carry as u32);
            result = r32 as u64;
            c.n = n;
            c.z = z;
            c.c = cc;
            c.v = v;
        }
        c.set_reg(rd, result);
    } else {
        let mut result = if op == 0 {
            a.wrapping_add(b)
        } else {
            a.wrapping_sub(b)
        };
        if !is64 {
            result &= 0xFFFF_FFFF;
        }
        c.set_reg(rd, result);
    }
    c.pc += 4;
    Ok(())
}

fn exec_add_sub_ext_reg(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let op = (inst >> 30) & 1;
    let setf = (inst >> 29) & 1;
    let rm = (inst >> 16) & 0x1F;
    let option = (inst >> 13) & 0x7;
    let imm3 = (inst >> 10) & 0x7;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let is64 = sf != 0;
    let mut a = c.reg_sp(rn);
    let rm_val = c.reg(rm);
    let mut extended = match option {
        0 => rm_val & 0xFF,
        1 => rm_val & 0xFFFF,
        2 => rm_val & 0xFFFF_FFFF,
        3 => rm_val,
        4 => sign_extend(rm_val & 0xFF, 8),
        5 => sign_extend(rm_val & 0xFFFF, 16),
        6 => sign_extend(rm_val & 0xFFFF_FFFF, 32),
        7 => rm_val,
        _ => 0,
    };
    extended <<= imm3;
    if !is64 {
        a &= 0xFFFF_FFFF;
        extended &= 0xFFFF_FFFF;
    }
    if setf != 0 {
        let (y, carry) = if op == 0 {
            (extended, 0u64)
        } else if is64 {
            (!extended, 1u64)
        } else {
            ((!(extended as u32)) as u64, 1u64)
        };
        let result;
        if is64 {
            let (r, n, z, cc, v) = add_with_carry64(a, y, carry);
            result = r;
            c.n = n;
            c.z = z;
            c.c = cc;
            c.v = v;
        } else {
            let (r32, n, z, cc, v) = add_with_carry32(a as u32, y as u32, carry as u32);
            result = r32 as u64;
            c.n = n;
            c.z = z;
            c.c = cc;
            c.v = v;
        }
        c.set_reg(rd, result);
    } else {
        let mut result = if op == 0 {
            a.wrapping_add(extended)
        } else {
            a.wrapping_sub(extended)
        };
        if !is64 {
            result &= 0xFFFF_FFFF;
        }
        c.set_reg_sp(rd, result);
    }
    c.pc += 4;
    Ok(())
}

fn exec_dp_11010(c: &mut Cpu, inst: u32) -> Result<(), String> {
    match (inst >> 21) & 7 {
        2 | 3 => exec_cond_compare(c, inst),
        4 => exec_cond_select(c, inst),
        6 => {
            if (inst >> 30) & 1 == 1 {
                exec_dp_1src(c, inst)
            } else {
                exec_dp_2src(c, inst)
            }
        }
        b => Err(format!("unhandled 11010 sub={} inst=0x{:08x}", b, inst)),
    }
}

fn exec_cond_compare(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let op = (inst >> 30) & 1;
    let rm = (inst >> 16) & 0x1F;
    let cond = (inst >> 12) & 0xF;
    let rn = (inst >> 5) & 0x1F;
    let nzcv = inst & 0xF;
    let is64 = sf != 0;
    let is_imm = (inst >> 11) & 1 != 0;
    if c.cond_holds(cond) {
        let mut a = c.reg(rn);
        let mut b = if is_imm { rm as u64 } else { c.reg(rm) };
        if !is64 {
            a &= 0xFFFF_FFFF;
            b &= 0xFFFF_FFFF;
        }
        let (y, carry) = if op == 1 {
            if is64 {
                (!b, 1u64)
            } else {
                ((!(b as u32)) as u64, 1u64)
            }
        } else {
            (b, 0u64)
        };
        if is64 {
            let (_, n, z, cc, v) = add_with_carry64(a, y, carry);
            c.n = n;
            c.z = z;
            c.c = cc;
            c.v = v;
        } else {
            let (_, n, z, cc, v) = add_with_carry32(a as u32, y as u32, carry as u32);
            c.n = n;
            c.z = z;
            c.c = cc;
            c.v = v;
        }
    } else {
        c.n = (nzcv >> 3) & 1 != 0;
        c.z = (nzcv >> 2) & 1 != 0;
        c.c = (nzcv >> 1) & 1 != 0;
        c.v = nzcv & 1 != 0;
    }
    c.pc += 4;
    Ok(())
}

fn exec_cond_select(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let op = (inst >> 30) & 1;
    let rm = (inst >> 16) & 0x1F;
    let cond = (inst >> 12) & 0xF;
    let op2 = (inst >> 10) & 0x3;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let is64 = sf != 0;
    let a = c.reg(rn);
    let b = c.reg(rm);
    let mut result = if c.cond_holds(cond) {
        a
    } else {
        match (op << 1) | (op2 & 1) {
            0 => b,
            1 => b.wrapping_add(1),
            2 => !b,
            3 => b.wrapping_neg(),
            _ => 0,
        }
    };
    if !is64 {
        result &= 0xFFFF_FFFF;
    }
    c.set_reg(rd, result);
    c.pc += 4;
    Ok(())
}

fn exec_dp_2src(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let rm = (inst >> 16) & 0x1F;
    let opcode = (inst >> 10) & 0x3F;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let is64 = sf != 0;
    let mut a = c.reg(rn);
    let mut b = c.reg(rm);
    if !is64 {
        a &= 0xFFFF_FFFF;
        b &= 0xFFFF_FFFF;
    }
    let mut result = match opcode {
        2 => {
            // UDIV
            if b == 0 {
                0
            } else if is64 {
                a / b
            } else {
                ((a as u32) / (b as u32)) as u64
            }
        }
        3 => {
            // SDIV
            if b == 0 {
                0
            } else if is64 {
                ((a as i64).wrapping_div(b as i64)) as u64
            } else {
                ((a as u32 as i32).wrapping_div(b as u32 as i32) as u32) as u64
            }
        }
        8 => {
            let mask = if is64 { 63u64 } else { 31 };
            a << (b & mask)
        }
        9 => {
            let mask = if is64 { 63u64 } else { 31 };
            a >> (b & mask)
        }
        10 => {
            let mask = if is64 { 63u64 } else { 31 };
            let shift = b & mask;
            if is64 {
                ((a as i64) >> shift) as u64
            } else {
                (((a as u32 as i32) >> shift) as u32) as u64
            }
        }
        11 => {
            let bits = if is64 { 64u64 } else { 32 };
            let shift = b % bits;
            if shift == 0 {
                a
            } else {
                (a >> shift) | (a << (bits - shift))
            }
        }
        _ => return Err(format!("unhandled DP-2-source opcode={} inst=0x{:08x}", opcode, inst)),
    };
    if !is64 {
        result &= 0xFFFF_FFFF;
    }
    c.set_reg(rd, result);
    c.pc += 4;
    Ok(())
}

fn exec_dp_1src(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let opcode = (inst >> 10) & 0x3F;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let is64 = sf != 0;
    let val = c.reg(rn);
    let mut result = match opcode {
        0 => {
            if is64 {
                rbit64(val)
            } else {
                rbit32(val as u32) as u64
            }
        }
        1 => {
            if is64 {
                rev16_64(val)
            } else {
                rev16_32(val as u32) as u64
            }
        }
        2 => {
            if is64 {
                let lo = rev32(val as u32);
                let hi = rev32((val >> 32) as u32);
                (lo as u64) | ((hi as u64) << 32)
            } else {
                rev32(val as u32) as u64
            }
        }
        3 => rev64(val),
        4 => {
            if is64 {
                clz64(val) as u64
            } else {
                clz32(val as u32) as u64
            }
        }
        _ => return Err(format!("unhandled DP-1-source opcode={} inst=0x{:08x}", opcode, inst)),
    };
    if !is64 {
        result &= 0xFFFF_FFFF;
    }
    c.set_reg(rd, result);
    c.pc += 4;
    Ok(())
}

fn exec_dp_3src(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let op31 = (inst >> 21) & 0x7;
    let rm = (inst >> 16) & 0x1F;
    let o0 = (inst >> 15) & 1;
    let ra = (inst >> 10) & 0x1F;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let is64 = sf != 0;
    let mut a = c.reg(rn);
    let mut b = c.reg(rm);
    let addend = c.reg(ra);
    let result = match op31 {
        0 => {
            if !is64 {
                a &= 0xFFFF_FFFF;
                b &= 0xFFFF_FFFF;
            }
            let prod = a.wrapping_mul(b);
            let mut r = if o0 == 0 {
                addend.wrapping_add(prod)
            } else {
                addend.wrapping_sub(prod)
            };
            if !is64 {
                r &= 0xFFFF_FFFF;
            }
            r
        }
        1 => {
            // SMADDL/SMSUBL
            let prod = (a as u32 as i32 as i64).wrapping_mul(b as u32 as i32 as i64) as u64;
            if o0 == 0 {
                addend.wrapping_add(prod)
            } else {
                addend.wrapping_sub(prod)
            }
        }
        2 => smulhi64(a, b),
        5 => {
            // UMADDL/UMSUBL
            let prod = (a as u32 as u64).wrapping_mul(b as u32 as u64);
            if o0 == 0 {
                addend.wrapping_add(prod)
            } else {
                addend.wrapping_sub(prod)
            }
        }
        6 => mulhi64(a, b),
        _ => return Err(format!("unhandled DP-3 op31={} inst=0x{:08x}", op31, inst)),
    };
    c.set_reg(rd, result);
    c.pc += 4;
    Ok(())
}

// ============================================================
// Branches
// ============================================================

fn exec_branch(c: &mut Cpu, _m: &mut Mem, inst: u32) -> Result<(), String> {
    let top6 = (inst >> 26) & 0x3F;
    match top6 {
        0x05 => return exec_b_uncond(c, inst, false),
        0x25 => return exec_b_uncond(c, inst, true),
        _ => {}
    }
    if (inst >> 25) & 0x3F == 0x1A {
        return exec_cbx(c, inst);
    }
    if (inst >> 25) & 0x7F == 0x2A {
        return exec_b_cond(c, inst);
    }
    if (inst >> 25) & 0x7F == 0x6B {
        return exec_branch_reg(c, inst);
    }
    if (inst >> 25) & 0x3F == 0x1B {
        return exec_tbx(c, inst);
    }
    Err(format!("unhandled branch inst=0x{:08x}", inst))
}

fn exec_b_uncond(c: &mut Cpu, inst: u32, link: bool) -> Result<(), String> {
    let imm26 = sign_extend((inst & 0x3FF_FFFF) as u64, 26);
    if link {
        c.x[30] = c.pc + 4;
    }
    c.pc = c.pc.wrapping_add(imm26.wrapping_mul(4));
    Ok(())
}

fn exec_b_cond(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let imm19 = sign_extend(((inst >> 5) & 0x7FFFF) as u64, 19);
    let cond = inst & 0xF;
    if c.cond_holds(cond) {
        c.pc = c.pc.wrapping_add(imm19.wrapping_mul(4));
    } else {
        c.pc += 4;
    }
    Ok(())
}

fn exec_cbx(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let sf = inst >> 31;
    let op = (inst >> 24) & 1;
    let imm19 = sign_extend(((inst >> 5) & 0x7FFFF) as u64, 19);
    let rt = inst & 0x1F;
    let mut val = c.reg(rt);
    if sf == 0 {
        val &= 0xFFFF_FFFF;
    }
    let take = if op == 0 { val == 0 } else { val != 0 };
    if take {
        c.pc = c.pc.wrapping_add(imm19.wrapping_mul(4));
    } else {
        c.pc += 4;
    }
    Ok(())
}

fn exec_branch_reg(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let opc = (inst >> 21) & 0xF;
    let rn = (inst >> 5) & 0x1F;
    let mut target = c.reg(rn);
    if rn == 31 {
        target = 0;
    }
    match opc {
        0 => c.pc = target,
        1 => {
            c.x[30] = c.pc + 4;
            c.pc = target;
        }
        2 => {
            c.pc = c.x[30];
            if rn != 30 {
                c.pc = c.reg(rn);
            }
        }
        _ => return Err(format!("unhandled branch-reg opc={} inst=0x{:08x}", opc, inst)),
    }
    Ok(())
}

fn exec_tbx(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let op = (inst >> 24) & 1; // 0=TBZ, 1=TBNZ
    let b5 = (inst >> 31) & 1;
    let b40 = (inst >> 19) & 0x1F;
    let bit = (b5 << 5) | b40;
    let imm14 = sign_extend(((inst >> 5) & 0x3FFF) as u64, 14);
    let rt = inst & 0x1F;
    let val = c.reg(rt);
    let bit_set = (val >> bit) & 1 != 0;
    let take = if op == 0 { !bit_set } else { bit_set };
    if take {
        c.pc = c.pc.wrapping_add(imm14.wrapping_mul(4));
    } else {
        c.pc += 4;
    }
    Ok(())
}

// ============================================================
// Loads and Stores
// ============================================================

fn exec_load_store(c: &mut Cpu, m: &mut Mem, inst: u32) -> Result<(), String> {
    let op1 = (inst >> 27) & 7;
    let v = (inst >> 26) & 1;
    if op1 == 5 && v == 0 {
        return exec_ldst_pair(c, m, inst);
    }
    if op1 == 5 && v == 1 {
        return exec_ldst_pair_simd(c, m, inst);
    }
    if op1 == 7 && v == 0 {
        if (inst >> 24) & 1 == 1 {
            return exec_ldst_unsigned(c, m, inst);
        }
        if (inst >> 21) & 1 == 1 {
            return exec_ldst_reg_off(c, m, inst);
        }
        return exec_ldst_imm9(c, m, inst);
    }
    if op1 == 7 && v == 1 {
        if (inst >> 24) & 1 == 1 {
            return exec_ldst_simd_unsigned(c, m, inst);
        }
        return exec_ldst_simd_imm9(c, m, inst);
    }
    if op1 == 3 && v == 0 {
        return exec_ldr_literal(c, m, inst);
    }
    if op1 == 3 && v == 1 {
        return exec_ldr_simd_literal(c, m, inst);
    }
    Err(format!("unhandled load/store op1={} v={} inst=0x{:08x}", op1, v, inst))
}

fn do_load_store(
    c: &mut Cpu,
    m: &mut Mem,
    size: u32,
    opc: u32,
    addr: u64,
    rt: u32,
) -> Result<(), String> {
    match opc {
        0 => match size {
            // STR
            0 => m.write8(addr, c.reg(rt) as u8),
            1 => m.write16(addr, c.reg(rt) as u16),
            2 => m.write32(addr, c.reg(rt) as u32),
            3 => m.write64(addr, c.reg(rt)),
            _ => {}
        },
        1 => {
            // LDR zero-extend
            let val = match size {
                0 => m.read8(addr) as u64,
                1 => m.read16(addr) as u64,
                2 => m.read32(addr) as u64,
                3 => m.read64(addr),
                _ => 0,
            };
            c.set_reg(rt, val);
        }
        2 => match size {
            // LDRS 64-bit sign-extend
            0 => {
                let v = sign_extend(m.read8(addr) as u64, 8);
                c.set_reg(rt, v);
            }
            1 => {
                let v = sign_extend(m.read16(addr) as u64, 16);
                c.set_reg(rt, v);
            }
            2 => {
                let v = sign_extend(m.read32(addr) as u64, 32);
                c.set_reg(rt, v);
            }
            _ => {} // PRFM nop
        },
        3 => match size {
            // LDRS 32-bit
            0 => {
                let v = ((m.read8(addr) as i8) as i32 as u32) as u64;
                c.set_reg(rt, v);
            }
            1 => {
                let v = ((m.read16(addr) as i16) as i32 as u32) as u64;
                c.set_reg(rt, v);
            }
            _ => {}
        },
        _ => {}
    }
    c.pc += 4;
    Ok(())
}

fn exec_ldst_unsigned(c: &mut Cpu, m: &mut Mem, inst: u32) -> Result<(), String> {
    let size = (inst >> 30) & 3;
    let opc = (inst >> 22) & 3;
    let imm12 = ((inst >> 10) & 0xFFF) as u64;
    let rn = (inst >> 5) & 0x1F;
    let rt = inst & 0x1F;
    let offset = imm12 * (1u64 << size);
    let addr = c.reg_sp(rn).wrapping_add(offset);
    do_load_store(c, m, size, opc, addr, rt)
}

fn exec_ldst_imm9(c: &mut Cpu, m: &mut Mem, inst: u32) -> Result<(), String> {
    let size = (inst >> 30) & 3;
    let opc = (inst >> 22) & 3;
    let imm9 = sign_extend(((inst >> 12) & 0x1FF) as u64, 9);
    let idx_type = (inst >> 10) & 3;
    let rn = (inst >> 5) & 0x1F;
    let rt = inst & 0x1F;
    let base = c.reg_sp(rn);
    let addr = match idx_type {
        0 => base.wrapping_add(imm9),
        1 => {
            c.set_reg_sp(rn, base.wrapping_add(imm9));
            base
        }
        3 => {
            let a = base.wrapping_add(imm9);
            c.set_reg_sp(rn, a);
            a
        }
        _ => return Err(format!("reserved ldst idxType={}", idx_type)),
    };
    do_load_store(c, m, size, opc, addr, rt)
}

fn exec_ldst_reg_off(c: &mut Cpu, m: &mut Mem, inst: u32) -> Result<(), String> {
    let size = (inst >> 30) & 3;
    let opc = (inst >> 22) & 3;
    let rm = (inst >> 16) & 0x1F;
    let option = (inst >> 13) & 7;
    let s = (inst >> 12) & 1;
    let rn = (inst >> 5) & 0x1F;
    let rt = inst & 0x1F;
    let base = c.reg_sp(rn);
    let mut offset = c.reg(rm);
    match option {
        2 => offset &= 0xFFFF_FFFF,
        6 => offset = sign_extend(offset & 0xFFFF_FFFF, 32),
        _ => {} // 3=LSL, 7=SXTX
    }
    if s != 0 {
        offset <<= size;
    }
    do_load_store(c, m, size, opc, base.wrapping_add(offset), rt)
}

fn exec_ldst_pair(c: &mut Cpu, m: &mut Mem, inst: u32) -> Result<(), String> {
    let opc = (inst >> 30) & 3;
    let pair_type = (inst >> 23) & 7;
    let load = (inst >> 22) & 1;
    let imm7 = sign_extend(((inst >> 15) & 0x7F) as u64, 7);
    let rt2 = (inst >> 10) & 0x1F;
    let rn = (inst >> 5) & 0x1F;
    let rt = inst & 0x1F;
    let scale = match opc {
        0 => 4u64,
        1 => 4,
        2 => 8,
        _ => return Err(format!("reserved LDP/STP opc={}", opc)),
    };
    let offset = imm7.wrapping_mul(scale);
    let base = c.reg_sp(rn);
    let addr = match pair_type {
        1 => {
            c.set_reg_sp(rn, base.wrapping_add(offset));
            base
        }
        2 => base.wrapping_add(offset),
        3 => {
            let a = base.wrapping_add(offset);
            c.set_reg_sp(rn, a);
            a
        }
        _ => return Err(format!("reserved LDP/STP type={}", pair_type)),
    };
    if load != 0 {
        match opc {
            0 => {
                let v1 = m.read32(addr) as u64;
                let v2 = m.read32(addr + 4) as u64;
                c.set_reg(rt, v1);
                c.set_reg(rt2, v2);
            }
            1 => {
                let v1 = sign_extend(m.read32(addr) as u64, 32);
                let v2 = sign_extend(m.read32(addr + 4) as u64, 32);
                c.set_reg(rt, v1);
                c.set_reg(rt2, v2);
            }
            2 => {
                let v1 = m.read64(addr);
                let v2 = m.read64(addr + 8);
                c.set_reg(rt, v1);
                c.set_reg(rt2, v2);
            }
            _ => {}
        }
    } else {
        match opc {
            0 => {
                m.write32(addr, c.reg(rt) as u32);
                m.write32(addr + 4, c.reg(rt2) as u32);
            }
            2 => {
                m.write64(addr, c.reg(rt));
                m.write64(addr + 8, c.reg(rt2));
            }
            _ => {}
        }
    }
    c.pc += 4;
    Ok(())
}

fn exec_ldr_literal(c: &mut Cpu, m: &mut Mem, inst: u32) -> Result<(), String> {
    let opc = (inst >> 30) & 3;
    let imm19 = sign_extend(((inst >> 5) & 0x7FFFF) as u64, 19);
    let rt = inst & 0x1F;
    let addr = c.pc.wrapping_add(imm19.wrapping_mul(4));
    match opc {
        0 => {
            let v = m.read32(addr) as u64;
            c.set_reg(rt, v);
        }
        1 => {
            let v = m.read64(addr);
            c.set_reg(rt, v);
        }
        2 => {
            let v = sign_extend(m.read32(addr) as u64, 32);
            c.set_reg(rt, v);
        }
        _ => {}
    }
    c.pc += 4;
    Ok(())
}

// ============================================================
// SIMD / Floating-Point
// ============================================================

fn exec_simd(c: &mut Cpu, _m: &mut Mem, inst: u32) -> Result<(), String> {
    // FMOV Dd, Xn
    if inst & 0xFFFFFC00 == 0x9E670000 {
        let rn = (inst >> 5) & 0x1F;
        let rd = inst & 0x1F;
        let v = c.reg(rn);
        c.vreg[rd as usize] = [v, 0];
        c.pc += 4;
        return Ok(());
    }
    // FMOV Xd, Dn
    if inst & 0xFFFFFC00 == 0x9E660000 {
        let rn = (inst >> 5) & 0x1F;
        let rd = inst & 0x1F;
        let v = c.vreg[rn as usize][0];
        c.set_reg(rd, v);
        c.pc += 4;
        return Ok(());
    }
    // FMOV Vd.D[1], Xn
    if inst & 0xFFFFFC00 == 0x9EAF0000 {
        let rn = (inst >> 5) & 0x1F;
        let rd = inst & 0x1F;
        let v = c.reg(rn);
        c.vreg[rd as usize][1] = v;
        c.pc += 4;
        return Ok(());
    }
    // FMOV Xd, Vn.D[1]
    if inst & 0xFFFFFC00 == 0x9EAE0000 {
        let rn = (inst >> 5) & 0x1F;
        let rd = inst & 0x1F;
        let v = c.vreg[rn as usize][1];
        c.set_reg(rd, v);
        c.pc += 4;
        return Ok(());
    }
    // FMOV Sd, Wn
    if inst & 0xFFFFFC00 == 0x1E270000 {
        let rn = (inst >> 5) & 0x1F;
        let rd = inst & 0x1F;
        let v = (c.reg(rn) as u32) as u64;
        c.vreg[rd as usize] = [v, 0];
        c.pc += 4;
        return Ok(());
    }
    // FMOV Wd, Sn
    if inst & 0xFFFFFC00 == 0x1E260000 {
        let rn = (inst >> 5) & 0x1F;
        let rd = inst & 0x1F;
        let v = (c.vreg[rn as usize][0] as u32) as u64;
        c.set_reg(rd, v);
        c.pc += 4;
        return Ok(());
    }
    if inst & 0xBFE0FC00 == 0x0E000C00 {
        return exec_dup(c, inst);
    }
    if inst & 0xBFE0FC00 == 0x0E003C00 {
        return exec_umov(c, inst);
    }
    if inst & 0xBFE0FC00 == 0x0E001C00 {
        return exec_ins(c, inst);
    }
    if inst & 0xBF80FC00 == 0x0F005400 {
        return exec_shl(c, inst);
    }
    if inst & 0x9FF80400 == 0x0F000400 {
        return exec_movi(c, inst);
    }
    if inst & 0xBF3FFC00 == 0x0E212800 {
        return exec_xtn(c, inst);
    }
    if inst & 0xBFE08400 == 0x2E000000 {
        return exec_ext(c, inst);
    }
    if inst & 0xBF3FFC00 == 0x0E200800 {
        return exec_rev64_vec(c, inst);
    }
    if inst & 0x9F200400 == 0x0E200400 {
        return exec_adv_simd_3same(c, inst);
    }
    // FMOV scalar imm
    if inst & 0x9F01FC00 == 0x1E201000 {
        let rd = inst & 0x1F;
        let imm8 = (inst >> 13) & 0xFF;
        c.vreg[rd as usize] = [vfp_expand_imm64(imm8), 0];
        c.pc += 4;
        return Ok(());
    }
    Err(format!("unhandled SIMD inst=0x{:08x}", inst))
}

fn exec_dup(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let q = (inst >> 30) & 1;
    let imm5 = (inst >> 16) & 0x1F;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let val = c.reg(rn);
    let mut result = [0u64; 2];
    if imm5 & 1 == 1 {
        let b = val as u8 as u64;
        for i in 0..8 {
            result[0] |= b << (i * 8);
        }
        if q != 0 {
            result[1] = result[0];
        }
    } else if imm5 & 3 == 2 {
        let h = val as u16 as u64;
        for i in 0..4 {
            result[0] |= h << (i * 16);
        }
        if q != 0 {
            result[1] = result[0];
        }
    } else if imm5 & 7 == 4 {
        let s = val as u32 as u64;
        result[0] = s | (s << 32);
        if q != 0 {
            result[1] = result[0];
        }
    } else if imm5 & 15 == 8 {
        result[0] = val;
        if q != 0 {
            result[1] = val;
        }
    }
    c.vreg[rd as usize] = result;
    c.pc += 4;
    Ok(())
}

fn exec_umov(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let imm5 = (inst >> 16) & 0x1F;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let lo = c.vreg[rn as usize][0];
    let hi = c.vreg[rn as usize][1];
    let val = if imm5 & 1 == 1 {
        let idx = imm5 >> 1;
        if idx < 8 {
            (lo >> (idx * 8)) & 0xFF
        } else {
            (hi >> ((idx - 8) * 8)) & 0xFF
        }
    } else if imm5 & 3 == 2 {
        let idx = imm5 >> 2;
        if idx < 4 {
            (lo >> (idx * 16)) & 0xFFFF
        } else {
            (hi >> ((idx - 4) * 16)) & 0xFFFF
        }
    } else if imm5 & 7 == 4 {
        let idx = imm5 >> 3;
        match idx {
            0 => lo & 0xFFFF_FFFF,
            1 => lo >> 32,
            2 => hi & 0xFFFF_FFFF,
            _ => hi >> 32,
        }
    } else if imm5 & 15 == 8 {
        let idx = imm5 >> 4;
        if idx == 0 {
            lo
        } else {
            hi
        }
    } else {
        0
    };
    c.set_reg(rd, val);
    c.pc += 4;
    Ok(())
}

fn exec_ins(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let imm5 = (inst >> 16) & 0x1F;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let val = c.reg(rn);
    let mut lo = c.vreg[rd as usize][0];
    let mut hi = c.vreg[rd as usize][1];
    if imm5 & 1 == 1 {
        let idx = imm5 >> 1;
        if idx < 8 {
            let shift = idx * 8;
            lo = (lo & !(0xFFu64 << shift)) | ((val & 0xFF) << shift);
        } else {
            let shift = (idx - 8) * 8;
            hi = (hi & !(0xFFu64 << shift)) | ((val & 0xFF) << shift);
        }
    } else if imm5 & 3 == 2 {
        let idx = imm5 >> 2;
        if idx < 4 {
            let shift = idx * 16;
            lo = (lo & !(0xFFFFu64 << shift)) | ((val & 0xFFFF) << shift);
        } else {
            let shift = (idx - 4) * 16;
            hi = (hi & !(0xFFFFu64 << shift)) | ((val & 0xFFFF) << shift);
        }
    } else if imm5 & 7 == 4 {
        let idx = imm5 >> 3;
        if idx < 2 {
            let shift = idx * 32;
            lo = (lo & !(0xFFFFFFFFu64 << shift)) | ((val & 0xFFFFFFFF) << shift);
        } else {
            let shift = (idx - 2) * 32;
            hi = (hi & !(0xFFFFFFFFu64 << shift)) | ((val & 0xFFFFFFFF) << shift);
        }
    } else if imm5 & 15 == 8 {
        let idx = imm5 >> 4;
        if idx == 0 {
            lo = val;
        } else {
            hi = val;
        }
    }
    c.vreg[rd as usize] = [lo, hi];
    c.pc += 4;
    Ok(())
}

fn exec_shl(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let q = (inst >> 30) & 1;
    let immh = (inst >> 19) & 0xF;
    let immb = (inst >> 16) & 0x7;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let immhb = (immh << 3) | immb;
    let src_lo = c.vreg[rn as usize][0];
    let src_hi = c.vreg[rn as usize][1];
    let mut dst_lo = 0u64;
    let mut dst_hi = 0u64;
    if immh & 0x8 != 0 {
        let shift = immhb - 64;
        dst_lo = src_lo << shift;
        if q != 0 {
            dst_hi = src_hi << shift;
        }
    } else if immh & 0xC == 0x4 {
        let shift = immhb - 32;
        let lo0 = (src_lo & 0xFFFFFFFF) << shift;
        let lo1 = ((src_lo >> 32) & 0xFFFFFFFF) << shift;
        dst_lo = (lo0 & 0xFFFFFFFF) | ((lo1 & 0xFFFFFFFF) << 32);
        if q != 0 {
            let hi0 = (src_hi & 0xFFFFFFFF) << shift;
            let hi1 = ((src_hi >> 32) & 0xFFFFFFFF) << shift;
            dst_hi = (hi0 & 0xFFFFFFFF) | ((hi1 & 0xFFFFFFFF) << 32);
        }
    } else if immh & 0xE == 0x2 {
        let shift = immhb - 16;
        for i in 0..4u32 {
            let elem = (src_lo >> (i * 16)) & 0xFFFF;
            dst_lo |= ((elem << shift) & 0xFFFF) << (i * 16);
        }
        if q != 0 {
            for i in 0..4u32 {
                let elem = (src_hi >> (i * 16)) & 0xFFFF;
                dst_hi |= ((elem << shift) & 0xFFFF) << (i * 16);
            }
        }
    } else if immh & 0xF == 0x1 {
        let shift = immhb - 8;
        for i in 0..8u32 {
            let elem = (src_lo >> (i * 8)) & 0xFF;
            dst_lo |= ((elem << shift) & 0xFF) << (i * 8);
        }
        if q != 0 {
            for i in 0..8u32 {
                let elem = (src_hi >> (i * 8)) & 0xFF;
                dst_hi |= ((elem << shift) & 0xFF) << (i * 8);
            }
        }
    }
    c.vreg[rd as usize] = [dst_lo, dst_hi];
    c.pc += 4;
    Ok(())
}

fn exec_movi(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let q = (inst >> 30) & 1;
    let op = (inst >> 29) & 1;
    let cmode = (inst >> 12) & 0xF;
    let rd = inst & 0x1F;
    let a = (inst >> 18) & 1;
    let b = (inst >> 17) & 1;
    let cc = (inst >> 16) & 1;
    let d = (inst >> 9) & 1;
    let e = (inst >> 8) & 1;
    let f = (inst >> 7) & 1;
    let g = (inst >> 6) & 1;
    let h = (inst >> 5) & 1;
    let imm8 = (a << 7) | (b << 6) | (cc << 5) | (d << 4) | (e << 3) | (f << 2) | (g << 1) | h;
    let mut imm64 = 0u64;
    if cmode <= 7 {
        // 32-bit shifted (even & odd sub-cases identical)
        let shift = (cmode / 2) * 8;
        let mut elem = (imm8 as u64) << shift;
        if op == 1 {
            elem = !elem & 0xFFFFFFFF;
        }
        imm64 = elem | (elem << 32);
    } else if cmode == 0x8 || cmode == 0x9 {
        let shift = (cmode & 1) * 8;
        let mut elem = (imm8 as u64) << shift;
        if op == 1 {
            elem = !elem & 0xFFFF;
        }
        for i in 0..4 {
            imm64 |= (elem & 0xFFFF) << (i * 16);
        }
    } else if cmode == 0xA || cmode == 0xB || cmode == 0xC || cmode == 0xD {
        let shift = (cmode & 1) * 8;
        let mut elem = if shift == 0 {
            ((imm8 as u64) << 8) | 0xFF
        } else {
            ((imm8 as u64) << 16) | 0xFFFF
        };
        if op == 1 {
            elem = !elem & 0xFFFFFFFF;
        }
        imm64 = elem | (elem << 32);
    } else if cmode == 0xE {
        if op == 0 {
            for i in 0..8 {
                imm64 |= (imm8 as u64) << (i * 8);
            }
        } else {
            for i in 0..8 {
                if (imm8 >> i) & 1 != 0 {
                    imm64 |= 0xFFu64 << (i * 8);
                }
            }
        }
    } else if cmode == 0xF {
        if op == 0 {
            imm64 = vfp_expand_imm32(imm8) as u64;
            imm64 = imm64 | (imm64 << 32);
        } else {
            imm64 = vfp_expand_imm64(imm8);
        }
    }
    c.vreg[rd as usize][0] = imm64;
    c.vreg[rd as usize][1] = if q != 0 { imm64 } else { 0 };
    c.pc += 4;
    Ok(())
}

fn exec_xtn(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let q = (inst >> 30) & 1;
    let size = (inst >> 22) & 3;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let src_lo = c.vreg[rn as usize][0];
    let src_hi = c.vreg[rn as usize][1];
    let mut narrow = 0u64;
    match size {
        0 => {
            for i in 0..4u32 {
                narrow |= ((src_lo >> (i * 16)) & 0xFF) << (i * 8);
            }
            for i in 0..4u32 {
                narrow |= ((src_hi >> (i * 16)) & 0xFF) << ((i + 4) * 8);
            }
        }
        1 => {
            for i in 0..2u32 {
                narrow |= ((src_lo >> (i * 32)) & 0xFFFF) << (i * 16);
            }
            for i in 0..2u32 {
                narrow |= ((src_hi >> (i * 32)) & 0xFFFF) << ((i + 2) * 16);
            }
        }
        2 => {
            narrow = (src_lo & 0xFFFFFFFF) | ((src_hi & 0xFFFFFFFF) << 32);
        }
        _ => {}
    }
    if q == 0 {
        c.vreg[rd as usize] = [narrow, 0];
    } else {
        c.vreg[rd as usize][1] = narrow;
    }
    c.pc += 4;
    Ok(())
}

fn exec_ext(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let rm = (inst >> 16) & 0x1F;
    let imm4 = (inst >> 11) & 0xF;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let mut src = [0u8; 32];
    let lo = c.vreg[rn as usize][0];
    let hi = c.vreg[rn as usize][1];
    for i in 0..8 {
        src[i] = (lo >> (i * 8)) as u8;
        src[i + 8] = (hi >> (i * 8)) as u8;
    }
    let lo2 = c.vreg[rm as usize][0];
    let hi2 = c.vreg[rm as usize][1];
    for i in 0..8 {
        src[i + 16] = (lo2 >> (i * 8)) as u8;
        src[i + 24] = (hi2 >> (i * 8)) as u8;
    }
    let mut dst_lo = 0u64;
    let mut dst_hi = 0u64;
    for i in 0..8 {
        dst_lo |= (src[imm4 as usize + i] as u64) << (i * 8);
        dst_hi |= (src[imm4 as usize + i + 8] as u64) << (i * 8);
    }
    c.vreg[rd as usize] = [dst_lo, dst_hi];
    c.pc += 4;
    Ok(())
}

fn exec_rev64_vec(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let q = (inst >> 30) & 1;
    let size = (inst >> 22) & 3;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let rev = |v: u64| -> u64 {
        match size {
            0 => {
                (v & 0xFF) << 56
                    | (v & 0xFF00) << 40
                    | (v & 0xFF0000) << 24
                    | (v & 0xFF000000) << 8
                    | (v >> 8) & 0xFF000000
                    | (v >> 24) & 0xFF0000
                    | (v >> 40) & 0xFF00
                    | (v >> 56) & 0xFF
            }
            1 => {
                (v & 0xFFFF) << 48
                    | ((v >> 16) & 0xFFFF) << 32
                    | ((v >> 32) & 0xFFFF) << 16
                    | (v >> 48)
            }
            2 => (v << 32) | (v >> 32),
            _ => v,
        }
    };
    let dst_lo = rev(c.vreg[rn as usize][0]);
    let dst_hi = if q != 0 { rev(c.vreg[rn as usize][1]) } else { 0 };
    c.vreg[rd as usize] = [dst_lo, dst_hi];
    c.pc += 4;
    Ok(())
}

fn exec_adv_simd_3same(c: &mut Cpu, inst: u32) -> Result<(), String> {
    let q = (inst >> 30) & 1;
    let u = (inst >> 29) & 1;
    let size = (inst >> 22) & 3;
    let rm = (inst >> 16) & 0x1F;
    let opcode = (inst >> 11) & 0x1F;
    let rn = (inst >> 5) & 0x1F;
    let rd = inst & 0x1F;
    let a_lo = c.vreg[rn as usize][0];
    let a_hi = c.vreg[rn as usize][1];
    let b_lo = c.vreg[rm as usize][0];
    let b_hi = c.vreg[rm as usize][1];
    let (lo_r, hi_r);
    match opcode {
        3 => match (u << 2) | size {
            0 => {
                lo_r = a_lo & b_lo;
                hi_r = a_hi & b_hi;
            }
            1 => {
                lo_r = a_lo & !b_lo;
                hi_r = a_hi & !b_hi;
            }
            2 => {
                lo_r = a_lo | b_lo;
                hi_r = a_hi | b_hi;
            }
            3 => {
                lo_r = a_lo | !b_lo;
                hi_r = a_hi | !b_hi;
            }
            4 => {
                lo_r = a_lo ^ b_lo;
                hi_r = a_hi ^ b_hi;
            }
            5 => {
                let d_lo = c.vreg[rd as usize][0];
                let d_hi = c.vreg[rd as usize][1];
                lo_r = (a_lo & d_lo) | (b_lo & !d_lo);
                hi_r = (a_hi & d_hi) | (b_hi & !d_hi);
            }
            6 => {
                let d_lo = c.vreg[rd as usize][0];
                let d_hi = c.vreg[rd as usize][1];
                lo_r = (a_lo & b_lo) | (d_lo & !b_lo);
                hi_r = (a_hi & b_hi) | (d_hi & !b_hi);
            }
            7 => {
                let d_lo = c.vreg[rd as usize][0];
                let d_hi = c.vreg[rd as usize][1];
                lo_r = (a_lo & !b_lo) | (d_lo & b_lo);
                hi_r = (a_hi & !b_hi) | (d_hi & b_hi);
            }
            _ => {
                lo_r = 0;
                hi_r = 0;
            }
        },
        16 => {
            let (l, h) = simd3_same_arith(a_lo, a_hi, b_lo, b_hi, size, u == 1);
            lo_r = l;
            hi_r = h;
        }
        _ => {
            return Err(format!(
                "unhandled AdvSIMD3Same opcode={} u={} inst=0x{:08x}",
                opcode, u, inst
            ))
        }
    }
    c.vreg[rd as usize][0] = lo_r;
    c.vreg[rd as usize][1] = if q != 0 { hi_r } else { 0 };
    c.pc += 4;
    Ok(())
}

fn simd3_same_arith(
    a_lo: u64,
    a_hi: u64,
    b_lo: u64,
    b_hi: u64,
    size: u32,
    is_sub: bool,
) -> (u64, u64) {
    let op = |a: u64, b: u64, mask: u64| -> u64 {
        if is_sub {
            a.wrapping_sub(b) & mask
        } else {
            a.wrapping_add(b) & mask
        }
    };
    let mut lo_r = 0u64;
    let mut hi_r = 0u64;
    match size {
        0 => {
            for i in 0..8u32 {
                let s = i * 8;
                lo_r |= op((a_lo >> s) & 0xFF, (b_lo >> s) & 0xFF, 0xFF) << s;
                hi_r |= op((a_hi >> s) & 0xFF, (b_hi >> s) & 0xFF, 0xFF) << s;
            }
        }
        1 => {
            for i in 0..4u32 {
                let s = i * 16;
                lo_r |= op((a_lo >> s) & 0xFFFF, (b_lo >> s) & 0xFFFF, 0xFFFF) << s;
                hi_r |= op((a_hi >> s) & 0xFFFF, (b_hi >> s) & 0xFFFF, 0xFFFF) << s;
            }
        }
        2 => {
            for i in 0..2u32 {
                let s = i * 32;
                lo_r |= op((a_lo >> s) & 0xFFFFFFFF, (b_lo >> s) & 0xFFFFFFFF, 0xFFFFFFFF) << s;
                hi_r |= op((a_hi >> s) & 0xFFFFFFFF, (b_hi >> s) & 0xFFFFFFFF, 0xFFFFFFFF) << s;
            }
        }
        3 => {
            lo_r = op(a_lo, b_lo, !0u64);
            hi_r = op(a_hi, b_hi, !0u64);
        }
        _ => {}
    }
    (lo_r, hi_r)
}

// ---- SIMD load/store helpers --------------------------------------------

fn simd_access_size(size: u32, opc: u32) -> usize {
    if size == 0 && opc >= 2 {
        16
    } else if size == 0 {
        1
    } else if size == 1 {
        2
    } else if size == 2 {
        4
    } else {
        8
    }
}

fn do_simd_store(c: &Cpu, m: &mut Mem, addr: u64, rt: u32, n: usize) {
    let rt = rt as usize;
    match n {
        1 => m.write8(addr, c.vreg[rt][0] as u8),
        2 => m.write16(addr, c.vreg[rt][0] as u16),
        4 => m.write32(addr, c.vreg[rt][0] as u32),
        8 => m.write64(addr, c.vreg[rt][0]),
        16 => {
            m.write64(addr, c.vreg[rt][0]);
            m.write64(addr + 8, c.vreg[rt][1]);
        }
        _ => {}
    }
}

fn do_simd_load(c: &mut Cpu, m: &mut Mem, addr: u64, rt: u32, n: usize) {
    let rt = rt as usize;
    c.vreg[rt] = [0, 0];
    match n {
        1 => c.vreg[rt][0] = m.read8(addr) as u64,
        2 => c.vreg[rt][0] = m.read16(addr) as u64,
        4 => c.vreg[rt][0] = m.read32(addr) as u64,
        8 => c.vreg[rt][0] = m.read64(addr),
        16 => {
            c.vreg[rt][0] = m.read64(addr);
            c.vreg[rt][1] = m.read64(addr + 8);
        }
        _ => {}
    }
}

fn exec_ldst_simd_unsigned(c: &mut Cpu, m: &mut Mem, inst: u32) -> Result<(), String> {
    let size = (inst >> 30) & 3;
    let opc = (inst >> 22) & 3;
    let imm12 = ((inst >> 10) & 0xFFF) as u64;
    let rn = (inst >> 5) & 0x1F;
    let rt = inst & 0x1F;
    let n = simd_access_size(size, opc);
    let offset = imm12 * (n as u64);
    let addr = c.reg_sp(rn).wrapping_add(offset);
    if opc & 1 == 0 {
        do_simd_store(c, m, addr, rt, n);
    } else {
        do_simd_load(c, m, addr, rt, n);
    }
    c.pc += 4;
    Ok(())
}

fn exec_ldst_simd_imm9(c: &mut Cpu, m: &mut Mem, inst: u32) -> Result<(), String> {
    let size = (inst >> 30) & 3;
    let opc = (inst >> 22) & 3;
    let imm9 = sign_extend(((inst >> 12) & 0x1FF) as u64, 9);
    let idx_type = (inst >> 10) & 3;
    let rn = (inst >> 5) & 0x1F;
    let rt = inst & 0x1F;
    let n = simd_access_size(size, opc);
    let base = c.reg_sp(rn);
    let addr = match idx_type {
        0 => base.wrapping_add(imm9),
        1 => {
            c.set_reg_sp(rn, base.wrapping_add(imm9));
            base
        }
        3 => {
            let a = base.wrapping_add(imm9);
            c.set_reg_sp(rn, a);
            a
        }
        _ => return Err(format!("reserved SIMD ldst idxType={}", idx_type)),
    };
    if opc & 1 == 0 {
        do_simd_store(c, m, addr, rt, n);
    } else {
        do_simd_load(c, m, addr, rt, n);
    }
    c.pc += 4;
    Ok(())
}

fn exec_ldst_pair_simd(c: &mut Cpu, m: &mut Mem, inst: u32) -> Result<(), String> {
    let opc = (inst >> 30) & 3;
    let pair_type = (inst >> 23) & 7;
    let load = (inst >> 22) & 1;
    let imm7 = sign_extend(((inst >> 15) & 0x7F) as u64, 7);
    let rt2 = (inst >> 10) & 0x1F;
    let rn = (inst >> 5) & 0x1F;
    let rt = inst & 0x1F;
    let scale = match opc {
        0 => 4u64,
        1 => 8,
        2 => 16,
        _ => return Err(format!("reserved SIMD LDP/STP opc={}", opc)),
    };
    let offset = imm7.wrapping_mul(scale);
    let base = c.reg_sp(rn);
    let addr = match pair_type {
        1 => {
            c.set_reg_sp(rn, base.wrapping_add(offset));
            base
        }
        2 => base.wrapping_add(offset),
        3 => {
            let a = base.wrapping_add(offset);
            c.set_reg_sp(rn, a);
            a
        }
        _ => return Err(format!("reserved SIMD LDP/STP type={}", pair_type)),
    };
    let elem_size = scale as usize;
    if load != 0 {
        do_simd_load(c, m, addr, rt, elem_size);
        do_simd_load(c, m, addr + elem_size as u64, rt2, elem_size);
    } else {
        do_simd_store(c, m, addr, rt, elem_size);
        do_simd_store(c, m, addr + elem_size as u64, rt2, elem_size);
    }
    c.pc += 4;
    Ok(())
}

fn exec_ldr_simd_literal(c: &mut Cpu, m: &mut Mem, inst: u32) -> Result<(), String> {
    let opc = (inst >> 30) & 3;
    let imm19 = sign_extend(((inst >> 5) & 0x7FFFF) as u64, 19);
    let rt = inst & 0x1F;
    let addr = c.pc.wrapping_add(imm19.wrapping_mul(4));
    let n = match opc {
        0 => 4,
        1 => 8,
        2 => 16,
        _ => 0,
    };
    do_simd_load(c, m, addr, rt, n);
    c.pc += 4;
    Ok(())
}
