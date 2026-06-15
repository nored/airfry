//! PlayFair stream-key derivation — faithful port of doubletake's playfair.go.
//! Tables and constants are embedded from src/playfair_data/ (little-endian dumps).
//! All u32/u8 arithmetic uses wrapping semantics to match Go's overflow behavior.

// ---------------------------------------------------------------------------
// Embedded tables / constants
// ---------------------------------------------------------------------------

static TABLE_S1: &[u8] = include_bytes!("playfair_data/tableS1.bin"); // 10240
static TABLE_S2: &[u8] = include_bytes!("playfair_data/tableS2.bin"); // 36864
static TABLE_S3: &[u8] = include_bytes!("playfair_data/tableS3.bin"); // 4096
static TABLE_S4: &[u8] = include_bytes!("playfair_data/tableS4.bin"); // 36864
static TABLE_S10: &[u8] = include_bytes!("playfair_data/tableS10.bin"); // 4096

static MESSAGE_KEY_RAW: &[u8] = include_bytes!("playfair_data/messageKey.bin"); // 576 = [4][144]
static MESSAGE_IV_RAW: &[u8] = include_bytes!("playfair_data/messageIv.bin"); // 64 = [4][16]

static Z_KEY: &[u8] = include_bytes!("playfair_data/zKey.bin"); // 16
static X_KEY: &[u8] = include_bytes!("playfair_data/xKey.bin"); // 16
static T_KEY: &[u8] = include_bytes!("playfair_data/tKey.bin"); // 16

static DEFAULT_SAP: &[u8] = include_bytes!("playfair_data/defaultSap.bin"); // 280
static STATIC_SOURCE1: &[u8] = include_bytes!("playfair_data/staticSource1.bin"); // 17
static STATIC_SOURCE2: &[u8] = include_bytes!("playfair_data/staticSource2.bin"); // 47
static INDEX_MANGLE: &[u8] = include_bytes!("playfair_data/indexMangle.bin"); // 11
static INITIAL_SESSION_KEY: &[u8] = include_bytes!("playfair_data/initialSessionKey.bin"); // 16
static MD5_SHIFT_RAW: &[u8] = include_bytes!("playfair_data/md5Shift.bin"); // 64

fn load_u32_table(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

struct Tables {
    s5: Vec<u32>, // 256
    s6: Vec<u32>, // 256
    s7: Vec<u32>, // 256
    s8: Vec<u32>, // 256
    s9: Vec<u32>, // 1024
}

fn tables() -> &'static Tables {
    use std::sync::OnceLock;
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| Tables {
        s5: load_u32_table(include_bytes!("playfair_data/tableS5.bin")),
        s6: load_u32_table(include_bytes!("playfair_data/tableS6.bin")),
        s7: load_u32_table(include_bytes!("playfair_data/tableS7.bin")),
        s8: load_u32_table(include_bytes!("playfair_data/tableS8.bin")),
        s9: load_u32_table(include_bytes!("playfair_data/tableS9.bin")),
    })
}

#[inline]
fn message_key(mode: usize, i: usize) -> u8 {
    MESSAGE_KEY_RAW[mode * 144 + i]
}

#[inline]
fn message_iv(mode: usize) -> &'static [u8] {
    &MESSAGE_IV_RAW[mode * 16..mode * 16 + 16]
}

// ---------------------------------------------------------------------------
// LE word helpers
// ---------------------------------------------------------------------------

#[inline]
fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
fn put_le_u32(b: &mut [u8], v: u32) {
    b[0..4].copy_from_slice(&v.to_le_bytes());
}

// ---------------------------------------------------------------------------
// XOR helpers
// ---------------------------------------------------------------------------

fn z_xor(input: &[u8], out: &mut [u8], blocks: usize) {
    for j in 0..blocks {
        for i in 0..16 {
            out[j * 16 + i] = input[j * 16 + i] ^ Z_KEY[i];
        }
    }
}

fn x_xor(input: &[u8], out: &mut [u8], blocks: usize) {
    for j in 0..blocks {
        for i in 0..16 {
            out[j * 16 + i] = input[j * 16 + i] ^ X_KEY[i];
        }
    }
}

fn t_xor(input: &[u8], out: &mut [u8]) {
    for i in 0..16 {
        out[i] = input[i] ^ T_KEY[i];
    }
}

fn xor_blocks(a: &[u8], b: &[u8], out: &mut [u8]) {
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
}

// ---------------------------------------------------------------------------
// Table index helpers
// ---------------------------------------------------------------------------

fn table_index(i: i64) -> &'static [u8] {
    let off = (((31 * i) % 0x28) << 8) as usize;
    &TABLE_S1[off..off + 256]
}

fn message_table_index(i: usize) -> &'static [u8] {
    let off = ((97 * i) % 144) << 8;
    &TABLE_S2[off..off + 256]
}

fn permute_table2(i: usize) -> &'static [u8] {
    let off = ((71 * i) % 144) << 8;
    &TABLE_S4[off..off + 256]
}

// ---------------------------------------------------------------------------
// Permutations
// ---------------------------------------------------------------------------

fn permute_block1(block: &mut [u8]) {
    block[0] = TABLE_S3[block[0] as usize];
    block[4] = TABLE_S3[0x400 + block[4] as usize];
    block[8] = TABLE_S3[0x800 + block[8] as usize];
    block[12] = TABLE_S3[0xc00 + block[12] as usize];

    let mut tmp = block[13];
    block[13] = TABLE_S3[0x100 + block[9] as usize];
    block[9] = TABLE_S3[0xd00 + block[5] as usize];
    block[5] = TABLE_S3[0x900 + block[1] as usize];
    block[1] = TABLE_S3[0x500 + tmp as usize];

    tmp = block[2];
    block[2] = TABLE_S3[0xa00 + block[10] as usize];
    block[10] = TABLE_S3[0x200 + tmp as usize];
    tmp = block[6];
    block[6] = TABLE_S3[0xe00 + block[14] as usize];
    block[14] = TABLE_S3[0x600 + tmp as usize];

    tmp = block[3];
    block[3] = TABLE_S3[0xf00 + block[7] as usize];
    block[7] = TABLE_S3[0x300 + block[11] as usize];
    block[11] = TABLE_S3[0x700 + block[15] as usize];
    block[15] = TABLE_S3[0xb00 + tmp as usize];
}

fn permute_block2(block: &mut [u8], round: i64) {
    let t2 = |idx: i64| -> &'static [u8] { permute_table2(idx as usize) };

    block[0] = t2(round * 16)[block[0] as usize];
    block[4] = t2(round * 16 + 4)[block[4] as usize];
    block[8] = t2(round * 16 + 8)[block[8] as usize];
    block[12] = t2(round * 16 + 12)[block[12] as usize];

    let mut tmp = block[13];
    block[13] = t2(round * 16 + 13)[block[9] as usize];
    block[9] = t2(round * 16 + 9)[block[5] as usize];
    block[5] = t2(round * 16 + 5)[block[1] as usize];
    block[1] = t2(round * 16 + 1)[tmp as usize];

    tmp = block[2];
    block[2] = t2(round * 16 + 2)[block[10] as usize];
    block[10] = t2(round * 16 + 10)[tmp as usize];
    tmp = block[6];
    block[6] = t2(round * 16 + 6)[block[14] as usize];
    block[14] = t2(round * 16 + 14)[tmp as usize];

    tmp = block[3];
    block[3] = t2(round * 16 + 3)[block[7] as usize];
    block[7] = t2(round * 16 + 7)[block[11] as usize];
    block[11] = t2(round * 16 + 11)[block[15] as usize];
    block[15] = t2(round * 16 + 15)[tmp as usize];
}

// ---------------------------------------------------------------------------
// Key schedule
// ---------------------------------------------------------------------------

fn generate_key_schedule(key_material: &[u8], key_schedule: &mut [[u32; 4]; 11]) {
    let mut key_data = [0u32; 4];
    let mut buf = [0u8; 16];
    t_xor(key_material, &mut buf);

    for i in 0..4 {
        key_data[i] = le_u32(&buf[i * 4..i * 4 + 4]);
    }

    let mut ti: i64 = 0;
    for round in 0..11 {
        for i in 0..4 {
            put_le_u32(&mut buf[i * 4..], key_data[i]);
        }

        key_schedule[round][0] = key_data[0];

        let table1 = table_index(ti);
        let table2 = table_index(ti + 1);
        let table3 = table_index(ti + 2);
        let table4 = table_index(ti + 3);
        ti += 4;

        buf[0] ^= table1[buf[0x0d] as usize] ^ INDEX_MANGLE[round];
        buf[1] ^= table2[buf[0x0e] as usize];
        buf[2] ^= table3[buf[0x0f] as usize];
        buf[3] ^= table4[buf[0x0c] as usize];

        for i in 0..4 {
            key_data[i] = le_u32(&buf[i * 4..i * 4 + 4]);
        }

        key_schedule[round][1] = key_data[1];
        key_data[1] ^= key_data[0];

        key_schedule[round][2] = key_data[2];
        key_data[2] ^= key_data[1];

        key_schedule[round][3] = key_data[3];
        key_data[3] ^= key_data[2];
    }
}

// ---------------------------------------------------------------------------
// AES-like cycle
// ---------------------------------------------------------------------------

fn cycle(block: &mut [u8], ks: &[[u32; 4]; 11]) {
    let mut b_words = [
        le_u32(&block[0..4]),
        le_u32(&block[4..8]),
        le_u32(&block[8..12]),
        le_u32(&block[12..16]),
    ];
    b_words[0] ^= ks[10][0];
    b_words[1] ^= ks[10][1];
    b_words[2] ^= ks[10][2];
    b_words[3] ^= ks[10][3];
    for i in 0..4 {
        put_le_u32(&mut block[i * 4..], b_words[i]);
    }

    permute_block1(block);

    let t = tables();

    for round in 0..9 {
        let k = ks[9 - round][0];
        let key0 = [k as u8, (k >> 8) as u8, (k >> 16) as u8, (k >> 24) as u8];

        let ptr1 = t.s5[(block[3] ^ key0[3]) as usize];
        let ptr2 = t.s6[(block[2] ^ key0[2]) as usize];
        let ptr3 = t.s8[(block[0] ^ key0[0]) as usize];
        let ptr4 = t.s7[(block[1] ^ key0[1]) as usize];
        let ab = ptr1 ^ ptr2 ^ ptr3 ^ ptr4;
        put_le_u32(&mut block[0..4], ab);

        let k = ks[9 - round][1];
        let key1 = [k as u8, (k >> 8) as u8, (k >> 16) as u8, (k >> 24) as u8];
        let ptr2 = t.s5[(block[7] ^ key1[3]) as usize];
        let ptr1 = t.s6[(block[6] ^ key1[2]) as usize];
        let ptr4 = t.s7[(block[5] ^ key1[1]) as usize];
        let ptr3 = t.s8[(block[4] ^ key1[0]) as usize];
        let ab = ptr1 ^ ptr2 ^ ptr3 ^ ptr4;
        put_le_u32(&mut block[4..8], ab);

        let k = ks[9 - round][2];
        let key2 = [k as u8, (k >> 8) as u8, (k >> 16) as u8, (k >> 24) as u8];
        let k = ks[9 - round][3];
        let key3 = [k as u8, (k >> 8) as u8, (k >> 16) as u8, (k >> 24) as u8];

        let w2 = t.s5[(block[11] ^ key2[3]) as usize]
            ^ t.s6[(block[10] ^ key2[2]) as usize]
            ^ t.s7[(block[9] ^ key2[1]) as usize]
            ^ t.s8[(block[8] ^ key2[0]) as usize];
        put_le_u32(&mut block[8..12], w2);

        let w3 = t.s5[(block[15] ^ key3[3]) as usize]
            ^ t.s6[(block[14] ^ key3[2]) as usize]
            ^ t.s7[(block[13] ^ key3[1]) as usize]
            ^ t.s8[(block[12] ^ key3[0]) as usize];
        put_le_u32(&mut block[12..16], w3);

        permute_block2(block, (8 - round) as i64);
    }

    b_words[0] = le_u32(&block[0..4]) ^ ks[0][0];
    b_words[1] = le_u32(&block[4..8]) ^ ks[0][1];
    b_words[2] = le_u32(&block[8..12]) ^ ks[0][2];
    b_words[3] = le_u32(&block[12..16]) ^ ks[0][3];
    for i in 0..4 {
        put_le_u32(&mut block[i * 4..], b_words[i]);
    }
}

// ---------------------------------------------------------------------------
// Message decryption
// ---------------------------------------------------------------------------

fn decrypt_message(message_in: &[u8], decrypted_message: &mut [u8]) {
    let mut buffer = [0u8; 16];
    let mode = message_in[12] as usize;
    let t = tables();

    for i in 0..8usize {
        for j in 0..16usize {
            if mode == 3 {
                buffer[j] = message_in[(0x80 - 0x10 * i) + j];
            } else {
                buffer[j] = message_in[(0x10 * (i + 1)) + j];
            }
        }

        for jj in 0..9usize {
            let base = 0x80 - 0x10 * jj;

            buffer[0x0] =
                message_table_index(base)[buffer[0x0] as usize] ^ message_key(mode, base);
            buffer[0x4] = message_table_index(base + 0x4)[buffer[0x4] as usize]
                ^ message_key(mode, base + 0x4);
            buffer[0x8] = message_table_index(base + 0x8)[buffer[0x8] as usize]
                ^ message_key(mode, base + 0x8);
            buffer[0xc] = message_table_index(base + 0xc)[buffer[0xc] as usize]
                ^ message_key(mode, base + 0xc);

            let mut tmp = buffer[0x0d];
            buffer[0xd] = message_table_index(base + 0xd)[buffer[0x9] as usize]
                ^ message_key(mode, base + 0xd);
            buffer[0x9] = message_table_index(base + 0x9)[buffer[0x5] as usize]
                ^ message_key(mode, base + 0x9);
            buffer[0x5] = message_table_index(base + 0x5)[buffer[0x1] as usize]
                ^ message_key(mode, base + 0x5);
            buffer[0x1] =
                message_table_index(base + 0x1)[tmp as usize] ^ message_key(mode, base + 0x1);

            tmp = buffer[0x02];
            buffer[0x2] = message_table_index(base + 0x2)[buffer[0xa] as usize]
                ^ message_key(mode, base + 0x2);
            buffer[0xa] =
                message_table_index(base + 0xa)[tmp as usize] ^ message_key(mode, base + 0xa);
            tmp = buffer[0x06];
            buffer[0x6] = message_table_index(base + 0x6)[buffer[0xe] as usize]
                ^ message_key(mode, base + 0x6);
            buffer[0xe] =
                message_table_index(base + 0xe)[tmp as usize] ^ message_key(mode, base + 0xe);

            tmp = buffer[0x3];
            buffer[0x3] = message_table_index(base + 0x3)[buffer[0x7] as usize]
                ^ message_key(mode, base + 0x3);
            buffer[0x7] = message_table_index(base + 0x7)[buffer[0xb] as usize]
                ^ message_key(mode, base + 0x7);
            buffer[0xb] = message_table_index(base + 0xb)[buffer[0xf] as usize]
                ^ message_key(mode, base + 0xb);
            buffer[0xf] =
                message_table_index(base + 0xf)[tmp as usize] ^ message_key(mode, base + 0xf);

            let b0 = t.s9[buffer[0x0] as usize]
                ^ t.s9[0x100 + buffer[0x1] as usize]
                ^ t.s9[0x200 + buffer[0x2] as usize]
                ^ t.s9[0x300 + buffer[0x3] as usize];
            let b1 = t.s9[buffer[0x4] as usize]
                ^ t.s9[0x100 + buffer[0x5] as usize]
                ^ t.s9[0x200 + buffer[0x6] as usize]
                ^ t.s9[0x300 + buffer[0x7] as usize];
            let b2 = t.s9[buffer[0x8] as usize]
                ^ t.s9[0x100 + buffer[0x9] as usize]
                ^ t.s9[0x200 + buffer[0xa] as usize]
                ^ t.s9[0x300 + buffer[0xb] as usize];
            let b3 = t.s9[buffer[0xc] as usize]
                ^ t.s9[0x100 + buffer[0xd] as usize]
                ^ t.s9[0x200 + buffer[0xe] as usize]
                ^ t.s9[0x300 + buffer[0xf] as usize];

            put_le_u32(&mut buffer[0..4], b0);
            put_le_u32(&mut buffer[4..8], b1);
            put_le_u32(&mut buffer[8..12], b2);
            put_le_u32(&mut buffer[12..16], b3);
        }

        // Final S-box permutation
        buffer[0x0] = TABLE_S10[buffer[0x0] as usize];
        buffer[0x4] = TABLE_S10[(0x4 << 8) + buffer[0x4] as usize];
        buffer[0x8] = TABLE_S10[(0x8 << 8) + buffer[0x8] as usize];
        buffer[0xc] = TABLE_S10[(0xc << 8) + buffer[0xc] as usize];

        let mut tmp = buffer[0x0d];
        buffer[0xd] = TABLE_S10[(0xd << 8) + buffer[0x9] as usize];
        buffer[0x9] = TABLE_S10[(0x9 << 8) + buffer[0x5] as usize];
        buffer[0x5] = TABLE_S10[(0x5 << 8) + buffer[0x1] as usize];
        buffer[0x1] = TABLE_S10[(0x1 << 8) + tmp as usize];

        tmp = buffer[0x02];
        buffer[0x2] = TABLE_S10[(0x2 << 8) + buffer[0xa] as usize];
        buffer[0xa] = TABLE_S10[(0xa << 8) + tmp as usize];
        tmp = buffer[0x06];
        buffer[0x6] = TABLE_S10[(0x6 << 8) + buffer[0xe] as usize];
        buffer[0xe] = TABLE_S10[(0xe << 8) + tmp as usize];

        tmp = buffer[0x3];
        buffer[0x3] = TABLE_S10[(0x3 << 8) + buffer[0x7] as usize];
        buffer[0x7] = TABLE_S10[(0x7 << 8) + buffer[0xb] as usize];
        buffer[0xb] = TABLE_S10[(0xb << 8) + buffer[0xf] as usize];
        buffer[0xf] = TABLE_S10[(0xf << 8) + tmp as usize];

        if mode == 2 || mode == 1 || mode == 0 {
            if i > 0 {
                let src = message_in[0x10 * i..0x10 * i + 16].to_vec();
                xor_blocks(&buffer, &src, &mut decrypted_message[0x10 * i..]);
            } else {
                let iv = message_iv(mode).to_vec();
                xor_blocks(&buffer, &iv, &mut decrypted_message[0x10 * i..]);
            }
        } else if i < 7 {
            let src = message_in[0x70 - 0x10 * i..0x70 - 0x10 * i + 16].to_vec();
            xor_blocks(&buffer, &src, &mut decrypted_message[0x70 - 0x10 * i..]);
        } else {
            let iv = message_iv(mode).to_vec();
            xor_blocks(&buffer, &iv, &mut decrypted_message[0x70 - 0x10 * i..]);
        }
    }
}

// ---------------------------------------------------------------------------
// Modified MD5
// ---------------------------------------------------------------------------

fn rol32(input: u32, count: u32) -> u32 {
    (input << count) | (input >> (32 - count))
}

fn modified_md5(original_block_in: &[u8], key_in: &[u8], key_out: &mut [u8]) {
    let mut block_in = [0u8; 64];
    block_in.copy_from_slice(&original_block_in[..64]);

    let key_words = [
        le_u32(&key_in[0..4]),
        le_u32(&key_in[4..8]),
        le_u32(&key_in[8..12]),
        le_u32(&key_in[12..16]),
    ];

    let mut a = key_words[0];
    let mut b = key_words[1];
    let mut c = key_words[2];
    let mut d = key_words[3];

    for i in 0..64usize {
        let j = if i < 16 {
            i
        } else if i < 32 {
            (5 * i + 1) % 16
        } else if i < 48 {
            (3 * i + 5) % 16
        } else {
            (7 * i) % 16
        };

        let input = (block_in[4 * j] as u32) << 24
            | (block_in[4 * j + 1] as u32) << 16
            | (block_in[4 * j + 2] as u32) << 8
            | (block_in[4 * j + 3] as u32);

        let sin_val = ((i as f64) + 1.0).sin().abs();
        let constant = (sin_val * (1u64 << 32) as f64) as u32;

        let mut z = a.wrapping_add(input).wrapping_add(constant);

        let shift = MD5_SHIFT_RAW[i] as u32;
        if i < 16 {
            z = rol32(z.wrapping_add((b & c) | (!b & d)), shift);
        } else if i < 32 {
            z = rol32(z.wrapping_add((b & d) | (c & !d)), shift);
        } else if i < 48 {
            z = rol32(z.wrapping_add(b ^ c ^ d), shift);
        } else {
            z = rol32(z.wrapping_add(c ^ (b | !d)), shift);
        }

        z = z.wrapping_add(b);
        // A, B, C, D = D, Z, B, C
        let (na, nb, nc, nd) = (d, z, b, c);
        a = na;
        b = nb;
        c = nc;
        d = nd;

        if i == 31 {
            let get = |bi: &[u8; 64], k: usize| -> u32 { le_u32(&bi[k * 4..k * 4 + 4]) };
            let swap = |bi: &mut [u8; 64], x: usize, y: usize| {
                let va = get(bi, x);
                let vb = get(bi, y);
                put_le_u32(&mut bi[x * 4..], vb);
                put_le_u32(&mut bi[y * 4..], va);
            };
            swap(&mut block_in, (a & 15) as usize, (b & 15) as usize);
            swap(&mut block_in, (c & 15) as usize, (d & 15) as usize);
            swap(
                &mut block_in,
                ((a & (15 << 4)) >> 4) as usize,
                ((b & (15 << 4)) >> 4) as usize,
            );
            swap(
                &mut block_in,
                ((a & (15 << 8)) >> 8) as usize,
                ((b & (15 << 8)) >> 8) as usize,
            );
            swap(
                &mut block_in,
                ((a & (15 << 12)) >> 12) as usize,
                ((b & (15 << 12)) >> 12) as usize,
            );
        }
    }

    put_le_u32(&mut key_out[0..4], key_words[0].wrapping_add(a));
    put_le_u32(&mut key_out[4..8], key_words[1].wrapping_add(b));
    put_le_u32(&mut key_out[8..12], key_words[2].wrapping_add(c));
    put_le_u32(&mut key_out[12..16], key_words[3].wrapping_add(d));
}

// ---------------------------------------------------------------------------
// SAP hash helpers
// ---------------------------------------------------------------------------

fn rol8(input: u8, count: u32) -> u8 {
    (((input as u32) << count) as u8) | (input >> (8 - count))
}

fn rol8x(input: u8, count: u32) -> u32 {
    // Go: uint32((input << count)) | uint32(input>>(8-count))
    // (input << count) computed in byte type (wraps to 8 bits), then widened.
    ((input.wrapping_shl(count)) as u32) | ((input >> (8 - count)) as u32)
}

fn weird_ror8(input: u8, count: u32) -> u32 {
    if count == 0 {
        return 0;
    }
    (((input >> count) & 0xff) as u32) | (((input & 0xff) as u32) << (8 - count))
}

fn weird_rol8(input: u8, count: u32) -> u32 {
    if count == 0 {
        return 0;
    }
    ((((input as u32) << count) & 0xff)) | (((input & 0xff) as u32) >> (8 - count))
}

fn weird_rol32(input: u8, count: u32) -> u32 {
    if count == 0 {
        return 0;
    }
    ((input as u32) << count) ^ ((input as u32) >> (8 - count))
}

fn sap_hash(block_in: &[u8], key_out: &mut [u8]) {
    let mut block_words = [0u32; 16];
    for i in 0..16 {
        block_words[i] = le_u32(&block_in[i * 4..i * 4 + 4]);
    }

    let mut buffer0: [u8; 20] = [
        0x96, 0x5F, 0xC6, 0x53, 0xF8, 0x46, 0xCC, 0x18, 0xDF, 0xBE, 0xB2, 0xF8, 0x38, 0xD7, 0xEC,
        0x22, 0x03, 0xD1, 0x20, 0x8F,
    ];
    let mut buffer1 = [0u8; 210];
    let mut buffer2: [u8; 35] = [
        0x43, 0x54, 0x62, 0x7A, 0x18, 0xC3, 0xD6, 0xB3, 0x9A, 0x56, 0xF6, 0x1C, 0x14, 0x3F, 0x0C,
        0x1D, 0x3B, 0x36, 0x83, 0xB1, 0x39, 0x51, 0x4A, 0xAA, 0x09, 0x3E, 0xFE, 0x44, 0xAF, 0xDE,
        0xC3, 0x20, 0x9D, 0x42, 0x3A,
    ];
    let mut buffer3 = [0u8; 132];
    let mut buffer4: [u8; 21] = [
        0xED, 0x25, 0xD1, 0xBB, 0xBC, 0x27, 0x9F, 0x02, 0xA2, 0xA9, 0x11, 0x00, 0x0C, 0xB3, 0x52,
        0xC0, 0xBD, 0xE3, 0x1B, 0x49, 0xC7,
    ];
    let i0_index: [usize; 11] = [18, 22, 23, 0, 5, 19, 32, 31, 10, 21, 30];

    for i in 0..210usize {
        let in_word = block_words[(i % 64) >> 2];
        let in_byte = ((in_word >> ((3 - (i % 4)) << 3)) & 0xff) as u8;
        buffer1[i] = in_byte;
    }

    // Scrambling. Go: buffer1[uint32(i-off)%210]
    for i in 0..840i64 {
        let idx = |off: i64| -> usize { (((i - off) as u32) % 210) as usize };
        let x = buffer1[idx(155)];
        let y = buffer1[idx(57)];
        let z = buffer1[idx(13)];
        let w = buffer1[idx(0)];
        let val = (rol8(y, 5) as u32)
            .wrapping_add((rol8(z, 3) as u32) ^ (w as u32))
            .wrapping_sub(rol8(x, 7) as u32)
            & 0xff;
        buffer1[(i % 210) as usize] = val as u8;
    }

    garble(
        &mut buffer0,
        &mut buffer1,
        &mut buffer2,
        &mut buffer3,
        &mut buffer4,
    );

    for i in 0..16 {
        key_out[i] = 0xE1;
    }

    for i in 0..11usize {
        if i == 3 {
            key_out[i] = 0x3d;
        } else {
            key_out[i] =
                ((key_out[i] as u32).wrapping_add(buffer3[i0_index[i] * 4] as u32) & 0xff) as u8;
        }
    }

    for i in 0..20usize {
        key_out[i % 16] ^= buffer0[i];
    }
    for i in 0..35usize {
        key_out[i % 16] ^= buffer2[i];
    }
    for i in 0..210usize {
        key_out[i % 16] ^= buffer1[i];
    }

    for _j in 0..16 {
        for i in 0..16i64 {
            let idx = |off: i64| -> usize { (((i - off) as u32) % 16) as usize };
            let x = key_out[idx(7)];
            let y = key_out[(i % 16) as usize];
            let z = key_out[idx(37)];
            let w = key_out[idx(177)];
            key_out[i as usize] = rol8(x, 1) ^ y ^ rol8(z, 6) ^ rol8(w, 5);
        }
    }
}

// ---------------------------------------------------------------------------
// Garble (hand_garble.c)
// ---------------------------------------------------------------------------

#[allow(clippy::needless_range_loop, unused_assignments, unused_variables)]
fn garble(
    buffer0: &mut [u8],
    buffer1: &mut [u8],
    buffer2: &mut [u8],
    buffer3: &mut [u8],
    buffer4: &mut [u8],
) {
    macro_rules! b0 {
        ($i:expr) => {
            buffer0[($i) as usize] as u32
        };
    }
    macro_rules! b1 {
        ($i:expr) => {
            buffer1[($i) as usize] as u32
        };
    }
    macro_rules! b2 {
        ($i:expr) => {
            buffer2[($i) as usize] as u32
        };
    }
    macro_rules! b4 {
        ($i:expr) => {
            buffer4[($i) as usize] as u32
        };
    }
    macro_rules! b3 {
        ($i:expr) => {
            buffer3[($i) as usize] as u32
        };
    }

    let tmp: u32;
    let tmp2: u32;
    let tmp3: u32;
    let (mut a, mut b, mut c, mut d, mut e, m, mut f, h, k, r, s, t, u, v, w, x, y, z);

    buffer2[12] = 0x14u32.wrapping_add(
        ((b1!(64) & 92) | ((b1!(99) / 3) & 35))
            & b4!((rol8x(buffer4[(b1!(206) % 21) as usize], 4) % 21)),
    ) as u8;
    buffer1[4] = (b1!(99) / 5).wrapping_mul(b1!(99) / 5).wrapping_mul(2) as u8;
    buffer2[34] = 0xb8;
    buffer1[153] ^= b2!((b1!(203) % 35))
        .wrapping_mul(b2!((b1!(203) % 35)))
        .wrapping_mul(b1!(190)) as u8;
    buffer0[3] = buffer0[3].wrapping_sub((((b4!((b1!(205) % 21)) >> 1) & 80) | 0x40) as u8);
    buffer0[16] = 0x93;
    buffer0[13] = 0x62;
    buffer1[33] = buffer1[33].wrapping_sub((b4!((b1!(36) % 21)) & 0xf6) as u8);

    tmp2 = b2!((b1!(67) % 35));
    buffer2[12] = 0x07;

    tmp = b0!((b1!(181) % 20));
    buffer1[2] = buffer1[2].wrapping_sub((3136u32 & 0xff) as u8);

    buffer0[19] = b4!((b1!(58) % 21)) as u8;

    buffer3[0] = 92u32.wrapping_sub(b2!((b1!(32) % 35))) as u8;
    buffer3[4] = b2!((b1!(15) % 35)).wrapping_add(0x9e) as u8;
    buffer1[34] = buffer1[34]
        .wrapping_add((b4!(((b2!((b1!(15) % 35)).wrapping_add(0x9e)) & 0xff) % 21) / 5) as u8);
    buffer0[19] = buffer0[19]
        .wrapping_add(0xfffffee6u32.wrapping_sub((b0!((b3!(4) % 20)) >> 1) & 102) as u8);

    // buffer1[15]
    let shift_amt = b4!((b1!(190) % 21)) & 7;
    let shifted = (b1!(72) >> shift_amt)
        ^ (b1!(72).wrapping_shl(7u32.wrapping_sub(b4!((b1!(190) % 21)).wrapping_sub(1)) & 7));
    buffer1[15] = (3u32.wrapping_mul(shifted.wrapping_sub(3u32.wrapping_mul(b4!((b1!(126) % 21)))))
        ^ b1!(15)) as u8;

    buffer0[15] ^= b2!((b1!(181) % 35))
        .wrapping_mul(b2!((b1!(181) % 35)))
        .wrapping_mul(b2!((b1!(181) % 35))) as u8;
    buffer2[4] ^= (b1!(202) / 3) as u8;

    a = 92u32.wrapping_sub(b0!((b3!(0) % 20)));
    e = (a & 0xc6) | (!b1!(105) & 0xc6) | (a & (!b1!(105)));
    buffer2[1] = buffer2[1].wrapping_add(e.wrapping_mul(e).wrapping_mul(e) as u8);

    buffer0[19] ^=
        (((224 | (b4!((b1!(92) % 21)) & 27)).wrapping_mul(b2!((b1!(41) % 35)))) / 3) as u8;
    buffer1[140] = buffer1[140].wrapping_add(weird_ror8(92, b1!(5) & 7) as u8);

    buffer2[12] = buffer2[12].wrapping_add(
        (((((!b1!(4)) ^ b2!((b1!(12) % 35))) | b1!(182)) & 192)
            | (((!b1!(4)) ^ b2!((b1!(12) % 35))) & b1!(182))) as u8,
    );
    buffer1[36] = buffer1[36].wrapping_add(125);

    buffer1[124] = rol8x(
        (((74 & b1!(138)) | ((74 | b1!(138)) & b0!(15))) & b0!((b1!(43) % 20))) as u8
            | ((((74 & b1!(138)) | ((74 | b1!(138)) & b0!(15)) | b0!((b1!(43) % 20))) & 95) as u8),
        4,
    ) as u8;

    buffer3[8] = ((((b0!((b3!(4) % 20)) & 95) & ((b4!((b1!(68) % 21)) & 46) << 1)) | 16) as u8) ^ 92;

    a = b1!(177).wrapping_add(b4!((b1!(79) % 21)));
    d = (((a >> 1) | ((3u32.wrapping_mul(b1!(148))) / 5)) & b2!(1))
        | ((a >> 1) & ((3u32.wrapping_mul(b1!(148))) / 5));
    buffer3[12] = (-34i32).wrapping_sub(d as i32) as u8;

    a = 8u32.wrapping_sub(b2!(22) & 7);
    b = b1!(33) >> (a & 7);
    c = b1!(33).wrapping_shl(b2!(22) & 7);
    buffer2[16] = buffer2[16].wrapping_add(
        (((b2!((b3!(0) % 35)) & 159) | b0!((b3!(4) % 20)) | 8).wrapping_sub((b ^ c) | 128)) as u8,
    );

    buffer0[14] ^= b2!((b3!(12) % 35)) as u8;

    // Monster
    a = weird_rol8(
        buffer4[(b0!((b1!(201) % 20)) % 21) as usize],
        (b2!((b1!(112) % 35)) << 1) & 7,
    );
    d = (b0!((b1!(208) % 20)) & 131) | (b0!((b1!(164) % 20)) & 124);
    buffer1[19] = buffer1[19].wrapping_add(((a & (d / 5)) | ((a | (d / 5)) & 37)) as u8);

    buffer2[8] = weird_ror8(
        140,
        (b4!((b1!(45) % 21)).wrapping_add(92)).wrapping_mul(b4!((b1!(45) % 21)).wrapping_add(92))
            & 7,
    ) as u8;
    buffer1[190] = 56;
    buffer2[8] ^= buffer3[0];

    buffer1[53] = (!((b0!((b1!(83) % 20)) | 204) / 5)) as u8;
    buffer0[13] = buffer0[13].wrapping_add(b0!((b1!(41) % 20)) as u8);
    buffer0[10] =
        (((b2!((b3!(0) % 35)) & b1!(2)) | ((b2!((b3!(0) % 35)) | b1!(2)) & b3!(12))) / 15) as u8;

    a = (((56 | (b4!((b1!(2) % 21)) & 68)) | b2!((b3!(8) % 35))) & 42)
        | (((b4!((b1!(2) % 21)) & 68) | 56) & b2!((b3!(8) % 35)));
    buffer3[16] = a.wrapping_mul(a).wrapping_add(110) as u8;
    buffer3[20] = 202u32.wrapping_sub(b3!(16)) as u8;
    buffer3[24] = buffer1[151];
    buffer2[13] ^= b4!((b3!(0) % 21)) as u8;

    b = ((b2!((b1!(179) % 35)).wrapping_sub(38)) & 177) | (b3!(12) & 177);
    c = (b2!((b1!(179) % 35)).wrapping_sub(38)) & b3!(12);
    buffer3[28] = 30u32.wrapping_add((b | c).wrapping_mul(b | c)) as u8;
    buffer3[32] = b3!(28).wrapping_add(62) as u8;

    // eek
    a = ((b3!(20).wrapping_add(b3!(0) & 74)) | !b4!((b3!(0) % 21))) & 121;
    b = (b3!(20).wrapping_add(b3!(0) & 74)) & !b4!((b3!(0) % 21));
    tmp3 = a | b;
    c = ((((a | b) ^ 0xffffffa6) | b3!(0)) & 4) | (((a | b) ^ 0xffffffa6) & b3!(0));
    buffer1[47] = ((b2!((b1!(89) % 35)).wrapping_add(c)) ^ b1!(47)) as u8;

    buffer3[36] = (((rol8((tmp & 179).wrapping_add(68) as u8, 2) as u32) & b0!(3))
        | (tmp2 & !b0!(3)))
    .wrapping_sub(15) as u8;
    buffer1[123] ^= 221;

    a = (b4!((b3!(0) % 21)) / 3).wrapping_sub(b2!((b3!(4) % 35)));
    c = (((b3!(0) & 163).wrapping_add(92)) & 246) | (b3!(0) & 92);
    e = ((c | b3!(24)) & 54) | (c & b3!(24));
    buffer3[40] = a.wrapping_sub(e) as u8;

    buffer3[44] = (tmp3 ^ 81 ^ (((b3!(0) >> 1) & 101).wrapping_add(26))) as u8;
    buffer3[48] = (b2!((b3!(4) % 35)) & 27) as u8;
    buffer3[52] = 27;
    buffer3[56] = 199;

    // caffeine
    buffer3[64] = b3!(4).wrapping_add(
        ((((((b3!(40) | b3!(24)) & 177) | (b3!(40) & b3!(24)))
            & (((b4!((b3!(0) % 20)) & 177) | 176) | (b4!((b3!(0) % 21)) & !3u32)))
            | ((((b3!(40) & b3!(24)) | ((b3!(40) | b3!(24)) & 177)) & 199)
                | ((((b4!((b3!(0) % 21)) & 1).wrapping_add(176)) | (b4!((b3!(0) % 21)) & !3u32))
                    & b3!(56))))
            & (!b3!(52)))
            | b3!(48),
    ) as u8;

    buffer2[33] ^= buffer1[26];
    buffer1[106] ^= (b3!(20) ^ 133) as u8;

    buffer2[30] = (((b3!(64) / 3).wrapping_sub(275 | (b3!(0) & 247))) ^ b0!((b1!(122) % 20))) as u8;
    buffer1[22] = ((b2!((b1!(90) % 35)) & 95) | 68) as u8;

    a = (b4!((b3!(36) % 21)) & 184) | (b2!((b3!(44) % 35)) & !184u32);
    buffer2[18] = buffer2[18].wrapping_add((a.wrapping_mul(a).wrapping_mul(a) >> 1) as u8);

    buffer2[5] = buffer2[5].wrapping_sub(b4!((b1!(92) % 21)) as u8);

    a = (((b1!(41) & !24u32) | (b2!((b1!(183) % 35)) & 24)) & (b3!(16).wrapping_add(53)))
        | (b3!(20) & b2!((b3!(20) % 35)));
    b = (b1!(17) & (!b3!(44))) | (b0!((b1!(59) % 20)) & b3!(44));
    buffer2[18] ^= a.wrapping_mul(b) as u8;

    a = weird_ror8(buffer1[11], b2!((b1!(28) % 35)) & 7) & 7;
    b = (((b0!((b1!(93) % 20)) & !b0!(14)) | (b0!(14) & 150)) & !28u32) | (b1!(7) & 28);
    buffer2[22] = (((b | weird_rol8(buffer2[(b3!(0) % 35) as usize], a)) & b2!(33))
        | (b & weird_rol8(buffer2[(b3!(0) % 35) as usize], a)))
    .wrapping_add(74) as u8;

    a = b4!(((b0!((b1!(39) % 20)) ^ 217) % 21));
    buffer0[15] = buffer0[15].wrapping_sub(
        (((((b3!(20) | b3!(0)) & 214) | (b3!(20) & b3!(0))) & a)
            | (((((b3!(20) | b3!(0)) & 214) | (b3!(20) & b3!(0))) | a) & b3!(32))) as u8,
    );

    // Save T
    b = ((b2!((b1!(57) % 35)) & b0!((b3!(64) % 20)))
        | ((b0!((b3!(64) % 20)) | b2!((b1!(57) % 35))) & 95)
        | (b3!(64) & 45)
        | 82)
        & 32;
    c = ((b2!((b1!(57) % 35)) & b0!((b3!(64) % 20)))
        | ((b2!((b1!(57) % 35)) | b0!((b3!(64) % 20))) & 95))
        & ((b3!(64) & 45) | 82);
    d = ((b3!(0) / 3).wrapping_sub(b3!(64) | b1!(22))) ^ (b3!(28).wrapping_add(62)) ^ (b | c);
    t = b0!(((d & 0xff) % 20));

    buffer3[68] = (b0!((b1!(99) % 20))
        .wrapping_mul(b0!((b1!(99) % 20)))
        .wrapping_mul(b0!((b1!(99) % 20)))
        .wrapping_mul(b0!((b1!(99) % 20)))
        | b2!((b3!(64) % 35))) as u8;

    u = b0!((b1!(50) % 20));
    w = b2!((b1!(138) % 35));
    x = b4!((b1!(39) % 21));
    y = b0!((b1!(4) % 20));
    z = b4!((b1!(202) % 21));
    v = b0!((b1!(151) % 20));
    s = b2!((b1!(14) % 35));
    r = b0!((b1!(145) % 20));

    a = (b2!((b3!(68) % 35)) & b0!((b1!(209) % 20)))
        | ((b2!((b3!(68) % 35)) | b0!((b1!(209) % 20))) & 24);
    b = weird_rol8(buffer4[(b1!(127) % 21) as usize], b2!((b3!(68) % 35)) & 7);
    c = (a & b0!(10)) | (b & !b0!(10));
    d = 7 ^ (b4!((b2!((b3!(36) % 35)) % 21)) << 1);
    buffer3[72] = ((c & 71) | (d & !71u32)) as u8;

    buffer2[2] = buffer2[2].wrapping_add(
        ((((b0!((b3!(20) % 20)) << 1) & 159) | (b4!((b1!(190) % 21)) & !159u32))
            & ((((b4!((b3!(64) % 21)) & 110) | (b0!((b1!(25) % 20)) & !110u32)) & !150u32)
                | (b1!(25) & 150))) as u8,
    );
    buffer2[14] = buffer2[14].wrapping_sub(
        (((b2!((b3!(20) % 35)) & (b3!(72) ^ b2!((b1!(100) % 35)))) & !34u32) | (b1!(97) & 34)) as u8,
    );
    buffer0[17] = 115;

    {
        let p = b4!((b1!(17) % 21)) | b0!((b3!(20) % 20));
        let q = b4!((b1!(17) % 21)) & b0!((b3!(20) % 20));
        let inner = (p & b3!(72)) | q;
        let val = ((inner & (b1!(50) / 3)) | ((inner | (b1!(50) / 3)) & 246)) << 1;
        buffer1[23] ^= val as u8;
    }

    buffer0[13] = ((((((b0!((b3!(40) % 20)) | b1!(10)) & 82) | (b0!((b3!(40) % 20)) & b1!(10)))
        & 209)
        | ((b0!((b1!(39) % 20)) << 1) & 46))
        >> 1) as u8;

    buffer2[33] = buffer2[33].wrapping_sub((b1!(113) & 9) as u8);
    buffer2[28] = buffer2[28]
        .wrapping_sub(((((2 | (b1!(110) & 222)) >> 1) & !223u32) | (b3!(20) & 223)) as u8);

    let jj = weird_rol8((v | z) as u8, u & 7);
    a = (b2!(16) & t) | (w & (!b2!(16)));
    b = (b1!(33) & 17) | (x & !17u32);
    e = ((y | ((a.wrapping_add(b)) / 5)) & 147) | (y & ((a.wrapping_add(b)) / 5));
    m = (b3!(40) & b4!(((b3!(8).wrapping_add(jj).wrapping_add(e)) & 0xff) % 21))
        | ((b3!(40) | b4!(((b3!(8).wrapping_add(jj).wrapping_add(e)) & 0xff) % 21)) & b2!(23));

    buffer0[15] = (((((b4!((b3!(20) % 21)).wrapping_sub(48)) & (!b1!(184)))
        | ((b4!((b3!(20) % 21)).wrapping_sub(48)) & 189)
        | (189 & !b1!(184)))
        & m.wrapping_mul(m).wrapping_mul(m))) as u8;

    buffer2[22] = buffer2[22].wrapping_add(buffer1[183]);
    buffer3[76] = ((3u32.wrapping_mul(b4!((b1!(1) % 21)))) ^ b3!(0)) as u8;

    a = b2!((((b3!(8).wrapping_add(jj.wrapping_add(e))) & 0xff) % 35));
    f = ((b4!((b1!(178) % 21)) & a) | ((b4!((b1!(178) % 21)) | a) & 209))
        .wrapping_mul(b0!((b1!(13) % 20)))
        .wrapping_mul(b4!((b1!(26) % 21)) >> 1);
    let g = (f.wrapping_add(0x733ffff9))
        .wrapping_mul(198)
        .wrapping_sub(((f.wrapping_add(0x733ffff9)).wrapping_mul(396).wrapping_add(212)) & 212)
        .wrapping_add(85);
    buffer3[80] = b3!(36)
        .wrapping_add(g ^ 148)
        .wrapping_add((g ^ 107) << 1)
        .wrapping_sub(127) as u8;

    buffer3[84] = ((b2!((b3!(64) % 35)) & 245) | (b2!((b3!(20) % 35)) & 10)) as u8;

    a = b0!((b3!(68) % 20)) | 81;
    buffer2[18] = buffer2[18].wrapping_sub(
        ((a.wrapping_mul(a).wrapping_mul(a) & !(buffer0[15] as u32))
            | ((b3!(80) / 15) & (buffer0[15] as u32))) as u8,
    );

    buffer3[88] = b3!(8)
        .wrapping_add(jj)
        .wrapping_add(e)
        .wrapping_sub(b0!((b1!(160) % 20)))
        .wrapping_add(b4!((b0!(((b3!(8).wrapping_add(jj).wrapping_add(e)) & 255) % 20) % 21)) / 3)
        as u8;

    b = ((r ^ b3!(72)) & !198u32) | ((s.wrapping_mul(s)) & 198);
    f = (b4!((b1!(69) % 21)) & b1!(172))
        | ((b4!((b1!(69) % 21)) | b1!(172)) & ((b3!(12).wrapping_sub(b)).wrapping_add(77)));
    buffer0[16] =
        147u32.wrapping_sub((b3!(72) & ((f & 251) | 1)) | (((f & 250) | b3!(72)) & 198)) as u8;

    c = (b4!((b1!(168) % 21)) & b0!((b1!(29) % 20)) & 7)
        | ((b4!((b1!(168) % 21)) | b0!((b1!(29) % 20))) & 6);
    f = (b4!((b1!(155) % 21)) & b1!(105)) | ((b4!((b1!(155) % 21)) | b1!(105)) & 141);
    buffer0[3] = buffer0[3].wrapping_sub(b4!((weird_rol32(f as u8, c) % 21)) as u8);

    buffer1[5] = (weird_ror8(buffer0[12], (b0!((b1!(61) % 20)) / 5) & 7)
        ^ ((!b2!((b3!(84) % 35)) & 0xffffffff) / 5)) as u8;

    buffer1[198] = buffer1[198].wrapping_add(buffer1[3]);

    a = 162 | b2!((b3!(64) % 35));
    buffer1[164] = buffer1[164].wrapping_add((a.wrapping_mul(a) / 5) as u8);

    let g2 = weird_ror8(139, b3!(80) & 7);
    c = (b4!((b3!(64) % 21))
        .wrapping_mul(b4!((b3!(64) % 21)))
        .wrapping_mul(b4!((b3!(64) % 21)))
        & 95)
        | (b0!((b3!(40) % 20)) & !95u32);
    buffer3[92] = ((g2 & 12) | (b0!((b3!(20) % 20)) & 12) | (g2 & b0!((b3!(20) % 20))) | c) as u8;

    buffer2[12] =
        buffer2[12].wrapping_add((((b1!(103) & 32) | (b3!(92) & (b1!(103) | 60)) | 16) / 3) as u8);
    buffer3[96] = buffer1[143];
    buffer3[100] = 27;

    buffer3[104] =
        ((((b3!(40) & !(buffer2[8] as u32)) | (b1!(35) & (buffer2[8] as u32))) & b3!(64)) ^ 119)
            as u8;
    buffer3[108] = (238
        & ((((b3!(40) & !(buffer2[8] as u32)) | (b1!(35) & (buffer2[8] as u32))) & b3!(64)) << 1))
        as u8;
    buffer3[112] = ((!b3!(64) & (b3!(84) / 3)) ^ 49) as u8;
    buffer3[116] = (98 & ((!b3!(64) & (b3!(84) / 3)) << 1)) as u8;

    // finale
    a = (b1!(35) & (buffer2[8] as u32)) | (b3!(40) & !(buffer2[8] as u32));
    b = (a & b3!(64)) | ((b3!(84) / 3) & !b3!(64));
    buffer1[143] = b3!(96).wrapping_sub(
        (b & (86 + ((b1!(172) & 64) >> 1)))
            | (((((b1!(172) & 65) >> 1) ^ 86)
                | ((!b3!(64) & (b3!(84) / 3))
                    | (((b3!(40) & !(buffer2[8] as u32)) | (b1!(35) & (buffer2[8] as u32)))
                        & b3!(64))))
                & b3!(100)),
    ) as u8;

    buffer2[29] = 162;

    a = ((b4!((b3!(88) % 21)) & 160) | (b0!((b1!(125) % 20)) & 95)) >> 1;
    b = b2!((b1!(149) % 35)) ^ (b1!(43).wrapping_mul(b1!(43)));
    buffer0[15] = buffer0[15].wrapping_add(((b & a) | ((a | b) & 115)) as u8);

    buffer3[120] = b3!(64).wrapping_sub(b0!((b3!(40) % 20))) as u8;
    buffer1[95] = b4!((b3!(20) % 21)) as u8;

    a = weird_ror8(
        buffer2[(b3!(80) % 35) as usize],
        b2!((b1!(17) % 35))
            .wrapping_mul(b2!((b1!(17) % 35)))
            .wrapping_mul(b2!((b1!(17) % 35)))
            & 7,
    );
    buffer0[7] = buffer0[7].wrapping_sub(a.wrapping_mul(a) as u8);

    buffer2[8] = (buffer2[8] as u32)
        .wrapping_sub(b1!(184))
        .wrapping_add(
            b4!((b1!(202) % 21))
                .wrapping_mul(b4!((b1!(202) % 21)))
                .wrapping_mul(b4!((b1!(202) % 21))),
        ) as u8;
    buffer0[16] = ((b2!((b1!(102) % 35)) << 1) & 132) as u8;

    buffer3[124] = ((b4!((b3!(40) % 21)) >> 1) ^ b3!(68)) as u8;

    buffer0[7] = buffer0[7].wrapping_sub(
        b0!((b1!(191) % 20)).wrapping_sub(
            ((b4!((b1!(80) % 21)) << 1) & !177u32) | (b4!((b4!((b3!(88) % 21)) % 21)) & 177),
        ) as u8,
    );
    buffer0[6] = b0!((b1!(119) % 20)) as u8;

    a = (b4!((b1!(190) % 21)) & !209u32) | (b1!(118) & 209);
    b = b0!((b3!(120) % 20)).wrapping_mul(b0!((b3!(120) % 20)));
    buffer0[12] = ((b0!((b3!(84) % 20)) ^ (b2!((b1!(71) % 35)).wrapping_add(b2!((b1!(15) % 35)))))
        & ((a & b) | ((a | b) & 27))) as u8;

    b = (b1!(32) & b2!((b3!(88) % 35))) | ((b1!(32) | b2!((b3!(88) % 35))) & 23);
    d = ((b4!((b1!(57) % 21)).wrapping_mul(231)) & 169) | (b & 86);
    f = (((b0!((b1!(82) % 20)) & !29u32) | (b4!((b3!(124) % 21)) & 29)) & 190)
        | (b4!((d / 5) % 21) & !190u32);
    h = b0!((b3!(40) % 20))
        .wrapping_mul(b0!((b3!(40) % 20)))
        .wrapping_mul(b0!((b3!(40) % 20)));
    k = (h & b1!(82)) | (h & 92) | (b1!(82) & 92);
    buffer3[128] = (((f & k) | ((f | k) & 192)) ^ (d / 5)) as u8;

    buffer2[25] ^= ((b0!((b3!(120) % 20)) << 1).wrapping_mul(b1!(5))).wrapping_sub(
        weird_rol8(b3!(76) as u8, b4!((b3!(124) % 21)) & 7) & (b3!(20).wrapping_add(110)),
    ) as u8;

    let _ = (m, jj, g, h, k, r, s, t, u, v, w, x, y, z, e, f, g2, tmp, tmp2, tmp3);
}

// ---------------------------------------------------------------------------
// Session key generation
// ---------------------------------------------------------------------------

fn generate_session_key(old_sap: &[u8], message_in: &[u8], session_key: &mut [u8]) {
    let mut decrypted_message = [0u8; 128];
    let mut new_sap = [0u8; 320];

    decrypt_message(message_in, &mut decrypted_message);

    new_sap[0x000..0x000 + STATIC_SOURCE1.len()].copy_from_slice(STATIC_SOURCE1);
    new_sap[0x011..0x011 + 0x80].copy_from_slice(&decrypted_message[..0x80]);
    new_sap[0x091..0x091 + 0x80].copy_from_slice(&old_sap[0x80..0x100]);
    new_sap[0x111..0x111 + STATIC_SOURCE2.len()].copy_from_slice(STATIC_SOURCE2);
    session_key[..16].copy_from_slice(INITIAL_SESSION_KEY);

    let mut md5_out = [0u8; 16];
    for round in 0..5 {
        let base_start = round * 64;
        let base = new_sap[base_start..].to_vec();
        modified_md5(&base, session_key, &mut md5_out);
        sap_hash(&base, session_key);

        for i in 0..4 {
            let skw = le_u32(&session_key[i * 4..]);
            let mdw = le_u32(&md5_out[i * 4..]);
            put_le_u32(&mut session_key[i * 4..], skw.wrapping_add(mdw));
        }
    }

    for i in (0..16).step_by(4) {
        session_key.swap(i, i + 3);
        session_key.swap(i + 1, i + 2);
    }

    for i in 0..16 {
        session_key[i] ^= 121;
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn playfair_decrypt(m3: &[u8], ekey: &[u8]) -> [u8; 16] {
    playfair_decrypt_with_sap(m3, ekey, DEFAULT_SAP)
}

fn playfair_decrypt_with_sap(m3: &[u8], ekey: &[u8], sap: &[u8]) -> [u8; 16] {
    let chunk1 = &ekey[16..32];
    let chunk2 = &ekey[56..72];

    let mut block_in = [0u8; 16];
    let mut sap_key = [0u8; 16];
    let mut key_schedule = [[0u32; 4]; 11];
    let mut key_out = [0u8; 16];

    generate_session_key(sap, m3, &mut sap_key);
    generate_key_schedule(&sap_key, &mut key_schedule);

    z_xor(chunk2, &mut block_in, 1);
    cycle(&mut block_in, &key_schedule);

    for i in 0..16 {
        key_out[i] = block_in[i] ^ chunk1[i];
    }
    let tmp = key_out;
    x_xor(&tmp, &mut key_out, 1);
    let tmp = key_out;
    z_xor(&tmp, &mut key_out, 1);

    key_out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        s.chunks(2)
            .map(|c| {
                let hi = (c[0] as char).to_digit(16).unwrap() as u8;
                let lo = (c[1] as char).to_digit(16).unwrap() as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    #[test]
    fn golden_vectors() {
        let m3 = hex(
            "46504c590301030000000098038f1a9c991ea22c511e45ba97f1af8dfb0f86f550c54486fe6b3ab233da431ef8e5fc1156dba321fffeabb1b392b09d227e88c712202866eb7bbf310015aa1d19a5df36d5dfd8d3ca1639b376eaece946edfe8b7a66cd302d04aac3c1251714019bd5f2d49b543e11eed1646291ec8efd96b69101b849fd93a02860d1a0dff5cd4414aa4b911e48af23d8406368aeafbb61bfcd569e3e55",
        );

        let ekey = hex(
            "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4",
        );
        let out = playfair_decrypt(&m3, &ekey);
        assert_eq!(out.to_vec(), hex("fdd753e0342022e45a188e9e39988aaa"));

        let ekey2 = hex(
            "5a6774818e9ba8b5c2cfdce9f603101d2a3744515e6b7885929facb9c6d3e0edfa0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d9aa7b4c1cedbe8f5",
        );
        let out2 = playfair_decrypt(&m3, &ekey2);
        assert_eq!(out2.to_vec(), hex("93193927255d3c164b3b1ad132c80d06"));
    }
}
