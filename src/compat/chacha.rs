//! The ChaCha20 stream snarkjs uses as a deterministic RNG (ffjavascript `chacha.js`): 8 seed
//! words as the key, a 64-bit block counter in words 12–13, zero nonce, 10 double rounds.

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// The deterministic stream; draws are consumed word by word.
pub struct ChaCha {
    state: [u32; 16],
    block: [u32; 16],
    idx: usize,
}

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

impl ChaCha {
    /// A stream keyed by eight seed words, block counter at zero.
    pub fn new(seed: [u32; 8]) -> Self {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&CONSTANTS);
        state[4..12].copy_from_slice(&seed);
        Self {
            state,
            block: [0; 16],
            idx: 16,
        }
    }

    /// Seed from the first 32 bytes, read as big-endian words (as snarkjs does).
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut seed = [0u32; 8];
        for (i, w) in seed.iter_mut().enumerate() {
            *w = u32::from_be_bytes([
                bytes[4 * i],
                bytes[4 * i + 1],
                bytes[4 * i + 2],
                bytes[4 * i + 3],
            ]);
        }
        Self::new(seed)
    }

    fn update(&mut self) {
        let mut b = self.state;
        for _ in 0..10 {
            quarter_round(&mut b, 0, 4, 8, 12);
            quarter_round(&mut b, 1, 5, 9, 13);
            quarter_round(&mut b, 2, 6, 10, 14);
            quarter_round(&mut b, 3, 7, 11, 15);
            quarter_round(&mut b, 0, 5, 10, 15);
            quarter_round(&mut b, 1, 6, 11, 12);
            quarter_round(&mut b, 2, 7, 8, 13);
            quarter_round(&mut b, 3, 4, 9, 14);
        }
        for (out, init) in b.iter_mut().zip(self.state) {
            *out = out.wrapping_add(init);
        }
        self.block = b;
        self.idx = 0;
        for w in 12..16 {
            self.state[w] = self.state[w].wrapping_add(1);
            if self.state[w] != 0 {
                break;
            }
        }
    }

    /// The next 32-bit word.
    pub fn next_u32(&mut self) -> u32 {
        if self.idx == 16 {
            self.update();
        }
        let v = self.block[self.idx];
        self.idx += 1;
        v
    }

    /// High word first, as `nextU64 = nextU32 · 2^32 + nextU32`.
    pub fn next_u64(&mut self) -> u64 {
        let hi = u64::from(self.next_u32());
        (hi << 32) | u64::from(self.next_u32())
    }

    /// The low bit of the next word.
    pub fn next_bool(&mut self) -> bool {
        self.next_u32() & 1 == 1
    }
}
