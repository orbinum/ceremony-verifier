use crate::error::{format, Result};

/// Bounds-checked little-endian cursor over a byte slice.
pub struct ByteReader<'a> {
    bytes: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> ByteReader<'a> {
    /// A cursor over the whole slice.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            end: bytes.len(),
        }
    }

    /// A cursor over `bytes[start..end]`, clamped so that start ≤ end ≤ len.
    pub fn bounded(bytes: &'a [u8], start: usize, end: usize) -> Self {
        let end = end.min(bytes.len());
        Self {
            bytes,
            pos: start.min(end),
            end,
        }
    }

    /// The current offset.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Bytes left before the end bound.
    pub fn remaining(&self) -> usize {
        self.end - self.pos
    }

    /// The next `n` bytes, or a format error past the end.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        match self.pos.checked_add(n) {
            Some(next) if next <= self.end => {
                let slice = &self.bytes[self.pos..next];
                self.pos = next;
                Ok(slice)
            }
            _ => format(format!("read of {n} bytes past the end at {}", self.pos)),
        }
    }

    /// A byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// A little-endian u32.
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A little-endian u64.
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
}
