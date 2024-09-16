use blake2::{Blake2s, Blake2s256};
use sha2::{Digest, Sha256};

use super::{pattern::HashChoice, NoiseHash};

pub(crate) fn resolve_hasher(choice: &HashChoice) -> Box<dyn NoiseHash> {
    match choice {
        HashChoice::SHA256 => Box::new(SHA256Hasher::default()),
        HashChoice::BLAKE2s => Box::new(Blake2sHasher::default()),
        HashChoice::BLAKE3 => Box::new(Blake3Hasher::default()),
        _ => unimplemented!()
    }
}

/// Wrapper for SHA256 hasher.
#[derive(Default)]
pub(crate) struct SHA256Hasher {
    inner: Sha256, 
}

impl NoiseHash for SHA256Hasher {
    fn name(&self) -> &'static str {
        "SHA256"
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn block_len(&self) -> usize {
        64
    }

    fn input(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    fn reset(&mut self) {
        self.inner = Sha256::default();
    }

    fn result(&mut self, out: &mut [u8]) {
        out.copy_from_slice(self.inner.finalize_reset().as_slice())
    }
}

/// Wrapper for BLAKE2s 256-bit hasher.
#[derive(Default)]
pub(crate) struct Blake2sHasher {
    inner: Blake2s256,
}

impl NoiseHash for Blake2sHasher {
    fn name(&self) -> &'static str {
        "BLAKE2s"
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn block_len(&self) -> usize {
        64
    }

    fn reset(&mut self) {
        self.inner = Blake2s::default();
    }

    fn input(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        out.copy_from_slice(self.inner.finalize_reset().as_slice());
    }
}

/// Wrapper for BLAKE3 256-bit hasher.
#[derive(Default)]
pub(crate) struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl NoiseHash for Blake3Hasher {
    fn name(&self) -> &'static str {
        "BLAKE3"
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn block_len(&self) -> usize {
        64
    }

    fn reset(&mut self) {
        self.inner = blake3::Hasher::default();
    }

    fn input(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        out.copy_from_slice(self.inner.finalize().as_bytes());
        self.inner.reset();
    }
}
