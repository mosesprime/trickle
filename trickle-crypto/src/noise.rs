//! Custom implimentation of the Noise protocol framework.
//! Reference: https://noiseprotocol.org/noise.pdf

use std::{fmt::Display, ops::{Deref, DerefMut}};
use aead::CipherError;
use handshakestate::HandshakeError;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod aead;
mod cipherstate;
mod dh;
pub mod handshakestate;
mod hash;
mod pattern;
mod symmetricstate;
pub mod transportstate;

pub const MAX_MESSAGE_SIZE: usize = 65_535;
pub const MAX_HASH_LEN: usize = 64;
pub const MAX_DH_LEN: usize = 56;
pub const PSK_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const CIPHER_KEY_LEN: usize = 32;
const MAX_BLOCK_LEN: usize = 128;

#[cfg(feature = "hfs")]
pub const MAX_KEM_PUB_LEN: usize = 4_096;
#[cfg(feature = "hfs")]
pub const MAX_KEM_CIPHERTEXT_LEN: usize = 4_096;
#[cfg(feature = "hfs")]
pub const MAX_KEM_SS_LEN: usize = 32;

pub(crate) struct Toggle<T> {
    inner: T,
    pub is_on: bool,
}

impl<T> Toggle<T> {
    fn new(inner: T, is_on: bool) -> Self {
        Self { inner, is_on }
    }

    fn enable(&mut self) {
        self.is_on = true
    }

    fn get(&self) -> Option<&T> {
        if self.is_on {
            return Some(&self.inner);
        }
        None
    }
}

impl<T> Deref for Toggle<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for Toggle<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[derive(Debug)]
pub enum NoiseError {
    InvalidMessageSize,
    InvalidMessagePattern,
    InvalidMessageDirection,
    Cipher(CipherError),
    Handshake(HandshakeError),
}

impl Display for NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for NoiseError {}

/// Reference: <https://noiseprotocol.org/noise.html#cipher-functions>
pub(crate) trait NoiseCipher: ZeroizeOnDrop + Zeroize + Send + Sync {
    /// Returns a string identifier for the cipher.          
    fn name(&self) -> &'static str;

    fn rekey(&mut self);
    
    fn set_key(&mut self, key: &[u8; CIPHER_KEY_LEN]);

    fn encrypt(&self, nonce: u64, associated_data: &[u8], plaintext: &[u8], out: &mut [u8]) -> Result<usize, CipherError>;

    fn decrypt(&self, nonce: u64, associated_data: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result<usize, CipherError>;
}

/// Reference: <https://noiseprotocol.org/noise.html#hash-functions>
pub(crate) trait NoiseHash: Send + Sync {
    fn name(&self) -> &'static str;

    fn block_len(&self) -> usize;

    fn hash_len(&self) -> usize;

    fn reset(&mut self);

    fn input(&mut self, data: &[u8]);

    fn result(&mut self, out: &mut [u8]);

    /// Standardized HMAC from Noise spec.
    /// Reference: <https://www.ietf.org/rfc/rfc2104.txt>
    /// WARN: Destroys existing internal state.
    fn hmac(&mut self, key: &[u8], data: &[u8], out: &mut [u8]) {
        debug_assert!(key.len() <= self.block_len());
        let block_len = self.block_len();
        let hash_len = self.hash_len();
        let mut ipad = [0x36u8; MAX_BLOCK_LEN];
        let mut opad = [0x5Cu8; MAX_BLOCK_LEN];
        for n in 0..key.len() {
            ipad[n] ^= key[n];
            opad[n] ^= key[n];
        }
        self.reset();
        self.input(&ipad[..block_len]);
        self.input(data);
        let mut inner_output = [0u8; MAX_HASH_LEN];
        self.result(&mut inner_output);
        self.reset();
        self.input(&opad[..block_len]);
        self.input(&inner_output[..hash_len]);
        self.result(out);
    }

    /// Standardized hash-based key derevation function from Noise spec.
    /// WARN: Destroys existing internal state.
    fn hkdf(&mut self, chain_key: &[u8], key_mat: &[u8], outputs: usize, out1: &mut [u8], out2: &mut[u8], out3: &mut [u8]) {
        let hash_len = self.hash_len();
        let mut temp = [0u8; MAX_HASH_LEN];
        self.hmac(chain_key, key_mat, &mut temp);
        self.hmac(&temp, &[1u8], out1);
        if outputs == 1 { return; }
        let mut in2 = [0u8; MAX_HASH_LEN + 1];
        in2.copy_from_slice(&out1[0..hash_len]);
        in2[hash_len] = 2;
        self.hmac(&temp, &in2[..=hash_len], out2);
        if outputs == 2 { return; }
        let mut in3 = [0u8; MAX_HASH_LEN + 1];
        in3.copy_from_slice(&out2[0..hash_len]);
        in3[hash_len] = 3;
        self.hmac(&temp, &in3[..=hash_len], out3);
    }
}

/// Reference: <https://noiseprotocol.org/noise.html#dh-functions>
pub(crate) trait NoiseDH: Send + Sync {
    fn name(&self) -> &'static str;

    fn pubkey_len(&self) -> usize;

    fn privkey_len(&self) -> usize;

    fn set_privkey(&mut self, privkey: &[u8]);

    fn pubkey(&self) -> &[u8];

    fn privkey(&self) -> &[u8];

    fn generate(&mut self);

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), Box<dyn std::error::Error>>;   
}

#[cfg(feature = "hfs")]
pub(crate) trait NoiseKem: ZeroizeOnDrop + Zeroize + Send + Sync {
    fn name(&self) -> &'static str;

    fn pubkey_len(&self) -> usize;

    fn ciphertext_len(&self) -> usize;

    fn shared_secret_len(&self) -> usize;

    fn pubkey(&self) -> &[u8];

    fn generate(&mut self);

    fn encapsulate(&self, pubkey: &[u8], shared_secret_out: &mut [u8], ciphertext_out: &mut [u8]) -> Result<(usize, usize), ()>;

    fn decapsulate(&self, ciphertext: &[u8], shared_secret_out: &mut [u8]) -> Result<usize, ()>;
}
