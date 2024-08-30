//! Custom implimentation of the Noise protocol framework.
//! Reference: http://noiseprotocol.org/noise.pdf

use std::fmt::Display;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::cipher::CipherError;

pub mod cipherstate;
pub mod handshakestate;
pub mod pattern;
pub mod symmetricstate;
pub mod transportstate;

pub const MAX_MESSAGE_SIZE: usize = 65_535;
pub const MAX_HASH_LEN: usize = 64;
pub const MAX_DH_LEN: usize = 56;
pub const PSK_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const CIPHER_KEY_LEN: usize = 32;

#[derive(Debug)]
pub enum NoiseError {
    InvalidMessageSize,
    InvalidMessagePattern,
    Cipher(CipherError),
}

impl Display for NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for NoiseError {}

/// Reference: http://noiseprotocol.org/noise.html#cipher-functions
pub(crate) trait NoiseCipher: ZeroizeOnDrop + Zeroize + Send + Sync {
    /// Returns a string identifier for the cipher.          
    fn name(&self) -> &'static str;

    fn rekey(&mut self);
    
    fn set_key(&mut self, key: &[u8; CIPHER_KEY_LEN]);

    fn encrypt(&self, nonce: u64, associated_data: &[u8], plaintext: &[u8], out: &mut [u8]) -> Result<usize, CipherError>;

    fn decrypt(&self, nonce: u64, associated_data: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result<usize, CipherError>;
}

/// Reference: http://noiseprotocol.org/noise.html#hash-functions
pub(crate) trait NoiseHash: Send + Sync {
    fn name(&self) -> &'static str;

    fn block_len(&self) -> usize;

    fn hash_len(&self) -> usize;

    fn reset(&mut self);

    fn input(&mut self, data: &[u8]);

    fn result(&mut self, out: &mut [u8]);

    fn hmac(&mut self, key: &[u8], data: &[u8], out: &mut [u8]) {
        todo!()
    }

    fn hkdf(&mut self, chain_key: &[u8], key_mat: &[u8], outputs: usize, out1: &mut [u8], out2: &mut[u8], out3: &mut [u8]) {
        todo!()
    }
}

/// Reference: http://noiseprotocol.org/noise.html#dh-functions
pub(crate) trait NoiseDH: ZeroizeOnDrop + Zeroize + Send + Sync {
    fn name(&self) -> &'static str;

    fn pubkey_len(&self) -> usize;

    fn privkey_len(&self) -> usize;

    fn set_privkey(&mut self, privkey: &[u8]);

    fn pubkey(&self) -> &[u8];

    fn privkey(&self) -> &[u8];

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), Box<dyn std::error::Error>>;   
}

#[cfg(feature = "hfs")]
pub(crate) trait NoiseKem: ZeroizeOnDrop + Zeroize + Send + Sync {
    fn name(&self) -> &'static str;

    fn pubkey_len(&self) -> usize;

    fn ciphertext_len(&self) -> usize;

    fn shared_secret_len(&self) -> usize;

    fn pubkey(&self) -> &[u8];

    fn encapsulate(&self, pubkey: &[u8], shared_secret_out: &mut [u8], ciphertext_out: &mut [u8]) -> Result<(usize, usize), ()>;

    fn decapsulate(&self, ciphertext: &[u8], shared_secret_out: &mut [u8]) -> Result<usize, ()>;
}
