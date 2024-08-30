use zeroize::ZeroizeOnDrop;

use crate::cipher::CipherError;

use super::{NoiseCipher, CIPHER_KEY_LEN};

/// Reference: http://noiseprotocol.org/noise.html#the-cipherstate-object
#[derive(ZeroizeOnDrop)]
pub(crate) struct CipherState {
    nonce: u64,
    cipher: Box<dyn NoiseCipher>,
    has_key: bool,
}

impl CipherState {
    pub fn new(cipher: Box<dyn NoiseCipher>) -> Self {
        Self { nonce: 0, cipher, has_key: false }
    }

    pub fn set_key(&mut self, key: &[u8; CIPHER_KEY_LEN]) {
        self.cipher.set_key(key);
        self.has_key = true;
    }

    pub fn encrypt(&mut self, associated_data: Option<&[u8]>, plaintext: &[u8], out: &mut [u8]) -> Result<usize, CipherError> {
        if !self.has_key {
            return Err(CipherError::MissingKeyMaterial);
        }
        if self.nonce == u64::MAX {
            return Err(CipherError::NonceExhausted);
        }
        let len = self.cipher.encrypt(self.nonce, associated_data.unwrap_or(&[]), plaintext, out)?;
        self.nonce += 1;
        Ok(len)
    }

    pub fn decrypt(&mut self, associated_data: Option<&[u8]>, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, CipherError> {
        if !self.has_key {
            return Err(CipherError::MissingKeyMaterial);
        }
        if self.nonce == u64::MAX {
            return Err(CipherError::NonceExhausted);
        }
        let len = self.cipher.decrypt(self.nonce, associated_data.unwrap_or(&[]), ciphertext, out)?;
        self.nonce += 1;
        Ok(len)
    }

    pub(crate) fn name(&self) -> &str {
        self.cipher.name()
    }

    pub(crate) fn has_key(&self) -> bool {
        self.has_key
    }

    pub(crate) fn rekey(&mut self) {
        self.cipher.rekey()
    }

    pub(crate) fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce
    }
}
