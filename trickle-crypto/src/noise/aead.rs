use aes_gcm::{aead::AeadMutInPlace, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::noise::{NoiseCipher, CIPHER_KEY_LEN};

use super::pattern::CipherChoice;

/// Resolves the desired cipher with default key.
pub(crate) fn resolve_cipher(choice: &CipherChoice) -> Box<dyn NoiseCipher> {
    match choice {
        CipherChoice::AESGCM => Box::new(Aes256GcmCipher::new([0u8; Aes256GcmCipher::KEY_LEN])),
        CipherChoice::ChaChaPoly => Box::new(ChaChaPolyCipher::new([0u8; ChaChaPolyCipher::KEY_LEN])),
    }
}

#[derive(Debug)]
pub enum CipherError {
    Encrypt,
    Decrypt,
    NonceExhausted,
    MissingKeyMaterial,
}

impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CipherError {}

/// Wrapped AES-GCM 256bit AEAD cipher.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Aes256GcmCipher {
    key: [u8; Self::KEY_LEN],
}

impl Aes256GcmCipher {
    pub(crate) const KEY_LEN: usize = 32;
    pub(crate) const TAG_LEN: usize = 16;
    pub(crate) const NONCE_LEN: usize = 12;

    pub fn new(key: [u8; Self::KEY_LEN]) -> Self {
        Self { key }
    }
}

impl NoiseCipher for Aes256GcmCipher {
    fn name(&self) -> &'static str {
        "AESGCM"
    }

    fn rekey(&mut self) {
        let mut cipher_text = [0; Self::KEY_LEN + Self::TAG_LEN];    
        self.encrypt(u64::MAX, &[], &[0; Self::KEY_LEN], &mut cipher_text).expect("failed encrypt");
        let mut key = [0; Self::KEY_LEN];
        key.copy_from_slice(&cipher_text[..Self::KEY_LEN]);
        self.set_key(&key)
    }

    fn set_key(&mut self, key: &[u8; CIPHER_KEY_LEN]) {
        self.key = *key;
    }

    fn encrypt(&self, nonce: u64, associated_data: &[u8], plaintext: &[u8], out: &mut [u8]) -> Result<usize, CipherError> {
        debug_assert_eq!(plaintext.len() + Self::TAG_LEN, out.len());
        out[..plaintext.len()].copy_from_slice(plaintext);
        let mut nonce_bytes = [0u8; Self::NONCE_LEN];
        nonce_bytes.copy_from_slice(&nonce.to_be_bytes());
        let tag = Aes256Gcm::new(&self.key.into())
            .encrypt_in_place_detached(&nonce_bytes.into(), associated_data, &mut out[..plaintext.len()])
            .map_err(|_| CipherError::Encrypt)?;
        out[plaintext.len()..].copy_from_slice(&tag);
        Ok(plaintext.len() + Self::TAG_LEN)
    }

    fn decrypt(&self, nonce: u64, associated_data: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result<usize, CipherError> {
        debug_assert_eq!(ciphertext.len(), out.len() + Self::TAG_LEN);
        let msg_len = ciphertext.len() - Self::TAG_LEN;
        out.copy_from_slice(&ciphertext[..msg_len]);
        let mut nonce_bytes = [0u8; Self::NONCE_LEN];
        nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());
        Aes256Gcm::new(&self.key.into())
            .decrypt_in_place_detached(&nonce_bytes.into(), associated_data, &mut out[..msg_len], ciphertext[msg_len..].into())
            .map_err(|_| CipherError::Decrypt)?;
        Ok(msg_len)
    }
}

/// Wrapped ChaCha20Poly1305 AEAD cipher.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct ChaChaPolyCipher {
    key: [u8; Self::KEY_LEN],
}

impl ChaChaPolyCipher {
    pub(crate) const KEY_LEN: usize = 32;
    pub(crate) const TAG_LEN: usize = 16;
    pub(crate) const NONCE_LEN: usize = 12;
    
    pub fn new(key: [u8; Self::KEY_LEN]) -> Self {
        Self { key }
    }
}

impl NoiseCipher for ChaChaPolyCipher {

    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn rekey(&mut self) {
        let mut cipher_text = [0; Self::KEY_LEN + Self::TAG_LEN];    
        self.encrypt(u64::MAX, &[], &[0; Self::KEY_LEN], &mut cipher_text).expect("failed encrypt");
        let mut key = [0; Self::KEY_LEN];
        key.copy_from_slice(&cipher_text[..Self::KEY_LEN]);
        self.set_key(&key)
    }
    
    fn set_key(&mut self, key: &[u8; CIPHER_KEY_LEN]) {
        self.key = *key;
    }

    fn encrypt(&self, nonce: u64, associated_data: &[u8], plaintext: &[u8], out: &mut [u8]) -> Result<usize, CipherError> {
        debug_assert_eq!(plaintext.len() + Self::TAG_LEN, out.len());
        out[..plaintext.len()].copy_from_slice(plaintext);
        let mut nonce_bytes = [0u8; Self::NONCE_LEN];
        nonce_bytes.copy_from_slice(&nonce.to_le_bytes());
        let tag = ChaCha20Poly1305::new(&self.key.into())
            .encrypt_in_place_detached(&nonce_bytes.into(), associated_data, &mut out[..plaintext.len()])
            .map_err(|_| CipherError::Encrypt)?;
        out[plaintext.len()..].copy_from_slice(&tag);
        Ok(plaintext.len() + tag.len())
    }

    fn decrypt(&self, nonce: u64, associated_data: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result<usize, CipherError> {
        debug_assert_eq!(ciphertext.len(), out.len() + Self::TAG_LEN);
        let msg_len = ciphertext.len() - Self::TAG_LEN;
        out.copy_from_slice(&ciphertext[..msg_len]);
        let mut nonce_bytes = [0u8; Self::NONCE_LEN];
        nonce_bytes.copy_from_slice(&nonce.to_le_bytes());
        ChaCha20Poly1305::new(&self.key.into())
            .decrypt_in_place_detached(&nonce_bytes.into(), associated_data, &mut out[..msg_len], ciphertext[msg_len..].into())
            .map_err(|_| CipherError::Decrypt)?;
        Ok(msg_len)
    }
}

#[test]
fn chachapoly_noise_cipher() {
    let key = [0; ChaChaPolyCipher::KEY_LEN];
    let nonce = 0;
    let msg = b"banana";
    let cipher = ChaChaPolyCipher::new(key);
    let mut ciphertext = vec![0u8; msg.len() + ChaChaPolyCipher::TAG_LEN];
    cipher.encrypt(nonce, &[], msg, &mut ciphertext).expect("failed encrypt");
    let mut plaintext = vec![0u8; msg.len()];
    cipher.decrypt(nonce, &[], &ciphertext, &mut plaintext).expect("failed decrypt");
    assert_eq!(plaintext, msg, "failed roundtrip");
}

#[test]
fn aes_256_gcm_noise_cipher() {
    let key = [0u8; Aes256GcmCipher::KEY_LEN];
    let nonce = 0;
    let authtext = [0u8; 0];
    let msg = b"banana";
    let cipher = Aes256GcmCipher::new(key);
    let mut ciphertext = vec![0u8; msg.len() + Aes256GcmCipher::TAG_LEN];
    cipher.encrypt(nonce, &authtext, msg, &mut ciphertext).expect("failed encrypt");
    let mut plaintext = vec![0u8; msg.len()];
    cipher.decrypt(nonce, &authtext, &ciphertext, &mut plaintext).expect("failed decrypt");
    assert_eq!(plaintext, msg, "failed roundtrip");
}
