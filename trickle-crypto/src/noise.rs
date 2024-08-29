//! Custom implimentation of the Noise protocol framework.
//! Reference: https://noiseprotocol.org/noise.pdf

use std::{fmt::Display, ops::{Deref, DerefMut}};

use pattern::{CipherChoice, HandshakePattern, MessagePattern, NoiseParams, Role};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cipher::{chacha::ChaChaPolyCipher, aes::Aes256GcmCipher, CipherError};

pub mod pattern;

pub const MAX_MESSAGE_SIZE: usize = 65_535;
pub const MAX_HASH_LEN: usize = 64;
pub const MAX_DH_LEN: usize = 56;
pub const PSK_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const CIPHER_KEY_LEN: usize = 32;

#[derive(ZeroizeOnDrop)]
struct SecretBox<T: Zeroize>(pub(crate) T);

impl<T: Zeroize> Deref for SecretBox<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Zeroize> DerefMut for SecretBox<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct HandshakeState {
    role: Role,
    params: NoiseParams,
    local_s: [u8; MAX_DH_LEN],
    local_e: [u8; MAX_DH_LEN],
    local_cipher: CipherState,
    remote_s: Option<[u8; MAX_DH_LEN]>,
    remote_e: Option<[u8; MAX_DH_LEN]>,
    remote_cipher: CipherState,
    psk: Option<[u8; PSK_LEN]>,
    #[cfg(feature = "hfs")]
    local_kem: Option<Box<dyn NoiseKem>>,
    #[cfg(feature = "hfs")]
    remote_kem_e: Option<[u8; 4096]>,
    message_pattern: MessagePattern<'static>,
}

impl HandshakeState {
    pub fn new(
        role: Role,
        params: NoiseParams,
        local_s: [u8; MAX_DH_LEN],
        local_e: [u8; MAX_DH_LEN],
        remote_s: Option<[u8; MAX_DH_LEN]>,
        remote_e: Option<[u8; MAX_DH_LEN]>,
        psk: Option<[u8; PSK_LEN]>,
    ) -> Result<HandshakeState, HandshakeError> {
        if remote_s.is_none() && params.handshake.pattern.requires_remote_public(role) {
            return Err(HandshakeError::MissingRemotePublicKey);
        }
        let (local_cipher, remote_cipher): (CipherState, CipherState) = match params.cipher {
            CipherChoice::ChaChaPoly => (
                CipherState::new(Box::new(ChaChaPolyCipher::new([0u8; CIPHER_KEY_LEN]))),
                CipherState::new(Box::new(ChaChaPolyCipher::new([0u8; CIPHER_KEY_LEN])))
            ),
            CipherChoice::AESGCM => (
                CipherState::new(Box::new(Aes256GcmCipher::new([0u8; CIPHER_KEY_LEN]))),
                CipherState::new(Box::new(Aes256GcmCipher::new([0u8; CIPHER_KEY_LEN])))
            ),
        };
        let message_pattern = MessagePattern::from(params.handshake.clone());
        Ok(HandshakeState {
            role,
            params,
            local_s,
            local_e,
            local_cipher,
            remote_s,
            remote_e,
            remote_cipher,
            psk,
            #[cfg(feature = "hfs")]
            local_kem: todo!(),
            #[cfg(feature = "hfs")]
            remote_kem_e: todo!(),
            message_pattern,
        })
    }

    pub fn remote_s(&self) -> Option<&[u8]> {
        let dh_len = todo!();
        Some(&self.remote_s?[..dh_len])
    }
}

#[derive(Debug)]
pub enum HandshakeError {
    MissingRemotePublicKey,
}

impl Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for HandshakeError {}

/// Reference: https://noiseprotocol.org/noise.html#the-symmetricstate-object
pub(crate) struct SymmetricState {
    hash: [u8; MAX_HASH_LEN],
    chaining_key: [u8; MAX_HASH_LEN],
    hasher: Box<dyn NoiseHash>,
    cipherstate: CipherState,
}

impl SymmetricState {
    fn new(cipherstate: CipherState, hasher: Box<dyn NoiseHash>) -> Self {
        Self { hash: [0u8; MAX_HASH_LEN], chaining_key: [0u8; MAX_HASH_LEN], hasher, cipherstate }
    }

    fn init(&mut self, protocol_name: &str) {
        if protocol_name.len() <= self.hasher.hash_len() {
            self.hash.copy_from_slice(protocol_name.as_bytes());
        } else {
            self.hasher.reset();
            self.hasher.input(protocol_name.as_bytes());
            self.hasher.result(&mut self.hash);
        }
        self.chaining_key.copy_from_slice(&self.hash);
    }

    fn mix_key(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hdkf_out1 = [0u8; MAX_HASH_LEN];
        let mut hdkf_out2 = [0u8; MAX_HASH_LEN];
        self.hasher.hkdf(&self.chaining_key[..hash_len], data, 2, &mut hdkf_out1, &mut hdkf_out2, &mut []);
        self.chaining_key = hdkf_out1;
        // TODO: IDK if there is a better way
        unsafe {
            self.cipherstate.set_key(&*hdkf_out2[..CIPHER_KEY_LEN].as_ptr().cast());
            self.cipherstate.set_nonce(0);
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        self.hasher.reset();
        self.hasher.input(&self.hash[..hash_len]);
        self.hasher.input(data);
        self.hasher.result(&mut self.hash);
    }

    fn mix_key_and_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_out1 = [0u8; MAX_HASH_LEN];
        let mut hkdf_out2 = [0u8; MAX_HASH_LEN];
        let mut hkdf_out3 = [0u8; MAX_HASH_LEN];
        self.hasher.hkdf(&self.chaining_key[..hash_len], data, 3, &mut hkdf_out1, &mut hkdf_out2, &mut hkdf_out3);
        self.chaining_key = hkdf_out1;
        self.mix_hash(&hkdf_out2[..hash_len]);
        // TODO: IDK if there is a better way
        unsafe {
            self.cipherstate.set_key(&*hkdf_out3[..CIPHER_KEY_LEN].as_ptr().cast());
            self.cipherstate.set_nonce(0);
        }
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, CipherError> {
        let hash_len = self.hasher.hash_len();
        let out_len = if self.cipherstate.has_key {
            self.cipherstate.encrypt(Some(&self.hash[..hash_len]), plaintext, out)?
        } else {
            out.copy_from_slice(plaintext);
            plaintext.len()
        };
        self.mix_hash(&out[..out_len]);
        Ok(out_len)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, CipherError> {
        let hash_len = self.hasher.hash_len();
        let payload_len = if self.cipherstate.has_key {
            self.cipherstate.decrypt(Some(&self.hash[..hash_len]), ciphertext, out)?
        } else {
            if out.len() < ciphertext.len() {
                return Err(CipherError::Decrypt);
            }
            out.copy_from_slice(ciphertext);
            ciphertext.len()
        };
        self.mix_hash(ciphertext);
        Ok(payload_len)
    }

    fn split(&mut self, cipher1: &mut CipherState, cipher2: &mut CipherState) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_out1 = [0u8; MAX_HASH_LEN];
        let mut hkdf_out2 = [0u8; MAX_HASH_LEN];
        self.hasher.hkdf(&self.chaining_key[..hash_len], &[], 2, &mut hkdf_out1, &mut hkdf_out2, &mut []);
        // TODO: IDK if there is a better way
        unsafe {
            cipher1.set_key(&*hkdf_out1[..CIPHER_KEY_LEN].as_ptr().cast());
            cipher1.set_nonce(0);
            cipher2.set_key(&*hkdf_out2[..CIPHER_KEY_LEN].as_ptr().cast());
            cipher2.set_nonce(0);
        }
    }
}

/// Result of the handshake. Used for data transport.
pub struct TransportState {
    local_cipher: CipherState,
    remote_cipher: CipherState,
    remote_s: Option<[u8; MAX_DH_LEN]>,
    pattern: HandshakePattern,
    role: Role,
}

impl TransportState {
    fn new(handshakestate: HandshakeState) -> Result<Self, NoiseError> {
        // TODO: check handshake is finished
        let dh_len = todo!();
        let HandshakeState { role, params, local_cipher, remote_cipher, remote_s, .. } = handshakestate;
        let pattern = params.handshake.pattern;
        if local_cipher.cipher.name() != remote_cipher.cipher.name() {
            todo!()
        }
        Ok(TransportState { local_cipher, remote_cipher, remote_s, role, pattern })
    }

    fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        let cipher = match self.role {
            Role::Initiator => &mut self.local_cipher,
            Role::Recipient => {
                if self.pattern.is_one_way() {
                    todo!()
                }
                &mut self.remote_cipher
            },
        };
        if (payload.len() + TAG_LEN > MAX_MESSAGE_SIZE) || (payload.len() + TAG_LEN > out.len()) {
            return Err(NoiseError::InvalidMessageSize);
        }
        Ok(cipher.encrypt(None, payload, out).map_err(|e| NoiseError::Cipher(e))?)
    }

    fn read_message(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        if message.len() > MAX_MESSAGE_SIZE {
            return Err(NoiseError::InvalidMessageSize);
        }
        let cipher = match self.role {
            Role::Initiator => {
                if self.pattern.is_one_way() {
                    return Err(NoiseError::InvalidMessagePattern);
                }
                &mut self.remote_cipher
            },
            Role::Recipient => &mut self.local_cipher,
        };
        Ok(cipher.decrypt(None, message, out).map_err(|e| NoiseError::Cipher(e))?)
    }

    fn rekey_outbound(&mut self) {
        self.local_cipher.rekey()
    }

    fn set_outboud_nonce(&mut self, nonce: u64) {
        self.local_cipher.set_nonce(nonce)
    }

    fn rekey_inbound(&mut self) {
        self.remote_cipher.rekey()
    }

    fn set_inbound_nonce(&mut self, nonce: u64) {
        self.remote_cipher.set_nonce(nonce)
    }

    pub fn remote_s(&self) -> Option<&[u8]> {
        let dh_len = todo!();
        Some(&self.remote_s?[..dh_len])
    }
}

#[derive(Debug)]
enum NoiseError {
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

/// Reference: https://noiseprotocol.org/noise.html#the-cipherstate-object
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

    fn rekey(&mut self) {
        self.cipher.rekey()
    }

    fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce
    }
}

/// Reference: https://noiseprotocol.org/noise.html#cipher-functions
pub(crate) trait NoiseCipher: ZeroizeOnDrop + Zeroize + Send + Sync {
    /// Returns a string identifier for the cipher.          
    fn name(&self) -> &'static str;

    fn rekey(&mut self);
    
    fn set_key(&mut self, key: &[u8; CIPHER_KEY_LEN]);

    fn encrypt(&self, nonce: u64, associated_data: &[u8], plaintext: &[u8], out: &mut [u8]) -> Result<usize, CipherError>;

    fn decrypt(&self, nonce: u64, associated_data: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result<usize, CipherError>;
}

/// Reference: https://noiseprotocol.org/noise.html#hash-functions
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

/// Reference: https://noiseprotocol.org/noise.html#dh-functions
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
