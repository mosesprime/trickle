use std::fmt::Display;

use crate::cipher::{aes::Aes256GcmCipher, chacha::ChaChaPolyCipher};

use super::{cipherstate::CipherState, pattern::{CipherChoice, MessagePattern, NoiseParams, Role}, NoiseKem, CIPHER_KEY_LEN, MAX_DH_LEN, PSK_LEN};

/// http://www.noiseprotocol.org/noise.html#the-handshakestate-object
pub struct HandshakeState {
    pub(crate) role: Role,
    pub(crate) params: NoiseParams,
    local_s: [u8; MAX_DH_LEN],
    local_e: [u8; MAX_DH_LEN],
    pub(crate) local_cipher: CipherState,
    pub(crate) remote_s: Option<[u8; MAX_DH_LEN]>,
    remote_e: Option<[u8; MAX_DH_LEN]>,
    pub(crate) remote_cipher: CipherState,
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

