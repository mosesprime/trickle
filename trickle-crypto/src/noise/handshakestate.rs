use std::fmt::Display;

use crate::noise::pattern::MessageToken;
use super::{aead::resolve_cipher, cipherstate::CipherState, dh::resolve_dh, hash::resolve_hasher, pattern::{MessagePattern, NoiseParams, Role}, symmetricstate::SymmetricState, NoiseDH, NoiseError, NoiseKem, Toggle, MAX_DH_LEN, MAX_KEM_CIPHERTEXT_LEN, MAX_KEM_PUB_LEN, MAX_KEM_SS_LEN, MAX_MESSAGE_SIZE, PSK_LEN, TAG_LEN};

/// Reference: <https://www.noiseprotocol.org/noise.html#the-handshakestate-object>
pub struct HandshakeState {
    pub(crate) role: Role,
    pub(crate) params: NoiseParams,
    pub(crate) local_s: Toggle<Box<dyn NoiseDH>>,
    pub(crate) local_e: Toggle<Box<dyn NoiseDH>>,
    pub(crate) local_cipher: CipherState,
    pub(crate) remote_s: Toggle<[u8; MAX_DH_LEN]>,
    pub(crate) remote_e: Toggle<[u8; MAX_DH_LEN]>,
    pub(crate) remote_cipher: CipherState,
    pub(crate) dh_len: usize,
    pub(crate) my_turn: bool,
    pub(crate) psk: Option<[u8; PSK_LEN]>,
    #[cfg(feature = "hfs")]
    pub(crate) local_kem: Option<Box<dyn NoiseKem>>,
    #[cfg(feature = "hfs")]
    pub(crate) remote_kem_e: Option<[u8; MAX_KEM_PUB_LEN]>,
    pub(crate) message_patterns: Vec<Vec<MessageToken>>,
    pub(crate) symmetric_state: SymmetricState,
    /// How far through the `message_pattern` we are.
    pub(crate) pattern_index: usize,
}

impl HandshakeState {
    pub fn new(
        role: Role,
        params: NoiseParams,
        local_s_priv: Option<&[u8]>,
        local_e_priv: Option<&[u8]>,
        remote_s_pub: Option<&[u8]>,
        remote_e_pub: Option<&[u8]>,
        psk: Option<[u8; PSK_LEN]>,
        prologue: &[u8],
    ) -> Result<HandshakeState, HandshakeError> {
        // resolvers
        let mut local_s = Toggle::new(resolve_dh(&params.diff_hell), false);
        let mut local_e = Toggle::new(resolve_dh(&params.diff_hell), false);
        let handshake_cipher = CipherState::new(resolve_cipher(&params.cipher));
        let local_cipher = CipherState::new(resolve_cipher(&params.cipher));
        let remote_cipher = CipherState::new(resolve_cipher(&params.cipher));
        let hasher = resolve_hasher(&params.hash);
        let dh_len = local_s.pubkey_len();

        // validate provided keys
        if let Some(k) = psk {
            if k.len() != PSK_LEN {
                return Err(HandshakeError::InvalidKeyLength);
            }
        }
        if let Some(s) = local_s_priv {
            if s.len() != local_s.pubkey_len() {
                return Err(HandshakeError::InvalidKeyLength);
            }
            local_s.set_privkey(s);
            local_s.enable();

        } else if params.handshake.pattern.requires_local_static(role) {
            return Err(HandshakeError::MissingLocalStatic);
        }
        if let Some(e) = local_e_priv {
            if e.len() != local_e.pubkey_len() {
                return Err(HandshakeError::InvalidKeyLength);
            }
            local_e.set_privkey(e);
            local_e.enable();
        }
        let remote_s = if let Some(rs) = remote_s_pub {
            if rs.len() < local_s.pubkey_len() {
                return Err(HandshakeError::InvalidKeyLength);
            }
            let mut buf = [0u8; MAX_DH_LEN];
            buf.copy_from_slice(rs);
            Toggle::new(buf, true)
        } else if params.handshake.pattern.requires_remote_public(role) {
            return Err(HandshakeError::MissingRemotePublicKey);
        } else {
            Toggle::new([0u8; MAX_DH_LEN], false)
        };
        let remote_e = if let Some(re) = remote_e_pub {
            if re.len() < local_e.pubkey_len() {
                return Err(HandshakeError::InvalidKeyLength);
            }
            let mut buf = [0u8; MAX_DH_LEN];
            buf.copy_from_slice(re);
            Toggle::new(buf, true)
        } else {
            Toggle::new([0u8; MAX_DH_LEN], false)
        }; 

        let mut symmetric_state = SymmetricState::new(handshake_cipher, hasher);
        symmetric_state.init(&params.name);
        symmetric_state.mix_hash(prologue);

        let message_pattern = MessagePattern::from(params.handshake.clone());
        let my_turn = role == Role::Initiator;
        if role == Role::Initiator {
            for tok in message_pattern.premessage_initiator.ok_or(HandshakeError::InvalidMessageOrder)? {
                symmetric_state.mix_hash(match tok {
                    MessageToken::S => &local_s,
                    MessageToken::E => &local_e,
                    _ => unreachable!(),
                }.get().ok_or(HandshakeError::MissingKeyMaterial)?.pubkey());
            }
            for tok in message_pattern.premessage_recipient.ok_or(HandshakeError::InvalidMessageOrder)? {
                symmetric_state.mix_hash(&match tok {
                    MessageToken::S => &remote_s,
                    MessageToken::E => &remote_e,
                    _ => unreachable!(),
                }.get().ok_or(HandshakeError::MissingKeyMaterial)?[..dh_len]);
            }
        } else {
            for tok in message_pattern.premessage_initiator.ok_or(HandshakeError::InvalidMessageOrder)? {
                symmetric_state.mix_hash(&match tok {
                    MessageToken::S => &remote_s,
                    MessageToken::E => &remote_e,
                    _ => unreachable!(),
                }.get().ok_or(HandshakeError::MissingKeyMaterial)?[..dh_len]);
            }
            for tok in message_pattern.premessage_recipient.ok_or(HandshakeError::InvalidMessageOrder)? {
                symmetric_state.mix_hash(match tok {
                    MessageToken::S => &local_s,
                    MessageToken::E => &local_e,
                    _ => unreachable!(),
                }.get().ok_or(HandshakeError::MissingKeyMaterial)?.pubkey());
            }
        }

        Ok(HandshakeState {
            role,
            params,
            local_s,
            local_e,
            local_cipher,
            remote_s,
            remote_e,
            remote_cipher,
            dh_len,
            my_turn,
            psk,
            #[cfg(feature = "hfs")]
            local_kem: todo!(),
            #[cfg(feature = "hfs")]
            remote_kem_e: todo!(),
            message_patterns: message_pattern.into(),
            symmetric_state,
            pattern_index: 0,
        })
    }

    pub(crate) fn dh_len(&self) -> usize {
        self.dh_len
    }

    pub fn remote_s(&self) -> Option<&[u8]> {
        self.remote_s.get().map(|rs| &rs[..self.dh_len])
    }

    pub(crate) fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        let (checkpoint_hash, checkpoint_chaining_key) = self.symmetric_state.checkpoint();
        match self.w_msg(payload, out) {
            Ok(n) => {
                self.pattern_index += 1;
                self.my_turn = false;
                Ok(n)
            },
            Err(e) => {
                self.symmetric_state.restore(checkpoint_hash, checkpoint_chaining_key);
                Err(e)
            },
        }
    }

    fn w_msg(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        if !self.my_turn {
            return Err(NoiseError::Handshake(HandshakeError::OutOfTurn));
        }
        if self.pattern_index >= self.message_patterns.len() {
            return Err(NoiseError::Handshake(HandshakeError::AlreadyComplete));
        }
        let mut byte_index = 0;
        for tok in &self.message_patterns[self.pattern_index] {
            match tok {
                MessageToken::E => {
                    if byte_index + self.local_e.pubkey_len() > out.len() {
                        return Err(NoiseError::InvalidMessageSize);
                    }
                    if !self.local_e.is_on {
                        self.local_e.generate();
                        self.local_e.enable();
                    }
                    let pubkey = self.local_e.pubkey();
                    out[byte_index..byte_index+pubkey.len()].copy_from_slice(pubkey);
                    byte_index += pubkey.len();
                    self.symmetric_state.mix_hash(pubkey);
                    if self.params.handshake.has_psk() {
                        self.symmetric_state.mix_key(pubkey);
                    }
                },
                MessageToken::S => {
                    if byte_index + self.local_s.pubkey_len() > out.len() {
                        return Err(NoiseError::InvalidMessageSize);
                    }
                    byte_index += self.symmetric_state.encrypt_and_mix_hash(self.local_s.pubkey(), &mut out[byte_index..]).map_err(|e| NoiseError::Cipher(e))?;
                },
                MessageToken::EE
                | MessageToken::ES
                | MessageToken::SE
                | MessageToken::SS => {
                    let mut out = [0u8; MAX_DH_LEN];
                    let (dh, key) = match (tok, self.role) {
                        (MessageToken::EE, _) => (&self.local_e, &self.remote_e),
                        (MessageToken::SS, _) => (&self.local_s, &self.remote_s),
                        (MessageToken::SE, Role::Initiator) | (MessageToken::ES, Role::Recipient) => (&self.local_s, &self.remote_e),
                        (MessageToken::ES, Role::Initiator) | (MessageToken::SE, Role::Recipient) => (&self.local_e, &self.remote_s),
                        _ => unreachable!(),
                    }; 
                    if !dh.is_on || !key.is_on {
                        return Err(NoiseError::Handshake(HandshakeError::MissingKeyMaterial));
                    };
                    dh.dh(&**key, &mut out).unwrap(); // TODO: handle dh error
                    self.symmetric_state.mix_key(&out[..self.dh_len]);
                },
                MessageToken::PSK => match self.psk {
                    Some(psk) => self.symmetric_state.mix_key_and_hash(&psk),
                    None => return Err(NoiseError::Handshake(HandshakeError::MissingPSK)),
                },
                #[cfg(feature = "hfs")]
                MessageToken::E1 => {
                    let kem = self.local_kem.as_mut().ok_or(NoiseError::Handshake(HandshakeError::MissingKEM))?;
                    if kem.pubkey_len() > out.len() {
                        return Err(NoiseError::InvalidMessageSize);
                    }
                    kem.generate();
                    byte_index += self.symmetric_state.encrypt_and_mix_hash(kem.pubkey(), &mut out[byte_index..]).map_err(|e| NoiseError::Cipher(e))?;
                },
                #[cfg(feature = "hfs")]
                MessageToken::EKEM1 => {
                    let kem = self.local_kem.as_mut().ok_or(NoiseError::Handshake(HandshakeError::MissingKEM))?;
                    let mut kem_out = [0u8; MAX_KEM_SS_LEN];
                    let mut ciphertext = [0u8; MAX_KEM_CIPHERTEXT_LEN];
                    if kem.ciphertext_len() > out.len() {
                        return Err(NoiseError::InvalidMessageSize);
                    }
                    let kem_out = &mut kem_out[..kem.shared_secret_len()];
                    let ciphertext = &mut ciphertext[..kem.ciphertext_len()];
                    let r_kem_e_pubkey = &self.remote_kem_e.as_ref().ok_or(NoiseError::Handshake(HandshakeError::MissingRemoteKEM))?[..kem.pubkey_len()];
                    if kem.encapsulate(r_kem_e_pubkey, kem_out, ciphertext).is_err() {
                        todo!()
                    }
                    byte_index += self.symmetric_state.encrypt_and_mix_hash(&ciphertext[..kem.ciphertext_len()], &mut out[byte_index..]).map_err(|e| NoiseError::Cipher(e))?;
                    self.symmetric_state.mix_key(&kem_out[..kem.shared_secret_len()]);
                },
            }
        }
        if byte_index + payload.len() + TAG_LEN > out.len() {
            return Err(NoiseError::InvalidMessageSize);
        }
        byte_index += self.symmetric_state.encrypt_and_mix_hash(payload, &mut out[byte_index..]).map_err(|e| NoiseError::Cipher(e))?;
        if byte_index > MAX_MESSAGE_SIZE {
            return Err(NoiseError::InvalidMessageSize);
        }
        if self.pattern_index == (self.message_patterns.len() - 1) {
            self.symmetric_state.split(&mut self.local_cipher, &mut self.remote_cipher);
        }
        Ok(byte_index)
    }

    pub(crate) fn read_message(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        let (checkpoint_hash, checkpoint_chaining_key) = self.symmetric_state.checkpoint();
        match self.r_msg(message, out) {
            Ok(n) => {
                self.pattern_index += 1;
                self.my_turn = true;
                Ok(n)
            },
            Err(e) => {
                self.symmetric_state.restore(checkpoint_hash, checkpoint_chaining_key);
                Err(e)
            },
        }
    }

    fn r_msg(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        if message.len() > MAX_MESSAGE_SIZE {
            return Err(NoiseError::InvalidMessageSize);
        } else if self.my_turn {
            return Err(NoiseError::Handshake(HandshakeError::OutOfTurn));
        } else if self.pattern_index >= self.message_patterns.len() {
            return Err(NoiseError::Handshake(HandshakeError::AlreadyComplete));
        }
        let is_last = self.pattern_index == (self.message_patterns.len() - 1);
        let mut msg = message;
        for tok in &self.message_patterns[self.pattern_index] {
            match tok {
                MessageToken::E => {
                    if msg.len() < self.dh_len {
                        return Err(NoiseError::InvalidMessageSize);
                    }
                    self.remote_e[..self.dh_len].copy_from_slice(&msg[..self.dh_len]);
                    msg = &msg[self.dh_len..];
                    self.symmetric_state.mix_hash(&self.remote_e[..self.dh_len]);
                    if self.params.handshake.has_psk() {
                        self.symmetric_state.mix_key(&self.remote_e[..self.dh_len]);
                    }
                },
                MessageToken::S => {
                    let data = if self.symmetric_state.has_key() {
                        if msg.len() < self.dh_len + TAG_LEN {
                            return Err(NoiseError::InvalidMessageSize);
                        }
                        let tmp = &msg[..self.dh_len + TAG_LEN];
                        msg = &msg[self.dh_len + TAG_LEN..];
                        tmp
                    } else {
                        if msg.len() < self.dh_len {
                            return Err(NoiseError::InvalidMessageSize);
                        }
                        let tmp = &msg[..self.dh_len];
                        msg = &msg[self.dh_len..];
                        tmp
                    };
                    self.symmetric_state.decrypt_and_mix_hash(data, &mut self.remote_s[..self.dh_len]).map_err(|e| NoiseError::Cipher(e))?;
                },
                MessageToken::PSK => match self.psk {
                    Some(psk) => self.symmetric_state.mix_key_and_hash(&psk),
                    None => return Err(NoiseError::Handshake(HandshakeError::MissingPSK)),
                },
                MessageToken::SE
                | MessageToken::ES
                | MessageToken::EE
                | MessageToken::SS => {
                    let mut out = [0u8; MAX_DH_LEN];
                    let (dh, key) = match (tok, self.role) {
                        (MessageToken::EE, _) => (&self.local_e, &self.remote_e),
                        (MessageToken::SS, _) => (&self.local_s, &self.remote_s),
                        (MessageToken::SE, Role::Initiator) | (MessageToken::ES, Role::Recipient) => (&self.local_s, &self.remote_e),
                        (MessageToken::ES, Role::Initiator) | (MessageToken::SE, Role::Recipient) => (&self.local_e, &self.remote_s),
                        _ => unreachable!(),
                    };
                    if !dh.is_on || !key.is_on {
                        return Err(NoiseError::Handshake(HandshakeError::MissingKeyMaterial));
                    };
                    dh.dh(&**key, &mut out).unwrap(); // TODO: handle dh error
                    self.symmetric_state.mix_key(&out[..self.dh_len]);
                },
                #[cfg(feature = "hfs")]
                MessageToken::E1 => {
                    let kem = self.local_kem.as_ref().ok_or(NoiseError::Handshake(HandshakeError::MissingKEM))?;
                    let read_len = if self.symmetric_state.has_key() {
                        kem.pubkey_len() + TAG_LEN
                    } else {
                        kem.pubkey_len()
                    };
                    if msg.len() < read_len {
                        return Err(NoiseError::InvalidMessageSize);
                    }
                    let mut out = [0u8; MAX_KEM_PUB_LEN];
                    let _ = self.symmetric_state.decrypt_and_mix_hash(&msg[..read_len], &mut out[..kem.pubkey_len()]).map_err(|e| NoiseError::Cipher(e));
                    self.remote_kem_e = Some(out);
                    msg = &msg[read_len..];
                },
                #[cfg(feature = "hfs")]
                MessageToken::EKEM1 => {
                    let kem = self.local_kem.as_ref().ok_or(NoiseError::Handshake(HandshakeError::MissingKEM))?;
                    let read_len = if self.symmetric_state.has_key() {
                        kem.pubkey_len() + TAG_LEN
                    } else {
                        kem.pubkey_len()
                    };
                    if msg.len() < read_len {
                        return Err(NoiseError::InvalidMessageSize);
                    }
                    let mut ciphertext_buf = [0u8; MAX_KEM_CIPHERTEXT_LEN];
                    let ciphertext = &mut ciphertext_buf[..kem.ciphertext_len()];
                    self.symmetric_state.decrypt_and_mix_hash(&msg[..read_len], ciphertext).map_err(|e| NoiseError::Cipher(e))?;
                    let mut kem_buf = [0u8; MAX_KEM_SS_LEN];
                    let shared_secret_out = &mut kem_buf[..kem.shared_secret_len()];
                    kem.decapsulate(ciphertext, shared_secret_out).unwrap(); // TODO: handle decapsulate error
                    self.symmetric_state.mix_key(&shared_secret_out[..kem.shared_secret_len()]);
                    msg = &msg[read_len..];
                },
            }
        }
        let _ = self.symmetric_state.decrypt_and_mix_hash(msg, out).map_err(|e| NoiseError::Cipher(e));
        if is_last {
            // TODO: ensure these are split into the correct ciphers
            self.symmetric_state.split(&mut self.local_cipher, &mut self.remote_cipher);
        }
        if self.symmetric_state.has_key() {
            Ok(msg.len() - TAG_LEN)
        } else {
            Ok(msg.len())
        }
    }
}

#[derive(Debug)]
pub enum HandshakeError {
    OutOfTurn,
    MissingPSK,
    MissingKEM,
    MissingLocalStatic,
    MissingRemoteKEM,
    MissingRemotePublicKey,
    MissingKeyMaterial,
    InvalidMessageOrder,
    InvalidKeyLength,
    AlreadyComplete,
}

impl Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for HandshakeError {}
