use super::{cipherstate::CipherState, handshakestate::HandshakeState, pattern::{HandshakePattern, Role}, NoiseError, MAX_DH_LEN, MAX_MESSAGE_SIZE, TAG_LEN};

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
        let dh_len = todo!(); // TODO: get dh len here
        let HandshakeState { role, params, local_cipher, remote_cipher, remote_s, .. } = handshakestate;
        let pattern = params.handshake.pattern;
        if local_cipher.name() != remote_cipher.name() {
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
        let dh_len = todo!(); // TODO: get dh len here
        Some(&self.remote_s?[..dh_len])
    }
}
