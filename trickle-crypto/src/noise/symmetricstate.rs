use super::{aead::CipherError, cipherstate::CipherState, NoiseHash, CIPHER_KEY_LEN, MAX_HASH_LEN};

/// Reference: <https://noiseprotocol.org/noise.html#the-symmetricstate-object>
pub(crate) struct SymmetricState {
    hash: [u8; MAX_HASH_LEN],
    chaining_key: [u8; MAX_HASH_LEN],
    hasher: Box<dyn NoiseHash>,
    cipherstate: CipherState,
}

impl SymmetricState {
    pub(crate) fn new(cipherstate: CipherState, hasher: Box<dyn NoiseHash>) -> Self {
        Self { hash: [0u8; MAX_HASH_LEN], chaining_key: [0u8; MAX_HASH_LEN], hasher, cipherstate }
    }

    /// Initialize the [SymmetricState].
    /// If the name of the handshake protocol (ex. Noise_XX_25519_ChaChaPoly_Blake2s)
    /// is longer than the desired hash lenght, use hashed name, otherwise use just the name.
    pub(crate) fn init(&mut self, protocol_name: &str) {
        if protocol_name.len() <= self.hasher.hash_len() {
            self.hash.copy_from_slice(protocol_name.as_bytes());
        } else {
            self.hasher.reset();
            self.hasher.input(protocol_name.as_bytes());
            self.hasher.result(&mut self.hash);
        }
        self.chaining_key.copy_from_slice(&self.hash);
    }

    pub(crate) fn mix_key(&mut self, data: &[u8]) {
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

    pub(crate) fn mix_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        self.hasher.reset();
        self.hasher.input(&self.hash[..hash_len]);
        self.hasher.input(data);
        self.hasher.result(&mut self.hash);
    }

    pub(crate) fn mix_key_and_hash(&mut self, data: &[u8]) {
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

    pub(crate) fn encrypt_and_mix_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, CipherError> {
        let hash_len = self.hasher.hash_len();
        let out_len = if self.cipherstate.has_key() {
            self.cipherstate.encrypt(Some(&self.hash[..hash_len]), plaintext, out)?
        } else {
            out.copy_from_slice(plaintext);
            plaintext.len()
        };
        self.mix_hash(&out[..out_len]);
        Ok(out_len)
    }

    pub(crate) fn decrypt_and_mix_hash(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, CipherError> {
        let hash_len = self.hasher.hash_len();
        let payload_len = if self.cipherstate.has_key() {
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

    pub(crate) fn split(&mut self, cipher1: &mut CipherState, cipher2: &mut CipherState) {
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

    /// Creates a checkpoint of the current inner state. Returns tuple `(`hash`, `chaining_key`)`.
    pub(crate) fn checkpoint(&self) -> ([u8; MAX_HASH_LEN], [u8; MAX_HASH_LEN]) {
        (self.hash, self.chaining_key)
    }

    /// Restore the inner state to that of a given checkpoint.
    pub(crate) fn restore(&mut self, checkpoint_hash: [u8; MAX_HASH_LEN], checkpoint_chaining_key: [u8; MAX_HASH_LEN]) {
        self.hash = checkpoint_hash;
        self.chaining_key = checkpoint_chaining_key;
    }

    pub(crate) fn has_key(&self) -> bool {
        self.cipherstate.has_key()
    }
}

