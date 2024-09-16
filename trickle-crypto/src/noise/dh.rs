use ed25519_dalek::ed25519::signature::SignerMut;
use rand::rngs::OsRng;

use super::{pattern::DiffHellChoice, NoiseDH};

/// Resolves the desired Diffie-Hellman with default keys.
pub(crate) fn resolve_dh(choice: &DiffHellChoice) -> Box<dyn NoiseDH> {
    match choice {
        DiffHellChoice::Curve25519 => Box::new(Curve25519DH::default()),
        DiffHellChoice::Curve443 => todo!(),
    }
}

pub(crate) struct Curve25519DH {
    pubkey: ed25519_dalek::VerifyingKey,
    privkey: ed25519_dalek::SigningKey,
}

impl Default for Curve25519DH {
    fn default() -> Self {
        Self {
            // shouldnt error as we are explicitly passing in the proper length slice
            pubkey: ed25519_dalek::VerifyingKey::from_bytes(&[0u8; ed25519_dalek::PUBLIC_KEY_LENGTH]).unwrap(), 
            privkey: ed25519_dalek::SigningKey::from_bytes(&[0u8; ed25519_dalek::SECRET_KEY_LENGTH]),
        }
    }
}

impl NoiseDH for Curve25519DH {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pubkey(&self) -> &[u8] {
        self.pubkey.as_bytes()
    }

    fn privkey(&self) -> &[u8] {
        self.privkey.as_bytes()
    }

    fn pubkey_len(&self) -> usize {
        ed25519_dalek::PUBLIC_KEY_LENGTH
    }

    fn privkey_len(&self) -> usize {
        ed25519_dalek::SECRET_KEY_LENGTH
    }

    fn set_privkey(&mut self, privkey: &[u8]) {
        let mut priv_key_bytes = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        priv_key_bytes.copy_from_slice(&privkey[..ed25519_dalek::SECRET_KEY_LENGTH]);
        self.privkey = ed25519_dalek::SigningKey::from_bytes(&priv_key_bytes);
        self.pubkey = self.privkey.verifying_key();
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: check for correctness
        let res = self.privkey.clone().sign(pubkey).to_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }

    fn generate(&mut self) {
        self.privkey = ed25519_dalek::SigningKey::generate(&mut OsRng);
    }
}
