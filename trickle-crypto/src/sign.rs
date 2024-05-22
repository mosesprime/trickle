use std::fmt::Debug;

use ed25519_dalek::ed25519::signature::Signer;

#[non_exhaustive]
pub enum SignatureScheme {
    Ed25519,
}

pub struct PublicKey {
    inner: PublicKeyInner,
}

enum PublicKeyInner {
    Ed25519(ed25519_dalek::VerifyingKey),
}

pub struct SecretKey {
    inner: SecretKeyInner,
}

enum SecretKeyInner {
    Ed25519(ed25519_dalek::SigningKey),
}

impl PublicKey {
    pub fn scheme(&self) -> SignatureScheme {
        match self.inner {
            PublicKeyInner::Ed25519(_) => SignatureScheme::Ed25519,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.inner {
            PublicKeyInner::Ed25519(vk) => vk.as_bytes(),
        }
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        match self.inner {
            PublicKeyInner::Ed25519(vk) => Ok(vk.verify_strict(message, &ed25519_dalek::Signature::from_slice(signature)?)?),
        }
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({:x?})", self.as_bytes())
    }
}

impl SecretKey {
    pub fn scheme(&self) -> SignatureScheme {
        match self.inner {
            SecretKeyInner::Ed25519(_) => SignatureScheme::Ed25519,
        }
    }

    pub fn public(&self) -> PublicKey {
        match &self.inner {
            SecretKeyInner::Ed25519(sk) => PublicKey{ inner: PublicKeyInner::Ed25519(sk.verifying_key()) },
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match &self.inner {
            SecretKeyInner::Ed25519(sk) => sk.sign(message).to_vec()
        }
    }
}
