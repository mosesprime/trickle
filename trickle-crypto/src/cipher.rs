pub mod aes;
pub mod chacha;

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
