use std::{fmt::Display, str::FromStr};

/// A parsed Noise protocol name string. (ex. `Noise_XX_25519_ChaChaPoly_BLAKE2s`)
pub struct NoiseParams {
    /// Original protocol name.
    pub name: Box<str>,
    /// Base protocol name. (typically `Noise`)
    pub base: BaseChoice,
    /// Prefered handshake pattern with modifiers. (ex. `XXpsk`)
    pub handshake: HandshakeChoice,
    /// Type of Diffi-Hellman used. (ex. `25519` would use eliptic curve 25519)
    pub diff_hell: DiffHellChoice,
    #[cfg(feature = "hfs")]
    pub kem: Option<KemChoice>,
    /// Type of AEAD cipher used. (ex. `ChaChaPoly` for ChaCha20Poly1305)
    pub cipher: CipherChoice,
    /// Type of hash function used. (ex. `BLAKE2s`)
    pub hash: HashChoice,
}

impl FromStr for NoiseParams {
    type Err = PatternError;

    #[cfg(feature = "hfs")]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('_').peekable();
        let params = NoiseParams {
            name: s.into(),
            base: parts.next().ok_or(PatternError::TooFewParameters)?.parse()?,
            handshake: parts.next().ok_or(PatternError::TooFewParameters)?.parse()?,
            diff_hell: parts
                .peek()
                .ok_or(PatternError::TooFewParameters)?
                .splitn(2, '+')
                .nth(0)
                .ok_or(PatternError::TooFewParameters)?
                .parse()?,
            kem: parts
                .next()
                .ok_or(PatternError::TooFewParameters)?
                .splitn(2, '+')
                .nth(1)
                .map(|s| s.parse())
                .transpose()?,
            cipher: parts.next().ok_or(PatternError::TooFewParameters)?.parse()?,
            hash: parts.next().ok_or(PatternError::TooFewParameters)?.parse()?,
        };
        if parts.next().is_some() {
            return Err(PatternError::TooManyParameters);
        }
        Ok(params)
    }
    
    #[cfg(not(feature = "hfs"))]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('_');
        let params = NoiseParams {
            name: s.into(),
            base: parts.next().ok_or(PatternError::TooFewParameters)?.parse()?,
            handshake:  parts.next().ok_or(PatternError::TooFewParameters)?.parse()?,
            diff_hell: parts.next().ok_or(PatternError::TooFewParameters)?.parse()?,
            cipher: parts.next().ok_or(PatternError::TooFewParameters)?.parse()?,
            hash: parts.next().ok_or(PatternError::TooFewParameters)?.parse()?,
        };
        if parts.next().is_some() {
            return Err(PatternError::TooManyParameters);
        }
        Ok(params)
    }
}

#[derive(Debug, PartialEq)]
pub enum BaseChoice {
    Noise,
}

impl FromStr for BaseChoice {
    type Err = PatternError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use BaseChoice::*;
        match s {
            "Noise" => Ok(Noise),
            _ => Err(PatternError::UnsupportedBase),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeChoice {
    pub pattern: HandshakePattern,
    pub modifiers: Vec<HandshakeModifier>,
}

impl HandshakeChoice {
    pub(crate) fn contains(&self, modifier: &HandshakeModifier) -> bool {
        self.modifiers.contains(modifier)
    }

    pub(crate) fn has_psk(&self) -> bool {
        for modifier in &self.modifiers {
            if let HandshakeModifier::PSK(_) = *modifier {
                return true;
            }
        }
        false
    }

    fn parse(s: &str) -> Result<(HandshakePattern, &str), PatternError> {
        for i in (1..=4).rev() {
            if s.len() > i - 1 && s.is_char_boundary(i) {
                if let Ok(p) = s[..i].parse() {
                    return Ok((p, &s[i..]));
                }
            }
        }
        Err(PatternError::UnsupportedPattern)
    }
}

impl FromStr for HandshakeChoice {
    type Err = PatternError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (pattern, remainder) = Self::parse(s)?;
        if remainder.is_empty() {
            return Ok(HandshakeChoice { pattern, modifiers: vec![] });
        }
        let labels = remainder.split('+');
        let mut modifiers = vec![];
        for label in labels {
            let modifier = label.parse()?;
            if modifiers.contains(&modifier) {
                return Err(PatternError::DuplicateModifier);
            }
            modifiers.push(modifier);
        }
        Ok(HandshakeChoice { pattern, modifiers })
    }
}

#[derive(Debug, PartialEq)]
pub enum DiffHellChoice {
    Curve25519,
    Curve443,
}

impl FromStr for DiffHellChoice {
    type Err = PatternError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use DiffHellChoice::*;
        match s {
            "25519" => Ok(Curve25519),
            "443" => Ok(Curve443),
            _ => Err(PatternError::UnsupportedDiffHell),
        }
    }
}

#[cfg(feature = "hfs")]
#[derive(Debug, PartialEq)]
pub enum KemChoice {
    Kyber512,
    Kyber1024,
}

#[cfg(feature = "hfs")]
impl FromStr for KemChoice {
    type Err = PatternError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use KemChoice::*;
        match s {
            "Kyber512" => Ok(Kyber512),
            "Kyber1024" => Ok(Kyber1024),
            _ => Err(PatternError::UnsupportedKem),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum CipherChoice {
    /// ChaCha20Poly1305
    ChaChaPoly,
    /// AES-256-GCM
    AESGCM,
}

impl FromStr for CipherChoice {
    type Err = PatternError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use CipherChoice::*;
        match s {
            "ChaChaPoly" => Ok(ChaChaPoly),
            "AESGCM" => Ok(AESGCM),
            _ => Err(PatternError::UnsupportedCipher),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum HashChoice {
    /// SHA2-256
    SHA256,
    /// SHA2-512
    SHA512,
    /// SHA3-256
    SHA3_256,
    BLAKE2s,
    BLAKE2b,
    BLAKE3,
}

impl FromStr for HashChoice {
    type Err = PatternError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use HashChoice::*;
        match s {
            "SHA256" => Ok(SHA256),
            "SHA512" => Ok(SHA512),
            "SHA3/256" => Ok(SHA3_256),
            "BLAKE2s" => Ok(BLAKE2s),
            "BLAKE2b" => Ok(BLAKE2b),
            "BLAKE3" => Ok(BLAKE3),
            _ => Err(PatternError::UnsupportedHash),
        }
    }
}

/// Reference: https://noiseprotocol.org/noise.html#handshake-patterns
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum MessageToken {
    E,
    S,
    EE,
    ES,
    SE,
    SS,
    PSK,
    #[cfg(feature = "hfs")]
    E1,
    #[cfg(feature = "hfs")]
    EKEM1,
}

impl FromStr for MessageToken {
    type Err = PatternError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use MessageToken::*;
        match s {
            "e" => Ok(E),
            "s" => Ok(S),
            "ee" => Ok(EE),
            "es" => Ok(ES),
            "se" => Ok(SE),
            "ss" => Ok(SS),
            "psk" => Ok(PSK),
            #[cfg(feature = "hfs")]
            "e1" => Ok(E1),
            #[cfg(feature = "hfs")]
            "ekem1" => Ok(EKEM1),
            _ => Err(PatternError::UnsupportedMessageToken),
        }
    }
}

macro_rules! parse_msg {
    (s) => { MessageToken::S };
    (e) => { MessageToken::E };
    (es) => { MessageToken::ES };
    (se) => { MessageToken::SE };
    (ee) => { MessageToken::EE };
    (ss) => { MessageToken::SS };
}

macro_rules! msg_sequence {
    (-> $($tok0:ident),*) => {
        &[&[$(parse_msg!($tok0)),*]]
    };
    (<- $($tok0:ident),*) => {
        &[&[$(parse_msg!($tok0)),*]]
    };
    (-> $($tok0:ident),* <- $($tok1:ident),*) => {
        &[&[$(parse_msg!($tok0)),*], &[$(parse_msg!($tok1)),*]]
    };
    (-> $($tok0:ident),* <- $($tok1:ident),* -> $($tok2:ident),*) => {
        &[&[$(parse_msg!($tok0)),*], &[$(parse_msg!($tok1)),*], &[$(parse_msg!($tok2)),*]]
    };
    (-> $($tok0:ident),* <- $($tok1:ident),* -> $($tok2:ident),* <- $($tok3:ident),*) => {
        &[&[$(parse_msg!($tok0)),*], &[$(parse_msg!($tok1)),*], &[$(parse_msg!($tok2)),*], &[$(parse_msg!($tok3)),*]]
    };
}

macro_rules! msg_pattern {
    (<- $($pre_r:ident),* ... $($rest:tt)*) => {
        MessagePattern::new(None, Some(&[$(parse_msg!($pre_r)),*]), msg_sequence!($($rest)*))
    };
    (-> $($pre_i:ident),* ... $($rest:tt)*) => {
        MessagePattern::new(Some(&[$(parse_msg!($pre_i)),*]), None, msg_sequence!($($rest)*))
    };
    (-> $($pre_i:ident),* <- $($pre_r:ident),* ... $($rest:tt)*) => {
        MessagePattern::new(Some(&[$(parse_msg!($pre_i)),*]), Some(&[$(parse_msg!($pre_r)),*]), msg_sequence!($($rest)*))
    };
    ($($rest:tt)*) => {
        MessagePattern::new(None, None, msg_sequence!($($rest)*))
    };
}

#[test]
fn parse_message_token_pattern() {
    use MessageToken::*;
    assert_eq!(parse_msg!(e), E);
    assert_eq!(msg_sequence!(<- e), &[&[E]]);
    assert_eq!(msg_pattern!(-> e ... -> s <- es, s), MessagePattern::new(Some(&[E]), None, &[&[S], &[ES, S]]));
    assert_eq!(msg_pattern!{
        -> e, s
        <- se
        -> es
        <- ee
    }, MessagePattern::new(None, None, &[&[E, S], &[SE], &[ES], &[EE]]));
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MessagePattern<'a> {
    pub premessage_initiator: Option<&'a [MessageToken]>,
    pub premessage_recipient: Option<&'a [MessageToken]>,
    pub message: &'a [&'a [MessageToken]],
}

impl<'a> MessagePattern<'a> {
    fn new(premessage_initiator: Option<&'a[MessageToken]>, premessage_recipient: Option<&'a[MessageToken]>, message: &'a [&'a [MessageToken]]) -> Self {
        Self { premessage_initiator, premessage_recipient, message }
    }
}

impl<'a> Into<Vec<Vec<MessageToken>>> for MessagePattern<'a> {
    fn into(self) -> Vec<Vec<MessageToken>> {
        let mut res = vec![];
        if let Some(msgs) = self.premessage_initiator {
            res.push(msgs.to_vec());
        }
        if let Some(msgs) = self.premessage_recipient {
            res.push(msgs.to_vec());
        }
        for group in self.message {
            res.push(group.to_vec());
        }
        res
    }
}

impl<'a> From<HandshakeChoice> for MessagePattern<'a> {
    fn from(value: HandshakeChoice) -> Self {
        use HandshakePattern::*;
        match value.pattern {
            N => msg_pattern!(
                <- s
                ...
                -> e, es
            ),
            K => msg_pattern!(
                -> s
                <- s
                ...
                -> e, es, ss
            ),
            X => msg_pattern!(
                <- s
                ...
                -> e, es, s, ss
            ),
            NN => msg_pattern!(
                -> e
                <- e, ee
            ),
            KN => msg_pattern!(
                -> s
                ...
                -> e
                <- e, ee, se
            ),
            NK => msg_pattern!(
                <- s
                ...
                -> e, es
                <- e, ee
            ),
            KK => msg_pattern!(
                -> s
                <- s
                ...
                -> e, es, ss
                <- e, ee, se
            ),
            NX => msg_pattern!(
                -> e
                <- e, ee, s, es
            ),
            KX => msg_pattern!(
                -> s
                ...
                -> e
                <- e, ee, se, s, es
            ),
            XN => msg_pattern!(
                -> e
                <- e, ee
                -> s, se
            ),
            IN => msg_pattern!(
                -> e, s
                <- e, ee, se
            ),
            XK => msg_pattern!(
                <- s
                ...
                -> e, es
                <- e, ee
                -> s, se
            ),
            IK => msg_pattern!(
                <- s
                ...
                -> e, es, s, ss
                <- e, ee, se
            ),
            XX => msg_pattern!(
                -> e
                <- e, ee, s, es
                -> s, se
            ),
            IX => msg_pattern!(
                -> e, s
                <- e, ee, se, s, es
            ),
            NK1 => msg_pattern!(
                <- s
                ...
                -> e
                <- e, ee, es
            ),
            X1X => msg_pattern!(
                -> e
                <- e, ee, s, es
                -> s
                <- se
            ),
            XX1 => msg_pattern!(
                -> e
                <- e, ee, s
                -> es, s, se
            ),
            X1X1 => msg_pattern!(
                -> e
                <- e, ee, s
                -> es, s
                <- se
            ),
            NX1 => msg_pattern!(
                -> e
                <- e, ee, s
                -> es
            ),
            X1N => msg_pattern!(
                -> e
                <- e, ee
                -> s
                <- se
            ),
            X1K => msg_pattern!(
                <- s
                ...
                -> e, es
                <- e, ee
                -> s
                <- se
            ),
            XK1 => msg_pattern!(
                <- s
                ...
                -> e
                <- e, ee, es
                -> s, se
            ),
            X1K1 => msg_pattern!(
                <- s
                ...
                -> e
                <- e, ee, es
                -> s
                <- se
            ),
            X1X => msg_pattern!(
                -> e
                <- e, ee, s, es
                -> s
                <- se
            ),
            XX1 => msg_pattern!(
                -> e
                <- e, ee, s
                -> es, s, se
            ),
            X1X1 => msg_pattern!(
                -> e
                <- e, ee, s
                -> es, s
                <- se
            ),
            K1N => msg_pattern!(
                -> s
                ...
                -> e
                <- e,ee
                -> se
            ),
            K1K => msg_pattern!(
                -> s
                <- s
                ...
                -> e, es
                <- e, ee
                -> se
            ),
            KK1 => msg_pattern!(
                -> s
                <- s
                ...
                -> e
                <- e, ee, se, es
            ),
            K1K1 => msg_pattern!(
                -> s
                <- s
                ...
                -> e
                <- e, ee, es
                -> se
            ),
            K1X => msg_pattern!(
                -> s
                ...
                -> e
                <- e, ee, s, es
                -> se
            ),
            KX1 => msg_pattern!(
                -> s
                ...
                -> e
                <- e, ee, se, s
                -> es
            ),
            K1X1 => msg_pattern!(
                -> s
                ...
                -> e
                <- e, ee, s
                -> se, es
            ),
            I1N => msg_pattern!(
                -> e, s
                <- e, ee
                -> se
            ),
            I1K => msg_pattern!(
                <- s
                ...
                -> e, es, s
                <- e, ee
                -> se
            ),
            IK1 => msg_pattern!(
                <- s
                ...
                -> e, s
                <- e, ee, se, es
            ),
            I1K1 => msg_pattern!(
                <- s
                ...
                -> e, s
                <- e, ee, es
                -> se
            ),
            I1X => msg_pattern!(
                -> e, s
                <- e, ee, s, es
                -> se
            ),
            IX1 => msg_pattern!(
                -> e, s
                <- e, ee, se, s
                -> es
            ),
            I1X1 => msg_pattern!(
                -> e, s
                <- e, ee, s
                -> se, es
            ),
        }
    }
}

macro_rules! define_pattern {
    ($name:ident { $($var:ident),* $(,)* }) => {
        const HANDSHAKE_PATTERNS: &'static [$name] = &[$($name::$var),*];
        
        ///
        #[derive(Debug, Copy, Clone, PartialEq)]
        pub enum $name {
            $($var),*,
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                use self::$name::*;
                match self {
                    $($var => stringify!($var)),*
                }
            }
        }
        
        impl FromStr for $name {
            type Err = PatternError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use self::$name::*;
                match s {
                    $(stringify!($var) => Ok($var)),*,
                    _ => return Err(PatternError::UnsupportedPattern),
                }
            }
        }
    };
}

define_pattern!{
    HandshakePattern {
        N, X, K,

        NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX,

        NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X, KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1
    }
}

impl HandshakePattern {
    /// Reference: <https://noiseprotocol.org/noise.html#one-way-handshake-patterns>
    pub(crate) fn is_one_way(self) -> bool {
        use HandshakePattern::*;
        matches!(self, N | X | K)
    }

    pub(crate) fn requires_local_static(self, role: Role) -> bool {
        use HandshakePattern::*;
        match (role, self) {
            (Role::Initiator, N | NN | NK | NX | NK1 | NX1) => false,
            (Role::Recipient, NN | XN | KN | IN | X1N | K1N | I1N) => false,
            _ => true, 
        }
    }

    pub(crate) fn requires_remote_public(self, role: Role) -> bool {
        use HandshakePattern::*;
        match (role, self) {
            (Role::Initiator, N | K | X | NK | XK | KK | IK | NK1 | X1K | XK1 | X1K1 | K1K | KK1 | K1K1 | I1K | IK1 | I1K1) => true,
            (Role::Recipient, K | KN | KK | KX | K1N | K1K | KK1 | K1K1 | K1X | KX1 | K1X1) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Role {
    Initiator,
    Recipient,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum HandshakeModifier {
    PSK(u8),
    Fallback,
    #[cfg(feature = "hfs")]
    HFS,
}

impl FromStr for HandshakeModifier {
    type Err = PatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            s if s.starts_with("psk") => Ok(HandshakeModifier::PSK(s[3..].parse::<u8>().map_err(|_| PatternError::InvalidPSK)?)),
            "fallback" => Ok(HandshakeModifier::Fallback),
            #[cfg(feature = "hfs")]
            "hfs" => Ok(HandshakeModifier::HFS),
             _ => Err(PatternError::UnsupportedModifier),
        }
    }
}

#[derive(Debug)]
pub enum PatternError {
    TooFewParameters,
    TooManyParameters,
    UnsupportedBase,
    UnsupportedPattern,
    UnsupportedModifier,
    UnsupportedDiffHell,
    UnsupportedHash,
    #[cfg(feature = "hfs")]
    UnsupportedKem,
    UnsupportedCipher,
    UnsupportedMessageToken,
    DuplicateModifier,
    InvalidPSK,
}

impl Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pattern error: {:?}", self)
    }
}

impl std::error::Error for PatternError {}

#[test]
fn parse_basic_handshake_params() {
    let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    assert_eq!(params.base, BaseChoice::Noise);
    assert!(params.handshake.modifiers.is_empty());
    assert_eq!(params.handshake.pattern, HandshakePattern::XX);
    assert_eq!(params.diff_hell, DiffHellChoice::Curve25519);
    assert_eq!(params.cipher, CipherChoice::ChaChaPoly);
    assert_eq!(params.hash, HashChoice::BLAKE2s);
}

#[test]
fn parse_defered_handshake() {
    let params: NoiseParams = "Noise_X1X1_25519_AESGCM_SHA256".parse().unwrap();
    assert!(params.handshake.modifiers.is_empty())
}

#[test]
fn parse_fallback_modifier() {
    let params: NoiseParams = "Noise_XXfallback_443_ChaChaPoly_BLAKE3".parse().unwrap();
    assert!(params.handshake.modifiers.len() == 1);
    assert!(params.handshake.modifiers[0] == HandshakeModifier::Fallback);
}

#[test]
fn parse_psk_modifier() {
    let params: NoiseParams = "Noise_XXpsk0_25519_AESGCM_SHA3/256".parse().unwrap();
    assert!(params.handshake.modifiers.len() == 1);
    assert!(params.handshake.modifiers[0] == HandshakeModifier::PSK(0));
}

#[cfg(feature = "hfs")]
#[test]
fn parse_hfs_modifier() {
    let params: NoiseParams = "Noise_XXhfs_443+Kyber1024_ChaChaPoly_BLAKE3".parse().unwrap();
    assert!(params.handshake.modifiers.len() == 1);
    assert!(params.handshake.modifiers[0] == HandshakeModifier::HFS);
    assert!(params.kem.is_some_and(|kem| kem == KemChoice::Kyber1024));
}

#[test]
fn parse_multi_modifiers() {
    let params: NoiseParams = "Noise_XXfallback+psk0+psk1_443_AESGCM_SHA512".parse().unwrap();
    let mods = params.handshake.modifiers;
    assert!(mods.len() == 3);
    assert!((&mods[0], &mods[1], &mods[2]) == (&HandshakeModifier::Fallback, &HandshakeModifier::PSK(0), &HandshakeModifier::PSK(1)));
}

