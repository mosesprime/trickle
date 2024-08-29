use quinn::crypto::{KeyPair, Keys, Session};
use quinn_proto::{transport_parameters::TransportParameters, ConnectionId, Side, TransportError, TransportErrorCode};
use trickle_crypto::noise::{pattern::Role, HandshakeState, NoiseCipher, TransportState, CIPHER_KEY_LEN, PSK_LEN};

static PATTERN: &'static str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

struct NoiseHeaderKey;

impl quinn::crypto::HeaderKey for NoiseHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        todo!()
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        todo!()
    }

    fn sample_size(&self) -> usize {
        todo!()
    }
}

struct NoisePacketKey;

impl quinn::crypto::PacketKey for NoisePacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        todo!()
    }

    fn decrypt(
            &self,
            packet: u64,
            header: &[u8],
            payload: &mut BytesMut,
        ) -> Result<(), quinn::crypto::CryptoError> {
        todo!()
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        u64::MAX
    }
}

enum SessionState {
    Init,
    ZeroRTT,
    Handshake,
    OneRTT,
    Data,
}

enum NoiseState {
    Handshake(HandshakeState),
    Transport(TransportState),
}

struct NoiseSession {
    noise: NoiseState,
    session: SessionState,
    zero_rtt_key: Option<NoisePacketKey>,
    transport_params: TransportParameters,
    remote_transport_params: Option<TransportParameters>,
}

impl quinn::crypto::Session for NoiseSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> quinn::crypto::Keys {
        quinn::crypto::Keys {
            header: quinn::crypto::KeyPair {
                local: Box::new(NoiseHeaderKey),
                remote: Box::new(NoiseHeaderKey),
            },
            packet: quinn::crypto::KeyPair {
                local: Box::new(NoisePacketKey::new([0u8; 32])),
                remote: Box::new(NoisePacketKey::new([0u8; 32])),
            } 
        }
    }

    fn handshake_data(&self) -> Option<Box<dyn std::any::Any>> {
        todo!()
    }

    fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        Some(match self.noise {
            NoiseState::Handshake(hs) => hs.remote_s(),
            NoiseState::Transport(ts) => ts.remote_s(),
        })
    }

    fn early_crypto(&self) -> Option<(Box<dyn quinn::crypto::HeaderKey>, Box<dyn quinn::crypto::PacketKey>)> {
        Some((
            Box::new(NoiseHeaderKey),
            Box::new(self.zero_rtt_key.clone()?),
        ))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        Some(true)
    }

    fn is_handshaking(&self) -> bool {
        self.state != SessionState::Data
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        tracing::trace!("read handshake {:?} {:?}", self.state, self.side);
        match (self.state, self.side) {
            (SessionState::Init, Side::Server) => todo!(),
            (SessionState::Handshake, Side::Client) => todo!(),
            _ => Err(TransportError {
                code: TransportErrorCode::CONNECTION_REFUSED,
                frame: None,
                reason: "unexpected frame".to_string(),
            }),
        }
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        if self.side == Side::Client {
            Ok(Some(self.transport_params))
        } else {
            Ok(self.remote_transport_params)
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<quinn::crypto::Keys> {
        tracing::trace!("write handshake {:?} {:?}", self.state, self.side);
        match (self.session, self.side) {
            (SessionState::Init, Side::Client) => todo!(),
            (SessionState::ZeroRTT, _) => todo!(),
            (SessionState::Handshake, Side::Server) => todo!(),
            (SessionState::OneRTT, _) => {
                let packet = self.next_1rtt_keys().unwrap();
                self.session = SessionState::Data;
                Some(Keys { header: todo!(), packet })
            },
            _ => None,
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<quinn::crypto::KeyPair<Box<dyn quinn::crypto::PacketKey>>> {
        // TODO: idk if this works
        Some(KeyPair {
            local: Box::new(NoisePacketKey::new([0u8; 32])),
            remote: Box::new(NoisePacketKey::new([0u8; 32])),
        })
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        todo!()
    }

    fn export_keying_material(
            &self,
            output: &mut [u8],
            label: &[u8],
            context: &[u8],
        ) -> Result<(), quinn::crypto::ExportKeyingMaterialError> {
        todo!()
    }
}

fn refuse_connection(reason: &str) -> TransportError {
    TransportError {
        code: TransportErrorCode::CONNECTION_REFUSED,
        frame: None,
        reason: reason.to_string(),
    }
}

pub struct NoiseConfig {
    keypair: quinn_proto::crypto::KeyPair<[u8; 32]>,
    psk: Option<[u8; PSK_LEN]>,
    remote_public_key: Option<[u8; 32]>,
}

impl NoiseConfig {
    fn start_session(&self, side: quinn_proto::Side, params: &TransportParameters) -> NoiseSession {
        let role = match side {
            Side::Client => Role::Initiator,
            Side::Server => Role::Recipient,
        };
        let noise_params = todo!();
        NoiseSession {
            noise: NoiseState::Handshake(todo!()),
            session: SessionState::Init,
            zero_rtt_key: None,
            transport_params: *params,
            remote_transport_params: None,
        }
    }
}

impl quinn::crypto::ClientConfig for NoiseConfig {
    fn start_session(
            self: std::sync::Arc<Self>,
            version: u32,
            server_name: &str,
            params: &TransportParameters,
        ) -> Result<Box<dyn quinn::crypto::Session>, quinn::ConnectError> {
        // TODO: check version and server name?
        Ok(Box::new(NoiseConfig::start_session(&self, Side::Client, params)))
    }
}

impl quinn::crypto::ServerConfig for NoiseConfig {
    fn initial_keys(
            &self,
            version: u32,
            dst_cid: &ConnectionId,
        ) -> Result<quinn::crypto::Keys, quinn::crypto::UnsupportedVersion> {
        // TODO: ensure supported quic version
        Ok(quinn::crypto::Keys {
            header: KeyPair {
                local: Box::new(NoiseHeaderKey),
                remote: Box::new(NoiseHeaderKey)
            },
            packet: KeyPair {
                local: Box::new(NoisePacketKey),
                remote: Box::new(NoisePacketKey)
            }
        })
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        todo!()
    }

    fn start_session(
            self: std::sync::Arc<Self>,
            version: u32,
            params: &TransportParameters,
        ) -> Box<dyn quinn::crypto::Session> {
        Box::new(NoiseConfig::start_session(&self, Side::Server, params))
    }
}
