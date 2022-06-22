use crate::crc::checksum;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DecodeError {
    // TODO: Add meaningful errors for each problem that can occur.
    Invalid,
}

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub enum Strkey {
    PublicKeyEd25519(StrkeyPublicKeyEd25519),
    PrivateKeyEd25519(StrkeyPrivateKeyEd25519),
    HashTx(StrkeyHashTx),
    HashX(StrkeyHashX),
    MuxedAccountEd25519(StrkeyMuxedAccountEd25519),
    SignedPayloadEd25519(StrkeySignedPayloadEd25519),
}

impl Strkey {
    pub fn to_string(&self) -> String {
        match self {
            Self::PublicKeyEd25519(x) => x.to_string(),
            Self::PrivateKeyEd25519(x) => x.to_string(),
            Self::HashTx(x) => x.to_string(),
            Self::HashX(x) => x.to_string(),
            Self::MuxedAccountEd25519(x) => x.to_string(),
            Self::SignedPayloadEd25519(x) => x.to_string(),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::PUBLIC_KEY_ED25519 => Ok(Self::PublicKeyEd25519(
                StrkeyPublicKeyEd25519::from_payload(&payload)?,
            )),
            version::PRIVATE_KEY_ED25519 => Ok(Self::PrivateKeyEd25519(
                StrkeyPrivateKeyEd25519::from_payload(&payload)?,
            )),
            version::HASH_TX => Ok(Self::HashTx(StrkeyHashTx::from_payload(&payload)?)),
            version::HASH_X => Ok(Self::HashX(StrkeyHashX::from_payload(&payload)?)),
            version::MUXED_ACCOUNT_ED25519 => Ok(Self::MuxedAccountEd25519(
                StrkeyMuxedAccountEd25519::from_payload(&payload)?,
            )),
            version::SIGNED_PAYLOAD_ED25519 => Ok(Self::SignedPayloadEd25519(
                StrkeySignedPayloadEd25519::from_payload(&payload)?,
            )),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub struct StrkeyPublicKeyEd25519(pub [u8; 32]);

impl StrkeyPublicKeyEd25519 {
    pub fn to_string(&self) -> String {
        encode(version::PUBLIC_KEY_ED25519, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::PUBLIC_KEY_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub struct StrkeyPrivateKeyEd25519(pub [u8; 32]);

impl StrkeyPrivateKeyEd25519 {
    pub fn to_string(&self) -> String {
        encode(version::PRIVATE_KEY_ED25519, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::PRIVATE_KEY_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub struct StrkeyMuxedAccountEd25519(pub [u8; 40]);

impl StrkeyMuxedAccountEd25519 {
    pub fn to_string(&self) -> String {
        encode(version::MUXED_ACCOUNT_ED25519, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(muxed) => Ok(Self(muxed)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::MUXED_ACCOUNT_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub struct StrkeyHashTx(pub [u8; 32]);

impl StrkeyHashTx {
    pub fn to_string(&self) -> String {
        encode(version::HASH_TX, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(hash_tx) => Ok(Self(hash_tx)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::HASH_TX => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub struct StrkeyHashX(pub [u8; 32]);

impl StrkeyHashX {
    pub fn to_string(&self) -> String {
        encode(version::HASH_X, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(hash_x) => Ok(Self(hash_x)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::HASH_X => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
// The largest strkey is a signed payload:
// 32-byte public key + 4-byte payload length + 64-byte payload
pub struct StrkeySignedPayloadEd25519(pub Vec<u8>);

impl StrkeySignedPayloadEd25519 {
    pub fn to_string(&self) -> String {
        encode(version::SIGNED_PAYLOAD_ED25519, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(signed_payload) => {
                let payload_len = payload.len() as u32;
                if payload_len < 32 + 4 + 4 || payload_len > 32 + 4 + 64 {
                    return Err(DecodeError::Invalid);
                }
                let inner_payload_len =
                    u32::from_be_bytes((&payload[32..32 + 4]).try_into().unwrap());
                if inner_payload_len + ((4 - inner_payload_len % 4) % 4) != payload_len - 32 - 4 {
                    return Err(DecodeError::Invalid);
                }
                Ok(Self(signed_payload))
            }
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::SIGNED_PAYLOAD_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

mod version {
    use super::public_key_alg::*;
    use super::typ;

    pub const PUBLIC_KEY_ED25519: u8 = typ::PUBLIC_KEY | ED25519;
    pub const PRIVATE_KEY_ED25519: u8 = typ::PRIVATE_KEY | ED25519;
    pub const MUXED_ACCOUNT_ED25519: u8 = typ::MUXED_ACCOUNT | ED25519;
    pub const HASH_TX: u8 = typ::HASH_TX;
    pub const HASH_X: u8 = typ::HASH_X;
    pub const SIGNED_PAYLOAD_ED25519: u8 = typ::SIGNED_PAYLOAD | ED25519;
}

mod typ {
    pub const PUBLIC_KEY: u8 = 6 << 3;
    pub const PRIVATE_KEY: u8 = 18 << 3;
    pub const MUXED_ACCOUNT: u8 = 12 << 3;
    pub const HASH_TX: u8 = 19 << 3;
    pub const HASH_X: u8 = 23 << 3;
    pub const SIGNED_PAYLOAD: u8 = 15 << 3;
}

mod public_key_alg {
    pub const ED25519: u8 = 0;
}

// TODO: Could encode and decode, and the functions upstream that call them, be
// const fn's?

fn encode(ver: u8, payload: &[u8]) -> String {
    let mut d: Vec<u8> = Vec::with_capacity(1 + payload.len() + 2);
    d.push(ver);
    d.extend_from_slice(&payload);
    d.extend_from_slice(&checksum(&d));
    base32::encode(base32::Alphabet::RFC4648 { padding: false }, &d)
}

fn decode(s: &str) -> Result<(u8, Vec<u8>), DecodeError> {
    let data = match data_encoding::BASE32_NOPAD.decode(s.as_bytes()) {
        Ok(data) => data,
        Err(_) => {
            return Err(DecodeError::Invalid);
        }
    };
    // The minimal data length is 3 bytes (version byte and 2-byte CRC)
    if data.len() < 3 {
        return Err(DecodeError::Invalid);
    }
    let ver = data[0];
    let (data_without_crc, crc_actual) = data.split_at(data.len() - 2);
    let crc_expect = checksum(&data_without_crc);
    if crc_actual != crc_expect {
        return Err(DecodeError::Invalid);
    }
    let payload = &data_without_crc[1..];
    Ok((ver, payload.to_vec()))
}
