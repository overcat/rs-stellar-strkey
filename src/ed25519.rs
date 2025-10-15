use crate::{convert, error::DecodeError, version};

#[cfg(feature = "alloc")]
use alloc::{string::String, vec, vec::Vec};
use core::{
    fmt::{self, Debug, Display},
    str::FromStr,
};

const SIGNED_PAYLOAD_MAX_INNER_LEN: usize = 64;
const SIGNED_PAYLOAD_HEADER_LEN: usize = 32 + 4;
const SIGNED_PAYLOAD_PAD_UNIT: usize = 4;

#[cfg(not(feature = "alloc"))]
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignedPayloadPayload {
    len: u8,
    bytes: [u8; SIGNED_PAYLOAD_MAX_INNER_LEN],
}

#[cfg(not(feature = "alloc"))]
impl SignedPayloadPayload {
    pub const fn new() -> Self {
        Self {
            len: 0,
            bytes: [0; SIGNED_PAYLOAD_MAX_INNER_LEN],
        }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    fn set_from_slice(&mut self, slice: &[u8]) -> Result<(), DecodeError> {
        if slice.len() > SIGNED_PAYLOAD_MAX_INNER_LEN {
            return Err(DecodeError::Invalid);
        }
        self.bytes[..slice.len()].copy_from_slice(slice);
        if slice.len() < self.bytes.len() {
            self.bytes[slice.len()..].fill(0);
        }
        self.len = slice.len() as u8;
        Ok(())
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, DecodeError> {
        let mut value = Self::new();
        value.set_from_slice(slice)?;
        Ok(value)
    }
}

#[cfg(not(feature = "alloc"))]
impl Default for SignedPayloadPayload {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "alloc"))]
impl AsRef<[u8]> for SignedPayloadPayload {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
#[cfg_attr(
    feature = "cli",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub struct PrivateKey(
    #[cfg_attr(feature = "cli", serde_as(as = "serde_with::hex::Hex"))] pub [u8; 32],
);

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(")?;
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl PrivateKey {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        convert::encode(version::PRIVATE_KEY_ED25519, &self.0)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; convert::MAX_PAYLOAD_LEN];
        let (ver, payload) = convert::decode_into(s, &mut payload)?;
        match ver {
            version::PRIVATE_KEY_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        convert::format_encoded(version::PRIVATE_KEY_ED25519, &self.0, f)
    }
}

impl FromStr for PrivateKey {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PrivateKey::from_string(s)
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
#[cfg_attr(
    feature = "cli",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub struct PublicKey(
    #[cfg_attr(feature = "cli", serde_as(as = "serde_with::hex::Hex"))] pub [u8; 32],
);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(")?;
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl PublicKey {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        convert::encode(version::PUBLIC_KEY_ED25519, &self.0)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; convert::MAX_PAYLOAD_LEN];
        let (ver, payload) = convert::decode_into(s, &mut payload)?;
        match ver {
            version::PUBLIC_KEY_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        convert::format_encoded(version::PUBLIC_KEY_ED25519, &self.0, f)
    }
}

impl FromStr for PublicKey {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PublicKey::from_string(s)
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
#[cfg_attr(
    feature = "cli",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub struct MuxedAccount {
    #[cfg_attr(feature = "cli", serde_as(as = "serde_with::hex::Hex"))]
    pub ed25519: [u8; 32],
    pub id: u64,
}

impl Debug for MuxedAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MuxedAccount(")?;
        for byte in self.ed25519.iter() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ", {}", self.id)?;
        f.write_str(")")
    }
}

impl MuxedAccount {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let mut payload: [u8; 40] = [0; 40];
        let (ed25519, id) = payload.split_at_mut(32);
        ed25519.copy_from_slice(&self.ed25519);
        id.copy_from_slice(&self.id.to_be_bytes());
        convert::encode(version::MUXED_ACCOUNT_ED25519, &payload)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < 40 {
            return Err(DecodeError::Invalid);
        }
        let (ed25519, id) = payload.split_at(32);
        Ok(Self {
            ed25519: ed25519.try_into().map_err(|_| DecodeError::Invalid)?,
            id: u64::from_be_bytes(id.try_into().map_err(|_| DecodeError::Invalid)?),
        })
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload_buf = [0u8; convert::MAX_PAYLOAD_LEN];
        let (ver, payload) = convert::decode_into(s, &mut payload_buf)?;
        match ver {
            version::MUXED_ACCOUNT_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for MuxedAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut payload: [u8; 40] = [0; 40];
        let (ed25519, id) = payload.split_at_mut(32);
        ed25519.copy_from_slice(&self.ed25519);
        id.copy_from_slice(&self.id.to_be_bytes());
        convert::format_encoded(version::MUXED_ACCOUNT_ED25519, &payload, f)
    }
}

impl FromStr for MuxedAccount {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MuxedAccount::from_string(s)
    }
}

/// Stores a signed payload ed25519 signer.
///
/// The payload must not have a size larger than u32::MAX.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
#[cfg_attr(
    feature = "cli",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub struct SignedPayload {
    #[cfg_attr(feature = "cli", serde_as(as = "serde_with::hex::Hex"))]
    pub ed25519: [u8; 32],

    #[cfg(feature = "alloc")]
    #[cfg_attr(feature = "cli", serde_as(as = "serde_with::hex::Hex"))]
    pub payload: Vec<u8>,

    #[cfg(not(feature = "alloc"))]
    #[cfg_attr(feature = "cli", serde_as(as = "serde_with::hex::Hex"))]
    pub payload: SignedPayloadPayload,
}

impl Debug for SignedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MuxedAccount(")?;
        for byte in self.ed25519.iter() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(", ")?;
        for byte in self.payload_bytes().iter() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl SignedPayload {
    fn payload_bytes(&self) -> &[u8] {
        #[cfg(feature = "alloc")]
        {
            self.payload.as_slice()
        }

        #[cfg(not(feature = "alloc"))]
        {
            self.payload.as_slice()
        }
    }

    fn padding_len(inner_payload_len: usize) -> usize {
        (SIGNED_PAYLOAD_PAD_UNIT - inner_payload_len % SIGNED_PAYLOAD_PAD_UNIT)
            % SIGNED_PAYLOAD_PAD_UNIT
    }

    fn encoded_payload_len(inner_payload_len: usize) -> usize {
        SIGNED_PAYLOAD_HEADER_LEN + inner_payload_len + Self::padding_len(inner_payload_len)
    }

    fn write_payload_bytes(&self, out: &mut [u8]) -> usize {
        let payload_bytes = self.payload_bytes();
        let inner_payload_len = payload_bytes.len();
        let inner_payload_len_u32 =
            u32::try_from(inner_payload_len).expect("payload length larger than u32::MAX");
        let payload_len = Self::encoded_payload_len(inner_payload_len);
        debug_assert!(out.len() >= payload_len);

        out[..payload_len].fill(0);

        out[..32].copy_from_slice(&self.ed25519);
        out[32..SIGNED_PAYLOAD_HEADER_LEN].copy_from_slice(&inner_payload_len_u32.to_be_bytes());
        out[SIGNED_PAYLOAD_HEADER_LEN..SIGNED_PAYLOAD_HEADER_LEN + inner_payload_len]
            .copy_from_slice(payload_bytes);

        payload_len
    }

    /// Returns the strkey string for the signed payload signer.
    ///
    /// ### Panics
    ///
    /// When the payload is larger than u32::MAX.
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let inner_payload_len = self.payload_bytes().len();
        let _ = u32::try_from(inner_payload_len).expect("payload length larger than u32::MAX");
        let payload_len = Self::encoded_payload_len(inner_payload_len);
        let mut payload = vec![0u8; payload_len];
        let written = self.write_payload_bytes(&mut payload);
        debug_assert_eq!(written, payload_len);
        convert::encode(version::SIGNED_PAYLOAD_ED25519, &payload)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        // 32-byte for the signer, 4-byte for the payload size, then either 4-byte for the
        // min or 64-byte for the max payload (including padding to 4-byte boundaries).
        const MIN_LENGTH: usize = SIGNED_PAYLOAD_HEADER_LEN + SIGNED_PAYLOAD_PAD_UNIT;
        const MAX_LENGTH: usize = SIGNED_PAYLOAD_HEADER_LEN + SIGNED_PAYLOAD_MAX_INNER_LEN;
        let payload_len = payload.len();
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&payload_len) {
            return Err(DecodeError::Invalid);
        }

        // Decode ed25519 public key. 32 bytes.
        let mut offset = 0;
        let ed25519: [u8; 32] = payload
            .get(offset..offset + 32)
            .ok_or(DecodeError::Invalid)?
            .try_into()
            .map_err(|_| DecodeError::Invalid)?;
        offset += 32;

        // Decode inner payload length. 4 bytes.
        let inner_payload_len = u32::from_be_bytes(
            payload
                .get(offset..offset + 4)
                .ok_or(DecodeError::Invalid)?
                .try_into()
                .map_err(|_| DecodeError::Invalid)?,
        ) as usize;
        offset += 4;

        // Check inner payload length is inside accepted range.
        if inner_payload_len > SIGNED_PAYLOAD_MAX_INNER_LEN {
            return Err(DecodeError::Invalid);
        }

        // Decode inner payload.
        let inner_payload = payload
            .get(offset..offset + inner_payload_len)
            .ok_or(DecodeError::Invalid)?;
        offset += inner_payload_len;

        // Calculate padding at end of inner payload. 0-3 bytes.
        let padding_len = (SIGNED_PAYLOAD_PAD_UNIT - inner_payload_len % SIGNED_PAYLOAD_PAD_UNIT)
            % SIGNED_PAYLOAD_PAD_UNIT;

        // Decode padding.
        let padding = payload
            .get(offset..offset + padding_len as usize)
            .ok_or(DecodeError::Invalid)?;
        offset += padding_len as usize;

        // Check padding is all zeros.
        if padding.iter().any(|b| *b != 0) {
            return Err(DecodeError::Invalid);
        }

        // Check that entire payload consumed.
        if offset != payload_len {
            return Err(DecodeError::Invalid);
        }

        #[cfg(feature = "alloc")]
        let payload = {
            let mut bytes = Vec::with_capacity(inner_payload_len);
            bytes.extend_from_slice(inner_payload);
            bytes
        };

        #[cfg(not(feature = "alloc"))]
        let payload = SignedPayloadPayload::from_slice(inner_payload)?;

        Ok(Self { ed25519, payload })
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload_buf = [0u8; convert::MAX_PAYLOAD_LEN];
        let (ver, payload) = convert::decode_into(s, &mut payload_buf)?;
        match ver {
            version::SIGNED_PAYLOAD_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for SignedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut payload = [0u8; convert::MAX_PAYLOAD_LEN];
        let payload_len = self.write_payload_bytes(&mut payload);
        convert::format_encoded(version::SIGNED_PAYLOAD_ED25519, &payload[..payload_len], f)
    }
}

impl FromStr for SignedPayload {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SignedPayload::from_string(s)
    }
}
