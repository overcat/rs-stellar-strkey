#[cfg(feature = "alloc")]
use alloc::string::String;
use core::{
    fmt::{self, Debug, Display},
    str::FromStr,
};

use crate::{convert, ed25519, error::DecodeError, version};

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
#[cfg_attr(
    feature = "cli",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum Strkey {
    PublicKeyEd25519(ed25519::PublicKey),
    PrivateKeyEd25519(ed25519::PrivateKey),
    PreAuthTx(PreAuthTx),
    HashX(HashX),
    MuxedAccountEd25519(ed25519::MuxedAccount),
    SignedPayloadEd25519(ed25519::SignedPayload),
    Contract(Contract),
    LiquidityPool(LiquidityPool),
    ClaimableBalance(ClaimableBalance),
}

impl Strkey {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        match self {
            Self::PublicKeyEd25519(x) => x.to_string(),
            Self::PrivateKeyEd25519(x) => x.to_string(),
            Self::PreAuthTx(x) => x.to_string(),
            Self::HashX(x) => x.to_string(),
            Self::MuxedAccountEd25519(x) => x.to_string(),
            Self::SignedPayloadEd25519(x) => x.to_string(),
            Self::Contract(x) => x.to_string(),
            Self::LiquidityPool(x) => x.to_string(),
            Self::ClaimableBalance(x) => x.to_string(),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload_buf = [0u8; convert::MAX_PAYLOAD_LEN];
        let (ver, payload) = convert::decode_into(s, &mut payload_buf)?;
        match ver {
            version::PUBLIC_KEY_ED25519 => Ok(Self::PublicKeyEd25519(
                ed25519::PublicKey::from_payload(&payload)?,
            )),
            version::PRIVATE_KEY_ED25519 => Ok(Self::PrivateKeyEd25519(
                ed25519::PrivateKey::from_payload(&payload)?,
            )),
            version::PRE_AUTH_TX => Ok(Self::PreAuthTx(PreAuthTx::from_payload(&payload)?)),
            version::HASH_X => Ok(Self::HashX(HashX::from_payload(&payload)?)),
            version::MUXED_ACCOUNT_ED25519 => Ok(Self::MuxedAccountEd25519(
                ed25519::MuxedAccount::from_payload(&payload)?,
            )),
            version::SIGNED_PAYLOAD_ED25519 => Ok(Self::SignedPayloadEd25519(
                ed25519::SignedPayload::from_payload(&payload)?,
            )),
            version::CONTRACT => Ok(Self::Contract(Contract::from_payload(&payload)?)),
            version::LIQUIDITY_POOL => {
                Ok(Self::LiquidityPool(LiquidityPool::from_payload(&payload)?))
            }
            version::CLAIMABLE_BALANCE => Ok(Self::ClaimableBalance(
                ClaimableBalance::from_payload(&payload)?,
            )),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for Strkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKeyEd25519(x) => Display::fmt(x, f),
            Self::PrivateKeyEd25519(x) => Display::fmt(x, f),
            Self::PreAuthTx(x) => Display::fmt(x, f),
            Self::HashX(x) => Display::fmt(x, f),
            Self::MuxedAccountEd25519(x) => Display::fmt(x, f),
            Self::SignedPayloadEd25519(x) => Display::fmt(x, f),
            Self::Contract(x) => Display::fmt(x, f),
            Self::LiquidityPool(x) => Display::fmt(x, f),
            Self::ClaimableBalance(x) => Display::fmt(x, f),
        }
    }
}

impl FromStr for Strkey {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Strkey::from_string(s)
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
pub struct PreAuthTx(
    #[cfg_attr(feature = "cli", serde_as(as = "serde_with::hex::Hex"))] pub [u8; 32],
);

impl Debug for PreAuthTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreAuthTx(")?;
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl PreAuthTx {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        convert::encode(version::PRE_AUTH_TX, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload_buf = [0u8; convert::MAX_PAYLOAD_LEN];
        let (ver, payload) = convert::decode_into(s, &mut payload_buf)?;
        match ver {
            version::PRE_AUTH_TX => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for PreAuthTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        convert::format_encoded(version::PRE_AUTH_TX, &self.0, f)
    }
}

impl FromStr for PreAuthTx {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PreAuthTx::from_string(s)
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
pub struct HashX(#[cfg_attr(feature = "cli", serde_as(as = "serde_with::hex::Hex"))] pub [u8; 32]);

impl Debug for HashX {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HashX(")?;
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl HashX {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        convert::encode(version::HASH_X, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload_buf = [0u8; convert::MAX_PAYLOAD_LEN];
        let (ver, payload) = convert::decode_into(s, &mut payload_buf)?;
        match ver {
            version::HASH_X => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for HashX {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        convert::format_encoded(version::HASH_X, &self.0, f)
    }
}

impl FromStr for HashX {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HashX::from_string(s)
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
pub struct Contract(
    #[cfg_attr(feature = "cli", serde_as(as = "serde_with::hex::Hex"))] pub [u8; 32],
);

impl Debug for Contract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Contract(")?;
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl Contract {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        convert::encode(version::CONTRACT, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload_buf = [0u8; convert::MAX_PAYLOAD_LEN];
        let (ver, payload) = convert::decode_into(s, &mut payload_buf)?;
        match ver {
            version::CONTRACT => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for Contract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        convert::format_encoded(version::CONTRACT, &self.0, f)
    }
}

impl FromStr for Contract {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Contract::from_string(s)
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
pub struct LiquidityPool(
    #[cfg_attr(feature = "cli", serde_as(as = "serde_with::hex::Hex"))] pub [u8; 32],
);

impl Debug for LiquidityPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LiquidityPool(")?;
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl LiquidityPool {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        convert::encode(version::LIQUIDITY_POOL, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload_buf = [0u8; convert::MAX_PAYLOAD_LEN];
        let (ver, payload) = convert::decode_into(s, &mut payload_buf)?;
        match ver {
            version::LIQUIDITY_POOL => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for LiquidityPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        convert::format_encoded(version::LIQUIDITY_POOL, &self.0, f)
    }
}

impl FromStr for LiquidityPool {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        LiquidityPool::from_string(s)
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
pub enum ClaimableBalance {
    V0(#[cfg_attr(feature = "cli", serde_as(as = "serde_with::hex::Hex"))] [u8; 32]),
}

impl Debug for ClaimableBalance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClaimableBalance(")?;
        match self {
            Self::V0(v0) => {
                f.write_str("V0(")?;
                for byte in v0.iter() {
                    write!(f, "{byte:02x}")?;
                }
                f.write_str(")")?;
            }
        }
        f.write_str(")")
    }
}

impl ClaimableBalance {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        match self {
            Self::V0(v0) => {
                // First byte is zero for v0
                let mut payload = [0; 33];
                payload[1..].copy_from_slice(v0);
                convert::encode(version::CLAIMABLE_BALANCE, &payload)
            }
        }
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload {
            // First byte is zero for v0
            [0, rest @ ..] => Ok(Self::V0(rest.try_into().map_err(|_| DecodeError::Invalid)?)),
            _ => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload_buf = [0u8; convert::MAX_PAYLOAD_LEN];
        let (ver, payload) = convert::decode_into(s, &mut payload_buf)?;
        match ver {
            version::CLAIMABLE_BALANCE => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for ClaimableBalance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V0(v0) => {
                let mut payload = [0u8; 33];
                payload[1..].copy_from_slice(v0);
                convert::format_encoded(version::CLAIMABLE_BALANCE, &payload, f)
            }
        }
    }
}

impl FromStr for ClaimableBalance {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ClaimableBalance::from_string(s)
    }
}
