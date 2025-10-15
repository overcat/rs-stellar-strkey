use core::{fmt, str};

use crate::{crc::checksum, error::DecodeError};

const PREFIX_LEN: usize = 1;
const CHECKSUM_LEN: usize = 2;

/// Maximum payload size across all supported Strkey types.
pub const MAX_PAYLOAD_LEN: usize = 100;
const MAX_DATA_LEN: usize = PREFIX_LEN + MAX_PAYLOAD_LEN + CHECKSUM_LEN;

/// Maximum encoded Strkey length (BASE32 without padding).
pub const MAX_ENCODED_STRKEY_LEN: usize = base32_encoded_len(MAX_DATA_LEN);

/// Errors that can occur while encoding without heap allocations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    PayloadTooLong,
    OutputTooSmall,
}

const fn base32_encoded_len(len: usize) -> usize {
    ((len * 8) + 4) / 5
}

/// Encode a payload into the provided output buffer.
///
/// Returns a `&str` view into the provided `output` slice on success.
pub fn encode_into<'a>(
    ver: u8,
    payload: &[u8],
    output: &'a mut [u8],
) -> Result<&'a str, EncodeError> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(EncodeError::PayloadTooLong);
    }

    let data_len = PREFIX_LEN + payload.len() + CHECKSUM_LEN;
    let encoded_len = data_encoding::BASE32_NOPAD.encode_len(data_len);
    debug_assert!(encoded_len <= MAX_ENCODED_STRKEY_LEN);
    if output.len() < encoded_len {
        return Err(EncodeError::OutputTooSmall);
    }

    let mut data = [0u8; MAX_DATA_LEN];
    data[0] = ver;
    data[1..1 + payload.len()].copy_from_slice(payload);
    let checksum_bytes = checksum(&data[..PREFIX_LEN + payload.len()]);
    data[PREFIX_LEN + payload.len()..data_len].copy_from_slice(&checksum_bytes);

    let encoded = &mut output[..encoded_len];
    data_encoding::BASE32_NOPAD.encode_mut(&data[..data_len], encoded);
    // SAFETY: Base32 encoding only yields ASCII characters.
    unsafe { Ok(str::from_utf8_unchecked(encoded)) }
}

/// Decode a Strkey payload into the provided buffer.
///
/// On success returns the version byte together with a slice that points into the provided buffer.
pub fn decode_into<'a>(s: &str, payload_out: &'a mut [u8]) -> Result<(u8, &'a [u8]), DecodeError> {
    let expected_len = data_encoding::BASE32_NOPAD
        .decode_len(s.len())
        .map_err(|_| DecodeError::Invalid)?;
    if expected_len > MAX_DATA_LEN {
        return Err(DecodeError::Invalid);
    }

    let mut data = [0u8; MAX_DATA_LEN];
    let data_slice = &mut data[..expected_len];
    let decoded_len = data_encoding::BASE32_NOPAD
        .decode_mut(s.as_bytes(), data_slice)
        .map_err(|_| DecodeError::Invalid)?;

    if decoded_len < PREFIX_LEN + CHECKSUM_LEN {
        return Err(DecodeError::Invalid);
    }

    let data_filled = &data_slice[..decoded_len];
    let ver = data_filled[0];
    let (without_crc, crc_actual) = data_filled.split_at(decoded_len - CHECKSUM_LEN);
    let crc_expect = checksum(without_crc);
    if crc_actual != crc_expect {
        return Err(DecodeError::Invalid);
    }

    let payload = &without_crc[PREFIX_LEN..];
    if payload_out.len() < payload.len() {
        return Err(DecodeError::Invalid);
    }
    payload_out[..payload.len()].copy_from_slice(payload);
    Ok((ver, &payload_out[..payload.len()]))
}

/// Helper that writes the encoded form into the provided formatter.
pub fn format_encoded(ver: u8, payload: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut buffer = [0u8; MAX_ENCODED_STRKEY_LEN];
    let encoded = encode_into(ver, payload, &mut buffer).map_err(|_| fmt::Error)?;
    f.write_str(encoded)
}

#[cfg(feature = "alloc")]
pub fn encode(ver: u8, payload: &[u8]) -> alloc::string::String {
    use alloc::{string::String, vec, vec::Vec};

    let data_len = PREFIX_LEN + payload.len() + CHECKSUM_LEN;
    let encoded_len = data_encoding::BASE32_NOPAD.encode_len(data_len);
    debug_assert!(encoded_len <= MAX_ENCODED_STRKEY_LEN);
    let mut buffer: Vec<u8> = vec![0u8; encoded_len];
    encode_into(ver, payload, buffer.as_mut_slice())
        .expect("encoding into freshly sized Vec never fails");
    // SAFETY: encode_into guarantees ASCII output.
    unsafe { String::from_utf8_unchecked(buffer) }
}

#[cfg(feature = "alloc")]
#[allow(dead_code)]
pub fn decode(s: &str) -> Result<(u8, alloc::vec::Vec<u8>), DecodeError> {
    use alloc::vec::Vec;

    let mut payload = [0u8; MAX_PAYLOAD_LEN];
    let (ver, payload_slice) = decode_into(s, &mut payload)?;
    let mut out = Vec::with_capacity(payload_slice.len());
    out.extend_from_slice(payload_slice);
    Ok((ver, out))
}
