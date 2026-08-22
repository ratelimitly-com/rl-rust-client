use std::convert::TryInto;

const GEN: [u32; 5] = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3];
const FORMAT_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApiKeyLimits {
    pub rate_buckets_max: u32,
    pub latency_services_max: u32,
    pub metrics_labels_max: u32,
    pub latency_buffer_size_max: u32,
    pub dedup_ttl_ms_max: u32,
    pub rate_window_size_ms_max: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DecodedApiKey {
    pub hrp: String,
    pub auth_method: String,
    pub format_version: u8,
    pub key_id: u64,
    pub auth_secret: Vec<u8>,
    pub limits: Option<ApiKeyLimits>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DecodeError {
    EmptyInput,
    NonPrintable,
    MixedCase,
    MissingSeparator,
    EmptyHrp,
    ChecksumTooShort,
    InvalidCharset(char),
    ChecksumFailed,
    InvalidPadding,
    InvalidHrpPrefix,
    UnsupportedAuthMethod(String),
    InvalidPayloadLength {
        auth_method: String,
        expected: usize,
        actual: usize,
    },
    UnsupportedFormatVersion(u8),
    InvalidPackedQuota,
}

fn char_to_value(c: char) -> Option<u8> {
    match c {
        'q' => Some(0),
        'p' => Some(1),
        'z' => Some(2),
        'r' => Some(3),
        'y' => Some(4),
        '9' => Some(5),
        'x' => Some(6),
        '8' => Some(7),
        'g' => Some(8),
        'f' => Some(9),
        '2' => Some(10),
        't' => Some(11),
        'v' => Some(12),
        'd' => Some(13),
        'w' => Some(14),
        '0' => Some(15),
        's' => Some(16),
        '3' => Some(17),
        'j' => Some(18),
        'n' => Some(19),
        '5' => Some(20),
        '4' => Some(21),
        'k' => Some(22),
        'h' => Some(23),
        'c' => Some(24),
        'e' => Some(25),
        '6' => Some(26),
        'm' => Some(27),
        'u' => Some(28),
        'a' => Some(29),
        '7' => Some(30),
        'l' => Some(31),
        _ => None,
    }
}

#[cfg(test)]
fn value_to_char(v: u8) -> Option<char> {
    match v {
        0 => Some('q'),
        1 => Some('p'),
        2 => Some('z'),
        3 => Some('r'),
        4 => Some('y'),
        5 => Some('9'),
        6 => Some('x'),
        7 => Some('8'),
        8 => Some('g'),
        9 => Some('f'),
        10 => Some('2'),
        11 => Some('t'),
        12 => Some('v'),
        13 => Some('d'),
        14 => Some('w'),
        15 => Some('0'),
        16 => Some('s'),
        17 => Some('3'),
        18 => Some('j'),
        19 => Some('n'),
        20 => Some('5'),
        21 => Some('4'),
        22 => Some('k'),
        23 => Some('h'),
        24 => Some('c'),
        25 => Some('e'),
        26 => Some('6'),
        27 => Some('m'),
        28 => Some('u'),
        29 => Some('a'),
        30 => Some('7'),
        31 => Some('l'),
        _ => None,
    }
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        out.push(b >> 5);
    }
    out.push(0);
    for b in hrp.bytes() {
        out.push(b & 31);
    }
    out
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1FF_FFFF) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if ((b >> i) & 1) != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == 1
}

#[cfg(test)]
fn create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let pm = polymod(&values) ^ 1;
    (0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8).collect()
}

fn convert_bits(
    data: &[u8],
    from_bits: u8,
    to_bits: u8,
    pad: bool,
) -> Result<Vec<u8>, DecodeError> {
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    let mut out = Vec::new();
    let maxv: u32 = (1u32 << to_bits) - 1;
    let max_acc: u32 = (1u32 << (from_bits + to_bits - 1)) - 1;

    for &value in data {
        if (value as u32) >> from_bits != 0 {
            return Err(DecodeError::InvalidPadding);
        }
        acc = ((acc << from_bits) | value as u32) & max_acc;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            out.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else {
        if bits >= from_bits {
            return Err(DecodeError::InvalidPadding);
        }
        if ((acc << (to_bits - bits)) & maxv) != 0 {
            return Err(DecodeError::InvalidPadding);
        }
    }

    Ok(out)
}

fn bech32_decode(addr: &str) -> Result<(String, Vec<u8>), DecodeError> {
    if addr.is_empty() {
        return Err(DecodeError::EmptyInput);
    }

    let mut has_lower = false;
    let mut has_upper = false;
    for c in addr.chars() {
        let code = c as u32;
        if !(33..=126).contains(&code) {
            return Err(DecodeError::NonPrintable);
        }
        if c.is_ascii_lowercase() {
            has_lower = true;
        }
        if c.is_ascii_uppercase() {
            has_upper = true;
        }
    }
    if has_lower && has_upper {
        return Err(DecodeError::MixedCase);
    }

    let s = addr.to_ascii_lowercase();
    let pos = s.rfind('1').ok_or(DecodeError::MissingSeparator)?;
    if pos < 1 {
        return Err(DecodeError::EmptyHrp);
    }
    if s.len() - pos - 1 < 6 {
        return Err(DecodeError::ChecksumTooShort);
    }

    let hrp = s[..pos].to_string();
    let mut data = Vec::with_capacity(s.len() - pos - 1);
    for c in s[pos + 1..].chars() {
        data.push(char_to_value(c).ok_or(DecodeError::InvalidCharset(c))?);
    }

    if !verify_checksum(&hrp, &data) {
        return Err(DecodeError::ChecksumFailed);
    }

    let payload5 = &data[..data.len() - 6];
    let payload = convert_bits(payload5, 5, 8, false)?;
    Ok((hrp, payload))
}

#[cfg(test)]
fn bech32_encode(hrp: &str, payload: &[u8]) -> Result<String, DecodeError> {
    if hrp.is_empty() {
        return Err(DecodeError::EmptyHrp);
    }
    if !hrp.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(DecodeError::NonPrintable);
    }

    let hrp = hrp.to_ascii_lowercase();
    let data = convert_bits(payload, 8, 5, true)?;
    let checksum = create_checksum(&hrp, &data);

    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + checksum.len());
    out.push_str(&hrp);
    out.push('1');
    for v in data.into_iter().chain(checksum) {
        out.push(value_to_char(v).expect("valid bech32 value"));
    }
    Ok(out)
}

fn limits_from_payload(payload: &[u8], offset: usize) -> Result<ApiKeyLimits, DecodeError> {
    let word = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
    let rate_exp = word & 0x1f;
    let latency_exp = (word >> 5) & 0x1f;
    let labels_exp = (word >> 10) & 0x1f;
    let buffer_exp = (word >> 15) & 0x0f;
    let dedup_units = (word >> 19) & 0xff;
    let window_exp = (word >> 27) & 0x1f;
    if rate_exp > 24 || latency_exp > 24 || !(1..=200).contains(&dedup_units) {
        return Err(DecodeError::InvalidPackedQuota);
    }
    Ok(ApiKeyLimits {
        rate_buckets_max: 1 << rate_exp,
        latency_services_max: 1 << latency_exp,
        metrics_labels_max: 1 << labels_exp,
        latency_buffer_size_max: 1 << buffer_exp,
        dedup_ttl_ms_max: dedup_units * 10,
        rate_window_size_ms_max: if window_exp == 31 {
            u32::MAX
        } else {
            1 << window_exp
        },
    })
}

pub(crate) fn decode_api_key(encoded: &str) -> Result<DecodedApiKey, DecodeError> {
    let (hrp, payload) = bech32_decode(encoded)?;
    let auth_method = hrp
        .strip_prefix("rl-")
        .ok_or(DecodeError::InvalidHrpPrefix)?
        .to_string();

    match auth_method.as_str() {
        "secret" => {
            if payload.len() != 32 {
                return Err(DecodeError::InvalidPayloadLength {
                    auth_method,
                    expected: 32,
                    actual: payload.len(),
                });
            }
            Ok(DecodedApiKey {
                hrp,
                auth_method: "secret".to_string(),
                format_version: 0,
                key_id: 0,
                auth_secret: payload,
                limits: None,
            })
        }
        "none" => {
            if payload.len() != 13 {
                return Err(DecodeError::InvalidPayloadLength {
                    auth_method,
                    expected: 13,
                    actual: payload.len(),
                });
            }
            if payload[0] != FORMAT_VERSION {
                return Err(DecodeError::UnsupportedFormatVersion(payload[0]));
            }
            let key_id = u64::from_le_bytes(payload[1..9].try_into().unwrap());
            Ok(DecodedApiKey {
                hrp,
                auth_method: "none".to_string(),
                format_version: FORMAT_VERSION,
                key_id,
                auth_secret: Vec::new(),
                limits: Some(limits_from_payload(&payload, 9)?),
            })
        }
        "cookie" | "aes" => {
            if payload.len() != 45 {
                return Err(DecodeError::InvalidPayloadLength {
                    auth_method: auth_method.clone(),
                    expected: 45,
                    actual: payload.len(),
                });
            }
            if payload[0] != FORMAT_VERSION {
                return Err(DecodeError::UnsupportedFormatVersion(payload[0]));
            }
            let key_id = u64::from_le_bytes(payload[1..9].try_into().unwrap());
            let auth_secret = payload[9..41].to_vec();
            Ok(DecodedApiKey {
                hrp,
                auth_method,
                format_version: FORMAT_VERSION,
                key_id,
                auth_secret,
                limits: Some(limits_from_payload(&payload, 41)?),
            })
        }
        _ => Err(DecodeError::UnsupportedAuthMethod(auth_method)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn decodes_canonical_format_v1_default_key() {
        let decoded = decode_api_key("rl-none1qyyqwps9qspsyq2sk8e0sfdp3ys").unwrap();
        assert_eq!(decoded.format_version, 1);
        assert_eq!(decoded.key_id, 0x0102_0304_0506_0708);
        let limits = decoded.limits.unwrap();
        assert_eq!(limits.rate_buckets_max, 65_536);
        assert_eq!(limits.latency_services_max, 1_024);
        assert_eq!(limits.metrics_labels_max, 4_096);
        assert_eq!(limits.latency_buffer_size_max, 32);
        assert_eq!(limits.dedup_ttl_ms_max, 300);
        assert_eq!(limits.rate_window_size_ms_max, u32::MAX);
    }

    #[test]
    fn rejects_unknown_versions_legacy_lengths_and_invalid_quota_codes() {
        for invalid in [
            "rl-aes1qqpqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqghjmuhccp9vn9",
            "rl-aes1qgpqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqghjmuhcchgqf0",
            "rl-aes1qyysqqqqqqqqqqqfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyqqqqqqurys6m",
            "rl-aes1qyysqqqqqqqqqqqfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyysjzgfpyvsqzqqs45cew",
            "rl-aes1qvqqqqqqqqqqqqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqemrljn",
        ] {
            assert!(
                decode_api_key(invalid).is_err(),
                "accepted invalid API key: {invalid}"
            );
        }
    }

    fn encode_api_key(
        auth_method: &str,
        key_id: u64,
        auth_secret: &[u8],
        limits: ApiKeyLimits,
    ) -> String {
        let mut payload = Vec::new();
        payload.push(FORMAT_VERSION);
        payload.extend_from_slice(&key_id.to_le_bytes());
        match auth_method {
            "none" => {}
            "cookie" | "aes" => payload.extend_from_slice(auth_secret),
            other => panic!("unsupported auth method: {other}"),
        }
        let rate_exp = limits.rate_buckets_max.trailing_zeros();
        let latency_exp = limits.latency_services_max.trailing_zeros();
        let labels_exp = limits.metrics_labels_max.trailing_zeros();
        let buffer_exp = limits.latency_buffer_size_max.trailing_zeros();
        let window_exp = if limits.rate_window_size_ms_max == u32::MAX {
            31
        } else {
            limits.rate_window_size_ms_max.trailing_zeros()
        };
        let quota_word = rate_exp
            | (latency_exp << 5)
            | (labels_exp << 10)
            | (buffer_exp << 15)
            | ((limits.dedup_ttl_ms_max / 10) << 19)
            | (window_exp << 27);
        payload.extend_from_slice(&quota_word.to_le_bytes());
        bech32_encode(&format!("rl-{auth_method}"), &payload).expect("encode API key")
    }

    fn sample_limits() -> ApiKeyLimits {
        ApiKeyLimits {
            rate_buckets_max: 65_536,
            latency_services_max: 1_024,
            metrics_labels_max: 4_096,
            latency_buffer_size_max: 64,
            dedup_ttl_ms_max: 300,
            rate_window_size_ms_max: u32::MAX,
        }
    }

    #[test]
    fn decodes_none_key_with_limits() {
        let key = encode_api_key("none", 1, &[], sample_limits());
        let decoded = decode_api_key(&key).unwrap();
        assert_eq!(decoded.auth_method, "none");
        assert_eq!(decoded.key_id, 1);
        assert_eq!(decoded.auth_secret, Vec::<u8>::new());
        assert_eq!(decoded.limits, Some(sample_limits()));
    }

    #[test]
    fn decodes_cookie_and_aes_keys() {
        let cookie =
            decode_api_key(&encode_api_key("cookie", 2, &[2u8; 32], sample_limits())).unwrap();
        assert_eq!(cookie.auth_method, "cookie");
        assert_eq!(cookie.key_id, 2);
        assert_eq!(cookie.auth_secret, vec![2u8; 32]);
        assert!(cookie.limits.is_some());

        let aes = decode_api_key(&encode_api_key("aes", 3, &[3u8; 32], sample_limits())).unwrap();
        assert_eq!(aes.auth_method, "aes");
        assert_eq!(aes.key_id, 3);
        assert_eq!(aes.auth_secret, vec![3u8; 32]);
        assert!(aes.limits.is_some());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn arbitrary_api_key_text_never_panics(input in any::<String>()) {
            let _ = decode_api_key(&input);
        }
    }
}
