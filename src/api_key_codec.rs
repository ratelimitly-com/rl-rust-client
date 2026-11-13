use std::convert::TryInto;

const GEN: [u32; 5] = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3];
#[cfg(test)]
const FORMAT_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApiKeyLimits {
    pub rate_buckets_max: u32,
    pub latency_services_max: u32,
    pub metrics_labels_max: u32,
    pub latency_buffer_size_max: u32,
    pub dedup_ttl_ms_max: u32,
    pub rate_window_size_ms_max: u64,
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
    if payload[0] == 2 && window_exp == 0 {
        return Err(DecodeError::InvalidPackedQuota);
    }
    const V2_WINDOWS: [u64; 31] = [
        0,
        1000,
        5000,
        10000,
        15000,
        30000,
        60000,
        120000,
        180000,
        300000,
        600000,
        900000,
        1800000,
        2700000,
        3600000,
        7200000,
        10800000,
        18000000,
        21600000,
        28800000,
        43200000,
        86400000,
        172800000,
        432000000,
        604800000,
        1209600000,
        2419200000,
        2592000000,
        7776000000,
        15724800000,
        31536000000,
    ];
    Ok(ApiKeyLimits {
        rate_buckets_max: 1 << rate_exp,
        latency_services_max: 1 << latency_exp,
        metrics_labels_max: 1 << labels_exp,
        latency_buffer_size_max: 1 << buffer_exp,
        dedup_ttl_ms_max: dedup_units * 10,
        rate_window_size_ms_max: if payload[0] == 2 {
            if window_exp == 31 {
                u64::MAX
            } else {
                V2_WINDOWS[window_exp as usize]
            }
        } else if window_exp == 31 {
            u32::MAX as u64
        } else {
            1u64 << window_exp
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
            if !matches!(payload[0], 1 | 2) {
                return Err(DecodeError::UnsupportedFormatVersion(payload[0]));
            }
            let key_id = u64::from_le_bytes(payload[1..9].try_into().unwrap());
            Ok(DecodedApiKey {
                hrp,
                auth_method: "none".to_string(),
                format_version: payload[0],
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
            if !matches!(payload[0], 1 | 2) {
                return Err(DecodeError::UnsupportedFormatVersion(payload[0]));
            }
            let key_id = u64::from_le_bytes(payload[1..9].try_into().unwrap());
            let auth_secret = payload[9..41].to_vec();
            Ok(DecodedApiKey {
                hrp,
                auth_method,
                format_version: payload[0],
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
        assert_eq!(limits.rate_window_size_ms_max, u32::MAX as u64);
    }

    #[test]
    fn rejects_unknown_versions_legacy_lengths_and_invalid_quota_codes() {
        for invalid in [
            "rl-aes1qqpqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqghjmuhccp9vn9",
            "rl-aes1qvpqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqghjmuhccu6xy2",
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
        let window_exp = if limits.rate_window_size_ms_max == u32::MAX as u64 {
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
            rate_window_size_ms_max: u32::MAX as u64,
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

#[cfg(test)]
mod v2_shared {
    use super::*;
    #[test]
    fn shared_caps() {
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8eqss80gln").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 1000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8epq2mg2px").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 5000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8epsl6qj54").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 10000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8ezqm4eduv").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 15000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8ezsw534fl").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 30000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8erq5gkhh2").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 60000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8erspf70ze").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 120000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8eyqsfjr0c").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 180000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8eys9g6m6t").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 300000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8e9ql5aey7").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 600000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8e9s244p3d").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 900000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8exqw6v7e5").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 1800000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8exsmmyxv8").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 2700000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8e8qp8ryjj").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 3600000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8e8s5xtu8p").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 7200000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8egqxcylqe").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 10800000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8egsnev842").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 18000000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8efqf9t9tl").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 21600000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8efsuyra7v").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 28800000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8e2qct6zk4").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 43200000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8e2sd2j6rx").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 86400000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8etqhk4can").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 172800000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8etszhaqgq").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 432000000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8evqnh3v9p").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 604800000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8evsxke5sj").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 1209600000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8edqu27kw8").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 2419200000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8edsftkwm5").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 2592000000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8ewqdy03nd").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 7776000000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8ewsc98fx7").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 15724800000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8e0qzeqtct").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 31536000000u64);
        let d = decode_api_key("rl-none1qgyqwps9qspsyq2sk8e0shcgndc").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(
            d.limits.unwrap().rate_window_size_ms_max,
            18446744073709551615u64
        );
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrusg08tcva").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 1000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrussyj8v8n").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 5000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrusc6xrqew").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 10000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3q7wqwex").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 15000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3gq6yz8m").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 30000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3st0gkv4").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 60000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3c4mv6jg").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 120000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrujq0q3fyv").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 180000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrujg354963").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 300000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrujs6pe33l").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 600000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrujcy4aa0z").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 900000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrunqqa7n02").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 1800000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrung7f6l3h").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 2700000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruns4ukt6e").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 3600000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrunctgj8yy").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 7200000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru5qyu68hc").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 10800000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru5g6g7tf9").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 18000000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru5s3ajlzt").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 21600000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru5c0fknuk").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 28800000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru4qtp4au7").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 43200000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru4g4433zr").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 86400000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru4s7qa9fd").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 172800000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru4cq5efhs").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 432000000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrukq60y6p5").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 604800000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrukgymqklf").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 1209600000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruks0wvz58").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 2419200000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrukc36gw26").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 2592000000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruhq4jtq2j").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 7776000000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruhgtx0v50").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 15724800000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruhsqnrclp").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 31536000000u64);
        let d=decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruhc7885pu").unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(
            d.limits.unwrap().rate_window_size_ms_max,
            18446744073709551615u64
        );
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrusgl8u0g8",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 1000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruss5jsmrf",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 5000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrusc2x5ha5",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 10000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3qwwheau",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 15000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3gs6n4rp",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 30000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3sm0lpg0",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 60000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3c9mmdkj",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 120000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrujqlqx7qk",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 180000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrujgp5zj7t",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 300000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrujs2pwx49",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 600000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrujc5422tc",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 900000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrunqsafyts",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 1800000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrungwfdg4d",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 2700000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruns9upu7r",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 3600000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruncmg9sq7",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 7200000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru5q5udsnz",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 10800000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru5g2gfudl",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 18000000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru5spa9gx3",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 21600000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru5clfpycv",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 28800000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru4qmpz2cy",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 43200000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru4g94xxxe",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 86400000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru4swq2jdh",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 172800000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru4cs5w7n2",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 432000000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrukq20nd9w",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 604800000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrukg5mhpmn",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 1209600000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrukslwm4sa",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 2419200000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrukcp6lewq",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 2592000000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruhq9juhwg",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 7776000000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruhgmxcms4",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 15724800000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruhssn50mm",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(d.limits.unwrap().rate_window_size_ms_max, 31536000000u64);
        let d = decode_api_key(
            "rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruhcw8sr9x",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(
            d.limits.unwrap().rate_window_size_ms_max,
            18446744073709551615u64
        );
        let d = decode_api_key(
            "rl-aes1qgpqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqghjmuhcchgqf0",
        )
        .unwrap();
        assert_eq!(d.format_version, 2);
        assert_eq!(
            d.limits.unwrap().rate_window_size_ms_max,
            18446744073709551615u64
        );
        assert!(decode_api_key("rl-none1qgyqwps9qspsyq2sk8eqq9x8s2q").is_err());
        assert!(decode_api_key("rl-none1qvyqwps9qspsyq2sk8erq7u3ws4").is_err());
        assert!(decode_api_key("rl-none1qgyqwps9qspsyq2ek8erq3lmvjl").is_err());
        assert!(decode_api_key("rl-none1qgyqwps9qspsyqfsk0erqrmw3u8").is_err());
        assert!(decode_api_key("rl-none1qgyqwps9qspsyq2skyprqh9za64").is_err());
        assert!(decode_api_key("rl-none1qgyqwps9qspsyq2sk99rvlllrly").is_err());
        assert!(decode_api_key("rl-none1qgyqwps9qspsyq2sk8eq3d3mar").is_err());
        assert!(decode_api_key("rl-none1qgyqwps9qspsyq2sk8erqqqmeq20l").is_err());
        assert!(decode_api_key("rl-none1qgyqwps9qspsyq2sk8erq5gkhhq").is_err());
        assert!(decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrusq3n05jq").is_err());
        assert!(decode_api_key("rl-cookie1qvyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3sty6sps").is_err());
        assert!(decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ravmru3sgxrplk").is_err());
        assert!(decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ruct8u3s9k5m8u").is_err());
        assert!(decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtzq3stj50gt").is_err());
        assert!(decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtzj3k6scugj").is_err());
        assert!(decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrus3eynem").is_err());
        assert!(decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3sqq9tdqg2").is_err());
        assert!(decode_api_key("rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3st0gkvq").is_err());
        assert!(decode_api_key("rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrusqpncrk6").is_err());
        assert!(decode_api_key("rl-aes1qvyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3smyd892").is_err());
        assert!(decode_api_key("rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ravmru3scx5kmv").is_err());
        assert!(decode_api_key("rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ruct8u3s4krvrx").is_err());
        assert!(decode_api_key("rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtzq3smjrcv3").is_err());
        assert!(decode_api_key("rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtzj3k2s0tvg").is_err());
        assert!(decode_api_key("rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtrus4xwxgs").is_err());
        assert!(decode_api_key("rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3sqq5f0yu3").is_err());
        assert!(decode_api_key("rl-aes1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtru3sm0lpgq").is_err());
    }
}
