// Wire protocol helpers for the r-client.
// Spec references: rl/docs/spec/wire_protocol.md and rl/docs/spec/r-client.md.
use aes_gcm::KeyInit;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or Aes128Gcm if you use 128-bit keys
use blake2::{Blake2s256, Digest};
use rand::RngExt;

const RESOURCE_ID_DOMAIN: &[u8] = b"ratelimitly.resource.v1\0";
const LATENCY_TRACKER_ID_DOMAIN: &[u8] = b"ratelimitly.latency-tracker.v1\0";

fn derive_content_id(domain: &[u8], name: &[u8], fields: &[u32]) -> [u8; 16] {
    let name_len = u32::try_from(name.len()).expect("identifier name exceeds the u32 wire limit");
    let mut hasher = Blake2s256::new();
    hasher.update(domain);
    hasher.update(name_len.to_le_bytes());
    hasher.update(name);
    for field in fields {
        hasher.update(field.to_le_bytes());
    }
    let result = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&result[..16]);
    id
}

/// Derives the canonical 16-byte bucket ID from raw name bytes.
pub fn derive_bucket_id_bytes(
    bucket_name: &[u8],
    window_size_ms: u32,
    rate_limit: u32,
) -> [u8; 16] {
    derive_content_id(
        RESOURCE_ID_DOMAIN,
        bucket_name,
        &[window_size_ms, rate_limit],
    )
}

/// Derives the canonical 16-byte bucket ID from a UTF-8 string name.
pub fn derive_bucket_id(bucket_name: &str, window_size_ms: u32, rate_limit: u32) -> [u8; 16] {
    derive_bucket_id_bytes(bucket_name.as_bytes(), window_size_ms, rate_limit)
}

/// Derives the canonical 16-byte latency-tracker ID from raw name bytes.
pub fn derive_latency_tracker_id_bytes(
    latency_tracker_name: &[u8],
    ttl_ms: u32,
    max_samples: u32,
    min_sample_threshold: u32,
) -> [u8; 16] {
    derive_content_id(
        LATENCY_TRACKER_ID_DOMAIN,
        latency_tracker_name,
        &[ttl_ms, max_samples, min_sample_threshold],
    )
}

/// Derives the canonical 16-byte latency-tracker ID from a UTF-8 string name.
pub fn derive_latency_tracker_id(
    latency_tracker_name: &str,
    ttl_ms: u32,
    max_samples: u32,
    min_sample_threshold: u32,
) -> [u8; 16] {
    derive_latency_tracker_id_bytes(
        latency_tracker_name.as_bytes(),
        ttl_ms,
        max_samples,
        min_sample_threshold,
    )
}

#[cfg(test)]
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

// Spec: r-client.md §4.3 (AES-256-GCM).
pub fn encrypt_pdu(pdu: &[u8], key: &[u8; 32], aad_prefix: &[u8]) -> (Vec<u8>, [u8; 12], [u8; 16]) {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let mut nonce = [0u8; 12];
    rand::rng().fill(&mut nonce);
    let nonce_obj = Nonce::from_slice(&nonce);
    let mut aad = Vec::with_capacity(aad_prefix.len() + nonce.len());
    aad.extend_from_slice(aad_prefix);
    aad.extend_from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            nonce_obj,
            Payload {
                msg: pdu,
                aad: &aad,
            },
        )
        .expect("encryption failure!");

    let tag_offset = ciphertext.len() - 16;
    let tag_slice = &ciphertext[tag_offset..];
    let encrypted_pdu = ciphertext[..tag_offset].to_vec();

    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(tag_slice);

    (encrypted_pdu, nonce, auth_tag)
}

// Spec: r-client.md §4.3 (AES-256-GCM).
pub fn decrypt_pdu(
    encrypted_pdu: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
    auth_tag: &[u8; 16],
    aad: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce_obj = Nonce::from_slice(nonce);

    let mut ciphertext_with_tag = Vec::from(encrypted_pdu);
    ciphertext_with_tag.extend_from_slice(auth_tag);

    cipher.decrypt(
        nonce_obj,
        Payload {
            msg: ciphertext_with_tag.as_ref(),
            aad,
        },
    )
}

// Spec: wire_protocol.md §PDU Type Summary and TLV definitions.
pub const TLV_TENANT: u16 = 0x4C52;
pub const TLV_AUTH_NONE: u16 = 0x414E;
pub const TLV_AUTH_COOKIE: u16 = 0x4143;
pub const TLV_AUTH_AES: u16 = 0x4541;
pub const TLV_METRICS_LABEL: u16 = 0x4C4D;
pub const PDU_RATE_REQUEST: u16 = 0x5452;
pub const PDU_RATE_RESPONSE: u16 = 0x5252;
pub const PDU_LATENCY_REPORT: u16 = 0x524C;
pub const GUARD_BLOCK_WIRE_LEN: usize = 36;
pub const SERVICE_LATENCY_BLOCK_WIRE_LEN: usize = 32;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TenantHeader {
    // Spec: r-client.md §5.1 (Tenant Header fields, little-endian encoding).
    pub tlv_type: u16,
    pub tlv_size: u16,
    pub key_id: u64,
    pub unique_id: [u8; 16],
    pub time_stamp: u64,
    pub steering_feedback: u8,
    pub tenant_mgmt_flag: u8,
    pub padding: [u8; 2],
}

impl TenantHeader {
    // Spec: wire_protocol.md §Tenant Header TLV (little-endian fields).
    pub fn write_to_buffer(&self, buffer: &mut [u8]) {
        buffer[0..2].copy_from_slice(&self.tlv_type.to_le_bytes());
        buffer[2..4].copy_from_slice(&self.tlv_size.to_le_bytes());
        buffer[4..12].copy_from_slice(&self.key_id.to_le_bytes());
        buffer[12..28].copy_from_slice(&self.unique_id);
        buffer[28..36].copy_from_slice(&self.time_stamp.to_le_bytes());
        buffer[36] = self.steering_feedback;
        buffer[37] = self.tenant_mgmt_flag;
        buffer[38..40].copy_from_slice(&self.padding);
    }

    // Spec: wire_protocol.md §Tenant Header TLV (little-endian fields).
    pub fn read_from_buffer(buffer: &[u8]) -> Result<Self, &'static str> {
        if buffer.len() < 40 {
            return Err("Buffer too small for TenantHeader");
        }
        let mut unique_id = [0u8; 16];
        unique_id.copy_from_slice(&buffer[12..28]);
        let mut padding = [0u8; 2];
        padding.copy_from_slice(&buffer[38..40]);

        Ok(TenantHeader {
            tlv_type: u16::from_le_bytes([buffer[0], buffer[1]]),
            tlv_size: u16::from_le_bytes([buffer[2], buffer[3]]),
            key_id: u64::from_le_bytes(buffer[4..12].try_into().unwrap()),
            unique_id,
            time_stamp: u64::from_le_bytes(buffer[28..36].try_into().unwrap()),
            steering_feedback: buffer[36],
            tenant_mgmt_flag: buffer[37],
            padding,
        })
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GuardBlock {
    // Spec: r-client.md §5.2 (Guard Block layout, 36 bytes).
    pub latency_tracker_id: [u8; 16],
    pub ttl_ms: u32,
    pub max_samples: u32,
    pub min_sample_threshold: u32,
    pub latency_threshold: u32,
    pub current_latency: u32,
}

impl GuardBlock {
    pub fn write_to_buffer(&self, buffer: &mut [u8]) {
        buffer[0..16].copy_from_slice(&self.latency_tracker_id);
        buffer[16..20].copy_from_slice(&self.ttl_ms.to_le_bytes());
        buffer[20..24].copy_from_slice(&self.max_samples.to_le_bytes());
        buffer[24..28].copy_from_slice(&self.min_sample_threshold.to_le_bytes());
        buffer[28..32].copy_from_slice(&self.latency_threshold.to_le_bytes());
        buffer[32..36].copy_from_slice(&self.current_latency.to_le_bytes());
    }

    pub fn read_from_buffer(buffer: &[u8]) -> Result<Self, &'static str> {
        if buffer.len() < GUARD_BLOCK_WIRE_LEN {
            return Err("Buffer too small for GuardBlock");
        }
        let mut latency_tracker_id = [0u8; 16];
        latency_tracker_id.copy_from_slice(&buffer[0..16]);

        Ok(GuardBlock {
            latency_tracker_id,
            ttl_ms: u32::from_le_bytes(buffer[16..20].try_into().unwrap()),
            max_samples: u32::from_le_bytes(buffer[20..24].try_into().unwrap()),
            min_sample_threshold: u32::from_le_bytes(buffer[24..28].try_into().unwrap()),
            latency_threshold: u32::from_le_bytes(buffer[28..32].try_into().unwrap()),
            current_latency: u32::from_le_bytes(buffer[32..36].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ResourceBlock {
    // Spec: r-client.md §5.3 (Resource Block layout, 28 bytes).
    pub bucket_id: [u8; 16],
    pub window_size_ms: u32,
    pub rate_limit: u32,
    pub tokens_requested: u16,
    pub padding: u16,
}

impl ResourceBlock {
    pub fn write_to_buffer(&self, buffer: &mut [u8]) {
        buffer[0..16].copy_from_slice(&self.bucket_id);
        buffer[16..20].copy_from_slice(&self.window_size_ms.to_le_bytes());
        buffer[20..24].copy_from_slice(&self.rate_limit.to_le_bytes());
        buffer[24..26].copy_from_slice(&self.tokens_requested.to_le_bytes());
        buffer[26..28].copy_from_slice(&self.padding.to_le_bytes());
    }

    pub fn read_from_buffer(buffer: &[u8]) -> Result<Self, &'static str> {
        if buffer.len() < 28 {
            return Err("Buffer too small for ResourceBlock");
        }
        let mut bucket_id = [0u8; 16];
        bucket_id.copy_from_slice(&buffer[0..16]);

        Ok(ResourceBlock {
            bucket_id,
            window_size_ms: u32::from_le_bytes(buffer[16..20].try_into().unwrap()),
            rate_limit: u32::from_le_bytes(buffer[20..24].try_into().unwrap()),
            tokens_requested: u16::from_le_bytes(buffer[24..26].try_into().unwrap()),
            padding: u16::from_le_bytes(buffer[26..28].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct ServiceLatencyBlock {
    // Spec: r-client.md §5.4 (Service Latency Block layout, 32 bytes).
    pub latency_tracker_id: [u8; 16],
    pub ttl_ms: u32,
    pub max_samples: u32,
    pub min_sample_threshold: u32,
    pub observed_latency: u32,
}

impl ServiceLatencyBlock {
    pub fn write_to_buffer(&self, buffer: &mut [u8]) {
        buffer[0..16].copy_from_slice(&self.latency_tracker_id);
        buffer[16..20].copy_from_slice(&self.ttl_ms.to_le_bytes());
        buffer[20..24].copy_from_slice(&self.max_samples.to_le_bytes());
        buffer[24..28].copy_from_slice(&self.min_sample_threshold.to_le_bytes());
        buffer[28..32].copy_from_slice(&self.observed_latency.to_le_bytes());
    }
}

// Request structures
#[derive(Debug, Clone)]
pub struct ResourceRequest {
    pub bucket_name: String,
    pub window_size_ms: u32,
    pub rate_limit: u32,
    pub tokens_requested: u16,
}

#[derive(Debug, Clone)]
pub struct LatencyGuard {
    pub latency_tracker_name: String,
    pub threshold_ms: u32,
    pub ttl_ms: u32,
    pub max_samples: u32,
    pub min_sample_threshold: u32,
}

#[derive(Debug, Clone)]
pub struct ServiceLatencyReport {
    pub latency_tracker_name: String,
    pub observed_latency: u32,
    pub ttl_ms: u32,
    pub max_samples: u32,
    pub min_sample_threshold: u32,
}

// Result structures
#[derive(Debug, Clone)]
pub struct GuardResult {
    pub latency_tracker_id: [u8; 16],
    pub threshold_ms: u32,
    pub current_latency_ms: u32,
    pub passed: bool,
}

#[derive(Debug, Clone)]
pub struct ResourceResult {
    pub bucket_id: [u8; 16],
    pub tokens_deficit: u16,
    pub actual_rate: u32,
}

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub success: bool,
    pub guard_results: Vec<GuardResult>,
    pub resource_results: Vec<ResourceResult>,
    pub server_id: u64,
    pub steering_feedback: bool,
}

#[cfg(test)]
mod id_tests {
    use super::*;

    #[test]
    fn canonical_bucket_id_vectors_match_the_protocol() {
        assert_eq!(
            bytes_to_hex(&derive_bucket_id("checkout", 1_000, 100)),
            "f5cf3ad8b8406854b596ba3614f16eff"
        );
        assert_eq!(
            bytes_to_hex(&derive_bucket_id("café", 60_000, 25)),
            "732b120606917c683e37433fa00a60dc"
        );
        assert_eq!(
            bytes_to_hex(&derive_bucket_id_bytes(
                b"binary\0bucket",
                u32::MAX,
                u32::MAX,
            )),
            "f57a48f69aa8c7a16fc73499ae8d07fa"
        );
    }

    #[test]
    fn canonical_latency_tracker_id_vectors_match_the_protocol() {
        assert_eq!(
            bytes_to_hex(&derive_latency_tracker_id(
                "inventory-backend",
                10_000,
                100,
                5,
            )),
            "04283c08fe9f735566898b6982eac6c7"
        );
        assert_eq!(
            bytes_to_hex(&derive_latency_tracker_id("café", 60_000, 200, 3)),
            "8dece110edb102594ddde5bf4805af6b"
        );
        assert_eq!(
            bytes_to_hex(&derive_latency_tracker_id_bytes(
                b"binary\0tracker",
                u32::MAX,
                u32::MAX,
                u32::MAX,
            )),
            "d7f118ffa4eebc99fdfe8b221f37a1f2"
        );
    }
}
