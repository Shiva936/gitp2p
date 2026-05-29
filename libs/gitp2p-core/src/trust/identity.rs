use std::fs;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use crate::{AppError, Identity, Result};
use crate::{field, optional_field, read_kv, write_kv};
use crate::metadata::util::{hostname, stable_id, timestamp};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

pub fn fingerprint_for_public_key(public_key_b64: &str) -> Result<String> {
    let bytes = BASE64
        .decode(public_key_b64)
        .map_err(|err| AppError::new(format!("invalid public key encoding: {err}")))?;
    let digest = Sha256::digest(bytes);
    Ok(digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

pub fn ensure_identity(path: &Path) -> Result<Identity> {
    if path.exists() {
        return load_identity(path);
    }
    create_identity(path)
}

pub fn load_identity(path: &Path) -> Result<Identity> {
    let map = read_kv(path)?;
    let public_key = field(&map, "public_key")?;
    if public_key.starts_with("local-ed25519-placeholder-") {
        return migrate_placeholder_identity(path, &map);
    }
    Ok(Identity {
        peer_id: field(&map, "peer_id")?,
        public_key: public_key.clone(),
        private_key: field(&map, "private_key")?,
        fingerprint: {
            let fp = optional_field(&map, "fingerprint");
            if fp.is_empty() {
                fingerprint_for_public_key(&public_key)?
            } else {
                fp
            }
        },
        created_at: field(&map, "created_at")?,
    })
}

fn migrate_placeholder_identity(
    path: &Path,
    map: &std::collections::BTreeMap<String, String>,
) -> Result<Identity> {
    if path.exists() {
        let backup = path.with_extension("identity.bak");
        fs::copy(path, &backup)?;
    }
    let peer_id = field(map, "peer_id")?;
    let created_at = optional_field(map, "created_at");
    let created_at = if created_at.is_empty() {
        timestamp()
    } else {
        created_at
    };
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = BASE64.encode(verifying_key.as_bytes());
    let private_key = BASE64.encode(signing_key.to_bytes());
    let fingerprint = fingerprint_for_public_key(&public_key)?;
    let identity = Identity {
        peer_id,
        public_key,
        private_key,
        fingerprint,
        created_at,
    };
    write_identity(path, &identity)?;
    Ok(identity)
}

pub fn create_identity(path: &Path) -> Result<Identity> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = BASE64.encode(verifying_key.as_bytes());
    let private_key = BASE64.encode(signing_key.to_bytes());
    let fingerprint = fingerprint_for_public_key(&public_key)?;
    let now = timestamp();
    let seed = format!("{}:{}", hostname(), now);
    let peer_id = format!("peer-{}", stable_id(&seed));
    let identity = Identity {
        peer_id,
        public_key,
        private_key,
        fingerprint,
        created_at: now,
    };
    write_identity(path, &identity)?;
    Ok(identity)
}

pub fn write_identity(path: &Path, identity: &Identity) -> Result<()> {
    write_kv(
        path,
        &[
            ("peer_id", &identity.peer_id),
            ("public_key", &identity.public_key),
            ("private_key", &identity.private_key),
            ("fingerprint", &identity.fingerprint),
            ("created_at", &identity.created_at),
        ],
    )
}

pub fn signing_key(identity: &Identity) -> Result<SigningKey> {
    let bytes = BASE64
        .decode(&identity.private_key)
        .map_err(|err| AppError::new(format!("invalid private key: {err}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::new("private key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn verifying_key(public_key_b64: &str) -> Result<VerifyingKey> {
    let bytes = BASE64
        .decode(public_key_b64)
        .map_err(|err| AppError::new(format!("invalid public key: {err}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::new("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|err| AppError::new(format!("invalid verifying key: {err}")))
}

pub fn validate_peer_identity(public_key: &str) -> Result<()> {
    if public_key.starts_with("local-ed25519-placeholder-") {
        return Err(AppError::new(
            "peer identity uses legacy placeholder key; upgrade peer gitp2p first",
        ));
    }
    verifying_key(public_key)?;
    Ok(())
}

pub fn sign_bytes(identity: &Identity, payload: &[u8]) -> Result<String> {
    let key = signing_key(identity)?;
    let signature = key.sign(payload);
    Ok(BASE64.encode(signature.to_bytes()))
}

pub fn verify_bytes(public_key_b64: &str, payload: &[u8], signature_b64: &str) -> Result<()> {
    let key = verifying_key(public_key_b64)?;
    let sig_bytes = BASE64
        .decode(signature_b64)
        .map_err(|err| AppError::new(format!("invalid signature encoding: {err}")))?;
    let arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| AppError::new("signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&arr);
    key.verify(payload, &signature)
        .map_err(|_| AppError::new("signature verification failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn identity_sign_verify_roundtrip() {
        let dir = env::temp_dir().join(format!("gitp2p-id-{}", stable_id("test")));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity");
        let identity = create_identity(&path).unwrap();
        let payload = b"checkpoint:test";
        let sig = sign_bytes(&identity, payload).unwrap();
        verify_bytes(&identity.public_key, payload, &sig).unwrap();
    }
}
