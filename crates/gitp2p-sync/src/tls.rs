use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gitp2p_metadata::{AppError, Result};
use gitp2p_metadata::util::create_dir_all;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub struct TlsIdentity {
    pub cert: CertificateDer<'static>,
    pub key: Vec<u8>,
}

pub fn tls_dir(home: &Path) -> PathBuf {
    home.join("tls")
}

pub fn ensure_server_identity(home: &Path) -> Result<TlsIdentity> {
    let dir = tls_dir(home);
    create_dir_all(&dir)?;
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    if cert_path.exists() && key_path.exists() {
        return Ok(TlsIdentity {
            cert: CertificateDer::from(fs::read(&cert_path)?),
            key: fs::read(&key_path)?,
        });
    }
    let cert = rcgen::generate_simple_self_signed(vec!["gitp2p.local".into()])
        .map_err(|err| AppError::new(err.to_string()))?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
    fs::write(&cert_path, &cert_der)?;
    fs::write(&key_path, &key_der)?;
    Ok(TlsIdentity {
        cert: CertificateDer::from(cert_der),
        key: key_der,
    })
}

pub fn pin_peer_cert(home: &Path, peer_id: &str, cert: &[u8]) -> Result<()> {
    let dir = tls_dir(home).join("pinned");
    create_dir_all(&dir)?;
    fs::write(dir.join(format!("{peer_id}.crt")), cert)?;
    Ok(())
}

pub fn pinned_peer_roots(home: &Path, peer_id: &str) -> Result<Option<rustls::RootCertStore>> {
    let path = tls_dir(home).join("pinned").join(format!("{peer_id}.crt"));
    if !path.exists() {
        return Ok(None);
    }
    let cert = fs::read(&path)?;
    let der = CertificateDer::from(cert);
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(der)
        .map_err(|err| AppError::new(err.to_string()))?;
    Ok(Some(roots))
}

pub fn make_server_config(identity: &TlsIdentity) -> Result<quinn::ServerConfig> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(identity.cert.as_ref().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key.clone())),
        )
        .map_err(|err| AppError::new(err.to_string()))?;
    server_crypto.alpn_protocols = vec![b"gitp2p/1".to_vec()];
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|err| AppError::new(err.to_string()))?,
    )))
}

pub fn make_client_config(home: &Path, peer_id: &str) -> Result<quinn::ClientConfig> {
    let roots = if let Some(roots) = pinned_peer_roots(home, peer_id)? {
        roots
    } else {
        let identity = ensure_server_identity(home)?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(identity.cert.as_ref().to_vec()))
            .map_err(|err| AppError::new(err.to_string()))?;
        roots
    };
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"gitp2p/1".to_vec()];
    Ok(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|err| AppError::new(err.to_string()))?,
    )))
}
