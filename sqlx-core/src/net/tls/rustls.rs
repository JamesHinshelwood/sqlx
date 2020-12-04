use rustls::{Certificate, ClientConfig, RootCertStore, ServerCertVerified, ServerCertVerifier, TLSError, WebPKIVerifier};
use sqlx_rt::fs;
use std::sync::Arc;
use std::{io::Cursor, path::Path};
use webpki::DNSNameRef;

use crate::error::Error;

pub async fn configure_tls_connector(
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
    root_cert_path: Option<&Path>,
    client_cert_key_path: Option<(&Path, &Path)>,
) -> Result<sqlx_rt::TlsConnector, Error> {
    let mut config = ClientConfig::new();

    if accept_invalid_certs {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(DummyTlsVerifier));
    } else {
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        if let Some(ca) = root_cert_path {
            let data = fs::read(ca).await?;
            let mut cursor = Cursor::new(data);
            config.root_store.add_pem_file(&mut cursor).map_err(|_| {
                Error::Tls(format!("Invalid certificate file: {}", ca.display()).into())
            })?;
        }

        if let Some((cert_path, key_path)) = client_cert_key_path {
            // FIXME: Using unstable internal APIs of rustls.
            use rustls::internal::pemfile;

            let cert_data = fs::read(cert_path).await?;
            let mut cert_cursor = Cursor::new(cert_data);
            let certs = pemfile::certs(&mut cert_cursor).unwrap();

            let key_data = fs::read(key_path).await?;
            let mut key_cursor = Cursor::new(key_data);
            let key = pemfile::rsa_private_keys(&mut key_cursor).unwrap().pop().expect("empty keys");
            config.set_single_client_cert(certs, key)
                .map_err(|_| {
                    Error::Tls(format!("Invalid client certificate or key file: {}, {}", cert_path.display(), key_path.display()).into())
                })?;
        }

        if accept_invalid_hostnames {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoHostnameTlsVerifier));
        }
    }

    Ok(Arc::new(config).into())
}

struct DummyTlsVerifier;

impl ServerCertVerifier for DummyTlsVerifier {
    fn verify_server_cert(
        &self,
        _roots: &RootCertStore,
        _presented_certs: &[Certificate],
        _dns_name: DNSNameRef<'_>,
        _ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }
}

pub struct NoHostnameTlsVerifier;

impl ServerCertVerifier for NoHostnameTlsVerifier {
    fn verify_server_cert(
        &self,
        roots: &RootCertStore,
        presented_certs: &[Certificate],
        dns_name: DNSNameRef<'_>,
        ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        let verifier = WebPKIVerifier::new();
        match verifier.verify_server_cert(roots, presented_certs, dns_name, ocsp_response) {
            Err(TLSError::WebPKIError(webpki::Error::CertNotValidForName)) => {
                Ok(ServerCertVerified::assertion())
            }
            res => res,
        }
    }
}
