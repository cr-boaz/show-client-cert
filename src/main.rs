use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::CertificateDer;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::DigitallySignedStruct;
use rustls::{DistinguishedName, ServerConfig, SignatureScheme};
use sha1::{Digest, Sha1};
use std::fs;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::{rustls, TlsAcceptor};
use x509_parser::prelude::*;

fn get_algorithm_name(oid: &str) -> String {
    match oid {
        // RSA algorithms
        "1.2.840.113549.1.1.1" => "RSA".to_string(),
        "1.2.840.113549.1.1.2" => "MD2 with RSA".to_string(),
        "1.2.840.113549.1.1.4" => "MD5 with RSA".to_string(),
        "1.2.840.113549.1.1.5" => "SHA-1 with RSA".to_string(),
        "1.2.840.113549.1.1.11" => "SHA-256 with RSA".to_string(),
        "1.2.840.113549.1.1.12" => "SHA-384 with RSA".to_string(),
        "1.2.840.113549.1.1.13" => "SHA-512 with RSA".to_string(),
        "1.2.840.113549.1.1.14" => "SHA-224 with RSA".to_string(),
        
        // RSA-PSS
        "1.2.840.113549.1.1.10" => "RSA-PSS".to_string(),
        
        // ECDSA algorithms
        "1.2.840.10045.4.1" => "ECDSA with SHA-1".to_string(),
        "1.2.840.10045.4.3.1" => "ECDSA with SHA-224".to_string(),
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256".to_string(),
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384".to_string(),
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512".to_string(),
        
        // DSA algorithms
        "1.2.840.10040.4.1" => "DSA".to_string(),
        "1.2.840.10040.4.3" => "DSA with SHA-1".to_string(),
        "2.16.840.1.101.3.4.3.1" => "DSA with SHA-224".to_string(),
        "2.16.840.1.101.3.4.3.2" => "DSA with SHA-256".to_string(),
        
        // EdDSA algorithms
        "1.3.101.112" => "Ed25519".to_string(),
        "1.3.101.113" => "Ed448".to_string(),
        
        // Hash algorithms
        "1.3.14.3.2.26" => "SHA-1".to_string(),
        "2.16.840.1.101.3.4.2.1" => "SHA-256".to_string(),
        "2.16.840.1.101.3.4.2.2" => "SHA-384".to_string(),
        "2.16.840.1.101.3.4.2.3" => "SHA-512".to_string(),
        "2.16.840.1.101.3.4.2.4" => "SHA-224".to_string(),
        
        // Other common algorithms
        "1.2.840.113549.2.5" => "MD5".to_string(),
        "1.2.840.113549.2.2" => "MD2".to_string(),
        
        // If not found, return the OID with a note
        _ => format!("{} (Unknown OID)", oid),
    }
}

#[derive(Clone)]
struct ClientCertInfo {
    common_name: Option<String>,
    subject_alt_names: Vec<String>,
    issuer: String,
    subject_key_id: Option<String>,
    thumbprint: String,
    signature_algorithm: String,
}

fn extract_cert_info(cert_der: &[u8]) -> Result<ClientCertInfo, Box<dyn std::error::Error>> {
    let (_, cert) = X509Certificate::from_der(cert_der)?;
    
    let common_name = cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());
    
    let mut subject_alt_names = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => subject_alt_names.push(format!("DNS:{}", dns)),
                GeneralName::IPAddress(ip) => {
                    let ip_str = match ip.len() {
                        4 => format!("IP:{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                        16 => {
                            let parts: Vec<String> = ip.chunks(2)
                                .map(|chunk| format!("{:02x}{:02x}", chunk[0], chunk.get(1).unwrap_or(&0)))
                                .collect();
                            format!("IP:{}", parts.join(":"))
                        },
                        _ => format!("IP:{}", hex::encode(ip)),
                    };
                    subject_alt_names.push(ip_str);
                },
                GeneralName::RFC822Name(email) => subject_alt_names.push(format!("EMAIL:{}", email)),
                _ => {}
            }
        }
    }
    
    let issuer = cert.issuer().to_string();
    
    let subject_key_id = cert.extensions()
        .iter()
        .find_map(|ext| {
            if let ParsedExtension::SubjectKeyIdentifier(ski) = ext.parsed_extension() {
                Some(hex::encode(ski.0))
            } else {
                None
            }
        });
    
    let mut hasher = Sha1::new();
    hasher.update(cert_der);
    let thumbprint = hex::encode(hasher.finalize());
    
    let signature_algorithm = get_algorithm_name(&cert.signature_algorithm.algorithm.to_string());
    
    Ok(ClientCertInfo {
        common_name,
        subject_alt_names,
        issuer,
        subject_key_id,
        thumbprint,
        signature_algorithm,
    })
}

#[derive(Debug, Clone)]
struct AllowAllClientCertVerifier;

impl ClientCertVerifier for AllowAllClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    cert_info: Option<ClientCertInfo>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() != Method::GET {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::from("Method not allowed")))
            .unwrap());
    }

    let response_body = if let Some(cert) = cert_info {
        format!(
            "Client Certificate Found!\n\nCommon Name: {}\nSubject Alternative Names: {}\nIssuer: {}\nSubject Key ID: {}\nThumbprint: {}\nSignature Algorithm: {}",
            cert.common_name.unwrap_or_else(|| "Not specified".to_string()),
            if cert.subject_alt_names.is_empty() { 
                "None".to_string() 
            } else { 
                cert.subject_alt_names.join(", ") 
            },
            cert.issuer,
            cert.subject_key_id.unwrap_or_else(|| "Not specified".to_string()),
            cert.thumbprint,
            cert.signature_algorithm
        )
    } else {
        "No client certificate found.".to_string()
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(response_body)))
        .unwrap())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider().install_default()
        .or(Err("initialization failed"))?;

    let addr: SocketAddr = "127.0.0.1:8443".parse()?;
    
    let cert_file = fs::File::open("server.crt")?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()?;
    
    let key_file = fs::File::open("server.key")?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or("No private key found")?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AllowAllClientCertVerifier))
        .with_single_cert(certs, key)?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(&addr).await?;

    println!("TLS server listening on https://{}", addr);
    println!("Server expects server.crt and server.key files in the current directory");

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(tls_stream) => tls_stream,
                Err(e) => {
                    eprintln!("TLS handshake failed: {}", e);
                    return;
                }
            };

            let cert_info = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|cert| extract_cert_info(cert.as_ref()).ok());

            let service = service_fn(move |req| {
                let cert_info = cert_info.clone();
                async move { handle_request(req, cert_info).await }
            });

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls_stream), service)
                .await
            {
                eprintln!("Error serving connection: {}", e);
            }
        });
    }
}
