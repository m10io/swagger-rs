//! Utility methods for instantiating common connectors for clients.
extern crate hyper_tls;
extern crate native_tls;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use hyper;

/// Returns a function which creates an http-connector. Used for instantiating
/// clients with custom connectors
pub fn http_connector() -> Box<Fn() -> hyper::client::HttpConnector + Send + Sync> {
    Box::new(move || hyper::client::HttpConnector::new(4))
}

/// Returns a function which creates an https-connector
///
/// # Arguments
///
/// * `ca_certificate` - Path to CA certificate used to authenticate the server
pub fn https_connector<CA>(
    ca_certificate: CA,
) -> Box<Fn() -> hyper_tls::HttpsConnector<hyper::client::HttpConnector> + Send + Sync>
where
    CA: AsRef<Path>,
{
    let ca_certificate = ca_certificate.as_ref().to_owned();
    Box::new(move || {
        let mut builder = native_tls::TlsConnector::builder();

        // Server authentication
        let mut cert_bytes = Vec::new();
        File::open(&ca_certificate)
            .unwrap()
            .read_to_end(&mut cert_bytes)
            .unwrap();
        let cert = native_tls::Certificate::from_pem(&cert_bytes).unwrap();
        builder.add_root_certificate(cert);

        let mut connector = hyper::client::HttpConnector::new(4);
        connector.enforce_http(false);
        let connector: hyper_tls::HttpsConnector<hyper::client::HttpConnector> =
            (connector, builder.build().unwrap()).into();
        connector
    })
}

/// Returns a function which creates https-connectors for mutually authenticated connections.
/// # Arguments
///
/// * `ca_certificate` - Path to CA certificate used to authenticate the server
/// * `client_key` - Path to the DER-formatted PKCS #12 archive containing the client private key
/// * `client_password` - Password for decrypting the client private key
pub fn https_mutual_connector<CA, K, P>(
    ca_certificate: CA,
    client_key: K,
    client_password: P,
) -> Box<Fn() -> hyper_tls::HttpsConnector<hyper::client::HttpConnector> + Send + Sync>
where
    CA: AsRef<Path>,
    K: AsRef<Path>,
    P: AsRef<str>,
{
    let ca_certificate = ca_certificate.as_ref().to_owned();
    let client_key = client_key.as_ref().to_owned();
    let client_password = client_password.as_ref().to_owned();
    Box::new(move || {
        let mut builder = native_tls::TlsConnector::builder();

        // Server authentication
        let mut cert_bytes = Vec::new();
        File::open(&ca_certificate)
            .unwrap()
            .read_to_end(&mut cert_bytes)
            .unwrap();
        let cert = native_tls::Certificate::from_pem(&cert_bytes).unwrap();
        builder.add_root_certificate(cert);

        // Client authentication
        let mut key_bytes = Vec::new();
        File::open(&client_key)
            .unwrap()
            .read_to_end(&mut key_bytes)
            .unwrap();
        let identity = native_tls::Identity::from_pkcs12(&key_bytes, &client_password).unwrap();
        builder.identity(identity);

        let mut connector = hyper::client::HttpConnector::new(4);
        connector.enforce_http(false);
        let connector: hyper_tls::HttpsConnector<hyper::client::HttpConnector> =
            (connector, builder.build().unwrap()).into();
        connector
    })
}
