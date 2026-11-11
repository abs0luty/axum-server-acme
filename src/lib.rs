//! Automatic TLS certificates for [axum-server] through the ACME protocol.
//!
//! [`rustls-acme`] handles account registration, certificate orders, caching
//! and renewal. [`Acceptor`] plugs the result into axum-server's accept hook
//! and serves TLS-ALPN-01 validation requests on the same listener.
//!
//! TLS-ALPN-01 requires the server to be reachable on the public port 443. The
//! application must keep polling the [`AcmeState`] for certificates to be
//! acquired and renewed; polling needs a `StreamExt` implementation such as
//! `futures_util::StreamExt`.
//!
//! ```rust,no_run
//! use axum::{routing::get, Router};
//! use axum_server_acme::{caches::DirCache, Acceptor, AcmeConfig};
//! use futures_util::StreamExt;
//!
//! # async fn run() -> std::io::Result<()> {
//! let mut state = AcmeConfig::new(["example.com"])
//!     .contact(["mailto:admin@example.com"])
//!     .cache(DirCache::new("./acme-cache"))
//!     .directory_lets_encrypt(true)
//!     .state();
//!
//! let acceptor = Acceptor::new(&state);
//!
//! // Without this loop certificates are never acquired or renewed.
//! tokio::spawn(async move {
//!     while let Some(event) = state.next().await {
//!         if let Err(error) = event {
//!             eprintln!("acme: {error:?}");
//!         }
//!     }
//! });
//!
//! let app = Router::new().route("/", get(|| async { "Hello, world!" }));
//!
//! axum_server::bind(std::net::SocketAddr::from(([0, 0, 0, 0], 443)))
//!     .acceptor(acceptor)
//!     .serve(app.into_make_service())
//!     .await
//! # }
//! ```
//!
//! `ZeroSSL` requires external account binding, which `rustls-acme` does not
//! support. This crate works with Let's Encrypt and other ACME CAs that do not
//! require it.
//!
//! [axum-server]: https://crates.io/crates/axum-server
//! [`rustls-acme`]: https://crates.io/crates/rustls-acme

use axum_server::{accept::Accept, tls::TlsInfo};
use http::Request;
use hyper::body::Incoming;
use rustls::ServerConfig;
use std::{fmt, future::Future, io, pin::Pin, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::{timeout_at, Instant},
};
use tokio_rustls::{server::TlsStream, LazyConfigAcceptor};
use tower_service::Service;

pub use rustls_acme::{caches, AcmeConfig, AcmeState};

const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// An acceptor that serves the certificates acquired by an [`AcmeState`].
///
/// Create it with [`Acceptor::new`] and pass it to
/// [`Server::acceptor`](axum_server::Server::acceptor). The application must
/// keep polling the `AcmeState`; see the [crate documentation](crate).
#[derive(Clone)]
pub struct Acceptor {
    normal: Arc<ServerConfig>,
    challenge: Arc<ServerConfig>,
    handshake_timeout: Duration,
}

impl Acceptor {
    /// Create an acceptor for the certificates acquired by `state`.
    ///
    /// Normal connections use the `h2` and `http/1.1` ALPN protocols.
    /// TLS-ALPN-01 challenge connections are accepted and closed after the
    /// handshake.
    pub fn new<EC, EA>(state: &AcmeState<EC, EA>) -> Self
    where
        EC: fmt::Debug + 'static,
        EA: fmt::Debug + 'static,
    {
        let mut normal = (*state.default_rustls_config()).clone();
        normal.alpn_protocols = ALPN_PROTOCOLS
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();

        Self {
            normal: Arc::new(normal),
            challenge: state.challenge_rustls_config(),
            handshake_timeout: Duration::from_secs(10),
        }
    }

    /// Override the default TLS handshake timeout of 10 seconds.
    pub fn handshake_timeout(mut self, val: Duration) -> Self {
        self.handshake_timeout = val;
        self
    }

    #[cfg(test)]
    fn from_configs(normal: Arc<ServerConfig>, challenge: Arc<ServerConfig>) -> Self {
        Self {
            normal,
            challenge,
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

impl fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Acceptor")
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

impl<I, S> Accept<I, S> for Acceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = TlsInfoService<S>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let normal = self.normal.clone();
        let challenge = self.challenge.clone();
        let handshake_timeout = self.handshake_timeout;

        Box::pin(async move {
            // One deadline covers reading the ClientHello and the handshake.
            let deadline = Instant::now() + handshake_timeout;

            let start = timeout_at(
                deadline,
                LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream),
            )
            .await
            .map_err(|_| timeout_error())??;

            let is_challenge = rustls_acme::is_tls_alpn_challenge(&start.client_hello());
            let config = if is_challenge { challenge } else { normal };

            let stream = timeout_at(deadline, start.into_stream(config))
                .await
                .map_err(|_| timeout_error())??;

            if is_challenge {
                return Err(io::Error::other("TLS-ALPN-01 validation request"));
            }

            let info = tls_info(&stream);

            Ok((stream, TlsInfoService::new(service, info)))
        })
    }
}

fn timeout_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "tls handshake timed out")
}

fn tls_info<I>(stream: &TlsStream<I>) -> TlsInfo {
    let (_, connection) = stream.get_ref();

    // `TlsInfo` is `non_exhaustive`, so start from `Default` and fill the fields.
    let mut info = TlsInfo::default();
    info.server_name = connection.server_name().map(str::to_owned);
    info.alpn_protocol = connection.alpn_protocol().map(<[u8]>::to_vec);
    info.peer_certificates = connection
        .peer_certificates()
        .map(|certs| certs.iter().map(|cert| cert.as_ref().to_vec()).collect())
        .unwrap_or_default();
    info
}

/// A service that adds `Arc<TlsInfo>` to the extensions of every request.
#[derive(Clone)]
pub struct TlsInfoService<S> {
    inner: S,
    info: Arc<TlsInfo>,
}

impl<S> TlsInfoService<S> {
    fn new(inner: S, info: TlsInfo) -> Self {
        Self {
            inner,
            info: Arc::new(info),
        }
    }
}

impl<S> fmt::Debug for TlsInfoService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsInfoService")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl<S> Service<Request<Incoming>> for TlsInfoService<S>
where
    S: Service<Request<Incoming>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Incoming>) -> Self::Future {
        req.extensions_mut().insert(self.info.clone());

        self.inner.call(req)
    }
}

#[cfg(test)]
mod tests {
    use super::{Acceptor, AcmeConfig};
    use axum::{routing::get, Extension, Router};
    use axum_server::{accept::Accept, tls::TlsInfo, tls_rustls::RustlsConfig, Handle, Server};
    use http_body_util::BodyExt;
    use hyper_util::rt::TokioIo;
    use rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        ClientConfig, DigitallySignedStruct, SignatureScheme,
    };
    use std::{sync::Arc, time::Duration};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    async fn acceptor_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ServerConfig>) {
        let normal = RustlsConfig::from_pem_file(
            "test-certs/localhost-cert.pem",
            "test-certs/localhost-key.pem",
        )
        .await
        .unwrap()
        .get_inner();

        let mut challenge = (*normal).clone();
        challenge.alpn_protocols = vec![b"acme-tls/1".to_vec()];

        (normal, Arc::new(challenge))
    }

    fn tls_connector(alpn: Vec<Vec<u8>>) -> TlsConnector {
        #[derive(Debug)]
        struct NoVerify;

        impl ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer,
                _intermediates: &[CertificateDer],
                _server_name: &ServerName,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
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
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                ]
            }
        }

        let mut config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
        config.alpn_protocols = alpn;

        TlsConnector::from(Arc::new(config))
    }

    fn dns_name() -> ServerName<'static> {
        ServerName::try_from("localhost").unwrap()
    }

    #[tokio::test]
    async fn builds_expected_alpn_configs() {
        let state = AcmeConfig::new(["example.com"]).state();
        let acceptor = Acceptor::new(&state);

        assert_eq!(
            acceptor.normal.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(
            acceptor.challenge.alpn_protocols,
            vec![b"acme-tls/1".to_vec()]
        );
    }

    #[tokio::test]
    async fn serves_normal_connections() {
        let (normal, challenge) = acceptor_configs().await;
        let acceptor = Acceptor::from_configs(normal, challenge);

        let (client_io, server_io) = tokio::io::duplex(4096);
        let server = acceptor.accept(server_io, ());
        let client = tls_connector(vec![b"h2".to_vec()]).connect(dns_name(), client_io);

        let (server_result, client_result) = tokio::join!(server, client);
        let (server_stream, _service) = server_result.unwrap();
        let client_stream = client_result.unwrap();

        assert_eq!(server_stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        assert_eq!(client_stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    }

    #[tokio::test]
    async fn closes_challenge_connections_after_handshake() {
        let (normal, challenge) = acceptor_configs().await;
        let acceptor = Acceptor::from_configs(normal, challenge);

        let (client_io, server_io) = tokio::io::duplex(4096);
        let server = acceptor.accept(server_io, ());
        let client = tls_connector(vec![b"acme-tls/1".to_vec()]).connect(dns_name(), client_io);

        let (server_result, client_result) = tokio::join!(server, client);

        client_result.expect("the TLS-ALPN-01 handshake should complete");
        let error = server_result.unwrap_err();
        assert_eq!(error.to_string(), "TLS-ALPN-01 validation request");
    }

    #[tokio::test]
    async fn times_out_without_client_hello() {
        let (normal, challenge) = acceptor_configs().await;
        let acceptor =
            Acceptor::from_configs(normal, challenge).handshake_timeout(Duration::from_millis(50));

        let (_client_io, server_io) = tokio::io::duplex(4096);
        let error = acceptor.accept(server_io, ()).await.unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn tls_info_is_available_to_handlers() {
        let (normal, challenge) = acceptor_configs().await;
        let acceptor = Acceptor::from_configs(normal, challenge);

        let app = Router::new().route(
            "/",
            get(|Extension(info): Extension<Arc<TlsInfo>>| async move {
                info.server_name.clone().unwrap_or_default()
            }),
        );

        let handle = Handle::new();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move {
            Server::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
                .handle(server_handle)
                .acceptor(acceptor)
                .serve(app.into_make_service())
                .await
        });
        let addr = handle.listening().await.unwrap();

        let stream = TcpStream::connect(addr).await.unwrap();
        let stream = tls_connector(vec![b"http/1.1".to_vec()])
            .connect(dns_name(), stream)
            .await
            .unwrap();

        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let response = sender
            .send_request(http::Request::new(axum::body::Body::empty()))
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"localhost");

        handle.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(1), server).await;
    }
}
