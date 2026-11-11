[![License](https://img.shields.io/crates/l/axum-server-acme)](https://choosealicense.com/licenses/mit/)
[![Crates.io](https://img.shields.io/crates/v/axum-server-acme)](https://crates.io/crates/axum-server-acme)
[![Docs](https://img.shields.io/crates/v/axum-server-acme?color=blue&label=docs)](https://docs.rs/axum-server-acme/)

# axum-server-acme

Automatic TLS certificates for [axum-server](https://crates.io/crates/axum-server)
through the ACME protocol, built on
[rustls-acme](https://crates.io/crates/rustls-acme).

This is a companion crate. `axum-server` intentionally leaves ACME out of its
core. This crate plugs certificate acquisition and renewal into its accept hook.

## Usage

```toml
[dependencies]
axum-server-acme = "0.1"
```

```rust,no_run
use axum::{routing::get, Router};
use axum_server_acme::{caches::DirCache, Acceptor, AcmeConfig};
use futures_util::StreamExt;

let mut state = AcmeConfig::new(["example.com"])
    .contact(["mailto:admin@example.com"])
    .cache(DirCache::new("./acme-cache"))
    .directory_lets_encrypt(true)
    .state();

let acceptor = Acceptor::new(&state);

tokio::spawn(async move {
    while let Some(event) = state.next().await {
        if let Err(error) = event {
            eprintln!("acme: {error:?}");
        }
    }
});

let app = Router::new().route("/", get(|| async { "Hello, world!" }));

axum_server::bind(std::net::SocketAddr::from(([0, 0, 0, 0], 443)))
    .acceptor(acceptor)
    .serve(app.into_make_service())
    .await?;
```

See [`examples/acme.rs`](examples/acme.rs) for the runnable version, including
the `ACME_DOMAINS` / `ACME_PRODUCTION` environment variables.

## Requirements and limitations

- TLS-ALPN-01 only: the server must be reachable on the public port 443.
- The application must keep polling the `AcmeState`; without that loop no
  certificate is acquired or renewed.
- rustls only. For the OpenSSL backend, use an external ACME client
  (certbot, lego, acme.sh) and `OpenSSLConfig::reload_from_pem_file`.
- ZeroSSL requires external account binding, which rustls-acme does not
  support. Let's Encrypt and other non-EAB ACME CAs work.

## License

MIT
