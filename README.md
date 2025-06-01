# `client-ip`

[![License](https://img.shields.io/crates/l/client-ip.svg)](https://choosealicense.com/licenses/mit/)
[![Crates.io](https://img.shields.io/crates/v/client-ip.svg)](https://crates.io/crates/client-ip)
[![Docs.rs](https://docs.rs/client-ip/badge.svg)](https://docs.rs/client-ip)

Secure extraction of a client IP from [http::HeaderMap]. The code was initially
extracted from the [axum-client-ip] crate for non-axum use.

If you're maintaining client IP extraction in other frameworks based on [http],
consider using this crate, so we can handle security-sensitive code in one
place. Look at the [axum-client-ip] integration for reference.

## Supported extractors

Open an issue if there's an uncovered header or send a PR straight away.

| Extractor                     | Header Used                 | Typical Proxy / Service                                 |
| ----------------------------- | --------------------------- | ------------------------------------------------------- |
| [`cf_connecting_ip`]          | `CF-Connecting-IP`          | Cloudflare                                              |
| [`cloudfront_viewer_address`] | `CloudFront-Viewer-Address` | AWS CloudFront                                          |
| [`fly_client_ip`]             | `Fly-Client-IP`             | Fly.io                                                  |
| [`rightmost_forwarded`]       | `Forwarded`                 | Proxies supporting RFC 7239 (extracts rightmost `for=`) |
| [`rightmost_x_forwarded_for`] | `X-Forwarded-For`           | Nginx, Apache, HAProxy, CDNs, LBs                       |
| [`true_client_ip`]            | `True-Client-IP`            | Cloudflare, Akamai                                      |
| [`x_real_ip`]                 | `X-Real-Ip`                 | Nginx                                                   |

## Contributing

- please run [.pre-commit.sh] before sending a PR, it will check everything

## License

This project is licensed under the [MIT license][license].

[.pre-commit.sh]: https://github.com/imbolc/client-ip/blob/main/pre-commit.sh
[axum-client-ip]: https://github.com/imbolc/axum-client-ip
[http::HeaderMap]: https://docs.rs/http/1.3.1/http/header/struct.HeaderMap.html
[http]: https://github.com/rust-lang/rust
[license]: https://github.com/imbolc/client-ip/blob/main/LICENSE
