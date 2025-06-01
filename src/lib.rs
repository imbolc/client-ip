#![doc = include_str!("../README.md")]
use std::net::IpAddr;

pub use error::Error;
use http::{HeaderMap, HeaderName};

type Result<T> = std::result::Result<T, Error>;

/// Extracts client IP from `CF-Connecting-IP` (Cloudflare) header
pub fn cf_connecting_ip(header_map: &HeaderMap) -> Result<IpAddr> {
    ip_from_last_header(header_map, &HeaderName::from_static("cf-connecting-ip"))
}

/// Extracts client IP from `CloudFront-Viewer-Address` (AWS CloudFront) header
pub fn cloudfront_viewer_address(header_map: &HeaderMap) -> Result<IpAddr> {
    const HEADER_NAME: HeaderName = HeaderName::from_static("cloudfront-viewer-address");

    fn ip_from_header_value(header_value: &str) -> Result<IpAddr> {
        // Spec: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html#cloudfront-headers-viewer-location
        // Note: Both IPv4 and IPv6 addresses (in the specified format) do not contain
        //       non-ascii characters, so no need to handle percent-encoding.
        //
        // CloudFront does not use `[::]:12345` style notation for IPv6 (unfortunately),
        // otherwise parsing via `SocketAddr` would be possible.
        header_value
            .rsplit_once(':')
            .map(|(ip, _port)| ip)
            .ok_or_else(|| Error::MalformedHeaderValue {
                header_name: HEADER_NAME,
                header_value: header_value.to_owned(),
            })?
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| Error::MalformedHeaderValue {
                header_name: HEADER_NAME,
                header_value: header_value.to_owned(),
            })
    }

    let header_value = last_header_value(header_map, &HEADER_NAME)?;
    ip_from_header_value(header_value)
}

/// Extracts client IP from `Fly-Client-IP` (Fly.io) header
///
/// When the extractor is run for health check path, provide required
/// `Fly-Client-IP` header through [`services.http_checks.headers`](https://fly.io/docs/reference/configuration/#services-http_checks)
/// or [`http_service.checks.headers`](https://fly.io/docs/reference/configuration/#services-http_checks)
pub fn fly_client_ip(header_map: &HeaderMap) -> Result<IpAddr> {
    ip_from_last_header(header_map, &HeaderName::from_static("fly-client-ip"))
}

#[cfg(feature = "forwarded-header")]
/// Extracts the rightmost IP from `Forwarded` header
pub fn rightmost_forwarded(header_map: &HeaderMap) -> Result<IpAddr> {
    const HEADER_NAME: HeaderName = HeaderName::from_static("forwarded");

    fn ip_from_header_value(header_value: &str) -> Result<IpAddr> {
        use forwarded_header_value::{ForwardedHeaderValue, Identifier};

        let stanza = ForwardedHeaderValue::from_forwarded(header_value)
            .map_err(|_| Error::MalformedHeaderValue {
                header_name: HEADER_NAME,
                header_value: header_value.to_owned(),
            })?
            .into_iter()
            .last()
            .ok_or_else(|| Error::MalformedHeaderValue {
                header_name: HEADER_NAME,
                header_value: header_value.to_owned(),
            })?;

        let forwarded_for = stanza.forwarded_for.ok_or_else(|| Error::ForwardedNoFor {
            header_value: header_value.to_owned(),
        })?;

        match forwarded_for {
            Identifier::SocketAddr(a) => Ok(a.ip()),
            Identifier::IpAddr(ip) => Ok(ip),
            Identifier::String(_) => Err(Error::ForwardedObfuscated {
                header_value: header_value.to_owned(),
            }),
            Identifier::Unknown => Err(Error::ForwardedUnknown {
                header_value: header_value.to_owned(),
            }),
        }
    }

    let header_value = last_header_value(header_map, &HEADER_NAME)?;
    ip_from_header_value(header_value)
}

/// Parses the rightmost IP from `X-Forwarded-For` header
pub fn rightmost_x_forwarded_for(header_map: &HeaderMap) -> Result<IpAddr> {
    const HEADER_NAME: HeaderName = HeaderName::from_static("x-forwarded-for");

    fn ip_from_header_value(header_value: &str) -> Result<IpAddr> {
        header_value
            .split(',')
            .next_back()
            .ok_or_else(|| Error::MalformedHeaderValue {
                header_name: HEADER_NAME,
                header_value: header_value.to_owned(),
            })?
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| Error::MalformedHeaderValue {
                header_name: HEADER_NAME,
                header_value: header_value.to_owned(),
            })
    }

    let header_value = last_header_value(header_map, &HEADER_NAME)?;
    ip_from_header_value(header_value)
}

/// Extracts client IP from `True-Client-IP` (Akamai, Cloudflare) header
pub fn true_client_ip(header_map: &HeaderMap) -> Result<IpAddr> {
    ip_from_last_header(header_map, &HeaderName::from_static("true-client-ip"))
}

/// Extracts client IP from `X-Real-Ip` (Nginx) header
pub fn x_real_ip(header_map: &HeaderMap) -> Result<IpAddr> {
    ip_from_last_header(header_map, &HeaderName::from_static("x-real-ip"))
}

/// Parses IP from the last occurring header.
/// Assumes the whole header value is a valid IP.
fn ip_from_last_header(header_map: &HeaderMap, header_name: &HeaderName) -> Result<IpAddr> {
    let header_value = last_header_value(header_map, header_name)?;
    ip_from_header_value(header_name, header_value)
}

/// Returns a decoded value of the last occurring header. Can also be used
/// for a header occurring only once.
fn last_header_value<'a>(header_map: &'a HeaderMap, header_name: &HeaderName) -> Result<&'a str> {
    header_map
        .get_all(header_name)
        .into_iter()
        .next_back()
        .ok_or_else(|| Error::AbsentHeader {
            header_name: header_name.to_owned(),
        })?
        .to_str()
        .map_err(|_| Error::NonAsciiHeaderValue {
            header_name: header_name.to_owned(),
        })
}

/// Parses IP from decoded header value.
/// Assumes the whole header value is a valid IP.
fn ip_from_header_value(header_name: &HeaderName, header_value: &str) -> Result<IpAddr> {
    header_value
        .trim()
        .parse()
        .map_err(|_| Error::MalformedHeaderValue {
            header_name: header_name.to_owned(),
            header_value: header_value.to_owned(),
        })
}

mod error {
    use std::fmt;

    use http::HeaderName;

    /// The crate error
    #[derive(Debug, PartialEq)]
    pub enum Error {
        /// The IP-related header is missing
        AbsentHeader {
            /// Header name
            header_name: HeaderName,
        },
        /// Header value contains not only visible ASCII characters
        NonAsciiHeaderValue {
            /// Header name
            header_name: HeaderName,
        },
        /// Header value has an unexpected format
        MalformedHeaderValue {
            /// Header name
            header_name: HeaderName,
            /// Header value
            header_value: String,
        },
        /// Forwarded header doesn't contain `for` directive
        ForwardedNoFor {
            /// Header value
            header_value: String,
        },
        /// RFC 7239 allows to [obfuscate IPs](https://www.rfc-editor.org/rfc/rfc7239.html#section-6.3)
        ForwardedObfuscated {
            /// Header value
            header_value: String,
        },
        /// RFC 7239 allows [unknown identifiers](https://www.rfc-editor.org/rfc/rfc7239.html#section-6.2)
        ForwardedUnknown {
            /// Header value
            header_value: String,
        },
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Error::AbsentHeader { header_name } => {
                    write!(f, "Missing required header: {header_name}")
                }
                Error::NonAsciiHeaderValue { header_name } => write!(
                    f,
                    "Header value contains non-ASCII characters: {header_name}",
                ),
                Error::MalformedHeaderValue {
                    header_name,
                    header_value,
                } => write!(
                    f,
                    "Malformed header value for `{header_name}`: {header_value}",
                ),
                Error::ForwardedNoFor { header_value } => write!(
                    f,
                    "`Forwarded` header missing `for` directive: {header_value}",
                ),
                Error::ForwardedObfuscated { header_value } => write!(
                    f,
                    "`Forwarded` header contains obfuscated IP: {header_value}",
                ),
                Error::ForwardedUnknown { header_value } => write!(
                    f,
                    "`Forwarded` header contains unknown identifier: {header_value}",
                ),
            }
        }
    }

    impl std::error::Error for Error {}
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_IPV4: &str = "1.2.3.4";
    const VALID_IPV6: &str = "1:23:4567:89ab:c:d:e:f";

    fn headers<'a>(items: impl IntoIterator<Item = (&'a str, &'a str)>) -> HeaderMap {
        HeaderMap::from_iter(
            items
                .into_iter()
                .map(|(name, value)| (name.parse().unwrap(), value.parse().unwrap())),
        )
    }

    #[test]
    fn test_cf_connecting_ip() {
        let header = "cf-connecting-ip";

        assert_eq!(
            cf_connecting_ip(&headers([])).unwrap_err(),
            Error::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            cf_connecting_ip(&headers([(header, "ы")])).unwrap_err(),
            Error::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            cf_connecting_ip(&headers([(header, "foo")])).unwrap_err(),
            Error::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "foo".into(),
            }
        );

        assert_eq!(
            cf_connecting_ip(&headers([(header, VALID_IPV4)])).unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            cf_connecting_ip(&headers([(header, VALID_IPV6)])).unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_cloudfront_viewer_address() {
        let header = "cloudfront-viewer-address";

        assert_eq!(
            cloudfront_viewer_address(&headers([])).unwrap_err(),
            Error::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            cloudfront_viewer_address(&headers([(header, "ы")])).unwrap_err(),
            Error::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            cloudfront_viewer_address(&headers([(header, VALID_IPV4)])).unwrap_err(),
            Error::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: VALID_IPV4.into(),
            }
        );
        assert_eq!(
            cloudfront_viewer_address(&headers([(header, "foo:8000")])).unwrap_err(),
            Error::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "foo:8000".into(),
            }
        );

        let valid_header_value_v4 = format!("{VALID_IPV4}:8000");
        let valid_header_value_v6 = format!("{VALID_IPV6}:8000");
        assert_eq!(
            cloudfront_viewer_address(&headers([(header, valid_header_value_v4.as_ref())]))
                .unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            cloudfront_viewer_address(&headers([(header, valid_header_value_v6.as_ref())]))
                .unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_fly_client_ip() {
        let header = "fly-client-ip";

        assert_eq!(
            fly_client_ip(&headers([])).unwrap_err(),
            Error::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            fly_client_ip(&headers([(header, "ы")])).unwrap_err(),
            Error::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            fly_client_ip(&headers([(header, "foo")])).unwrap_err(),
            Error::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "foo".into(),
            }
        );

        assert_eq!(
            fly_client_ip(&headers([(header, VALID_IPV4)])).unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            fly_client_ip(&headers([(header, VALID_IPV6)])).unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );
    }

    #[cfg(feature = "forwarded-header")]
    #[test]
    fn test_rightmost_forwarded() {
        let header = "forwarded";

        assert_eq!(
            rightmost_forwarded(&headers([])).unwrap_err(),
            Error::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            rightmost_forwarded(&headers([(header, "ы")])).unwrap_err(),
            Error::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            rightmost_forwarded(&headers([(header, "foo")])).unwrap_err(),
            Error::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "foo".into(),
            }
        );
        assert_eq!(
            rightmost_forwarded(&headers([
                (header, format!("for={VALID_IPV4}").as_ref()),
                (header, "proto=http"),
            ]))
            .unwrap_err(),
            Error::ForwardedNoFor {
                header_value: "proto=http".into(),
            }
        );
        assert_eq!(
            rightmost_forwarded(&headers([(header, "for=unknown")])).unwrap_err(),
            Error::ForwardedUnknown {
                header_value: "for=unknown".into(),
            }
        );
        assert_eq!(
            rightmost_forwarded(&headers([(header, "for=_foo")])).unwrap_err(),
            Error::ForwardedObfuscated {
                header_value: "for=_foo".into(),
            }
        );

        assert_eq!(
            rightmost_forwarded(&headers([
                (header, "proto=http"),
                (header, format!("for={VALID_IPV4};proto=http").as_ref()),
            ]))
            .unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            rightmost_forwarded(&headers([(
                header,
                format!("for={VALID_IPV4}:8000").as_ref()
            ),]))
            .unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );

        assert_eq!(
            rightmost_forwarded(&headers([(header, format!("for={VALID_IPV6}").as_ref()),]))
                .unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            rightmost_forwarded(&headers([(
                header,
                format!("for=[{VALID_IPV6}]:8000").as_ref()
            ),]))
            .unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_rightmost_x_forwarded_for() {
        let header = "x-forwarded-for";

        assert_eq!(
            rightmost_x_forwarded_for(&headers([])).unwrap_err(),
            Error::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            rightmost_x_forwarded_for(&headers([(header, "ы")])).unwrap_err(),
            Error::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            rightmost_x_forwarded_for(&headers([(header, "1.2.3.4,foo")])).unwrap_err(),
            Error::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "1.2.3.4,foo".into(),
            }
        );

        assert_eq!(
            rightmost_x_forwarded_for(&headers([(header, format!("foo,{VALID_IPV4}").as_ref())]))
                .unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            rightmost_x_forwarded_for(&headers([(header, VALID_IPV6)])).unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_true_client_ip() {
        let header = "true-client-ip";

        assert_eq!(
            true_client_ip(&headers([])).unwrap_err(),
            Error::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            true_client_ip(&headers([(header, "ы")])).unwrap_err(),
            Error::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            true_client_ip(&headers([(header, "foo")])).unwrap_err(),
            Error::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "foo".into(),
            }
        );

        assert_eq!(
            true_client_ip(&headers([(header, VALID_IPV4)])).unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            true_client_ip(&headers([(header, VALID_IPV6)])).unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_x_real_ip() {
        let header = "x-real-ip";

        assert_eq!(
            x_real_ip(&headers([])).unwrap_err(),
            Error::AbsentHeader {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            x_real_ip(&headers([(header, "ы")])).unwrap_err(),
            Error::NonAsciiHeaderValue {
                header_name: HeaderName::from_static(header)
            }
        );
        assert_eq!(
            x_real_ip(&headers([(header, "foo")])).unwrap_err(),
            Error::MalformedHeaderValue {
                header_name: HeaderName::from_static(header),
                header_value: "foo".into(),
            }
        );

        assert_eq!(
            x_real_ip(&headers([(header, VALID_IPV4)])).unwrap(),
            VALID_IPV4.parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            x_real_ip(&headers([(header, VALID_IPV6)])).unwrap(),
            VALID_IPV6.parse::<IpAddr>().unwrap()
        );
    }
}
