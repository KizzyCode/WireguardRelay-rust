//! The server config

use crate::error;
use crate::error::Error;
use base64ct::{Base64, Encoding};
use std::borrow::Cow;
use std::env::{self, VarError};
use std::fmt::{self, Display, Formatter};
use std::net::{SocketAddr, ToSocketAddrs};
use std::ops::RangeInclusive;
use std::time::Duration;

/// The server config
#[derive(Debug, Clone)]
#[allow(non_snake_case, reason = "We want to map the exact naming of the environment variables")]
pub struct Config {
    /// The server address to forward the traffic to
    ///
    /// # Example
    /// An `address:port` combination
    pub WGPROXY_SERVER: SocketAddr,
    /// The public keys for handshake validation
    ///
    /// # Note
    /// The public keys are used for handshake verfication and quick rejection when a new proxy connection is created.
    /// This is a security feature to ensure that the relay will not forward arbitrary rogue packets.
    /// **If the handshake does not match one of the configured public keys, the packet will be dropped.**
    pub WGPROXY_PUBKEYS: Vec<[u8; 32]>,
    /// The UDP ports to listen on and to use for relaying
    ///
    /// # Note
    /// As the ports are required to uniquely identify an upstream session, this is also the upper boundary for
    /// simultaneous proxy connections.
    ///
    /// # Example
    /// An inclusive range of ports, defaults to [`Self::WGPROXY_PORTS_DEFAULT`]
    pub WGPROXY_PORTS: RangeInclusive<u16>,
    /// The timeout duration for NAT mappings to expire
    ///
    /// # Example
    /// A duration in seconds, defaults to [`Self::WGPROXY_TIMEOUT_DEFAULT`]
    pub WGPROXY_TIMEOUT: Duration,
    /// The log level
    ///
    /// # Possible Values
    /// Possible values are:
    /// - `0`: Logs **errors** only
    /// - `1`: Logs **warnings** and **errors**
    /// - `2`: Logs **informational** messages, **warnings**, and **errors**
    /// - `3`: Logs **debug** and **informational** messages, **warnings**, and **errors**
    ///
    /// # Example
    /// A positive integer value, defaults to [`Self::WGPROXY_LOGLEVEL_DEFAULT`]
    pub WGPROXY_LOGLEVEL: u8,
}
impl Config {
    /// The default port range if [`Self::WGPROXY_PORTS`] is not specified
    pub const WGPROXY_PORTS_DEFAULT: &str = "51820-51829";
    /// The default timeout in seconds if [`Self::WGPROXY_TIMEOUT`] is not specified
    pub const WGPROXY_TIMEOUT_DEFAULT: &str = "60";
    /// The default loglevel if [`Self::WGPROXY_LOGLEVEL`] is not specified
    pub const WGPROXY_LOGLEVEL_DEFAULT: &str = "1";

    /// Gets the config from the environment
    pub fn from_env() -> Result<Self, Error> {
        Ok(Config {
            WGPROXY_SERVER: Self::wgproxy_server()?,
            WGPROXY_PUBKEYS: Self::wgproxy_pubkeys()?,
            WGPROXY_PORTS: Self::wgproxy_ports()?,
            WGPROXY_TIMEOUT: Self::wgproxy_timeout()?,
            WGPROXY_LOGLEVEL: Self::wgproxy_loglevel()?,
        })
    }

    /// Parses the `WGPROXY_SERVER` environment variable
    fn wgproxy_server() -> Result<SocketAddr, Error> {
        let address = Self::env("WGPROXY_SERVER", "<unspecified>")?;
        let mut addresses = address.to_socket_addrs()?;
        addresses.next().ok_or(error!(r#"Failed to parse address {address}"#))
    }

    /// Parses the `WGPROXY_PUBKEYS` environment variable
    fn wgproxy_pubkeys() -> Result<Vec<[u8; 32]>, Error> {
        /// Parses a base64 encoded pubkey to its binary representation
        fn base64_to_bin(base64: &str) -> Result<[u8; 32], Error> {
            (Base64::decode_vec(base64).ok())
                .and_then(|binary| <[u8; 32]>::try_from(binary).ok())
                .ok_or(error!(r#"Failed to parse base64 public key "{base64}""#))
        }

        // Parse the comma-separated pubkey list
        let pubkeys = Self::env("WGPROXY_PUBKEYS", "<unspecified>")?;
        pubkeys.split(',').map(base64_to_bin).collect()
    }

    /// Parses the `WGPROXY_PORTS` environment variable, or falls back to [`Self::WGPROXY_PORTS_DEFAULT`]
    fn wgproxy_ports() -> Result<RangeInclusive<u16>, Error> {
        let ports = Self::env("WGPROXY_PORTS", Self::WGPROXY_PORTS_DEFAULT)?;
        let (lower, upper) = ports.split_once('-').ok_or(error!(r#"Invalid port range "{ports}""#))?;
        let (lower, upper) = (lower.parse()?, upper.parse()?);
        Ok(lower..=upper)
    }

    /// Parses the `WGPROXY_TIMEOUT` environment variable, or falls back to [`Self::WGPROXY_TIMEOUT_DEFAULT`]
    fn wgproxy_timeout() -> Result<Duration, Error> {
        let seconds = Self::env("WGPROXY_TIMEOUT", Self::WGPROXY_TIMEOUT_DEFAULT)?;
        let seconds = seconds.parse()?;
        Ok(Duration::from_secs(seconds))
    }

    /// Parses the `WGPROXY_LOGLEVEL` environment variable, or falls back to [`Self::WGPROXY_LOGLEVEL_DEFAULT`]
    pub fn wgproxy_loglevel() -> Result<u8, Error> {
        let loglevel = Self::env("WGPROXY_LOGLEVEL", Self::WGPROXY_LOGLEVEL_DEFAULT)?;
        Ok(loglevel.parse()?)
    }

    /// Gets the environment variable with the given name or returns the default value
    fn env(name: &str, default: &'static str) -> Result<Cow<'static, str>, Error> {
        match env::var(name) {
            Ok(value) => Ok(Cow::Owned(value)),
            Err(VarError::NotPresent) => Ok(Cow::Borrowed(default)),
            Err(e) => Err(error!(with: e, r#"Invalid environment variable "{name}""#)),
        }
    }
}
impl Display for Config {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Re-encode the public keys to display them
        let pubkeys: Vec<_> = self.WGPROXY_PUBKEYS.iter().map(|pubkey| Base64::encode_string(pubkey)).collect();

        // Format struct
        f.debug_struct("Config")
            .field("WGPROXY_SERVER", &self.WGPROXY_SERVER)
            .field("WGPROXY_PUBKEYS", &pubkeys)
            .field("WGPROXY_PORTS", &self.WGPROXY_PORTS)
            .field("WGPROXY_TIMEOUT", &self.WGPROXY_TIMEOUT)
            .field("WGPROXY_LOGLEVEL", &self.WGPROXY_LOGLEVEL)
            .finish()
    }
}
