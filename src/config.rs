//! The server config

use crate::error;
use crate::error::Error;
use base64ct::{Base64, Encoding};
use std::borrow::Cow;
use std::env::{self, VarError};
use std::fmt::{self, Display, Formatter};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

/// The server config
#[derive(Debug, Clone)]
#[allow(non_snake_case, reason = "We want to map the exact naming of the environment variables")]
pub struct Config {
    /// The server address to forward the traffic to
    ///
    /// # Example
    /// An `address:port` combination
    pub WGPROXY_SERVER: String,
    /// The server public key for handshake validation
    ///
    /// # Note
    /// The public key is used for handshake verfication and quick rejection when a new proxy connection is created.
    /// This is a security feature to ensure that the relay will not forward arbitrary rogue packets.
    /// **If the handshake does not match the configured public key, the packet will be dropped.**
    pub WGPROXY_PUBKEY: [u8; 32],
    /// The address to listen on and to use for relaying
    ///
    /// # Example
    /// An inclusive range of ports, defaults to [`Self::WGPROXY_LISTEN_DEFAULT`]
    pub WGPROXY_LISTEN: SocketAddr,
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
    /// The default listening address if [`Self::WGPROXY_LISTEN`] is not specified
    pub const WGPROXY_LISTEN_DEFAULT: &str = "[::]:51820";
    /// The default timeout in seconds if [`Self::WGPROXY_TIMEOUT`] is not specified
    pub const WGPROXY_TIMEOUT_DEFAULT: &str = "60";
    /// The default loglevel if [`Self::WGPROXY_LOGLEVEL`] is not specified
    pub const WGPROXY_LOGLEVEL_DEFAULT: &str = "1";

    /// Gets the config from the environment
    pub fn from_env() -> Result<Self, Error> {
        Ok(Config {
            WGPROXY_SERVER: Self::wgproxy_server()?,
            WGPROXY_PUBKEY: Self::wgproxy_pubkey()?,
            WGPROXY_LISTEN: Self::wgproxy_listen()?,
            WGPROXY_TIMEOUT: Self::wgproxy_timeout()?,
            WGPROXY_LOGLEVEL: Self::wgproxy_loglevel()?,
        })
    }

    /// Parses the `WGPROXY_SERVER` environment variable
    fn wgproxy_server() -> Result<String, Error> {
        let address = Self::env("WGPROXY_SERVER", "<unspecified>")?;
        let Some(_) = address.to_socket_addrs()?.next() else {
            // The address cannot be resolved; fail fast
            return Err(error!(r#"Failed to resolve server address {address}"#));
        };

        // Retain the address as string so we can periodically re-resolve DNS names for to catch e.g. dynDNS or load
        //  balancing
        Ok(address.to_string())
    }

    /// Parses the `WGPROXY_PUBKEY` environment variable
    fn wgproxy_pubkey() -> Result<[u8; 32], Error> {
        // Decode pubkey
        let pubkey = Self::env("WGPROXY_PUBKEY", "<unspecified>")?;
        let binary = Base64::decode_vec(&pubkey)
            .map_err(|e| error!(with: e, r#"Failed to base64-decode public key "{pubkey}""#))?;

        // Ensure the decoded public key is exactly 32 bytes
        let maybe_binary = <[u8; 32]>::try_from(binary).ok();
        maybe_binary.ok_or(error!(r#"Invalid public key "{pubkey}""#))
    }

    /// Parses the `WGPROXY_LISTEN` environment variable, or falls back to [`Self::WGPROXY_LISTEN_DEFAULT`]
    fn wgproxy_listen() -> Result<SocketAddr, Error> {
        let address = Self::env("WGPROXY_LISTEN", Self::WGPROXY_LISTEN_DEFAULT)?;
        let maybe_address: Result<SocketAddr, _> = address.parse();
        maybe_address.map_err(|e| error!(with: e, r#"Invalid listening address "{address}""#))
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
        // Re-encode the public key to display them
        let pubkey = Base64::encode_string(&self.WGPROXY_PUBKEY);

        // Format struct
        f.debug_struct("Config")
            .field("WGPROXY_SERVER", &self.WGPROXY_SERVER)
            .field("WGPROXY_PUBKEY", &pubkey)
            .field("WGPROXY_LISTEN", &self.WGPROXY_LISTEN)
            .field("WGPROXY_TIMEOUT", &self.WGPROXY_TIMEOUT)
            .field("WGPROXY_LOGLEVEL", &self.WGPROXY_LOGLEVEL)
            .finish()
    }
}
