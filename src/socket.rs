//! A polling UDP socket pool

use crate::error::Error;
use mio::{Events, Interest, Poll, Token};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Extensions for `SocketAddr`
pub trait SocketAddrExt {
    /// Transforms `self` into a canonical IPv6 format
    fn to_canonicalized_ipv6(self) -> SocketAddrV6;
    /// Transforms `self` into a canonical IPv4 format _if possible_
    fn to_canonicalized_ipv4(self) -> Option<SocketAddrV4>;
}
impl SocketAddrExt for SocketAddr {
    fn to_canonicalized_ipv6(self) -> SocketAddrV6 {
        // Map IP address
        let ipv6 = match self.ip() {
            IpAddr::V4(ipv4_addr) => ipv4_addr.to_ipv6_mapped(),
            IpAddr::V6(ipv6_addr) => ipv6_addr,
        };

        // Create canonicalized socket address
        SocketAddrV6::new(ipv6, self.port(), 0, 0)
    }

    fn to_canonicalized_ipv4(self) -> Option<SocketAddrV4> {
        // Map IP address
        let ipv4 = match self.ip() {
            IpAddr::V4(ipv4_addr) => ipv4_addr,
            IpAddr::V6(ipv6_addr) => ipv6_addr.to_ipv4_mapped()?,
        };

        // Create canonicalized socket address
        Some(SocketAddrV4::new(ipv4, self.port()))
    }
}

/// A UDP socket
#[derive(Debug)]
pub struct UdpSocket {
    /// The underlying MIO socket
    inner: mio::net::UdpSocket,
    /// The local address the socket is bound to
    address: SocketAddrV6,
    is_ipv4: bool,
}
impl UdpSocket {
    /// Wraps a [`mio::net::UdpSocket`]
    pub fn new(socket: mio::net::UdpSocket) -> Result<Self, Error> {
        let address = socket.local_addr()?;
        let is_ipv4 = address.to_canonicalized_ipv4().is_some();
        let address = address.to_canonicalized_ipv6();
        Ok(Self { inner: socket, address, is_ipv4 })
    }

    /// The local address the socket is bound to
    pub fn address(&self) -> SocketAddrV6 {
        self.address
    }

    /// Sends data on the socket to the given address and returns the number of bytes written on success
    pub fn send_to(&self, packet: &[u8], address: SocketAddrV6) -> Result<usize, Error> {
        // Create generic socket address from the given v6 address
        let mut address = SocketAddr::from(address);
        if self.is_ipv4
            && let Some(ipv4) = address.to_canonicalized_ipv4()
        {
            // Convert mapped v6 address to v4
            address = SocketAddr::from(ipv4);
        }

        // Sent the packet
        let sent = self.inner.send_to(packet, address)?;
        Ok(sent)
    }

    /// Destructures `self` and returns the underlying socket
    pub fn into_inner(self) -> mio::net::UdpSocket {
        self.inner
    }
}
impl Deref for UdpSocket {
    type Target = mio::net::UdpSocket;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// A polling UDP socket pool
#[derive(Debug)]
pub struct SocketPool {
    /// The pollset
    pollset: Poll,
    /// Reusable event buffer
    events: Events,
    /// The sockets by their file descriptor
    sockets: HashMap<Token, UdpSocket>,
    /// The socket file descriptors by their local address
    by_address: HashMap<SocketAddrV6, Token>,
}
impl SocketPool {
    /// Creates a new socket pool
    pub fn new() -> Result<Self, Error> {
        let pollset = Poll::new()?;
        let events = Events::with_capacity(1024);
        let sockets = HashMap::new();
        let by_address = HashMap::new();
        Ok(Self { pollset, events, sockets, by_address })
    }

    /// Creates and binds a new socket within the polling pool
    pub fn init(&mut self, bind_address: SocketAddr, interests: Interest) -> Result<&UdpSocket, Error> {
        /// A shared, atomic counter to allocate unique tokens per socket
        static TOKEN_COUNTER: AtomicUsize = AtomicUsize::new(0);

        // Bind the UDP socket and register the socket for polling
        let mut socket = mio::net::UdpSocket::bind(bind_address)?;
        let token = Token(TOKEN_COUNTER.fetch_add(1, Ordering::SeqCst));
        self.pollset.registry().register(&mut socket, token, interests)?;

        // Index the socket
        let socket = UdpSocket::new(socket)?;
        self.by_address.insert(socket.address(), token);

        // Register the socket and resize event buffer if necessary
        self.sockets.insert(token, socket);
        if self.sockets.len() > self.events.capacity() {
            // Ensure we can store events for each socket; allocate by doubling
            self.events = Events::with_capacity(self.sockets.len() * 2);
        }

        // Lookup socket to get a reference that is tied to `self`
        let socket = self.sockets.get(&token).expect("failed to get newly registered socket");
        Ok(socket)
    }

    /// Gets a socket by its event token
    pub fn by_token(&self, token: &Token) -> Option<&UdpSocket> {
        self.sockets.get(token)
    }
    /// Gets a socket by its associated local address
    pub fn by_address(&self, address: &SocketAddrV6) -> Option<&UdpSocket> {
        let token = self.by_address.get(&address)?;
        self.sockets.get(token)
    }

    /// Gets all local (aka potential outbound) addresses that are currently available within the pool
    pub fn addresses(&self) -> HashSet<SocketAddrV6> {
        self.by_address.keys().copied().collect()
    }

    /// Waits for an I/O event on one or more of the pool sockets
    pub fn wait_for_io(&mut self, timeout: Duration) -> Result<&Events, Error> {
        self.pollset.poll(&mut self.events, Some(timeout))?;
        Ok(&self.events)
    }
    /// Direct access to the events that were yielded by the last call to [`Self::wait_for_io`]
    ///
    /// # Note
    /// This function is used to circumvent the borrow checker as [`Self::wait_for_io`] creates a mutable borrow, even
    /// if the resulting event set is immutable.
    pub fn events(&self) -> &Events {
        &self.events
    }
}
impl Drop for SocketPool {
    fn drop(&mut self) {
        for (_, socket) in self.sockets.drain() {
            // We never panic during drop, so we ignore the error here
            let mut socket = socket.into_inner();
            let _ = self.pollset.registry().deregister(&mut socket);
        }
    }
}
