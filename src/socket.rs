//! A polling UDP socket pool

use crate::error::Error;
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

/// A polling UDP socket pool
#[derive(Debug)]
pub struct SocketPool {
    /// The pollset
    pollset: Poll,
    /// Reusable event buffer
    events: Events,
    /// The sockets by their file descriptor
    sockets: HashMap<RawFd, UdpSocket>,
    /// The socket file descriptors by their local address
    by_address: HashMap<SocketAddr, RawFd>,
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
        // Bind the UDP socket and use the file descriptor as token
        let mut sockets = UdpSocket::bind(bind_address)?;
        let address = sockets.local_addr()?;
        let raw_fd = sockets.as_raw_fd();

        // Register the new socket for polling
        let token = Token(raw_fd.try_into()?);
        self.pollset.registry().register(&mut sockets, token, interests)?;

        // Index the socket and resize event buffer
        self.sockets.insert(raw_fd, sockets);
        self.by_address.insert(address, raw_fd);
        if self.sockets.len() > self.events.capacity() {
            // Ensure we can store events for each socket; allocate by doubling
            self.events = Events::with_capacity(self.sockets.len() * 2);
        }

        // Lookup socket to get a reference that is tied to `self`
        let socket = self.sockets.get(&raw_fd).expect("failed to get newly registered socket");
        Ok(socket)
    }

    /// Gets a socket by its event token
    pub fn by_token(&self, token: &Token) -> Option<&UdpSocket> {
        let fd = RawFd::try_from(token.0).ok()?;
        self.sockets.get(&fd)
    }
    /// Gets a socket by its associated local address
    pub fn by_address(&self, address: &SocketAddr) -> Option<&UdpSocket> {
        let fd = self.by_address.get(address)?;
        self.sockets.get(fd)
    }

    /// Gets all local (aka potential outbound) addresses that are currently available within the pool
    pub fn addresses(&self) -> HashSet<SocketAddr> {
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
        for socket in self.sockets.values_mut() {
            // We never panic during drop, so we ignore the error here
            let _ = self.pollset.registry().deregister(socket);
        }
    }
}
