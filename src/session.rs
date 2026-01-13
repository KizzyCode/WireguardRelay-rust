//! A relay NAT session

use crate::error::Error;
use crate::socket::SocketPool;
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Display, Formatter};
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Instant;

/// A unique route
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Route {
    /// The local address
    local: SocketAddr,
    /// The remote peer address
    remote: SocketAddr,
}
impl Route {
    /// Creates a new route from the given addresses
    pub const fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        Self { local, remote }
    }
}
impl Display for Route {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Debug::fmt(&self, f)
    }
}

/// A session handle
#[derive(Debug)]
pub struct Session {
    /// The first associated route
    route0: Route,
    /// The second associated route
    route1: Route,
    /// The time the session was last accessed
    atime: Cell<Instant>,
}
impl Session {
    /// Creates a new session with the given routes
    pub fn new(route0: Route, route1: Route) -> Self {
        let atime = Cell::new(Instant::now());
        Self { route0, route1, atime }
    }

    /// Forwards a packet from the given source to the associated destination
    ///
    /// # Panics
    /// This function panics if the source address is not associated with the current connection. This function also
    /// panics if the pool does not have a socket for the associated outbound address.
    pub fn forward(&self, packet: &[u8], source: &Route, socketpool: &SocketPool) -> Result<(), Error> {
        // Select destination route
        // Note: A source that doesn't match is invalid and an API violation
        let destination = match source {
            source if source.remote == self.route0.remote => self.route1,
            source if source.remote == self.route1.remote => self.route0,
            _ => panic!("source address is not associated with session"),
        };

        // Get the associated outbound socket from the socket pool and forward the packet
        // Note: This should never happen as we should never have routes that don't map to an outbound session
        let socket = socketpool.by_address(&destination.local).expect("failed to get outbound socket for session");
        socket.send_to(packet, destination.remote)?;

        // Update the atime on success
        self.atime.set(Instant::now());
        Ok(())
    }

    /// The time the session was last accessed
    pub fn atime(&self) -> Instant {
        self.atime.get()
    }
}
impl Display for Session {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

/// A session pool
#[derive(Debug)]
pub struct SessionPool {
    /// The session by their route
    sessions: HashMap<Route, Rc<Session>>,
}
impl SessionPool {
    /// Creates a new session pool
    pub fn new() -> Self {
        Self { sessions: HashMap::new() }
    }

    /// Starts a new session with the given routes
    pub fn init(&mut self, route0: Route, route1: Route) -> &Session {
        // Create and register the new session
        let session = Rc::new(Session::new(route0, route1));
        self.sessions.insert(route0, session.clone());
        self.sessions.insert(route1, session);

        // Get newly created session
        self.by_route(&route0).expect("failed to get newly registered session")
    }

    /// Gets a session by one of its associated routes
    pub fn by_route(&self, route: &Route) -> Option<&Session> {
        let session = self.sessions.get(route)?;
        Some(session.as_ref())
    }

    /// Gets all local (aka potential outbound) addresses that are currently in use within the pool
    pub fn addresses(&self) -> HashSet<SocketAddr> {
        // Collect all local addresses for all registered sessions
        self.sessions.values().flat_map(|session| [session.route0.local, session.route1.local]).collect()
    }

    /// Retains only the sessions specified by the filter predicate
    pub fn retain<F>(&mut self, mut filter: F)
    where
        F: FnMut(&Session) -> bool,
    {
        // Apply the filter to the session registry
        self.sessions.retain(|_, session| filter(session));
    }
}
