//! Wireguard handshake validator

use crate::error;
use crate::error::Error;
use blake2::digest::Mac;
use blake2::digest::consts::U16;
use blake2::digest::generic_array::GenericArray;
use blake2::{Blake2s256, Blake2sMac, Digest};
use std::collections::{HashSet, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::ops::Range;

/// An identity hasher for valid aka evenly distributed MAC values
#[derive(Debug, Clone, Copy)]
struct MacHasher(u64);
impl Hasher for MacHasher {
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            // Append byte to state
            self.0 = (self.0 << 8) | (*byte as u64);
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }

    fn finish(&self) -> u64 {
        self.0
    }
}
impl BuildHasher for MacHasher {
    type Hasher = Self;

    fn build_hasher(&self) -> Self::Hasher {
        *self
    }
}

/// A handshake validator
///
/// # Purpose
/// The idea of the handshake validator is to ensure that a new session starts with a valid wireguard handshake. This
/// provides a good best-effort baseline to reject invalid or rogue packets, as the handshake implicitly depends on the
/// server public key, which is impossible to match accidentally, and which is also usually not known to an arbitrary
/// attacker.
///
/// See <https://www.wireguard.com/protocol/> for more information.
#[derive(Debug)]
pub struct Handshake {
    /// The allowed public key for handshakes
    public_key: [u8; 32],
    /// A fast-lookup set of seen MACs
    mac_index: HashSet<u64, MacHasher>,
    /// An ordered history of seen MACs
    mac_history: VecDeque<u64>,
}
impl Handshake {
    /// MAC history size (~4 MiB of storage)
    const HISTORY_SIZE: usize = 1024 * 256;

    /// Creates a new handshake validator
    pub fn new(public_key: [u8; 32]) -> Self {
        let mac_index = HashSet::with_capacity_and_hasher(Self::HISTORY_SIZE, MacHasher(0));
        let mac_history = VecDeque::with_capacity(Self::HISTORY_SIZE);
        Self { public_key, mac_index, mac_history }
    }

    /// Validates if a packet is a valid handshake initiation packet
    pub fn is_valid_handshake(&mut self, packet: &[u8]) -> Result<(), Error> {
        /// The exact length of a handshake initiation packet
        const PACKET_LENGTH: usize = 148;
        /// The offset/range of the message type field
        const MTYPE_RANGE: Range<usize> = 0..4;
        /// The expected message type for a handshake initiation packet
        const MTYPE_VALUE: &[u8] = b"\x01\x00\x00\x00";
        /// The offset/range of the payload for MAC1 computation
        const PAYLOAD_RANGE: Range<usize> = 0..116;
        /// The offset/range of the MAC1 field
        const MAC1_RANGE: Range<usize> = 116..132;
        /// The label constant for MAC1 computation
        const MAC1_LABEL: &[u8] = b"mac1----";

        // Validate basic structure
        let PACKET_LENGTH = packet.len() else {
            // The packet has an invalid length
            return Err(error!("Packet is not a handshake initiation packet"));
        };
        let MTYPE_VALUE = &packet[MTYPE_RANGE] else {
            // The packet has an invalid message type/magic number
            return Err(error!("Packet is not a handshake initiation packet"));
        };

        // Compute MAC1 over the packet
        let label_pubkey_hash = Blake2s256::new().chain_update(MAC1_LABEL).chain_update(self.public_key).finalize();
        let mac1 = Blake2sMac::<U16>::new(&label_pubkey_hash).chain_update(&packet[PAYLOAD_RANGE]);

        // See if the computed MAC1 matches the packet MAC1
        let packet_mac1 = GenericArray::from_slice(&packet[MAC1_RANGE]);
        let Ok(_) = mac1.verify(packet_mac1) else {
            // MAC1 does not match our public key
            return Err(error!("MAC1 does not match the server public key"));
        };

        // MAC1 is valid, so check for previous occurrences and register it
        let packet_mac1 = <[u8; 16]>::from(*packet_mac1);
        self.register_mac1(&packet_mac1)
    }

    /// Registers a new MAC with the history and returns `true` on success, or `false` if the MAC exists already
    ///
    /// # Collisions
    /// For performance reasons, the registry only stores the middle 64 bit of the full 128 bit hash. In theory, this
    /// could cause some collisions over time; however in practice this should not happen too often. If a collision
    /// occurs, the client will simply send a new handshake with a new MAC.
    // Note: This function uses a boolean return value to avoid the more expensive error creation on failure
    #[must_use]
    fn register_mac1(&mut self, mac: &[u8; 16]) -> Result<(), Error> {
        // See if the shortened MAC exists already
        let mac64 = u64::from_ne_bytes([mac[4], mac[5], mac[6], mac[7], mac[8], mac[9], mac[10], mac[11]]);
        let false = self.mac_index.contains(&mac64) else {
            // MAC has already been seen before
            let mac = u128::from_be_bytes(*mac);
            return Err(error!("MAC1 {mac:032x} has already been seen before"));
        };

        // Evict old MAC if necessary
        if self.mac_history.len() == Self::HISTORY_SIZE
            && let Some(to_evict) = self.mac_history.pop_front()
        {
            // Remove oldest value from index
            self.mac_index.remove(&to_evict);
        }

        // Insert new value
        self.mac_index.insert(mac64);
        self.mac_history.push_back(mac64);
        Ok(())
    }
}
