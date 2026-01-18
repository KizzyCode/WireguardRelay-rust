//! Wireguard handshake validator

use crate::error;
use crate::error::Error;
use blake2::digest::Mac;
use blake2::digest::consts::U16;
use blake2::digest::generic_array::GenericArray;
use blake2::{Blake2s256, Blake2sMac, Digest};
use std::ops::Range;

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
}
impl Handshake {
    /// Creates a new handshake validator
    pub const fn new(public_key: [u8; 32]) -> Self {
        Self { public_key }
    }

    /// Validates if a packet is a valid handshake initiation packet
    pub fn is_valid_handshake(&self, packet: &[u8]) -> Result<(), Error> {
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
        let Err(_) = mac1.verify(packet_mac1) else {
            // MAC1 matches our public key
            return Ok(());
        };

        // MAC1 validation failed for our public key
        Err(error!("MAC1 does not match the server public key"))
    }
}
