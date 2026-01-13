//! Testing utils

use blake2::digest::Mac;
use blake2::digest::consts::U16;
use blake2::{Blake2s256, Blake2sMac, Digest};
use hex_literal::hex;

/// Computes a handshake packet
pub fn handshake(public_key: &[u8; 32], number: u16) -> [u8; 148] {
    /// A template packet
    const TEMPLATE: [u8; 148] = hex! {
        "01000000"
        "4B6172696E6D6167656E20 4B6172696E6D6167656E20 4B6172696E6D6167656E20 4B6172696E6D6167656E20"
        "4B6172696E6D6167656E20 4B6172696E6D6167656E20 4B6172696E6D6167656E20 4B6172696E6D6167656E20"
        "4B6172696E6D6167656E20 4B6172696E6D6167656E20 5858"
        "58585858585858585858585858585858 00000000000000000000000000000000"
    };

    // Set the packet number
    let mut packet = TEMPLATE;
    packet[114..116].copy_from_slice(&number.to_be_bytes());

    // Compute MAC1 over the packet
    let label_pubkey_hash = Blake2s256::new().chain_update(b"mac1----").chain_update(public_key).finalize();
    let mac1 = Blake2sMac::<U16>::new(&label_pubkey_hash).chain_update(&packet[..116]).finalize();

    // Copy MAC1 into packet
    packet[116..132].copy_from_slice(&mac1.into_bytes());
    packet
}
