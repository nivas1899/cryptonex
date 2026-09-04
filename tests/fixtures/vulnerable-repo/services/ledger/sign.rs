use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

// ledger entry signing — Ed25519
pub fn sign_entry(key: &SigningKey, entry: &[u8]) -> Vec<u8> {
    key.sign(entry).to_bytes().to_vec()
}

pub fn digest(entry: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(entry);
    h.finalize().to_vec()
}
