use core::fmt::Debug;

use alloc::{boxed::Box, string::String, vec::Vec};
use async_trait::async_trait;
use base64::Engine;
use ed25519_dalek::{Signer, Verifier};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;

use crate::{
    packet::SignedMessage,
    random::{random_bytes, RNG},
    TruncatedHash,
};

#[derive(Debug, PartialEq)]
pub enum CryptoError {
    InvalidKey,
    EncryptFailed,
    DecryptFailed,
    InvalidSignature,
}

#[async_trait]
pub trait IdentityCommon {
    async fn encrypt_for(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn verify_from(&self, message: Box<dyn SignedMessage>) -> Result<(), CryptoError>;
    fn truncated_hash(&self) -> [u8; 16];
    fn hex_hash(&self) -> String {
        let hash = self.truncated_hash();
        hex::encode(hash)
    }
    fn handle(&self) -> TruncatedHash {
        TruncatedHash(self.truncated_hash())
    }
    fn wire_repr(&self) -> [u8; 64];
}

pub trait LocalIdentity {
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

#[derive(Debug, Clone)]
pub struct PeerIdentityInner {
    identity_key: x25519_dalek::PublicKey,
    sign_key: ed25519_dalek::VerifyingKey,
}

#[async_trait]
impl IdentityCommon for PeerIdentityInner {
    async fn encrypt_for(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut rng_guard = RNG.lock().await;
        let rng = rng_guard.as_mut().unwrap();
        let ephemeral_key = x25519_dalek::EphemeralSecret::random_from_rng(rng);
        let ephemeral_pubkey = PublicKey::from(&ephemeral_key);
        let shared_secret = ephemeral_key.diffie_hellman(&self.identity_key);

        let salt = self.truncated_hash();
        let ikm = shared_secret.as_bytes();
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), ikm);
        let mut okm = [0u8; 32];
        hkdf.expand(&[], &mut okm).unwrap();

        let base64_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(okm);
        if let Some(fernet_key) = fernet::Fernet::new(&base64_key) {
            let message = fernet_key.encrypt(message);
            if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(message) {
                let ephemeral_pubkey = ephemeral_pubkey.as_bytes();
                assert_eq!(ephemeral_pubkey.len(), 32);
                Ok([ephemeral_pubkey, bytes.as_slice()].concat())
            } else {
                Err(CryptoError::EncryptFailed)
            }
        } else {
            Err(CryptoError::InvalidKey)
        }
    }

    fn verify_from(&self, message: Box<dyn SignedMessage>) -> Result<(), CryptoError> {
        let signature = message.signature();
        let signed_data = message.signed_data();
        if let Ok(signature_fixed_len) = signature[0..64].try_into() {
            let signature = ed25519_dalek::Signature::from_bytes(signature_fixed_len);
            if self.sign_key.verify(signed_data, &signature).is_ok() {
                Ok(())
            } else {
                Err(CryptoError::InvalidSignature)
            }
        } else {
            Err(CryptoError::InvalidSignature)
        }
    }

    fn truncated_hash(&self) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(self.wire_repr());
        let hash = hasher.finalize();
        let mut truncated_hash = [0u8; 16];
        truncated_hash.copy_from_slice(&hash[0..16]);
        truncated_hash
    }

    fn wire_repr(&self) -> [u8; 64] {
        let mut public_keys = [0u8; 64];
        let identity_key = *self.identity_key.as_bytes();
        let sign_key = self.sign_key.to_bytes();
        public_keys[0..32].copy_from_slice(&identity_key);
        public_keys[32..64].copy_from_slice(&sign_key);
        public_keys
    }
}

#[derive(Clone)]
pub struct LocalIdentityInner {
    public_keys: PeerIdentityInner,
    private_key: x25519_dalek::StaticSecret,
    private_sign_key: ed25519_dalek::SigningKey,
}

impl Debug for LocalIdentityInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalIdentityInner")
            .field("public_keys", &self.public_keys)
            .finish()
    }
}

#[async_trait]
impl IdentityCommon for LocalIdentityInner {
    async fn encrypt_for(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.public_keys.encrypt_for(message).await
    }

    fn verify_from(&self, message: Box<dyn SignedMessage>) -> Result<(), CryptoError> {
        self.public_keys.verify_from(message)
    }

    fn truncated_hash(&self) -> [u8; 16] {
        self.public_keys.truncated_hash()
    }

    fn wire_repr(&self) -> [u8; 64] {
        self.public_keys.wire_repr()
    }
}

impl LocalIdentity for LocalIdentityInner {
    fn decrypt(&self, message_encoded: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let message_pubkey: &[u8; 32] = message_encoded[0..32].try_into().unwrap();
        let message_ciphertext = &message_encoded[32..];

        let other_pubkey = x25519_dalek::PublicKey::from(message_pubkey.clone());
        let shared_secret = self.private_key.diffie_hellman(&other_pubkey);

        let salt = self.truncated_hash();
        let ikm = shared_secret.as_bytes();
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), ikm);
        let mut okm = [0u8; 32];
        hkdf.expand(&[], &mut okm).unwrap();

        let base64_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(okm);
        let message_ciphertext_base64 =
            base64::engine::general_purpose::URL_SAFE.encode(message_ciphertext);
        if let Some(fernet_key) = fernet::Fernet::new(&base64_key) {
            let message_cleartext = fernet_key.decrypt(&message_ciphertext_base64).unwrap();
            Ok(message_cleartext)
        } else {
            Err(CryptoError::InvalidKey)
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature = self.private_sign_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }
}

#[derive(Debug, Clone)]
pub enum Identity {
    Local(LocalIdentityInner),
    Peer(PeerIdentityInner),
}

#[async_trait]
impl IdentityCommon for Identity {
    async fn encrypt_for(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            Identity::Local(local_identity) => local_identity.encrypt_for(message).await,
            Identity::Peer(peer_identity) => peer_identity.encrypt_for(message).await,
        }
    }

    fn verify_from(&self, message: Box<dyn SignedMessage>) -> Result<(), CryptoError> {
        match self {
            Identity::Local(local_identity) => local_identity.verify_from(message),
            Identity::Peer(peer_identity) => peer_identity.verify_from(message),
        }
    }

    fn truncated_hash(&self) -> [u8; 16] {
        match self {
            Identity::Local(local_identity) => local_identity.truncated_hash(),
            Identity::Peer(peer_identity) => peer_identity.truncated_hash(),
        }
    }

    fn wire_repr(&self) -> [u8; 64] {
        match self {
            Identity::Local(local_identity) => local_identity.wire_repr(),
            Identity::Peer(peer_identity) => peer_identity.wire_repr(),
        }
    }
}

impl Identity {
    pub async fn new_local() -> Identity {
        let mut key = [0u8; 32];
        random_bytes(&mut key).await;
        let private_key = x25519_dalek::StaticSecret::from(key);
        let public_key = x25519_dalek::PublicKey::from(&private_key);

        random_bytes(&mut key).await;
        let private_sign_key = ed25519_dalek::SigningKey::from_bytes(&key);
        let public_sign_key = private_sign_key.verifying_key();
        let peer_identity = PeerIdentityInner {
            identity_key: public_key,
            sign_key: public_sign_key,
        };
        let local_identity = LocalIdentityInner {
            public_keys: peer_identity,
            private_key,
            private_sign_key,
        };
        Identity::Local(local_identity)
    }

    pub fn from_wire_repr(wire_repr: &[u8]) -> Result<Identity, CryptoError> {
        if wire_repr.len() != 64 {
            return Err(CryptoError::InvalidKey);
        }
        let identity_key_bytes: [u8; 32] = wire_repr[0..32]
            .try_into()
            .expect("Slice must yield 32 bytes");
        let identity_key = x25519_dalek::PublicKey::from(identity_key_bytes);
        let sign_key_bytes: [u8; 32] = wire_repr[32..64]
            .try_into()
            .expect("Slice must yield 32 bytes");
        let sign_key = ed25519_dalek::VerifyingKey::from_bytes(&sign_key_bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        let peer_identity = PeerIdentityInner {
            identity_key,
            sign_key,
        };
        Ok(Identity::Peer(peer_identity))
    }

    pub fn is_local(&self) -> bool {
        match self {
            Identity::Local(_) => true,
            _ => false,
        }
    }

    pub fn full_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.wire_repr());
        let hash = hasher.finalize();
        let mut full_hash = [0u8; 32];
        full_hash.copy_from_slice(&hash[0..32]);
        full_hash
    }
}

#[cfg(test)]
mod test {
    use alloc::{boxed::Box, vec::Vec};

    use crate::{packet::SignedMessage, test::init_test};

    use super::{IdentityCommon, LocalIdentity};

    struct TestSignedMessage {
        signed_data: Vec<u8>,
        signature: Vec<u8>,
    }

    impl SignedMessage for TestSignedMessage {
        fn signed_data(&self) -> &[u8] {
            &self.signed_data
        }

        fn signature(&self) -> &[u8] {
            &self.signature
        }
    }

    #[test]
    fn create_identity() {
        init_test();
        tokio_test::block_on(async {
            let identity = super::Identity::new_local().await;
            match identity {
                super::Identity::Local(_) => (),
                _ => panic!("Expected local identity"),
            }
        })
    }

    #[test]
    fn encrypt_decrypt_local() {
        init_test();
        tokio_test::block_on(async {
            let identity = super::Identity::new_local().await;
            let message = b"Hello, world!";
            let encrypted = identity.encrypt_for(message).await.unwrap();
            match identity {
                super::Identity::Local(identity) => {
                    let decrypted = identity.decrypt(&encrypted).unwrap();
                    assert_eq!(message, decrypted.as_slice());
                }
                _ => panic!("Expected local identity"),
            }
        });
    }

    #[test]
    fn sign_verify_local() {
        init_test();
        tokio_test::block_on(async {
            let identity = super::Identity::new_local().await;
            let message = b"Hello, world!";
            let signature = match &identity {
                super::Identity::Local(identity) => identity.sign(message).unwrap(),
                _ => panic!("Expected local identity"),
            };
            let _ = identity
                .verify_from(Box::new(TestSignedMessage {
                    signed_data: message.to_vec(),
                    signature: signature.to_vec(),
                }))
                .unwrap();
        });
    }

    #[test]
    fn sign_verify_local_tampering() {
        init_test();
        tokio_test::block_on(async {
            let identity = super::Identity::new_local().await;
            let message = b"Hello, world!";
            let mut signature = match &identity {
                super::Identity::Local(identity) => identity.sign(message).unwrap(),
                _ => panic!("Expected local identity"),
            };
            signature[0] = signature[0].wrapping_add(128);
            assert!(identity
                .verify_from(Box::new(TestSignedMessage {
                    signed_data: message.to_vec(),
                    signature: signature.to_vec(),
                }))
                .is_err());
        });
    }
}
