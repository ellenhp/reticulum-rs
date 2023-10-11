#![no_std]
#![feature(error_in_core)]

//! Fernet provides symmetric-authenticated-encryption with an API that makes
//! misusing it difficult. It is based on a public specification and there are
//! interoperable implementations in Rust, Python, Ruby, Go, and Clojure.

//! # Example
//! ```rust
//! // Store `key` somewhere safe!
//! let key = fernet::Fernet::generate_key();
//! let fernet = fernet::Fernet::new(&key).unwrap();
//! let plaintext = b"my top secret message!";
//! let ciphertext = fernet.encrypt(plaintext);
//! let decrypted_plaintext = fernet.decrypt(&ciphertext);
//! assert_eq!(decrypted_plaintext.unwrap(), plaintext);
// ```

extern crate alloc;

use core::convert::TryInto;
use core::fmt::Display;
use core::{error::Error, fmt};

use alloc::{string::String, vec::Vec};
use base64::Engine;
use byteorder::{BigEndian, ByteOrder};
use zeroize::Zeroize;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::Mac;
use sha2::Sha256;

const MAX_CLOCK_SKEW: u64 = 60;

// Automatically zero out the contents of the memory when the struct is drop'd.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Fernet {
    encryption_key: [u8; 16],
    signing_key: [u8; 16],
}

/// This error is returned when fernet cannot decrypt the ciphertext for any
/// reason. It could be an expired token, incorrect key or other failure. If
/// you recieve this error, you should consider the fernet token provided as
/// invalid.
#[derive(Debug, PartialEq, Eq)]
pub struct DecryptionError;

impl Error for DecryptionError {}

impl Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fernet decryption error")
    }
}

#[derive(Clone)]
pub struct MultiFernet {
    fernets: Vec<Fernet>,
}

/// `MultiFernet` encapsulates the encrypt operation with the first `Fernet`
/// instance and decryption with  the `Fernet` instances provided in order
/// until successful decryption or a `DecryptionError`.
impl MultiFernet {
    pub fn new(keys: Vec<Fernet>) -> MultiFernet {
        assert!(!keys.is_empty(), "keys must not be empty");
        MultiFernet { fernets: keys }
    }

    /// Encrypts data with the first `Fernet` instance. Returns a value
    /// (which is base64-encoded) that can be passed to `MultiFernet::decrypt`.
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.fernets[0].encrypt(data)
    }

    /// Decrypts a ciphertext, using the `Fernet` instances provided. Returns
    /// either `Ok(plaintext)` if decryption is successful or
    /// `Err(DecryptionError)` if no decryption was possible across the set of
    /// fernet keys.
    pub fn decrypt(&self, token: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        for fernet in self.fernets.iter() {
            let res = fernet.decrypt(token);
            if res.is_ok() {
                return res;
            }
        }

        Err(DecryptionError)
    }
}

/// Token split into parts before decryption.
struct ParsedToken {
    /// message is the whole token except for the HMAC
    message: Vec<u8>,
    /// 128 bit IV
    iv: [u8; 16],
    /// Ciphertext (part of message)
    ciphertext: Vec<u8>,
    /// 256 bit HMAC
    hmac: [u8; 32],
}

/// `Fernet` encapsulates encrypt and decrypt operations for a particular symmetric key.
impl Fernet {
    /// Returns a new fernet instance with the provided key. The key should be
    /// 32-bytes, url-safe base64-encoded. Generating keys with `Fernet::generate_key`
    /// is recommended. DO NOT USE A HUMAN READABLE PASSWORD AS A KEY. Returns
    /// `None` if the key is not 32-bytes base64 encoded.
    pub fn new(key: &[u8]) -> Option<Fernet> {
        if key.len() != 32 {
            return None;
        }

        let mut signing_key: [u8; 16] = Default::default();
        signing_key.copy_from_slice(&key[..16]);
        let mut encryption_key: [u8; 16] = Default::default();
        encryption_key.copy_from_slice(&key[16..]);

        Some(Fernet {
            signing_key,
            encryption_key,
        })
    }

    /// Generates a new, random, key. Can be safely passed to `Fernet::new()`.
    /// Store this somewhere safe!
    pub fn generate_key() -> Vec<u8> {
        let mut key: [u8; 32] = Default::default();
        getrandom::getrandom(&mut key).expect("Error in getrandom");
        key.to_vec()
    }

    /// Encrypts data into a token. Returns a value (which is base64-encoded) that can be
    /// passed to `Fernet::decrypt` for decryption and verification..
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let current_time = 0;
        self._encrypt_at_time(data, current_time)
    }

    /// Encrypts data with the current_time. Returns a value (which is base64-encoded) that can be
    /// passed to `Fernet::decrypt`.
    ///
    /// This function has the capacity to be used incorrectly or insecurely due to
    /// to the "current_time" parameter. current_time must be the systems `time::SystemTime::now()`
    /// with `duraction_since(time::UNIX_EPOCH)` as seconds.
    ///
    /// The motivation for a function like this is for your application to be able to test
    /// ttl expiry of tokens in your API. This allows you to pass in mock time data to assert
    /// correct behaviour of your application. Care should be taken to ensure you always pass in
    /// correct current_time values for deployments.
    #[inline]
    #[cfg(feature = "fernet_danger_timestamps")]
    pub fn encrypt_at_time(&self, data: &[u8], current_time: u64) -> String {
        self._encrypt_at_time(data, current_time)
    }

    fn _encrypt_at_time(&self, data: &[u8], current_time: u64) -> Vec<u8> {
        let mut iv: [u8; 16] = Default::default();
        getrandom::getrandom(&mut iv).expect("Error in getrandom");
        self._encrypt_from_parts(data, current_time, &iv)
    }

    fn _encrypt_from_parts(&self, data: &[u8], _current_time: u64, iv: &[u8]) -> Vec<u8> {
        let ciphertext = cbc::Encryptor::<aes::Aes128>::new_from_slices(&self.encryption_key, iv)
            .unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(data);

        let mut result = iv.to_vec();
        result.extend_from_slice(&ciphertext);

        let mut hmac_signer = hmac::Hmac::<Sha256>::new_from_slice(&self.signing_key)
            .expect("Signing key has unexpected size");
        hmac_signer.update(&result);

        result.extend_from_slice(&hmac_signer.finalize().into_bytes());
        result
    }

    /// Decrypts a ciphertext. Returns either `Ok(plaintext)` if decryption is
    /// successful or `Err(DecryptionError)` if there are any errors. Errors could
    /// include incorrect key or tampering with the data.
    pub fn decrypt(&self, token: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        let current_time = 0;
        self._decrypt_at_time(token, None, current_time)
    }

    /// Decrypts a ciphertext with a time-to-live. Returns either `Ok(plaintext)`
    /// if decryption is successful or `Err(DecryptionError)` if there are any errors.
    /// Note if the token timestamp + ttl > current time, then this will also yield a
    /// DecryptionError. The ttl is measured in seconds. This is a relative time, not
    /// the absolute time of expiry. IE you would use 60 as a ttl_secs if you wanted
    /// tokens to be considered invalid after that time.
    pub fn decrypt_with_ttl(
        &self,
        token: &[u8],
        ttl_secs: u64,
    ) -> Result<Vec<u8>, DecryptionError> {
        let current_time = 0;
        self._decrypt_at_time(token, Some(ttl_secs), current_time)
    }

    /// Decrypt a ciphertext with a time-to-live, and the current time.
    /// Returns either `Ok(plaintext)` if decryption is
    /// successful or `Err(DecryptionError)` if there are any errors.
    ///
    /// This function has the capacity to be used incorrectly or insecurely due to
    /// to the "current_time" parameter. current_time must be the systems time::SystemTime::now()
    /// with duraction_since(time::UNIX_EPOCH) as seconds.
    ///
    /// The motivation for a function like this is for your application to be able to test
    /// ttl expiry of tokens in your API. This allows you to pass in mock time data to assert
    /// correct behaviour of your application. Care should be taken to ensure you always pass in
    /// correct current_time values for deployments.
    #[inline]
    #[cfg(feature = "fernet_danger_timestamps")]
    pub fn decrypt_at_time(
        &self,
        token: &str,
        ttl: Option<u64>,
        current_time: u64,
    ) -> Result<Vec<u8>, DecryptionError> {
        self._decrypt_at_time(token, ttl, current_time)
    }

    fn _decrypt_at_time(
        &self,
        data: &[u8],
        ttl: Option<u64>,
        current_time: u64,
    ) -> Result<Vec<u8>, DecryptionError> {
        let parsed = Self::_decrypt_parse(data, ttl, current_time)?;

        let mut hmac_signer = hmac::Hmac::<Sha256>::new_from_slice(&self.signing_key)
            .expect("Signing key has unexpected size");
        hmac_signer.update(&parsed.message);

        let expected_hmac = hmac_signer.finalize().into_bytes();

        use subtle::ConstantTimeEq;
        let hmac_matches: bool = parsed.hmac.ct_eq(&expected_hmac).into();
        if !hmac_matches {
            return Err(DecryptionError);
        }

        let plaintext =
            cbc::Decryptor::<aes::Aes128>::new_from_slices(&self.encryption_key, &parsed.iv)
                .unwrap()
                .decrypt_padded_vec_mut::<Pkcs7>(&parsed.ciphertext)
                .map_err(|_| DecryptionError)?;

        Ok(plaintext)
    }

    /// Parse the base64-encoded token into parts, verify timestamp TTL if given
    fn _decrypt_parse(
        data: &[u8],
        ttl: Option<u64>,
        current_time: u64,
    ) -> Result<ParsedToken, DecryptionError> {
        let iv: [u8; 16] = data[0..16].try_into().map_err(|_| DecryptionError)?;

        let rest = &data[16..];
        if rest.len() < 32 {
            return Err(DecryptionError);
        }
        let ciphertext = rest[..rest.len() - 32].to_vec();

        let hmac = data[data.len() - 32..]
            .try_into()
            .map_err(|_| DecryptionError)?;

        let message = data[..data.len() - 32].to_vec();
        Ok(ParsedToken {
            message,
            iv,
            ciphertext,
            hmac,
        })
    }
}
