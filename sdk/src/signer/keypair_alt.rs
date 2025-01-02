#![cfg(feature = "core")]

use {
    super::{Signer, SignerError},
    crate::{pubkey::Pubkey, signature::Signature},
    nostd::{fmt, format_args, prelude::*},
    sp_core::{ed25519, Pair},
};

const KEYPAIR_LENGTH: usize = 64;

pub type SecretKey = [u8; 32];

pub struct Keypair(ed25519::Pair);

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SignatureError(String);

impl SignatureError {
    pub fn from_source(source: String) -> Self {
        Self(source)
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("secret", &format_args!("SecretKey: {:?}", self.0.seed()))
            .field("public", &format_args!("PublicKey: {:?}", self.0.public()))
            .finish()
    }
}

impl Keypair {
    /// Can be used for generating a Keypair without a dependency on `rand` types
    pub const SECRET_KEY_LENGTH: usize = 32;

    /// Constructs a new, random `Keypair` using `OsRng`
    #[cfg(feature = "std")]
    pub fn new() -> Self {
        Self(ed25519::Pair::generate().0)
    }

    /// Recovers a `Keypair` from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() < KEYPAIR_LENGTH {
            return Err(SignatureError::from_source(String::from(
                "candidate keypair byte array is too short",
            )));
        }
        let pair = ed25519::Pair::from_seed_slice(&bytes[..Self::SECRET_KEY_LENGTH])
            .map_err(|_| SignatureError::from_source("invalid secret key".into()))?;
        let public = &bytes[Self::SECRET_KEY_LENGTH..];
        let expected_public = pair.public();
        (public == &expected_public[..])
            .then_some(Self(pair))
            .ok_or(SignatureError::from_source(String::from(
                "keypair bytes do not specify same pubkey as derived from their secret key",
            )))
    }

    /// Returns this `Keypair` as a byte array
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(self.0.seed().as_ref());
        bytes[32..].copy_from_slice(self.0.public().0.as_ref());
        bytes
    }

    /// Recovers a `Keypair` from a base58-encoded string
    pub fn from_base58_string(s: &str) -> Self {
        Self::from_bytes(&bs58::decode(s).into_vec().unwrap()).unwrap()
    }

    /// Returns this `Keypair` as a base58-encoded string
    pub fn to_base58_string(&self) -> String {
        bs58::encode(&self.to_bytes()).into_string()
    }

    /// Gets this `Keypair`'s SecretKey
    pub fn secret(&self) -> SecretKey {
        self.0.seed()
    }

    /// Allows Keypair cloning
    ///
    /// Note that the `Clone` trait is intentionally unimplemented because making a
    /// second copy of sensitive secret keys in memory is usually a bad idea.
    ///
    /// Only use this in tests or when strictly required. Consider using [`std::sync::Arc<Keypair>`]
    /// instead.
    pub fn insecure_clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Signer for Keypair {
    #[inline]
    fn pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.0.public().0)
    }

    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        Ok(self.pubkey())
    }

    #[allow(unused)]
    fn sign_message(&self, message: &[u8]) -> Signature {
        #[cfg(feature = "std")]
        {
            Signature::from(self.0.sign(message).into())
        }

        #[cfg(not(feature = "std"))]
        {
            unimplemented!()
        }
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        Ok(self.sign_message(message))
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

impl<T> PartialEq<T> for Keypair
where
    T: Signer,
{
    fn eq(&self, other: &T) -> bool {
        self.pubkey() == other.pubkey()
    }
}
