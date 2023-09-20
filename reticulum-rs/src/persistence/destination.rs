use std::{sync::Arc, time::SystemTime};

use log::debug;
use sha2::{Digest, Sha256};
use smol::{
    channel::{Receiver, Sender},
    lock::Mutex,
};

use crate::{
    identity::{CryptoError, Identity, IdentityCommon},
    packet::{DestinationType, Packet, PacketError, WirePacket},
    persistence::DestinationStore,
    NameHash, TruncatedHash,
};

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum DestinationError {
    #[error("app_name must not be empty")]
    EmptyAppName,
    #[error("app_name must not contain a dot")]
    DotInAppName,
    #[error("aspect must not be empty")]
    EmptyAspect,
    #[error("aspect must not contain a dot")]
    DotInAspect,
}

#[derive(Debug, Clone)]
pub struct Destination {
    app_name: String,
    aspects: Vec<String>,
    inner: DestinationInner,
}

#[derive(Debug, Clone)]
enum DestinationInner {
    Single(SingleDestination),
    Group(GroupDestination),
    Plain(PlainDestination),
}

impl Destination {
    async fn new<DestStore: DestinationStore + 'static>(
        app_name: String,
        aspects: Vec<String>,
        inner: DestinationInner,
        store: &mut DestStore,
    ) -> Result<Destination, DestinationError> {
        if app_name.is_empty() {
            return Err(DestinationError::EmptyAppName);
        }
        if app_name.contains('.') {
            return Err(DestinationError::DotInAppName);
        }
        for aspect in &aspects {
            if aspect.is_empty() {
                return Err(DestinationError::EmptyAspect);
            }
            if aspect.contains('.') {
                return Err(DestinationError::DotInAspect);
            }
        }
        let dest = Destination {
            app_name,
            aspects,
            inner,
        };
        if match dest.identity() {
            Some(Identity::Local(_)) => true,
            _ => false,
        } {
            if let Err(err) = store.register_local_destination(&dest) {
                debug!("failed to register local destination: {}", err);
            }
        } else {
            if let Err(err) = store.add_destination(&dest).await {
                debug!("failed to register non-local destination: {}", err);
            }
        }
        Ok(dest)
    }

    pub(crate) fn builder(app_name: &str) -> DestinationBuilder {
        DestinationBuilder::new(app_name.to_string())
    }

    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    pub fn aspects(&self) -> &[String] {
        &self.aspects
    }

    pub fn identity(&self) -> Option<&Identity> {
        match &self.inner {
            DestinationInner::Single(single) => Some(&single.identity),
            _ => None,
        }
    }

    /// Returns the full name of the destination according to the Reticulum spec.
    pub fn full_name(&self) -> String {
        let mut aspects = self.aspects.clone();
        // For single destinations the spec requires that we include the identity hash as an aspect.
        if let DestinationInner::Single(single) = &self.inner {
            aspects.push(single.identity.hex_hash())
        }
        [&[self.app_name.clone()], aspects.as_slice()]
            .concat()
            .join(".")
    }

    /// Returns the truncated hash of this destination according to the Reticulum spec.
    pub fn truncated_hash(&self) -> TruncatedHash {
        let name = self.full_name();
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        TruncatedHash(
            hasher.finalize()[..16]
                .try_into()
                .expect("slice operation must produce 16 bytes"),
        )
    }

    /// Returns the name hash of this destination according to the Reticulum spec.
    pub fn name_hash(&self) -> NameHash {
        let name = self.full_name();
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        NameHash(
            hasher.finalize()[..10]
                .try_into()
                .expect("slice operation must produce 16 bytes"),
        )
    }

    /// Returns the hex representation of the truncated hash of this destination according to the Reticulum spec.
    pub fn hex_hash(&self) -> String {
        hex::encode(self.truncated_hash().0)
    }

    pub fn destination_type(&self) -> DestinationType {
        match self.inner {
            DestinationInner::Single(_) => DestinationType::Single,
            DestinationInner::Group(_) => DestinationType::Group,
            DestinationInner::Plain(_) => DestinationType::Plain,
        }
    }

    pub fn encrypt(&self, payload: Vec<u8>) -> Result<Vec<u8>, PacketError> {
        match &self.inner {
            DestinationInner::Single(single) => single
                .identity
                .encrypt_for(&payload)
                .map_err(|err| PacketError::CryptoError(err)),
            DestinationInner::Group(_) => {
                todo!("implement group destination encryption")
            }
            DestinationInner::Plain(_) => Ok(payload),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SingleDestination {
    identity: Identity,
}

#[derive(Debug, Clone)]
pub struct GroupDestination {}

#[derive(Debug, Clone)]
pub struct PlainDestination {}

#[cfg(test)]
mod tests {
    use crate::{identity::IdentityCommon, persistence::in_memory::InMemoryDestinationStore};

    use super::*;

    #[test]
    fn test_full_name_single() {
        smol::block_on(async {
            let mut store = InMemoryDestinationStore::new();
            let identity = Identity::new_local();
            let hex_hash = identity.hex_hash();
            let destination = Destination::builder("app")
                .aspect("aspect1")
                .aspect("aspect2")
                .build_single(&identity, &mut store)
                .await;
            assert!(destination.is_ok());
            let destination = destination.unwrap();
            assert_eq!(
                destination.full_name(),
                format!("app.aspect1.aspect2.{}", hex_hash)
            );
        });
    }

    #[test]
    fn test_full_name_group() {
        smol::block_on(async {
            let mut store = InMemoryDestinationStore::new();
            let destination = Destination::builder("app")
                .aspect("aspect1")
                .aspect("aspect2")
                .build_group(&mut store)
                .await;
            assert!(destination.is_ok());
            let destination = destination.unwrap();
            assert_eq!(destination.full_name(), "app.aspect1.aspect2");
        });
    }

    #[test]
    fn test_full_name_plain() {
        smol::block_on(async {
            let mut store = InMemoryDestinationStore::new();
            let destination = Destination::builder("app")
                .aspect("aspect1")
                .aspect("aspect2")
                .build_plain(&mut store)
                .await;
            assert!(destination.is_ok());
            let destination = destination.unwrap();
            assert_eq!(destination.full_name(), "app.aspect1.aspect2");
        });
    }

    #[test]
    fn test_hex_hash_single() {
        smol::block_on(async {
            let mut store = InMemoryDestinationStore::new();
            let identity = Identity::new_local();
            let hex_hash = identity.hex_hash();
            let destination = Destination::builder("app")
                .aspect("aspect1")
                .aspect("aspect2")
                .build_single(&identity, &mut store)
                .await;
            assert!(destination.is_ok());
            let destination = destination.unwrap();
            assert_eq!(
                destination.full_name(),
                format!("app.aspect1.aspect2.{}", hex_hash)
            );
            let mut hasher = Sha256::new();
            hasher.update(destination.full_name().as_bytes());
            let hash = hasher.finalize();
            assert_eq!(destination.truncated_hash().0, &hash[..16]);
            assert_eq!(destination.hex_hash(), hex::encode(&hash[..16]));
        });
    }

    #[test]
    fn test_dot_in_app_name() {
        smol::block_on(async {
            let mut store = InMemoryDestinationStore::new();
            let identity = Identity::new_local();
            let destination = Destination::builder("app.name")
                .aspect("aspect")
                .build_single(&identity, &mut store)
                .await;
            assert!(destination.is_err());
            let err = destination.unwrap_err();
            assert_eq!(err, DestinationError::DotInAppName);
        });
    }

    #[test]
    fn test_dot_in_aspect() {
        smol::block_on(async {
            let mut store = InMemoryDestinationStore::new();
            let identity = Identity::new_local();
            let destination = Destination::builder("app")
                .aspect("aspect.name")
                .build_single(&identity, &mut store)
                .await;
            assert!(destination.is_err());
            let err = destination.unwrap_err();
            assert_eq!(err, DestinationError::DotInAspect);
        });
    }
}

pub struct DestinationBuilder {
    app_name: String,
    aspects: Vec<String>,
}

impl DestinationBuilder {
    fn new(app_name: String) -> DestinationBuilder {
        DestinationBuilder {
            app_name,
            aspects: Vec::new(),
        }
    }

    pub fn aspect(mut self, aspect: &str) -> DestinationBuilder {
        self.aspects.push(aspect.to_string());
        self
    }

    pub(crate) async fn build_single<DestStore: DestinationStore + 'static>(
        self,
        identity: &Identity,
        store: &mut DestStore,
    ) -> Result<Destination, DestinationError> {
        Destination::new(
            self.app_name,
            self.aspects,
            DestinationInner::Single(SingleDestination {
                identity: identity.clone(),
            }),
            store,
        )
        .await
    }

    pub(crate) async fn build_group<DestStore: DestinationStore + 'static>(
        self,
        store: &mut DestStore,
    ) -> Result<Destination, DestinationError> {
        Destination::new(
            self.app_name,
            self.aspects,
            DestinationInner::Group(GroupDestination {}),
            store,
        )
        .await
    }

    pub(crate) async fn build_plain<DestStore: DestinationStore + 'static>(
        self,
        store: &mut DestStore,
    ) -> Result<Destination, DestinationError> {
        Destination::new(
            self.app_name,
            self.aspects,
            DestinationInner::Plain(PlainDestination {}),
            store,
        )
        .await
    }
}
