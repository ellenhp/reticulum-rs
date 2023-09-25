#[cfg(test)]
extern crate std;

#[cfg(feature = "embassy")]
use defmt::*;
#[cfg(feature = "tokio")]
use log::*;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use sha2::{Digest, Sha256};

use crate::{
    identity::{Identity, IdentityCommon},
    packet::{DestinationType, PacketError},
    persistence::ReticulumStore,
    NameHash, TruncatedHash,
};

#[derive(Debug, PartialEq)]
pub enum DestinationError {
    EmptyAppName,
    DotInAppName,
    EmptyAspect,
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
    async fn new<S: ReticulumStore + ?Sized, R: AsRef<S>>(
        app_name: String,
        aspects: Vec<String>,
        inner: DestinationInner,
        store: R,
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
            if let Err(_err) = store.as_ref().register_local_destination(&dest).await {
                debug!("failed to register local destination");
            }
        } else {
            if let Err(_err) = store.as_ref().add_destination(dest.clone()).await {
                debug!("failed to register non-local destination");
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
    pub fn partial_name(&self) -> String {
        let aspects = self.aspects.clone();
        let name = [&[self.app_name.clone()], aspects.as_slice()]
            .concat()
            .join(".");
        //     name.as_str(),
        //     hex::encode(&hash).as_str()
        // );
        name
    }

    /// Returns the full name of the destination according to the Reticulum spec.
    pub fn full_name(&self) -> String {
        let mut aspects = self.aspects.clone();
        // For single destinations the spec requires that we include the identity hash as an aspect.
        if let DestinationInner::Single(single) = &self.inner {
            aspects.push(single.identity.hex_hash())
        }
        let name = [&[self.app_name.clone()], aspects.as_slice()]
            .concat()
            .join(".");
        // info!(
        //     "full name: {}, {}",
        //     name.as_str(),
        //     hex::encode(&hash).as_str()
        // );
        name
    }

    /// Returns the truncated hash of this destination according to the Reticulum spec.
    pub fn address_hash_old(&self) -> TruncatedHash {
        let mut hasher = Sha256::new();
        hasher.update(self.name_hash().0);
        if let Some(identity) = self.identity() {
            // info!(
            //     "identity: {:?}",
            //     hex::encode(identity.truncated_hash()).as_str()
            // );
            hasher.update(identity.truncated_hash());
        } else {
            info!("no identity");
        }
        TruncatedHash(
            hasher.finalize()[..16]
                .try_into()
                .expect("slice operation must produce 16 bytes"),
        )
    }

    /// Returns the truncated hash of this destination according to the Reticulum spec.
    pub fn address_hash(&self) -> TruncatedHash {
        let mut hasher = Sha256::new();
        hasher.update(self.partial_name().as_bytes());
        let name_hash = hasher.finalize();
        hasher = Sha256::new();
        hasher.update(name_hash[..10].as_ref());
        if let Some(identity) = self.identity() {
            // info!(
            //     "identity: {:?}",
            //     hex::encode(identity.truncated_hash()).as_str()
            // );
            hasher.update(identity.truncated_hash());
        } else {
            info!("no identity");
        }
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
        hex::encode(self.address_hash().0)
    }

    pub fn destination_type(&self) -> DestinationType {
        match self.inner {
            DestinationInner::Single(_) => DestinationType::Single,
            DestinationInner::Group(_) => DestinationType::Group,
            DestinationInner::Plain(_) => DestinationType::Plain,
        }
    }

    pub async fn encrypt(&self, payload: Vec<u8>) -> Result<Vec<u8>, PacketError> {
        match &self.inner {
            DestinationInner::Single(single) => single
                .identity
                .encrypt_for(&payload)
                .await
                .map_err(|err| PacketError::CryptoError(err)),
            DestinationInner::Group(_) => {
                core::todo!("implement group destination encryption")
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

    #[cfg(test)]
    pub async fn build_single<S: ReticulumStore + ?Sized, R: AsRef<S>>(
        self,
        identity: &Identity,
        store: R,
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

    #[cfg(not(test))]
    pub async fn build_single<S: ReticulumStore + ?Sized, R: core::convert::AsRef<S>>(
        self,
        identity: &Identity,
        store: R,
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

    pub async fn build_group<S: ReticulumStore + ?Sized, R: AsRef<S>>(
        self,
        store: R,
    ) -> Result<Destination, DestinationError> {
        Destination::new(
            self.app_name,
            self.aspects,
            DestinationInner::Group(GroupDestination {}),
            store,
        )
        .await
    }

    pub async fn build_plain<S: ReticulumStore + ?Sized, R: AsRef<S>>(
        self,
        store: R,
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

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, format};

    use crate::{
        identity::IdentityCommon, persistence::in_memory::InMemoryReticulumStore, test::init_test,
    };

    use super::*;

    #[test]
    fn test_full_name_single() {
        init_test();
        tokio_test::block_on(async {
            let store: Box<dyn ReticulumStore> = Box::new(InMemoryReticulumStore::new());
            let identity = Identity::new_local().await;
            let hex_hash = identity.hex_hash();
            let destination = Destination::builder("app")
                .aspect("aspect1")
                .aspect("aspect2")
                .build_single(&identity, &store)
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
        init_test();
        tokio_test::block_on(async {
            let store: Box<dyn ReticulumStore> = Box::new(InMemoryReticulumStore::new());
            let destination = Destination::builder("app")
                .aspect("aspect1")
                .aspect("aspect2")
                .build_group(&store)
                .await;
            assert!(destination.is_ok());
            let destination = destination.unwrap();
            assert_eq!(destination.full_name(), "app.aspect1.aspect2");
        });
    }

    #[test]
    fn test_full_name_plain() {
        init_test();
        tokio_test::block_on(async {
            let store: Box<dyn ReticulumStore> = Box::new(InMemoryReticulumStore::new());
            let destination = Destination::builder("app")
                .aspect("aspect1")
                .aspect("aspect2")
                .build_plain(&store)
                .await;
            assert!(destination.is_ok());
            let destination = destination.unwrap();
            assert_eq!(destination.full_name(), "app.aspect1.aspect2");
        });
    }

    #[test]
    fn test_hex_hash_single() {
        init_test();
        tokio_test::block_on(async {
            let store: Box<dyn ReticulumStore> = Box::new(InMemoryReticulumStore::new());
            let identity = Identity::new_local().await;
            let hex_hash = identity.hex_hash();
            let destination = Destination::builder("app")
                .aspect("aspect1")
                .aspect("aspect2")
                .build_single(&identity, &store)
                .await;
            assert!(destination.is_ok());
            let destination = destination.unwrap();
            assert_eq!(
                destination.full_name(),
                format!("app.aspect1.aspect2.{}", hex_hash)
            );
            let mut hasher = Sha256::new();
            hasher.update(destination.name_hash().0);
            hasher.update(identity.truncated_hash());
            let hash = hasher.finalize();
            assert_eq!(destination.address_hash().0, &hash[..16]);
            assert_eq!(destination.hex_hash(), hex::encode(&hash[..16]));
        });
    }

    #[test]
    fn test_dot_in_app_name() {
        init_test();
        tokio_test::block_on(async {
            let store: Box<dyn ReticulumStore> = Box::new(InMemoryReticulumStore::new());
            let identity = Identity::new_local().await;
            let destination = Destination::builder("app.name")
                .aspect("aspect")
                .build_single(&identity, &store)
                .await;
            assert!(destination.is_err());
            let err = destination.unwrap_err();
            assert_eq!(err, DestinationError::DotInAppName);
        });
    }

    #[test]
    fn test_dot_in_aspect() {
        init_test();
        tokio_test::block_on(async {
            let store: Box<dyn ReticulumStore> = Box::new(InMemoryReticulumStore::new());
            let identity = Identity::new_local().await;
            let destination = Destination::builder("app")
                .aspect("aspect.name")
                .build_single(&identity, &store)
                .await;
            assert!(destination.is_err());
            let err = destination.unwrap_err();
            assert_eq!(err, DestinationError::DotInAspect);
        });
    }
}
