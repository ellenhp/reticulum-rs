#[cfg(feature = "stores")]
pub mod in_memory;

use async_trait::async_trait;

use crate::{
    destination::Destination,
    identity::{self, Identity, IdentityCommon},
    TruncatedHash,
};

#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("unspecified error: {0}")]
    Unspecified(String),
}

pub struct IdentityMetadata(pub Vec<u8>);

#[async_trait]
pub trait IdentityStore: Send + Sync {
    async fn get_all_identities(&self) -> Result<Vec<Identity>, PersistenceError>;

    async fn get_self_identities(&self) -> Result<Vec<Identity>, PersistenceError> {
        let all_identities = self.get_all_identities().await?;
        let mut self_identities = Vec::new();
        for identity in all_identities {
            match identity {
                Identity::Local(_) => self_identities.push(identity),
                Identity::Peer(_) => (),
            }
        }
        Ok(self_identities)
    }

    async fn get_identity_by_handle(
        &self,
        handle: &TruncatedHash,
    ) -> Result<Identity, PersistenceError> {
        let all_identities = self.get_all_identities().await?;
        for identity in all_identities {
            if &identity.handle() == handle {
                return Ok(identity);
            }
        }
        Err(PersistenceError::Unspecified(format!(
            "identity not found: {:?}",
            handle
        )))
    }

    async fn add_identity(
        &mut self,
        identity: &Identity,
        metadata: &IdentityMetadata,
    ) -> Result<(), PersistenceError>;

    async fn remove_identity(&mut self, identity: &Identity) -> Result<(), PersistenceError>;
}

#[async_trait]
pub trait DestinationStore: Send + Sync {
    async fn get_all_destinations(&self) -> Result<Vec<Destination>, PersistenceError>;
    async fn get_destinations_by_identity_handle(
        &self,
        handle: &TruncatedHash,
    ) -> Result<Vec<Destination>, PersistenceError> {
        let all_destinations = self.get_all_destinations().await?;
        let mut matching_destinations = Vec::new();
        for destination in all_destinations {
            if let Some(identity) = destination.get_identity() {
                if &identity.handle() == handle {
                    matching_destinations.push(destination);
                }
            }
        }
        Ok(matching_destinations)
    }
    async fn get_destinations_by_name(
        &self,
        name: &str,
    ) -> Result<Vec<Destination>, PersistenceError> {
        let all_destinations = self.get_all_destinations().await?;
        let mut matching_destinations = Vec::new();
        for destination in all_destinations {
            if destination.full_name() == name {
                matching_destinations.push(destination);
            }
        }
        Ok(matching_destinations)
    }

    async fn add_destination(&mut self, destination: &Destination) -> Result<(), PersistenceError>;
    async fn remove_destination(
        &mut self,
        destination: &Destination,
    ) -> Result<(), PersistenceError>;
}
