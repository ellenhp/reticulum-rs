use async_trait::async_trait;

use crate::{
    destination::Destination,
    identity::{self, Identity, IdentityCommon, IdentityHandle},
};

#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("unspecified error: {0}")]
    Unspecified(String),
}

pub struct IdentityMetadata(pub Vec<u8>);
pub trait IdentityStore {
    fn get_all_identities(&self) -> Result<Vec<Identity>, PersistenceError>;

    fn get_self_identities(&self) -> Result<Vec<Identity>, PersistenceError> {
        let all_identities = self.get_all_identities()?;
        let mut self_identities = Vec::new();
        for identity in all_identities {
            match identity {
                Identity::Local(_) => self_identities.push(identity),
                Identity::Peer(_) => (),
            }
        }
        Ok(self_identities)
    }

    fn get_identity_by_handle(
        &self,
        handle: &IdentityHandle,
    ) -> Result<Identity, PersistenceError> {
        let all_identities = self.get_all_identities()?;
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

    fn add_identity(
        &self,
        identity: &Identity,
        metadata: &IdentityMetadata,
    ) -> Result<(), PersistenceError>;

    fn remove_identity(&self, identity: &Identity) -> Result<(), PersistenceError>;
}

#[async_trait]
pub trait DestinationStore {
    async fn get_all_destinations(&self) -> Result<Vec<Destination>, PersistenceError>;
    async fn get_destinations_by_identity_handle(
        &self,
        handle: &IdentityHandle,
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
}
