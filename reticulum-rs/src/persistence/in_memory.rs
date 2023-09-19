use std::{collections::HashMap, rc::Rc, sync::Arc, time::Duration};

use async_trait::async_trait;
use smol::lock::Mutex;

use crate::{
    destination::Destination,
    identity::{Identity, IdentityCommon},
    TruncatedHash,
};

use super::{
    AnnounceTable, AnnounceTableEntry, AnnounceTableEntryArc, DestinationStore, IdentityMetadata,
    IdentityStore, PersistenceError,
};

pub struct InMemoryIdentityStore {
    identities: HashMap<TruncatedHash, Identity>,
}

impl InMemoryIdentityStore {
    pub fn new() -> InMemoryIdentityStore {
        InMemoryIdentityStore {
            identities: HashMap::new(),
        }
    }
}

#[async_trait]
impl IdentityStore for InMemoryIdentityStore {
    async fn get_all_identities(&self) -> Result<Vec<Identity>, PersistenceError> {
        let mut all_identities = Vec::new();
        for identity in self.identities.values() {
            all_identities.push(identity.clone());
        }
        Ok(all_identities)
    }

    async fn get_identity_by_handle(
        &self,
        handle: &TruncatedHash,
    ) -> Result<Identity, PersistenceError> {
        for identity in self.identities.values() {
            if &identity.handle() == handle {
                return Ok(identity.clone());
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
    ) -> Result<(), PersistenceError> {
        self.identities.insert(identity.handle(), identity.clone());
        Ok(())
    }

    async fn remove_identity(&mut self, identity: &Identity) -> Result<(), PersistenceError> {
        self.identities.remove(&identity.handle()).ok_or_else(|| {
            PersistenceError::Unspecified(format!("identity not found: {:?}", identity))
        })?;
        Ok(())
    }
}

pub struct InMemoryDestinationStore {
    destinations: HashMap<String, Destination>,
}

impl InMemoryDestinationStore {
    pub fn new() -> InMemoryDestinationStore {
        InMemoryDestinationStore {
            destinations: HashMap::new(),
        }
    }
}

#[async_trait]
impl DestinationStore for InMemoryDestinationStore {
    async fn get_all_destinations(&self) -> Result<Vec<Destination>, PersistenceError> {
        let mut all_destinations = Vec::new();
        for destination in self.destinations.values() {
            all_destinations.push(destination.clone());
        }
        Ok(all_destinations)
    }

    async fn get_destinations_by_identity_handle(
        &self,
        handle: &TruncatedHash,
    ) -> Result<Vec<Destination>, PersistenceError> {
        let mut matching_destinations = Vec::new();
        for destination in self.destinations.values() {
            if let Some(identity) = destination.identity() {
                if &identity.handle() == handle {
                    matching_destinations.push(destination.clone());
                }
            }
        }
        Ok(matching_destinations)
    }

    async fn add_destination(&mut self, destination: &Destination) -> Result<(), PersistenceError> {
        self.destinations
            .insert(destination.full_name(), destination.clone());
        Ok(())
    }

    async fn remove_destination(
        &mut self,
        destination: &Destination,
    ) -> Result<(), PersistenceError> {
        self.destinations
            .remove(&destination.full_name())
            .ok_or_else(|| {
                PersistenceError::Unspecified(format!("destination not found: {:?}", destination))
            })?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct InMemoryAnnounceTable {
    announces: Arc<Mutex<Vec<AnnounceTableEntryArc>>>,
}

pub struct InMemoryAnnounceIterator {
    announces: Vec<AnnounceTableEntryArc>,
}

impl Iterator for InMemoryAnnounceIterator {
    type Item = AnnounceTableEntryArc;

    fn next(&mut self) -> Option<Self::Item> {
        self.announces.pop()
    }
}

#[async_trait]
impl AnnounceTable for InMemoryAnnounceTable {
    type AnnounceIterator = InMemoryAnnounceIterator;

    async fn table_iter(&self) -> Self::AnnounceIterator {
        let announces = self.announces.lock();
        let announces = announces.await;
        InMemoryAnnounceIterator {
            announces: announces.clone(),
        }
    }

    async fn push_announce(
        &mut self,
        announce: AnnounceTableEntryArc,
    ) -> Result<(), PersistenceError> {
        let announces = self.announces.lock();
        let mut announces = announces.await;
        announces.push(announce);
        Ok(())
    }

    async fn expire_announces(&mut self, max_age: Duration) -> Result<(), PersistenceError> {
        let announces = self.announces.lock();
        let mut announces = announces.await;
        let mut new_announces = Vec::new();
        for announce in announces.iter() {
            if announce.received_time.elapsed() < max_age {
                new_announces.push(announce.clone());
            }
        }
        *announces = new_announces;
        Ok(())
    }
}
