#[cfg(test)]
extern crate std;

use core::cell::{Ref, RefCell};
use std::{collections::HashMap, sync::Arc};

use alloc::boxed::Box;
use alloc::format;
use alloc::{string::String, vec::Vec};
use async_trait::async_trait;
use log::{trace, warn};

use crate::identity::Identity;
use crate::NameHash;
use crate::{identity::IdentityCommon, packet::Packet, TruncatedHash};

use super::destination::DestinationBuilder;
use super::{destination::Destination, PersistenceError};
use super::{AnnounceTableEntry, ReticulumStore};

#[derive(Clone)]
pub struct InMemoryReticulumStore {
    destination_names: Arc<tokio::sync::Mutex<Vec<(String, Vec<String>)>>>,
    destinations: Arc<tokio::sync::Mutex<HashMap<String, Destination>>>,
    messages: Arc<
        tokio::sync::Mutex<
            HashMap<
                TruncatedHash,
                (
                    tokio::sync::mpsc::Sender<Packet>,
                    Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Packet>>>,
                ),
            >,
        >,
    >,
}

impl InMemoryReticulumStore {
    pub fn new() -> InMemoryReticulumStore {
        InMemoryReticulumStore {
            #[cfg(feature = "embassy")]
            messages: HashMap::new(),
            #[cfg(feature = "tokio")]
            messages: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            destination_names: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            destinations: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ReticulumStore for InMemoryReticulumStore {
    async fn register_destination_name(
        &self,
        app_name: String,
        aspects: Vec<String>,
    ) -> Result<(), PersistenceError> {
        self.destination_names
            .lock()
            .await
            .push((app_name, aspects));
        Ok(())
    }

    async fn register_local_destination(
        &self,
        destination: &Destination,
    ) -> Result<(), PersistenceError> {
        self.destinations
            .lock()
            .await
            .insert(destination.full_name(), destination.clone());
        Ok(())
    }

    async fn get_destination_names(&self) -> Result<Vec<(String, Vec<String>)>, PersistenceError> {
        Ok(self.destination_names.lock().await.clone())
    }

    async fn get_all_destinations(&self) -> Result<Vec<Destination>, PersistenceError> {
        let mut all_destinations = Vec::new();
        for destination in self.destinations.lock().await.values() {
            all_destinations.push(destination.clone());
        }
        Ok(all_destinations)
    }

    async fn get_destinations_by_identity_handle(
        &self,
        handle: &TruncatedHash,
    ) -> Result<Vec<Destination>, PersistenceError> {
        let mut matching_destinations = Vec::new();
        for destination in self.destinations.lock().await.values() {
            if let Some(identity) = destination.identity() {
                if &identity.handle() == handle {
                    matching_destinations.push(destination.clone());
                }
            }
        }
        Ok(matching_destinations)
    }

    async fn add_destination(&self, destination: Destination) -> Result<(), PersistenceError> {
        if !self
            .destinations
            .lock()
            .await
            .contains_key(&destination.full_name())
        {
            self.destinations
                .lock()
                .await
                .insert(destination.full_name(), destination.clone());
        } else {
            trace!("destination already exists: {:?}", destination);
        }
        Ok(())
    }

    async fn remove_destination(&self, destination: &Destination) -> Result<(), PersistenceError> {
        self.destinations
            .lock()
            .await
            .remove(&destination.full_name())
            .ok_or_else(|| {
                PersistenceError::Unspecified(format!("destination not found: {:?}", destination))
            })?;
        Ok(())
    }
    async fn poll_inbox(&self, destination_hash: &TruncatedHash) -> Option<Packet> {
        #[cfg(feature = "embassy")]
        let (_sender, receiver) = self.messages.get(&destination_hash)?;
        #[cfg(feature = "embassy")]
        match receiver.try_receive() {
            Ok(packet) => Some(packet),
            // TODO: Do these errors mean we need to do something?
            Err(_) => None,
        }

        #[cfg(feature = "tokio")]
        {
            let mut messages = self.messages.lock().await;
            let (_sender, receiver) = messages.get_mut(&destination_hash)?;
            let retval = match receiver.lock().await.try_recv() {
                Ok(packet) => Some(packet),
                Err(_) => None,
            };
            return retval;
        }
    }

    async fn next_inbox(&self, destination_hash: &TruncatedHash) -> Option<Packet> {
        #[cfg(feature = "embassy")]
        {
            let (_sender, receiver) = self.messages.lock().await.get_mut(&destination_hash)?;
            return Some(receiver.receive().await);
        }
        #[cfg(feature = "tokio")]
        {
            let mut messages = self.messages.lock().await;
            let (_sender, receiver) = messages.get_mut(&destination_hash)?;
            let retval = match receiver.lock().await.try_recv() {
                Ok(packet) => Some(packet),
                Err(_) => None,
            };
            return retval;
        }
    }

    async fn get_local_destinations(&self) -> Result<Vec<Destination>, PersistenceError> {
        let all_destinations = self.get_all_destinations().await?;
        let mut local_destinations = Vec::new();
        for destination in all_destinations {
            if let Some(Identity::Local(_)) = destination.identity() {
                local_destinations.push(destination);
            }
        }
        Ok(local_destinations)
    }
    async fn get_peer_destinations(&self) -> Result<Vec<Destination>, PersistenceError> {
        let all_destinations = self.get_all_destinations().await?;
        let mut peer_destinations = Vec::new();
        for destination in all_destinations {
            if let Some(Identity::Peer(_)) = destination.identity() {
                peer_destinations.push(destination);
            }
        }
        Ok(peer_destinations)
    }
    fn destination_builder(&self, app_name: &str) -> DestinationBuilder {
        Destination::builder(app_name)
    }
    async fn resolve_destination(
        &self,
        hash: &NameHash,
        identity: &Identity,
    ) -> Option<Destination> {
        if let Ok(Some(destination)) = self.get_destination(hash).await {
            if destination.name_hash() == *hash {
                return Some(destination);
            }
        }
        let destination_names = if let Ok(names) = self.get_destination_names().await {
            names
        } else {
            warn!("error getting destination names");
            return None;
        };
        for (app_name, aspects) in destination_names {
            let mut builder = Destination::builder(app_name.as_str());
            for aspect in aspects {
                builder = builder.aspect(aspect.as_str());
            }
            let destination = if let Ok(destination) =
                builder.build_single(identity, self).await.map_err(|err| {
                    PersistenceError::Unspecified(format!("error building destination: {:?}", err))
                }) {
                destination
            } else {
                warn!("error building destination");
                return None;
            };
            if destination.name_hash() == *hash {
                self.add_destination(destination.clone()).await.unwrap();
                return Some(destination);
            }
        }
        None
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

    async fn get_destination(
        &self,
        hash: &NameHash,
    ) -> Result<Option<Destination>, PersistenceError> {
        let all_destinations = self.get_all_destinations().await?;
        for existing_destination in all_destinations {
            if &existing_destination.name_hash() == hash {
                return Ok(Some(existing_destination));
            }
        }
        Ok(None)
    }
}

impl AsRef<dyn ReticulumStore> for InMemoryReticulumStore {
    fn as_ref(&self) -> &dyn ReticulumStore {
        self
    }
}

#[derive(Clone)]
pub struct InMemoryAnnounceTable {
    #[cfg(feature = "embassy")]
    announces: Arc<
        embassy_sync::mutex::Mutex<
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            Vec<AnnounceTableEntry>,
        >,
    >,
    #[cfg(feature = "tokio")]
    announces: Arc<tokio::sync::Mutex<Vec<AnnounceTableEntry>>>,
}

pub struct InMemoryAnnounceIterator {
    announces: Vec<AnnounceTableEntry>,
}

impl Iterator for InMemoryAnnounceIterator {
    type Item = AnnounceTableEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.announces.pop()
    }
}

pub struct InMemoryMessageStore {
    #[cfg(feature = "embassy")]
    messages: HashMap<
        TruncatedHash,
        (
            embassy_sync::channel::Sender<
                'static,
                embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
                Packet,
                1,
            >,
            embassy_sync::channel::Receiver<
                'static,
                embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
                Packet,
                1,
            >,
        ),
    >,
    #[cfg(feature = "tokio")]
    messages: HashMap<
        TruncatedHash,
        (
            tokio::sync::mpsc::Sender<Packet>,
            tokio::sync::mpsc::Receiver<Packet>,
        ),
    >,
}
