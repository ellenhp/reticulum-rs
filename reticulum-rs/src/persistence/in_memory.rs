#[cfg(test)]
extern crate std;

use std::{collections::HashMap, sync::Arc, time::Duration};

use alloc::boxed::Box;
use alloc::format;
use alloc::{string::String, vec::Vec};
use async_trait::async_trait;

use crate::{
    identity::{Identity, IdentityCommon},
    packet::Packet,
    TruncatedHash,
};

use super::AnnounceTableEntry;
use super::{
    destination::Destination, AnnounceTable, DestinationStore, IdentityMetadata, IdentityStore,
    MessageStore, PersistenceError,
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
        _metadata: &IdentityMetadata,
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
    destination_names: Vec<(String, Vec<String>)>,
    destinations: HashMap<String, Destination>,
}

impl InMemoryDestinationStore {
    pub fn new() -> InMemoryDestinationStore {
        InMemoryDestinationStore {
            destination_names: Vec::new(),
            destinations: HashMap::new(),
        }
    }
}

#[async_trait]
impl DestinationStore for InMemoryDestinationStore {
    fn register_destination_name(
        &mut self,
        app_name: String,
        aspects: Vec<String>,
    ) -> Result<(), PersistenceError> {
        self.destination_names.push((app_name, aspects));
        Ok(())
    }

    fn register_local_destination(
        &mut self,
        destination: &Destination,
    ) -> Result<(), PersistenceError> {
        self.destinations
            .insert(destination.full_name(), destination.clone());
        Ok(())
    }

    fn get_destination_names(&self) -> Result<Vec<(String, Vec<String>)>, PersistenceError> {
        Ok(self.destination_names.clone())
    }

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

    async fn add_destination(&mut self, destination: Destination) -> Result<(), PersistenceError> {
        if !self.destinations.contains_key(&destination.full_name()) {
            self.destinations
                .insert(destination.full_name(), destination.clone());
        }
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

#[async_trait]
impl AnnounceTable for InMemoryAnnounceTable {
    async fn table_iter(&self) -> Box<dyn Iterator<Item = AnnounceTableEntry>> {
        let announces = self.announces.lock().await;
        Box::new(InMemoryAnnounceIterator {
            announces: announces.clone(),
        })
    }

    async fn push_announce(
        &mut self,
        announce: AnnounceTableEntry,
    ) -> Result<(), PersistenceError> {
        let mut announces = self.announces.lock().await;
        announces.push(announce);
        Ok(())
    }

    async fn expire_announces(&mut self, max_age: Duration) -> Result<(), PersistenceError> {
        let mut announces = self.announces.lock().await;
        let mut new_announces = Vec::new();
        for announce in announces.iter() {
            #[cfg(feature = "embassy")]
            if announce.received_time.elapsed()
                < embassy_time::Duration::from_secs(max_age.as_secs())
            {
                new_announces.push(announce.clone());
            }
            #[cfg(feature = "tokio")]
            if announce.received_time.elapsed() < max_age {
                new_announces.push(announce.clone());
            }
        }
        *announces = new_announces;
        Ok(())
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

#[async_trait]
impl MessageStore for InMemoryMessageStore {
    fn poll_inbox(&mut self, destination_hash: &TruncatedHash) -> Option<Packet> {
        #[cfg(feature = "embassy")]
        let (_sender, receiver) = self.messages.get(&destination_hash)?;
        #[cfg(feature = "tokio")]
        let (_sender, receiver) = self.messages.get_mut(&destination_hash)?;
        #[cfg(feature = "embassy")]
        match receiver.try_receive() {
            Ok(packet) => Some(packet),
            // TODO: Do these errors mean we need to do something?
            Err(_) => None,
        }
        #[cfg(feature = "tokio")]
        match receiver.try_recv() {
            Ok(packet) => Some(packet),
            Err(_) => None,
        }
    }

    async fn next_inbox(&mut self, destination_hash: &TruncatedHash) -> Option<Packet> {
        let (_sender, receiver) = self.messages.get_mut(&destination_hash)?;
        #[cfg(feature = "embassy")]
        return Some(receiver.receive().await);
        #[cfg(feature = "tokio")]
        return receiver.recv().await;
    }

    // fn sender(
    //     &mut self,
    //     destination_hash: &TruncatedHash,
    // ) -> Option<Sender<'static, CriticalSectionRawMutex, Packet, 1>> {
    //     if let Some((sender, _receiver)) = self.messages.get(&destination_hash) {
    //         Some(sender.clone())
    //     } else {
    //         let channel = embassy_sync::channel::Channel::new();
    //         self.messages.insert(
    //             destination_hash.clone(),
    //             (channel.sender(), channel.receiver()),
    //         );
    //         Some(channel.sender())
    //     }
    // }
}

impl InMemoryMessageStore {
    pub fn new() -> InMemoryMessageStore {
        InMemoryMessageStore {
            messages: HashMap::new(),
        }
    }
}
