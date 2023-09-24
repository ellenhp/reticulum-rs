use alloc::boxed::Box;
use alloc::format;
use alloc::{string::String, vec::Vec};
use async_trait::async_trait;
use defmt::{trace, warn};

use crate::identity::Identity;
use crate::NameHash;
use crate::{identity::IdentityCommon, packet::Packet, TruncatedHash};

use super::destination::DestinationBuilder;
use super::ReticulumStore;
use super::{destination::Destination, PersistenceError};

pub struct InMemoryReticulumStore {
    #[cfg(feature = "embassy")]
    destination_names: embassy_sync::mutex::Mutex<
        embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
        Vec<(String, Vec<String>)>,
    >,
    #[cfg(feature = "tokio")]
    destination_names: tokio::sync::Mutex<Vec<(String, Vec<String>)>>,
    #[cfg(feature = "embassy")]
    destinations: embassy_sync::mutex::Mutex<
        embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
        Vec<(String, Destination)>,
    >,
    #[cfg(feature = "tokio")]
    destinations: tokio::sync::Mutex<Vec<(String, Destination)>>,
    #[cfg(feature = "embassy")]
    messages: embassy_sync::mutex::Mutex<
        embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
        Vec<(
            TruncatedHash,
            embassy_sync::channel::Channel<
                embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
                Packet,
                1,
            >,
        )>,
    >,
    #[cfg(feature = "tokio")]
    messages: tokio::sync::Mutex<
        Vec<(
            TruncatedHash,
            (
                tokio::sync::mpsc::Sender<Packet>,
                tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Packet>>,
            ),
        )>,
    >,
}

impl InMemoryReticulumStore {
    pub fn new() -> InMemoryReticulumStore {
        InMemoryReticulumStore {
            #[cfg(feature = "embassy")]
            messages: embassy_sync::mutex::Mutex::new(Vec::new()),
            #[cfg(feature = "tokio")]
            messages: tokio::sync::Mutex::new(Vec::new()),
            #[cfg(feature = "embassy")]
            destination_names: embassy_sync::mutex::Mutex::new(Vec::new()),
            #[cfg(feature = "tokio")]
            destination_names: tokio::sync::Mutex::new(Vec::new()),
            #[cfg(feature = "embassy")]
            destinations: embassy_sync::mutex::Mutex::new(Vec::new()),
            #[cfg(feature = "tokio")]
            destinations: tokio::sync::Mutex::new(Vec::new()),
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
            .push((destination.full_name(), destination.clone()));
        Ok(())
    }

    async fn get_destination_names(&self) -> Result<Vec<(String, Vec<String>)>, PersistenceError> {
        Ok(self.destination_names.lock().await.clone())
    }

    async fn get_all_destinations(&self) -> Result<Vec<Destination>, PersistenceError> {
        let mut all_destinations = Vec::new();
        for (_, destination) in self.destinations.lock().await.iter() {
            all_destinations.push(destination.clone());
        }
        Ok(all_destinations)
    }

    async fn get_destinations_by_identity_handle(
        &self,
        handle: &TruncatedHash,
    ) -> Result<Vec<Destination>, PersistenceError> {
        let mut matching_destinations = Vec::new();
        for (_, destination) in self.destinations.lock().await.iter() {
            if let Some(identity) = destination.identity() {
                if &identity.handle() == handle {
                    matching_destinations.push(destination.clone());
                }
            }
        }
        Ok(matching_destinations)
    }

    async fn add_destination(&self, destination: Destination) -> Result<(), PersistenceError> {
        let name = destination.full_name();
        if !self
            .destinations
            .lock()
            .await
            .iter()
            .any(|(key, _)| key == &name)
        {
            self.destinations
                .lock()
                .await
                .push((destination.full_name(), destination.clone()));
        } else {
            trace!("destination already exists");
        }
        Ok(())
    }

    async fn remove_destination(&self, destination: &Destination) -> Result<(), PersistenceError> {
        let mut destinations = self.destinations.lock().await;
        *destinations = destinations
            .iter()
            .filter(|(_, existing_destination)| {
                existing_destination.address_hash() != destination.address_hash()
            })
            .cloned()
            .collect();
        Ok(())
    }
    async fn poll_inbox(&self, destination_hash: &TruncatedHash) -> Option<Packet> {
        #[cfg(feature = "embassy")]
        {
            let messages = self.messages.lock().await;
            let (_hash, channel) = messages
                .iter()
                .filter(|(hash, _)| hash == destination_hash)
                .next()?;
            match channel.try_receive() {
                Ok(packet) => Some(packet),
                // TODO: Do these errors mean we need to do something?
                Err(_) => None,
            }
        }
        #[cfg(feature = "tokio")]
        {
            let mut messages = self.messages.lock().await;
            let (_, (_sender, receiver)) = messages
                .iter_mut()
                .filter(|(hash, _)| hash == destination_hash)
                .next()?;
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
            let messages = self.messages.lock().await;
            let (_hash, channel) = messages
                .iter()
                .filter(|(hash, _)| hash == destination_hash)
                .next()?;
            return Some(channel.receive().await);
        }
        #[cfg(feature = "tokio")]
        {
            let mut messages = self.messages.lock().await;
            let (_, (_sender, receiver)) = messages
                .iter_mut()
                .filter(|(hash, _)| hash == destination_hash)
                .next()?;
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
