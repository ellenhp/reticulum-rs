#[cfg(all(test, feature = "stores"))]
pub mod in_memory;

pub mod destination;

use core::time::Duration;

use alloc::{boxed::Box, format, string::String, vec::Vec};
use async_trait::async_trait;
use log::warn;

use crate::{
    identity::{Identity, IdentityCommon},
    interface::InterfaceHandle,
    packet::{AnnouncePacket, Packet},
    NameHash, TruncatedHash,
};

use self::destination::{Destination, DestinationBuilder};

#[derive(Debug)]
pub enum PersistenceError {
    Unspecified(String),
}

#[async_trait]
pub trait ReticulumStore: Clone + Send + Sync + Sized + 'static {
    async fn poll_inbox(&self, destination_hash: &TruncatedHash) -> Option<Packet>;
    async fn next_inbox(&self, destination_hash: &TruncatedHash) -> Option<Packet>;

    async fn register_destination_name(
        &self,
        app_name: String,
        aspects: Vec<String>,
    ) -> Result<(), PersistenceError>;
    async fn get_destination_names(&self) -> Result<Vec<(String, Vec<String>)>, PersistenceError>;
    async fn register_local_destination(
        &self,
        destination: &Destination,
    ) -> Result<(), PersistenceError>;
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
    async fn get_all_destinations(&self) -> Result<Vec<Destination>, PersistenceError>;
    async fn get_destinations_by_identity_handle(
        &self,
        handle: &TruncatedHash,
    ) -> Result<Vec<Destination>, PersistenceError> {
        let all_destinations = self.get_all_destinations().await?;
        let mut matching_destinations = Vec::new();
        for destination in all_destinations {
            if let Some(identity) = destination.identity() {
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

    async fn add_destination(&self, destination: Destination) -> Result<(), PersistenceError>;
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
    async fn remove_destination(&self, destination: &Destination) -> Result<(), PersistenceError>;
}

#[derive(Clone)]
pub struct AnnounceTableEntry {
    #[cfg(feature = "embassy")]
    received_time: embassy_time::Instant,
    #[cfg(feature = "tokio")]
    received_time: tokio::time::Instant,
    _retransmit_timeout: Duration,
    _retries: u8,
    _received_from: Option<Identity>,
    destination: Destination,
    packet: AnnouncePacket,
    _local_rebroadcasts: u8,
    _block_rebroadcasts: bool,
    _attached_interface: Option<InterfaceHandle>,
}

#[async_trait]
pub trait MessageStore: Send + Sync + Sized + 'static {
    // fn sender(
    //     &mut self,
    //     destination_hash: &TruncatedHash,
    // ) -> Option<Sender<'static, CriticalSectionRawMutex, Packet, 1>>;
}
