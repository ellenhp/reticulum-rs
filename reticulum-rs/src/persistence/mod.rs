#[cfg(feature = "stores")]
pub mod in_memory;

pub mod destination;

use std::{
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use async_trait::async_trait;
use smol::{channel::Sender, lock::Mutex};

use crate::{
    identity::{self, Identity, IdentityCommon},
    interface::InterfaceHandle,
    packet::{AnnouncePacket, Packet},
    TruncatedHash,
};

use self::destination::{Destination, DestinationBuilder};

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
pub trait DestinationStore: Send + Sync + Sized + 'static {
    fn register_destination_name(
        &mut self,
        app_name: String,
        aspects: Vec<String>,
    ) -> Result<(), PersistenceError>;
    fn get_destination_names(&self) -> Result<Vec<(String, Vec<String>)>, PersistenceError>;
    fn register_local_destination(
        &mut self,
        destination: &Destination,
    ) -> Result<(), PersistenceError>;
    fn builder(&self, app_name: &str) -> DestinationBuilder {
        Destination::builder(app_name)
    }
    async fn resolve_destination(
        &mut self,
        hash: &TruncatedHash,
        identity: &Identity,
    ) -> Option<Destination> {
        if let Ok(Some(destination)) = self.get_destination(hash).await {
            if destination.truncated_hash() == *hash {
                return Some(destination);
            }
        }
        let destination_names = if let Ok(names) = self.get_destination_names() {
            names
        } else {
            println!("error getting destination names");
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
                return None;
            };
            if destination.truncated_hash() == *hash {
                self.add_destination(&destination).await.unwrap();
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

    async fn add_destination(&mut self, destination: &Destination) -> Result<(), PersistenceError>;
    async fn get_destination(
        &self,
        hash: &TruncatedHash,
    ) -> Result<Option<Destination>, PersistenceError> {
        let all_destinations = self.get_all_destinations().await?;
        for existing_destination in all_destinations {
            if &existing_destination.truncated_hash() == hash {
                return Ok(Some(existing_destination));
            }
        }
        Ok(None)
    }
    async fn remove_destination(
        &mut self,
        destination: &Destination,
    ) -> Result<(), PersistenceError>;
}

pub type AnnounceTableEntryArc = Arc<AnnounceTableEntry>;

#[derive(Debug, Clone)]
pub struct AnnounceTableEntry {
    received_time: Instant,
    retransmit_timeout: Duration,
    retries: u8,
    received_from: Option<Identity>,
    destination: Arc<Destination>,
    packet: AnnouncePacket,
    local_rebroadcasts: u8,
    block_rebroadcasts: bool,
    attached_interface: Option<InterfaceHandle>,
}

#[async_trait]
pub trait AnnounceTable {
    async fn table_iter(&self) -> Box<dyn Iterator<Item = AnnounceTableEntryArc>>;

    async fn push_announce(
        &mut self,
        announce: AnnounceTableEntryArc,
    ) -> Result<(), PersistenceError>;

    async fn expire_announces(&mut self, max_age: Duration) -> Result<(), PersistenceError>;

    async fn get_announce_by_destination(
        &self,
        destination: &Destination,
    ) -> Result<Option<AnnounceTableEntryArc>, PersistenceError> {
        let all_announces = self.table_iter().await;
        let mut matching_announces = Vec::new();
        let mut earliest_receipt = None;
        for announce in all_announces {
            if announce.destination.truncated_hash() == destination.truncated_hash() {
                earliest_receipt = if let Some(receipt) = earliest_receipt {
                    if announce.received_time < receipt {
                        Some(announce.received_time)
                    } else {
                        Some(receipt)
                    }
                } else {
                    Some(announce.received_time)
                };
                matching_announces.push(announce);
            }
        }
        if matching_announces.is_empty() {
            return Ok(None);
        }
        let earliest_receipt = if let Some(earliest_receipt) = earliest_receipt {
            earliest_receipt
        } else {
            println!("no earliest receipt, but have packets, this should be unreachable");
            return Ok(None);
        };
        let mut best_latency = u64::MAX;
        let mut top_announce = None;
        for announce in matching_announces {
            let hops = announce
                .packet
                .wire_packet()
                .header()
                .header_common()
                .hops() as i32;
            let age_seconds = announce
                .received_time
                .duration_since(earliest_receipt)
                .as_secs();
            // Penalize hops by assuming they take about 15 minutes.
            let estimated_latency = (hops as u64 * 60 * 15) + age_seconds;
            if estimated_latency < best_latency {
                best_latency = estimated_latency;
                top_announce = Some(announce);
            }
        }

        Ok(top_announce)
    }
}

#[async_trait]
pub trait MessageStore: Send + Sync + Sized + 'static {
    fn poll_inbox(&self, destination_hash: &TruncatedHash) -> Option<Packet>;
    async fn next_inbox(&self, destination_hash: &TruncatedHash) -> Option<Packet>;
    fn sender(&self, destination_hash: &TruncatedHash) -> Option<Sender<Packet>>;
}
