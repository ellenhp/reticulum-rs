pub mod destination;
pub mod in_memory;

use core::time::Duration;

use alloc::{boxed::Box, string::String, vec::Vec};
use async_trait::async_trait;

use crate::{
    identity::Identity,
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
pub trait ReticulumStore: Send + Sync + 'static {
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
    async fn get_local_destinations(&self) -> Result<Vec<Destination>, PersistenceError>;
    async fn get_peer_destinations(&self) -> Result<Vec<Destination>, PersistenceError>;
    fn destination_builder(&self, app_name: &str) -> DestinationBuilder;
    async fn resolve_destination(
        &self,
        hash: &NameHash,
        identity: &Identity,
    ) -> Option<Destination>;
    async fn get_all_destinations(&self) -> Result<Vec<Destination>, PersistenceError>;
    async fn get_destinations_by_identity_handle(
        &self,
        handle: &TruncatedHash,
    ) -> Result<Vec<Destination>, PersistenceError>;
    async fn get_destinations_by_name(
        &self,
        name: &str,
    ) -> Result<Vec<Destination>, PersistenceError>;

    async fn add_destination(&self, destination: Destination) -> Result<(), PersistenceError>;
    async fn get_destination(
        &self,
        hash: &NameHash,
    ) -> Result<Option<Destination>, PersistenceError>;
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
