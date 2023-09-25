#![no_std]
#![feature(async_closure)]
#![feature(error_in_core)]
#![feature(type_alias_impl_trait)]

extern crate alloc;

use core::error::Error;

#[cfg(feature = "embassy")]
use defmt::*;
#[cfg(feature = "tokio")]
use log::*;

use alloc::{boxed::Box, string::String, vec::Vec};
pub use fernet;
use identity::Identity;
use packet::{AnnouncePacket, Packet, PacketContextType, PacketError, WirePacket};
use persistence::{destination::Destination, PersistenceError, ReticulumStore};
use sha2::{Digest, Sha256};

use crate::{identity::IdentityCommon, packet::PacketHeaderVariable};

pub mod constants;
pub mod identity;
pub mod packet;
pub mod persistence;
pub mod random;

#[derive(Debug)]
pub enum ReticulumError {
    Persistence(PersistenceError),
    Transport(TransportError),
    Unspecified(Box<dyn Error>),
}

#[derive(Debug)]
pub enum TransportError {
    Thread(Box<dyn Error>),
    Persistence(PersistenceError),
    Packet(PacketError),
    Unspecified(Box<dyn Error>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TruncatedHash(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NameHash(pub [u8; 10]);

pub enum PacketChannelData {
    Packet(WirePacket),
    Close,
}

#[cfg(feature = "embassy")]
pub type PacketSender = embassy_sync::channel::Sender<
    'static,
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    PacketChannelData,
    1,
>;

#[cfg(feature = "embassy")]
pub type PacketReceiver = embassy_sync::channel::Receiver<
    'static,
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    PacketChannelData,
    1,
>;

#[cfg(feature = "tokio")]
pub type PacketSender = tokio::sync::mpsc::Sender<PacketChannelData>;

#[cfg(feature = "tokio")]
pub type PacketReceiver = tokio::sync::mpsc::Receiver<PacketChannelData>;

#[derive(Clone)]
pub struct Reticulum<'a> {
    #[cfg(feature = "embassy")]
    reticulum_store: &'a Box<dyn ReticulumStore>,
    #[cfg(feature = "tokio")]
    reticulum_store: alloc::sync::Arc<Box<dyn ReticulumStore>>,
    _phantom: core::marker::PhantomData<&'a ()>,
}

impl<'a> Reticulum<'a> {
    #[cfg(feature = "embassy")]
    pub fn new(
        reticulum_store: &'a Box<dyn ReticulumStore>,
    ) -> Result<Reticulum<'a>, ReticulumError> {
        return Ok(Reticulum {
            reticulum_store,
            _phantom: core::marker::PhantomData,
        });
    }
    #[cfg(feature = "tokio")]
    pub fn new(
        reticulum_store: alloc::sync::Arc<Box<dyn ReticulumStore>>,
    ) -> Result<Reticulum<'a>, ReticulumError> {
        return Ok(Reticulum {
            reticulum_store,
            _phantom: core::marker::PhantomData,
        });
    }

    pub async fn get_known_destinations(&self) -> Vec<Destination> {
        self.reticulum_store.get_all_destinations().await.unwrap()
    }

    pub async fn get_local_destinations(&self) -> Vec<Destination> {
        let all_destinations = self.reticulum_store.get_all_destinations().await.unwrap();
        let mut local_destinations = Vec::new();
        for destination in all_destinations {
            if let Some(Identity::Local(_)) = destination.identity() {
                local_destinations.push(destination);
            }
        }
        local_destinations
    }

    pub async fn get_peer_destinations(&self) -> Result<Vec<Destination>, PersistenceError> {
        let all_destinations = self.reticulum_store.get_all_destinations().await.unwrap();
        let mut peer_destinations = Vec::new();
        for destination in all_destinations {
            if let Some(Identity::Peer(_)) = destination.identity() {
                peer_destinations.push(destination);
            }
        }
        Ok(peer_destinations)
    }

    pub async fn register_destination_prefix(
        &self,
        app_name: String,
        aspects: Vec<String>,
    ) -> Result<(), PersistenceError> {
        self.reticulum_store
            .register_destination_name(app_name, aspects)
            .await
    }

    pub async fn poll_inbox(&self, destination: &TruncatedHash) -> Option<Packet> {
        self.reticulum_store.poll_inbox(destination).await
    }

    pub async fn next_inbox(&self, destination: &TruncatedHash) -> Option<Packet> {
        self.reticulum_store.next_inbox(destination).await
    }

    pub async fn announce_local_destinations(&self) -> Result<Vec<WirePacket>, TransportError> {
        let mut packets = Vec::new();
        let destinations = self
            .reticulum_store
            .get_all_destinations()
            .await
            .map_err(|err| TransportError::Persistence(err))?;
        for destination in destinations {
            match destination.identity() {
                Some(Identity::Local(_)) => {}
                _ => continue,
            }

            // Packet response doesn't make sense here if the intention is to force an announce.
            let packet = AnnouncePacket::new(destination, PacketContextType::None, Vec::new())
                .await
                .map_err(|err| TransportError::Packet(err))?;

            packets.push(packet.wire_packet().clone());
        }
        Ok(packets)
    }

    async fn maybe_process_announce(
        semantic_packet: &Packet,
        reticulum_store: &Box<dyn ReticulumStore>,
    ) {
        match &semantic_packet {
            crate::packet::Packet::Announce(announce_packet) => {
                // Add to the identity store and announce table.
                let identity = announce_packet.identity();
                trace!(
                    "name then identity truncated hashes (real) {:?}\n{:?}",
                    hex::encode(announce_packet.destination_name_hash().0),
                    hex::encode(identity.truncated_hash())
                );
                let mut hasher = sha2::Sha256::new();
                hasher.update(announce_packet.destination_name_hash().0);
                hasher.update(identity.truncated_hash());
                let destination_hash = hasher.finalize();
                trace!("Destination hash: {:?}", hex::encode(destination_hash));
                let resolved_destination = {
                    let resolved_destination = reticulum_store
                        .resolve_destination(&announce_packet.destination_name_hash(), identity);
                    resolved_destination.await
                };
                if let Some(destination) = resolved_destination {
                    match reticulum_store.add_destination(destination).await {
                        Ok(_) => {
                            trace!("Added destination to store");
                        }
                        Err(_err) => {
                            debug!("Failed to add destination to store");
                        }
                    }
                } else {
                    trace!("Failed to resolve destination");
                }
            }
            crate::packet::Packet::Other(_) => {}
        }
    }

    pub async fn process_packet(&self, packet: WirePacket) -> Result<(), ()> {
        // trace!("Common: {:?}", packet.header().header_common());
        match packet.header().header_variable() {
            PacketHeaderVariable::LrProof(_hash) => {
                // trace!("Received LR proof: {:?}", hash);
            }
            PacketHeaderVariable::Header1(_header1) => {
                // trace!("Received header1: {:?}", header1);
            }
            PacketHeaderVariable::Header2(_header2) => {
                // trace!("Received header2: {:?}", header2);
            }
        }
        let semantic_packet = match packet.into_semantic_packet() {
            Ok(semantic_packet) => {
                trace!("Converted packet to semantic packet");
                semantic_packet
            }
            Err(_err) => {
                debug!("Failed to convert packet to semantic packet");
                return Ok(());
            }
        };
        // trace!("Semantic packet: {:?}", semantic_packet);
        Self::maybe_process_announce(&semantic_packet, &self.reticulum_store).await;
        if let Some(destination) = semantic_packet.destination(&self.reticulum_store).await {
            if let Some(Identity::Local(_)) = destination.identity() {
                trace!("Destination is local");
                // if let Some(sender) = message_store
                //     .lock()
                //     .await
                //     .as_mut()
                //     .sender(&destination.address_hash())
                // {
                //     match sender.try_send(semantic_packet) {
                //         Ok(_) => {}
                //         Err(err) => {
                //             debug!("Failed to send packet to inbox");
                //         }
                //     }
                // } else {
                //     debug!("No sender found for local destination");
                // }
            } else {
                trace!("Destination is not local");
            }
        } else {
            trace!("No destination found for packet");
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    #[cfg(test)]
    extern crate std;
    #[cfg(feature = "tokio")]
    extern crate tokio;

    use crate::{
        identity::Identity,
        persistence::{
            destination::Destination, in_memory::InMemoryReticulumStore, ReticulumStore,
        },
        Reticulum,
    };
    use alloc::{boxed::Box, string::ToString, sync::Arc, vec::Vec};
    use rand::Rng;
    use rand_chacha::rand_core::OsRng;

    pub(crate) fn init_test() {
        let _ = env_logger::try_init();

        tokio_test::block_on(async {
            let mut seed = [0; 32];
            OsRng.fill(&mut seed);
            crate::random::init_from_seed(seed).await;
        });
    }

    async fn create_node<'a>(store: Arc<Box<dyn ReticulumStore>>) -> Reticulum<'a> {
        store
            .register_destination_name("app".to_string(), Vec::new())
            .await
            .unwrap();

        let node = Reticulum::new(store).unwrap();
        node
    }

    async fn setup_node<'a>(node: &'a Reticulum<'a>) -> Destination {
        let builder = node.reticulum_store.destination_builder("app");
        let destination = builder
            .build_single(&Identity::new_local().await, node.reticulum_store.as_ref())
            .await
            .unwrap();
        destination
    }

    #[test]
    fn test_announce() {
        init_test();
        tokio_test::block_on(async {
            let store1: Arc<Box<dyn ReticulumStore>> =
                Arc::new(Box::new(InMemoryReticulumStore::new()));
            let store2: Arc<Box<dyn ReticulumStore>> =
                Arc::new(Box::new(InMemoryReticulumStore::new()));
            let reticulum1 = create_node(store1.clone()).await;
            let reticulum2 = create_node(store2.clone()).await;
            let node1 = &reticulum1;
            let node2 = &reticulum2;
            let _destination1 = setup_node(&node1).await;
            // let destination2 = setup_node(&node2).await;

            assert_eq!(node2.get_known_destinations().await.len(), 0);
            let packets = node1.announce_local_destinations().await.unwrap();
            assert_eq!(packets.len(), 1);
            for packet in packets {
                node2.process_packet(packet).await.unwrap();
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            assert_eq!(node2.get_known_destinations().await.len(), 1);
        })
    }

    #[test]
    fn test_announce_bidirectional() {
        init_test();
        tokio_test::block_on(async {
            let store1: Arc<Box<dyn ReticulumStore>> =
                Arc::new(Box::new(InMemoryReticulumStore::new()));
            let store2: Arc<Box<dyn ReticulumStore>> =
                Arc::new(Box::new(InMemoryReticulumStore::new()));
            let reticulum1 = create_node(store1.clone()).await;
            let reticulum2 = create_node(store2.clone()).await;
            let node1 = &reticulum1;
            let node2 = &reticulum2;
            let _destination1 = setup_node(&node1).await;
            let _destination2 = setup_node(&node2).await;

            assert_eq!(node1.get_local_destinations().await.len(), 1);
            assert_eq!(node2.get_local_destinations().await.len(), 1);
            for packet in node1.announce_local_destinations().await.unwrap() {
                node2.process_packet(packet).await.unwrap();
            }
            for packet in node2.announce_local_destinations().await.unwrap() {
                node1.process_packet(packet).await.unwrap();
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            assert_eq!(node1.get_known_destinations().await.len(), 2);
            assert_eq!(node2.get_known_destinations().await.len(), 2);
        })
    }

    #[test]
    fn test_encrypted_packet() {
        init_test();
        tokio_test::block_on(async {
            let store1: Arc<Box<dyn ReticulumStore>> =
                Arc::new(Box::new(InMemoryReticulumStore::new()));
            let store2: Arc<Box<dyn ReticulumStore>> =
                Arc::new(Box::new(InMemoryReticulumStore::new()));
            let reticulum1 = create_node(store1.clone()).await;
            let reticulum2 = create_node(store2.clone()).await;
            let node1 = &reticulum1;
            let node2 = &reticulum2;
            let _destination1 = setup_node(&node1).await;
            let _destination2 = setup_node(&node2).await;

            assert_eq!(node1.get_local_destinations().await.len(), 1);
            assert_eq!(node2.get_local_destinations().await.len(), 1);
            for packet in node1.announce_local_destinations().await.unwrap() {
                node2.process_packet(packet).await.unwrap();
            }
            for packet in node2.announce_local_destinations().await.unwrap() {
                node1.process_packet(packet).await.unwrap();
            }
        })
    }
}
