#![no_std]
#![feature(async_closure)]
#![feature(error_in_core)]
#![feature(type_alias_impl_trait)]

extern crate alloc;

use core::error::Error;

use alloc::{boxed::Box, string::String, vec::Vec};
pub use fernet;
use identity::Identity;
use interface::{ChannelData, Interface, InterfaceError};
use log::{debug, trace, warn};
use packet::{AnnouncePacket, Packet, PacketContextType, PacketError, WirePacket};
use persistence::{destination::Destination, PersistenceError, ReticulumStore};

use crate::packet::PacketHeaderVariable;

pub mod constants;
pub mod identity;
pub mod interface;
pub mod packet;
pub mod persistence;
pub mod random;

#[derive(Debug)]
pub enum ReticulumError {
    Persistence(PersistenceError),
    Interface(InterfaceError),
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
pub struct TruncatedHash([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NameHash([u8; 10]);

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

pub struct Reticulum<'a> {
    interfaces: &'a [Box<dyn Interface>],
    #[cfg(feature = "tokio")]
    packet_sender: PacketSender,
    #[cfg(feature = "tokio")]
    packet_receiver: tokio::sync::Mutex<PacketReceiver>,
    #[cfg(feature = "embassy")]
    channel: embassy_sync::channel::Channel<
        embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
        PacketChannelData,
        1,
    >,
    reticulum_store: &'a Box<dyn ReticulumStore>,
}

impl<'a> Reticulum<'a> {
    #[cfg(feature = "tokio")]
    pub fn new(
        interfaces: &'a [Box<dyn Interface>],
        reticulum_store: &'a Box<dyn ReticulumStore>,
    ) -> Result<Reticulum<'a>, ReticulumError> {
        let (packet_sender, mut packet_receiver) = tokio::sync::mpsc::channel(10);

        let store = &reticulum_store;

        return Ok(Reticulum {
            packet_sender,
            packet_receiver: tokio::sync::Mutex::new(packet_receiver),
            interfaces,
            reticulum_store,
        });
    }

    #[cfg(feature = "embassy")]
    pub async fn new_from_channel(
        interfaces: &'a [Box<dyn Interface>],
        reticulum_store: &'a Box<dyn ReticulumStore>,
        channel: embassy_sync::channel::Channel<
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            PacketChannelData,
            1,
        >,
        spawner: embassy_executor::Spawner,
    ) -> Result<Reticulum<'a>, ReticulumError> {
        let interfaces = interfaces;
        let channel = channel;
        let node = Reticulum {
            interfaces,
            channel,
            reticulum_store,
        };
        spawner.spawn(embassy_process_packets_task()).unwrap();
        spawner.spawn(embassy_process_interface_tasks()).unwrap();
        return Ok(node);
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

    pub async fn force_announce_all_local(&self) -> Result<(), TransportError> {
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

            for interface in self.interfaces {
                let message = packet
                    .wire_packet()
                    .pack()
                    .map_err(|err| TransportError::Packet(err))?;
                let interface = interface;
                let message = message;
                interface.queue_send(&message).await.unwrap();
            }
        }
        Ok(())
    }

    async fn interface_receive_loop(interface: &Box<dyn Interface>, packet_sender: &PacketSender) {
        loop {
            let future = interface.recv();
            let message = match future.await {
                Ok(message) => message,
                Err(InterfaceError::Recoverable(inner)) => {
                    panic!();
                    debug!("Recoverable error: {:?}", inner);
                    continue;
                }
                Err(inner) => {
                    panic!();
                    warn!("Unrecoverable error: {:?}", inner);
                    break;
                }
            };
            let message = match message {
                ChannelData::Message(message) => message,
                ChannelData::Close => {
                    panic!();
                    break;
                }
            };
            let packet = match WirePacket::unpack(&message) {
                Ok(packet) => packet,
                Err(_) => {
                    panic!();
                    debug!("Failed to unpack packet");
                    continue;
                }
            };
            if let Err(err) = packet_sender.try_send(PacketChannelData::Packet(packet)) {
                panic!();
                debug!("Failed to send packet to processing task");
            }
        }
        #[cfg(feature = "embassy")]
        packet_sender.send(PacketChannelData::Close).await;
        #[cfg(feature = "tokio")]
        packet_sender.send(PacketChannelData::Close).await.unwrap();
    }

    async fn maybe_process_announce(
        semantic_packet: &Packet,
        reticulum_store: &Box<dyn ReticulumStore>,
    ) {
        match &semantic_packet {
            crate::packet::Packet::Announce(announce_packet) => {
                // Add to the identity store and announce table.
                let identity = announce_packet.identity();
                trace!("Resolving destination");
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
                        Err(err) => {
                            debug!("Failed to add destination to store: {:?}", err);
                        }
                    }
                } else {
                    trace!("Failed to resolve destination");
                }
            }
            crate::packet::Packet::Other(_) => todo!(),
        }
    }

    pub async fn packet_process_iter(&self) -> Result<(), ()> {
        trace!("Waiting for packet");
        #[cfg(feature = "embassy")]
        let packet = self.channel.receive().await;
        #[cfg(feature = "tokio")]
        let packet = self.packet_receiver.lock().await.recv().await.unwrap();
        let packet = match packet {
            PacketChannelData::Packet(packet) => packet,
            PacketChannelData::Close => {
                debug!("Received close message");
                return Err(());
            }
        };
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
            Err(err) => {
                debug!("Failed to convert packet to semantic packet: {:?}", err);
                return Ok(());
            }
        };
        // trace!("Semantic packet: {:?}", semantic_packet);
        Self::maybe_process_announce(&semantic_packet, &self.reticulum_store).await;
        if let Some(destination) = semantic_packet.destination(&self.reticulum_store).await {
            trace!("Destination: {:?}", destination);
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

#[cfg(feature = "embassy")]
#[embassy_executor::task]
async fn embassy_process_packets_task() {}

#[cfg(feature = "embassy")]
#[embassy_executor::task]
async fn embassy_process_interface_tasks() {}

#[cfg(test)]
mod test {
    #[cfg(test)]
    extern crate std;
    #[cfg(feature = "tokio")]
    extern crate tokio;

    use crate::{
        identity::Identity,
        interface::{channel::ChannelInterface, Interface},
        persistence::{
            destination::Destination, in_memory::InMemoryReticulumStore, ReticulumStore,
        },
        Reticulum,
    };
    use alloc::{boxed::Box, string::ToString, vec::Vec};
    use log::warn;
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

    async fn create_node<'a>(
        interfaces: &'a [Box<dyn Interface>],
        store: &'a Box<dyn ReticulumStore>,
    ) -> Reticulum<'a> {
        store
            .register_destination_name("app".to_string(), Vec::new())
            .await
            .unwrap();

        let node = Reticulum::new(interfaces, &store).unwrap();
        node
    }

    async fn setup_node<'a>(node: &'a Reticulum<'a>) -> Destination {
        let builder = node.reticulum_store.destination_builder("app");
        let destination = builder
            .build_single(&Identity::new_local().await, &node.reticulum_store)
            .await
            .unwrap();
        destination
    }

    #[test]
    fn test_announce() {
        init_test();
        tokio_test::block_on(async {
            let interface1 = ChannelInterface::new();
            let interface2 = interface1.clone().await;
            let store: Box<dyn ReticulumStore> = Box::new(InMemoryReticulumStore::new());
            let interface1: Box<dyn Interface> = Box::new(interface1);
            let interface2: Box<dyn Interface> = Box::new(interface2);
            let interfaces1 = &[interface1];
            let interfaces2 = &[interface2];
            let reticulum1 = create_node(interfaces1, &store).await;
            let reticulum2 = create_node(interfaces2, &store).await;
            let node1 = &reticulum1;
            let node2 = &reticulum2;
            let destination1 = setup_node(&node1).await;
            // let destination2 = setup_node(&node2).await;

            node1.force_announce_all_local().await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            assert_eq!(node2.get_known_destinations().await.len(), 1);
        })
    }

    #[test]
    fn test_announce_bidirectional() {
        init_test();
        tokio_test::block_on(async {
            let interface1 = ChannelInterface::new();
            let interface2 = interface1.clone().await;
            let store: Box<dyn ReticulumStore> = Box::new(InMemoryReticulumStore::new());
            let interface1: Box<dyn Interface> = Box::new(interface1);
            let interface2: Box<dyn Interface> = Box::new(interface2);
            let interfaces1 = &[interface1];
            let interfaces2 = &[interface2];
            let reticulum1 = create_node(interfaces1, &store).await;
            let reticulum2 = create_node(interfaces2, &store).await;
            let node1 = &reticulum1;
            let node2 = &reticulum2;
            let destination1 = setup_node(&node1).await;
            let destination2 = setup_node(&node2).await;
            warn!("destination1: {:?}", destination1);
            warn!("destination2: {:?}", destination2);

            node1.force_announce_all_local().await.unwrap();
            node2.force_announce_all_local().await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            assert_eq!(node1.get_known_destinations().await.len(), 2);
            assert_eq!(node2.get_known_destinations().await.len(), 2);
        })
    }
}
