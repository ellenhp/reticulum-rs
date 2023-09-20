use std::{
    borrow::{Borrow, BorrowMut},
    error::Error,
    sync::Arc,
    thread,
};

use log::{debug, trace, warn};
use smol::{
    channel::{Receiver, Sender},
    lock::Mutex,
    Task,
};

use crate::{
    identity::{Identity, IdentityCommon},
    interface::{self, Interface, InterfaceError},
    packet::{
        AnnouncePacket, Packet, PacketContextType, PacketHeaderVariable, PacketType, TransportType,
        WirePacket,
    },
    persistence::{AnnounceTable, DestinationStore, IdentityStore, MessageStore, PersistenceError},
};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("threading error: {0}")]
    Thread(Box<dyn Error>),
    #[error("persistence error: {0}")]
    Persistence(PersistenceError),
    #[error("unspecified error: {0}")]
    Unspecified(Box<dyn Error>),
}

pub(crate) struct Transport<DestStore: DestinationStore, MsgStore: MessageStore> {
    interfaces: Vec<Arc<dyn Interface>>,
    destination_store: Arc<Mutex<Box<DestStore>>>,
    message_store: Arc<Mutex<Box<MsgStore>>>,
}

impl<DestStore: DestinationStore + 'static, MsgStore: MessageStore + 'static>
    Transport<DestStore, MsgStore>
{
    pub fn new(
        interfaces: Vec<Arc<dyn Interface>>,
        destination_store: Arc<Mutex<Box<DestStore>>>,
        message_store: Arc<Mutex<Box<MsgStore>>>,
    ) -> Result<Transport<DestStore, MsgStore>, TransportError> {
        Transport::<DestStore, MsgStore>::spawn_processing_tasks(
            interfaces.clone(),
            destination_store.clone(),
            message_store.clone(),
        )?;
        Ok(Transport {
            destination_store,
            message_store,
            interfaces,
        })
    }

    pub async fn force_announce_all_local(&self) -> Result<(), TransportError> {
        let destinations = self
            .destination_store
            .lock()
            .await
            .get_all_destinations()
            .await
            .map_err(|err| TransportError::Persistence(err))?;
        for destination in destinations {
            match destination.identity() {
                Some(Identity::Local(_)) => {}
                _ => continue,
            }
            // Packet response doesn't make sense here if the intention is to force an announce.
            let packet = AnnouncePacket::new(destination, PacketContextType::None, vec![])
                .map_err(|err| TransportError::Unspecified(Box::new(err)))?;

            for interface in self.interfaces.clone() {
                let interface = interface.clone();
                let message = packet
                    .wire_packet()
                    .pack()
                    .map_err(|err| TransportError::Unspecified(Box::new(err)))?;
                let interface = interface;
                let message = message;
                interface.queue_send(&message).await.unwrap();
            }
        }
        Ok(())
    }

    fn spawn_processing_tasks(
        interfaces: Vec<Arc<dyn Interface>>,
        destination_store: Arc<Mutex<Box<DestStore>>>,
        message_store: Arc<Mutex<Box<MsgStore>>>,
    ) -> Result<(), TransportError> {
        let (packet_sender, packet_receiver) = smol::channel::bounded(32);
        for interface in interfaces {
            let interface = interface.clone();
            let packet_sender = packet_sender.clone();
            smol::spawn(async move {
                let interface = interface;
                trace!("Starting interface processing task");
                Self::recv_from_interface(interface.clone(), packet_sender.clone()).await
            })
            .detach();
        }
        smol::spawn(async move {
            let destination_store = destination_store.clone();
            let message_store = message_store.clone();
            let packet_receiver = packet_receiver;
            trace!("Starting packet processing task");
            Self::process_packets(packet_receiver, destination_store, message_store).await;
        })
        .detach();
        Ok(())
    }

    async fn recv_from_interface(
        interface: Arc<dyn crate::interface::Interface>,
        packet_sender: Sender<WirePacket>,
    ) {
        loop {
            let interface = interface.clone();
            let future = async move { interface.recv().await };
            let message = match future.await {
                Ok(message) => message,
                Err(InterfaceError::Recoverable(inner)) => {
                    debug!("Recoverable error: {:?}", inner);
                    continue;
                }
                Err(inner) => {
                    warn!("Unrecoverable error: {:?}", inner);
                    break;
                }
            };
            let packet = match WirePacket::unpack(&message) {
                Ok(packet) => packet,
                Err(_) => {
                    debug!("Failed to unpack packet");
                    continue;
                }
            };
            if let Err(err) = packet_sender.try_send(packet) {
                debug!("Failed to send packet to processing task: {:?}", err);
            }
        }
    }

    async fn announce_loop(
        interfaces: Vec<Arc<dyn Interface>>,
        destination_store: Arc<Mutex<Box<DestStore>>>,
        announce_table: Arc<Box<dyn AnnounceTable>>,
    ) {
        loop {}
    }

    async fn maybe_process_announce(
        semantic_packet: &Packet,
        destination_store: Arc<Mutex<Box<DestStore>>>,
    ) {
        match &semantic_packet {
            crate::packet::Packet::Announce(announce_packet) => {
                // Add to the identity store and announce table.
                let identity = announce_packet.identity();
                trace!("Resolving destination");
                let resolved_destination = {
                    let mut destination_store = destination_store.lock().await;
                    let resolved_destination = destination_store
                        .resolve_destination(&announce_packet.destination_name_hash(), identity);
                    resolved_destination.await
                };
                if let Some(destination) = resolved_destination {
                    let mut destination_store = destination_store.lock().await;
                    match destination_store.add_destination(&destination).await {
                        Ok(a) => {
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

    async fn process_packets(
        packet_receiver: Receiver<WirePacket>,
        destination_store: Arc<Mutex<Box<DestStore>>>,
        message_store: Arc<Mutex<Box<MsgStore>>>,
    ) {
        loop {
            trace!("Waiting for packet");
            let packet = packet_receiver.recv();
            let packet = if let Ok(packet) = packet.await {
                packet
            } else {
                debug!("Failed to receive packet from interface");
                continue;
            };
            trace!("Common: {:?}", packet.header().header_common());
            match packet.header().header_variable() {
                PacketHeaderVariable::LrProof(hash) => {
                    trace!("Received LR proof: {:?}", hash);
                }
                PacketHeaderVariable::Header1(header1) => {
                    trace!("Received header1: {:?}", header1);
                }
                PacketHeaderVariable::Header2(header2) => {
                    trace!("Received header2: {:?}", header2);
                }
            }
            let semantic_packet = match packet.into_semantic_packet() {
                Ok(semantic_packet) => {
                    trace!("Converted packet to semantic packet");
                    semantic_packet
                }
                Err(err) => {
                    debug!("Failed to convert packet to semantic packet: {:?}", err);
                    continue;
                }
            };
            trace!("Semantic packet: {:?}", semantic_packet);
            Self::maybe_process_announce(&semantic_packet, destination_store.clone()).await;
            if let Some(destination) = semantic_packet.destination(&destination_store).await {
                trace!("Destination: {:?}", destination);
                if let Some(Identity::Local(_)) = destination.identity() {
                    trace!("Destination is local");
                    if let Some(sender) = message_store
                        .lock()
                        .await
                        .as_mut()
                        .sender(&destination.truncated_hash())
                    {
                        match sender.try_send(semantic_packet) {
                            Ok(_) => {}
                            Err(err) => {
                                debug!("Failed to send packet to inbox: {:?}", err);
                            }
                        }
                    } else {
                        debug!("No sender found for local destination");
                    }
                } else {
                    trace!("Destination is not local");
                }
            } else {
                trace!("No destination found for packet");
            }
        }
    }
}
