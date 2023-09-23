use core::borrow::BorrowMut;
use core::error::Error;

use alloc::{boxed::Box, vec::Vec};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Receiver, Sender};
use embassy_sync::mutex::Mutex;
use log::{debug, trace, warn};

use crate::packet::PacketError;
use crate::{
    identity::Identity,
    interface::{Interface, InterfaceError},
    packet::{AnnouncePacket, Packet, PacketContextType, PacketHeaderVariable, WirePacket},
    persistence::{AnnounceTable, DestinationStore, MessageStore, PersistenceError},
};

#[derive(Debug)]
pub enum TransportError {
    Thread(Box<dyn Error>),
    Persistence(PersistenceError),
    Packet(PacketError),
    Unspecified(Box<dyn Error>),
}

pub(crate) struct Transport<
    'a,
    DestStore: DestinationStore,
    MsgStore: MessageStore,
    Iface: Interface,
> {
    pub(crate) interfaces: &'a [Iface],
    pub(crate) destination_store: Mutex<CriticalSectionRawMutex, Box<DestStore>>,
    pub(crate) message_store: Mutex<CriticalSectionRawMutex, Box<MsgStore>>,
}

impl<
        'a,
        DestStore: DestinationStore + 'static,
        MsgStore: MessageStore + 'static,
        Iface: Interface + 'static,
    > Transport<'a, DestStore, MsgStore, Iface>
{
    pub fn new(
        interfaces: &'a [Iface],
        destination_store: Mutex<CriticalSectionRawMutex, Box<DestStore>>,
        message_store: Mutex<CriticalSectionRawMutex, Box<MsgStore>>,
    ) -> Result<Transport<'a, DestStore, MsgStore, Iface>, TransportError> {
        // Transport::<DestStore, MsgStore, Iface>::spawn_processing_tasks(
        //     interfaces.clone(),
        //     destination_store.clone(),
        //     message_store.clone(),
        // )?;
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
            let packet = AnnouncePacket::new(destination, PacketContextType::None, Vec::new())
                .await
                .map_err(|err| TransportError::Packet(err))?;

            for interface in self.interfaces.clone() {
                let interface = interface.clone();
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

    // fn spawn_processing_tasks(
    //     interfaces: &'a [Iface>],
    //     destination_store: Mutex<CriticalSectionRawMutex, Box<DestStore>>,
    //     message_store: Mutex<CriticalSectionRawMutex, Box<MsgStore>>,
    // ) -> Result<(), TransportError> {
    //     // let channel = embassy_sync::channel::Channel::new();
    //     // for interface in interfaces {
    //     //     let interface = interface.clone();
    //     //     let packet_sender = channel.sender();
    //     //     smol::spawn(async move {
    //     //         let interface = interface;
    //     //         trace!("Starting interface processing task");
    //     //         Self::recv_from_interface(interface.clone(), packet_sender.clone()).await
    //     //     })
    //     //     .detach();
    //     // }
    //     // smol::spawn(async move {
    //     //     let destination_store = destination_store.clone();
    //     //     let message_store = message_store.clone();
    //     //     let packet_receiver = channel.receiver();
    //     //     trace!("Starting packet processing task");
    //     //     Self::process_packets(packet_receiver, destination_store, message_store).await;
    //     // })
    //     // .detach();
    //     Ok(())
    // }

    async fn recv_from_interface(
        interface: Iface,
        packet_sender: Sender<'static, CriticalSectionRawMutex, WirePacket, 1>,
    ) {
        loop {
            let future = interface.recv();
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
                debug!("Failed to send packet to processing task");
            }
        }
    }

    async fn maybe_process_announce(
        semantic_packet: &Packet,
        destination_store: &Mutex<CriticalSectionRawMutex, Box<DestStore>>,
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
                    match destination_store.add_destination(destination).await {
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
        packet_receiver: Receiver<'static, CriticalSectionRawMutex, WirePacket, 1>,
        destination_store: Mutex<CriticalSectionRawMutex, Box<DestStore>>,
        message_store: Mutex<CriticalSectionRawMutex, Box<MsgStore>>,
    ) {
        loop {
            trace!("Waiting for packet");
            let packet = packet_receiver.receive().await;
            // trace!("Common: {:?}", packet.header().header_common());
            match packet.header().header_variable() {
                PacketHeaderVariable::LrProof(hash) => {
                    // trace!("Received LR proof: {:?}", hash);
                }
                PacketHeaderVariable::Header1(header1) => {
                    // trace!("Received header1: {:?}", header1);
                }
                PacketHeaderVariable::Header2(header2) => {
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
                    continue;
                }
            };
            // trace!("Semantic packet: {:?}", semantic_packet);
            Self::maybe_process_announce(&semantic_packet, &destination_store).await;
            if let Some(destination) = semantic_packet.destination(&destination_store).await {
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
        }
    }
}
