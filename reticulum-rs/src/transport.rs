use core::error::Error;

use alloc::{boxed::Box, vec::Vec};
use log::{debug, trace, warn};

use crate::packet::PacketError;
use crate::{
    identity::Identity,
    interface::{Interface, InterfaceError},
    packet::{AnnouncePacket, Packet, PacketContextType, PacketHeaderVariable, WirePacket},
    persistence::{DestinationStore, MessageStore, PersistenceError},
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
    #[cfg(feature = "embassy")]
    pub(crate) destination_store: embassy_sync::mutex::Mutex<
        embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
        Box<DestStore>,
    >,
    #[cfg(feature = "embassy")]
    pub(crate) message_store: embassy_sync::mutex::Mutex<
        embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
        Box<MsgStore>,
    >,
    #[cfg(feature = "tokio")]
    pub(crate) destination_store: tokio::sync::Mutex<Box<DestStore>>,
    #[cfg(feature = "tokio")]
    pub(crate) message_store: tokio::sync::Mutex<Box<MsgStore>>,
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
        #[cfg(feature = "embassy")] destination_store: embassy_sync::mutex::Mutex<
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            Box<DestStore>,
        >,
        #[cfg(feature = "embassy")] message_store: embassy_sync::mutex::Mutex<
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            Box<MsgStore>,
        >,
        #[cfg(feature = "tokio")] destination_store: tokio::sync::Mutex<Box<DestStore>>,
        #[cfg(feature = "tokio")] message_store: tokio::sync::Mutex<Box<MsgStore>>,
    ) -> Result<Transport<'a, DestStore, MsgStore, Iface>, TransportError> {
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

            for interface in self.interfaces {
                let interface = interface;
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

    pub(crate) async fn interface_processing_task(
        interface: &Iface,
        #[cfg(feature = "embassy")] packet_sender: &embassy_sync::channel::Sender<
            'static,
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            WirePacket,
            1,
        >,
        #[cfg(feature = "tokio")] packet_sender: &tokio::sync::mpsc::Sender<WirePacket>,
    ) {
        loop {
            trace!("Starting interface processing task");
            Self::recv_from_interface(interface, packet_sender).await
        }
    }

    pub(crate) async fn packet_processing_task(
        #[cfg(feature = "embassy")] packet_receiver: &embassy_sync::channel::Receiver<
            'static,
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            WirePacket,
            1,
        >,
        #[cfg(feature = "embassy")] destination_store: &embassy_sync::mutex::Mutex<
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            Box<DestStore>,
        >,
        #[cfg(feature = "embassy")] message_store: &embassy_sync::mutex::Mutex<
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            Box<MsgStore>,
        >,
        #[cfg(feature = "tokio")] packet_receiver: &mut tokio::sync::mpsc::Receiver<WirePacket>,
        #[cfg(feature = "tokio")] destination_store: &tokio::sync::Mutex<Box<DestStore>>,
        #[cfg(feature = "tokio")] message_store: &tokio::sync::Mutex<Box<MsgStore>>,
    ) {
        loop {
            trace!("Starting packet processing task");
            Self::process_packets(packet_receiver, destination_store, message_store).await;
        }
    }

    async fn recv_from_interface(
        interface: &Iface,
        #[cfg(feature = "embassy")] packet_sender: &embassy_sync::channel::Sender<
            'static,
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            WirePacket,
            1,
        >,
        #[cfg(feature = "tokio")] packet_sender: &tokio::sync::mpsc::Sender<WirePacket>,
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
        #[cfg(feature = "embassy")] destination_store: &embassy_sync::mutex::Mutex<
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            Box<DestStore>,
        >,
        #[cfg(feature = "tokio")] destination_store: &tokio::sync::Mutex<Box<DestStore>>,
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
        #[cfg(feature = "embassy")] packet_receiver: &embassy_sync::channel::Receiver<
            'static,
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            WirePacket,
            1,
        >,
        #[cfg(feature = "embassy")] destination_store: &embassy_sync::mutex::Mutex<
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            Box<DestStore>,
        >,
        #[cfg(feature = "embassy")] message_store: &embassy_sync::mutex::Mutex<
            embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
            Box<MsgStore>,
        >,
        #[cfg(feature = "tokio")] packet_receiver: &mut tokio::sync::mpsc::Receiver<WirePacket>,
        #[cfg(feature = "tokio")] destination_store: &tokio::sync::Mutex<Box<DestStore>>,
        #[cfg(feature = "tokio")] message_store: &tokio::sync::Mutex<Box<MsgStore>>,
    ) {
        loop {
            trace!("Waiting for packet");
            #[cfg(feature = "embassy")]
            let packet = packet_receiver.receive().await;
            #[cfg(feature = "tokio")]
            let packet = packet_receiver.recv().await.unwrap();
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
