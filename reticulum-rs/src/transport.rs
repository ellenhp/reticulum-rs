use std::{error::Error, sync::Arc, thread};

use smol::{
    channel::{Receiver, Sender},
    lock::Mutex,
    Task,
};

use crate::{
    identity::IdentityCommon,
    interface::{self, Interface, InterfaceError},
    packet::{Packet, PacketContextType, PacketType, TransportType},
    persistence::{DestinationStore, IdentityStore, PersistenceError},
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

pub(crate) struct Transport {
    interfaces: Vec<Arc<dyn Interface>>,
    identity_store: Arc<Box<dyn IdentityStore>>,
    destination_store: Arc<Box<dyn DestinationStore>>,
}

impl Transport {
    pub fn new(
        interfaces: Vec<Arc<dyn Interface>>,
        identity_store: Arc<Box<dyn IdentityStore>>,
        destination_store: Arc<Box<dyn DestinationStore>>,
    ) -> Result<Transport, TransportError> {
        Transport::spawn_processing_tasks(interfaces.clone())?;
        Ok(Transport {
            identity_store,
            destination_store,
            interfaces,
        })
    }

    pub async fn announce(&self) -> Result<(), TransportError> {
        let self_identities = self
            .identity_store
            .get_self_identities()
            .await
            .map_err(|err| TransportError::Unspecified(Box::new(err)))?;
        for identity in self_identities {
            let destinations = self
                .destination_store
                .get_destinations_by_identity_handle(&identity.handle())
                .await
                .map_err(|err| TransportError::Persistence(err))?;
            for destination in destinations {
                let packet = Packet::new_without_transport(
                    PacketType::Announce,
                    PacketContextType::None,
                    TransportType::Broadcast,
                    &destination,
                    Vec::new(),
                )
                .map_err(|err| TransportError::Unspecified(Box::new(err)))?;

                for interface in self.interfaces.clone() {
                    let interface = interface.clone();
                    let message = packet
                        .pack()
                        .map_err(|err| TransportError::Unspecified(Box::new(err)))?;
                    let interface = interface;
                    let message = message;
                    interface.queue_send(&message).await.unwrap();
                }
            }
        }
        Ok(())
    }

    fn spawn_processing_tasks(interfaces: Vec<Arc<dyn Interface>>) -> Result<(), TransportError> {
        let (packet_sender, packet_receiver) = smol::channel::bounded(32);
        for interface in interfaces {
            let interface = interface.clone();
            let packet_sender = packet_sender.clone();
            smol::spawn(async move {
                let interface = interface;
                println!("Starting interface processing task");
                Self::recv_from_interface(interface.clone(), packet_sender.clone()).await
            })
            .detach();
        }
        smol::spawn(async move {
            let packet_receiver = packet_receiver;
            println!("Starting packet processing task");
            Self::process_packets(packet_receiver).await;
        })
        .detach();
        Ok(())
    }

    async fn recv_from_interface(
        interface: Arc<dyn crate::interface::Interface>,
        packet_sender: Sender<Packet>,
    ) {
        loop {
            let interface = interface.clone();
            let future = async move { interface.recv().await };
            let message = match future.await {
                Ok(message) => message,
                Err(InterfaceError::Recoverable(inner)) => {
                    println!("Recoverable error: {:?}", inner);
                    continue;
                }
                Err(inner) => {
                    println!("Unrecoverable error: {:?}", inner);
                    break;
                }
            };
            let packet = match Packet::unpack(&message) {
                Ok(packet) => packet,
                Err(_) => {
                    println!("Failed to unpack packet");
                    continue;
                }
            };
            println!("Received packet: {:?}", packet);
            if let Err(err) = packet_sender.send(packet).await {
                println!("Failed to send packet to processing task: {:?}", err);
            }
        }
    }

    async fn process_packets(packet_receiver: Receiver<Packet>) {
        loop {
            let packet = if let Ok(packet) = packet_receiver.recv().await {
                packet
            } else {
                println!("Failed to receive packet from interface");
                continue;
            };
            match packet.header() {
                crate::packet::PacketHeader::LrProof(common, hash) => {
                    println!("Common: {:?}", common);
                    println!("Received LR proof: {:?}", hash);
                }
                crate::packet::PacketHeader::Header1(common, header1) => {
                    println!("Common: {:?}", common);
                    println!("Received header1: {:?}", header1);
                }
                crate::packet::PacketHeader::Header2(common, header2) => {
                    println!("Common: {:?}", common);
                    println!("Received header2: {:?}", header2);
                }
            }
        }
    }
}
