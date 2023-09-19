use std::{error::Error, sync::Arc, thread};

use smol::{lock::Mutex, Task};

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
        for interface in interfaces {
            let interface = interface.clone();
            smol::spawn(async move {
                let interface = interface;
                println!("Starting interface processing task");
                Self::process_interface(interface.clone()).await
            })
            .detach();
        }
        Ok(())
    }

    async fn process_interface(interface: Arc<dyn crate::interface::Interface>) {
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
            println!("Received message: {:?}", message);
        }
    }
}
