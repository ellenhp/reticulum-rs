#![allow(unused_imports)]
use std::{error::Error, sync::Arc};

pub use fernet;
use identity::{Identity, IdentityCommon};
use interface::{Interface, InterfaceError};
use packet::Packet;
use persistence::{
    destination::Destination, in_memory::InMemoryMessageStore, DestinationStore, IdentityStore,
    MessageStore, PersistenceError,
};
use smol::lock::Mutex;
use transport::{Transport, TransportError};

pub mod constants;
pub mod identity;
pub mod interface;
pub mod packet;
pub mod persistence;
pub mod transport;

#[derive(Debug, thiserror::Error)]
pub enum ReticulumError {
    #[error("persistence error: {0}")]
    Persistence(PersistenceError),
    #[error("interface error: {0}")]
    Interface(InterfaceError),
    #[error("transport error: {0}")]
    Transport(TransportError),
    #[error("unspecified error, inner: {0}")]
    Unspecified(Box<dyn Error>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TruncatedHash([u8; 16]);

pub struct Reticulum<DestStore: DestinationStore + 'static, MsgStore: MessageStore + 'static> {
    destination_store: Arc<Mutex<Box<DestStore>>>,
    message_store: Arc<Mutex<Box<MsgStore>>>,
    transport: Transport<DestStore, MsgStore>,
}

impl<DestStore: DestinationStore, MsgStore: MessageStore> Reticulum<DestStore, MsgStore> {
    pub fn new(
        interfaces: Vec<Arc<dyn Interface>>,
        destination_store: Arc<Mutex<Box<DestStore>>>,
        message_store: Arc<Mutex<Box<MsgStore>>>,
    ) -> Result<Reticulum<DestStore, MsgStore>, ReticulumError> {
        let transport =
            Transport::new(interfaces, destination_store.clone(), message_store.clone())
                .map_err(|err| ReticulumError::Transport(err))?;

        Ok(Reticulum {
            destination_store: destination_store.clone(),
            message_store: message_store.clone(),
            transport,
        })
    }

    pub async fn get_known_destinations(&self) -> Vec<Destination> {
        self.destination_store
            .lock()
            .await
            .get_all_destinations()
            .await
            .unwrap()
    }

    pub async fn get_local_destinations(&self) -> Vec<Destination> {
        let all_destinations = self
            .destination_store
            .lock()
            .await
            .get_all_destinations()
            .await
            .unwrap();
        let mut local_destinations = Vec::new();
        for destination in all_destinations {
            if let Some(Identity::Local(_)) = destination.identity() {
                local_destinations.push(destination);
            }
        }
        local_destinations
    }

    pub async fn poll_inbox(&self, destination: &TruncatedHash) -> Option<Packet> {
        let message_store = self.message_store.lock().await;
        message_store.poll_inbox(destination)
    }

    pub async fn next_inbox(&self, destination: &TruncatedHash) -> Option<Packet> {
        let message_store = self.message_store.lock().await;
        message_store.next_inbox(destination).await
    }
}

#[cfg(test)]
mod test {
    use std::{sync::Arc, time::Duration};

    use smol::{lock::Mutex, Timer};

    use crate::{
        identity::Identity,
        interface::channel::ChannelInterface,
        persistence::{
            self,
            destination::Destination,
            in_memory::{InMemoryDestinationStore, InMemoryIdentityStore, InMemoryMessageStore},
            DestinationStore, IdentityMetadata, IdentityStore,
        },
        Reticulum,
    };

    async fn setup_node(
        interface: ChannelInterface,
    ) -> (
        Destination,
        Reticulum<InMemoryDestinationStore, InMemoryMessageStore>,
    ) {
        let destination_store = Arc::new(Mutex::new(Box::new(
            persistence::in_memory::InMemoryDestinationStore::new(),
        )));
        destination_store
            .lock()
            .await
            .register_destination_name("app".to_string(), vec![])
            .unwrap();
        let message_store = Arc::new(Mutex::new(Box::new(InMemoryMessageStore::new())));
        let node = Reticulum::new(
            vec![Arc::new(interface)],
            destination_store.clone(),
            message_store.clone(),
        )
        .unwrap();
        let builder = destination_store.lock().await.builder("app");
        let destination = builder
            .build_single(
                &Identity::new_local(),
                destination_store.lock().await.as_mut(),
            )
            .await
            .unwrap();

        (destination, node)
    }

    #[test]
    fn test_announce() {
        smol::block_on(async {
            let interface1 = ChannelInterface::new();
            let interface2 = interface1.clone().await;
            let (destination1, node1) = setup_node(interface1).await;
            let (_destination2, node2) = setup_node(interface2).await;

            println!("Running announce");

            node1.transport.force_announce_all_local().await.unwrap();
            Timer::after(Duration::from_millis(10)).await;
            assert_eq!(node2.get_known_destinations().await.len(), 2);
        });
    }
}
