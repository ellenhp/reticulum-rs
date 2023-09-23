#![no_std]
#![feature(async_closure)]
#![feature(error_in_core)]

extern crate alloc;

use core::error::Error;

use alloc::{boxed::Box, string::String, vec::Vec};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
pub use fernet;
use identity::{Identity, IdentityCommon};
use interface::{Interface, InterfaceError};
use packet::Packet;
use persistence::{
    destination::Destination, DestinationStore, IdentityStore, MessageStore, PersistenceError,
};
use transport::{Transport, TransportError};

pub mod constants;
pub mod identity;
pub mod interface;
pub mod packet;
pub mod persistence;
mod random;
pub mod transport;

#[derive(Debug)]
pub enum ReticulumError {
    Persistence(PersistenceError),
    Interface(InterfaceError),
    Transport(TransportError),
    Unspecified(Box<dyn Error>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TruncatedHash([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NameHash([u8; 10]);

pub struct Reticulum<
    'a,
    DestStore: DestinationStore + 'static,
    MsgStore: MessageStore + 'static,
    Iface: Interface + 'static,
> {
    transport: Transport<'a, DestStore, MsgStore, Iface>,
    _phantom: core::marker::PhantomData<&'a ()>,
}

impl<'a, DestStore: DestinationStore, MsgStore: MessageStore, Iface: Interface + 'static>
    Reticulum<'a, DestStore, MsgStore, Iface>
{
    pub fn new(
        interfaces: &'a [Iface],
        destination_store: Mutex<CriticalSectionRawMutex, Box<DestStore>>,
        message_store: Mutex<CriticalSectionRawMutex, Box<MsgStore>>,
    ) -> Result<Reticulum<'a, DestStore, MsgStore, Iface>, ReticulumError> {
        let transport = Transport::new(interfaces, destination_store, message_store)
            .map_err(|err| ReticulumError::Transport(err))?;

        Ok(Reticulum {
            transport,
            _phantom: core::marker::PhantomData,
        })
    }

    pub async fn get_known_destinations(&self) -> Vec<Destination> {
        self.transport
            .destination_store
            .lock()
            .await
            .get_all_destinations()
            .await
            .unwrap()
    }

    pub async fn get_local_destinations(&self) -> Vec<Destination> {
        let all_destinations = self
            .transport
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

    pub async fn get_peer_destinations(&self) -> Result<Vec<Destination>, PersistenceError> {
        let all_destinations = self
            .transport
            .destination_store
            .lock()
            .await
            .get_all_destinations()
            .await
            .unwrap();
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
        self.transport
            .destination_store
            .lock()
            .await
            .register_destination_name(app_name, aspects)
    }

    pub async fn poll_inbox(&self, destination: &TruncatedHash) -> Option<Packet> {
        let message_store = self.transport.message_store.lock().await;
        message_store.poll_inbox(destination)
    }

    pub async fn next_inbox(&self, destination: &TruncatedHash) -> Option<Packet> {
        let message_store = self.transport.message_store.lock().await;
        message_store.next_inbox(destination).await
    }

    pub async fn force_announce_all_local(&self) -> Result<(), TransportError> {
        self.transport.force_announce_all_local().await
    }
}

#[cfg(test)]
mod test {
    #[cfg(test)]
    extern crate std;

    use alloc::{boxed::Box, string::ToString, vec::Vec};
    use embassy_sync::mutex::Mutex;
    use embassy_time::{Duration, Timer};

    use crate::{
        identity::Identity,
        interface::channel::ChannelInterface,
        interface::Interface,
        persistence::{
            self,
            destination::Destination,
            in_memory::{InMemoryDestinationStore, InMemoryMessageStore},
            DestinationStore, IdentityMetadata, IdentityStore,
        },
        Reticulum,
    };

    async fn setup_node<'a>(
        interfaces: &'a [ChannelInterface],
    ) -> (
        Destination,
        Reticulum<'a, InMemoryDestinationStore, InMemoryMessageStore, ChannelInterface>,
    ) {
        let destination_store = Mutex::new(Box::new(
            persistence::in_memory::InMemoryDestinationStore::new(),
        ));
        destination_store
            .lock()
            .await
            .register_destination_name("app".to_string(), Vec::new())
            .unwrap();
        let message_store = Mutex::new(Box::new(InMemoryMessageStore::new()));
        let builder = destination_store.lock().await.builder("app");
        let destination = builder
            .build_single(
                &Identity::new_local(),
                destination_store.lock().await.as_mut(),
            )
            .await
            .unwrap();
        let node = Reticulum::new(interfaces, destination_store, message_store).unwrap();

        (destination, node)
    }

    #[test]
    fn test_announce() {
        embassy_futures::block_on(async {
            let interface1 = ChannelInterface::new();
            let interface2 = interface1.clone().await;
            let interfaces1 = [interface1].to_vec();
            let interfaces2 = [interface2].to_vec();
            let (destination1, node1) = setup_node(&interfaces1).await;
            let (destination2, node2) = setup_node(&interfaces2).await;

            node1.transport.force_announce_all_local().await.unwrap();
            Timer::after(Duration::from_millis(10)).await;
            assert_eq!(node2.get_known_destinations().await.len(), 2);
            assert!(node1
                .poll_inbox(&destination1.address_hash())
                .await
                .is_some());
            assert!(node1
                .poll_inbox(&destination2.address_hash())
                .await
                .is_none());
            assert!(node2
                .poll_inbox(&destination1.address_hash())
                .await
                .is_none());
            assert!(node2
                .poll_inbox(&destination2.address_hash())
                .await
                .is_none());
        });
    }
}
