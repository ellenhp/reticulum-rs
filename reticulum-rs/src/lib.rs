#![allow(unused_imports)]
use std::{error::Error, sync::Arc};

pub use fernet;
use identity::Identity;
use interface::{Interface, InterfaceError};
use persistence::{DestinationStore, IdentityStore, PersistenceError};
use smol::lock::Mutex;
use transport::{Transport, TransportError};

pub mod constants;
pub mod destination;
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

pub struct Reticulum {
    identity_store: Arc<Box<dyn IdentityStore>>,
    destination_store: Arc<Box<dyn DestinationStore>>,
    transport: Transport,
}

impl Reticulum {
    pub fn new(
        interfaces: Vec<Arc<dyn Interface>>,
        identity_store: Box<dyn IdentityStore>,
        destination_store: Box<dyn DestinationStore>,
    ) -> Result<Reticulum, ReticulumError> {
        let identity_store = Arc::new(identity_store);
        let destination_store = Arc::new(destination_store);
        let transport = Transport::new(
            interfaces,
            identity_store.clone(),
            destination_store.clone(),
        )
        .map_err(|err| ReticulumError::Transport(err))?;

        Ok(Reticulum {
            identity_store: identity_store.clone(),
            destination_store: destination_store.clone(),
            transport,
        })
    }
}

#[cfg(test)]
mod test {
    use std::{sync::Arc, time::Duration};

    use smol::{lock::Mutex, Timer};

    use crate::{
        destination::Destination,
        identity::Identity,
        interface::channel::ChannelInterface,
        persistence::{self, DestinationStore, IdentityMetadata, IdentityStore},
        Reticulum,
    };

    #[test]
    fn test_announce() {
        smol::block_on(async {
            let interface1 = ChannelInterface::new();
            let interface2 = interface1.clone().await;
            let (_identity1, _destination1, node1) = {
                let identity = Identity::new_local();
                let mut identity_store =
                    Box::new(persistence::in_memory::InMemoryIdentityStore::new());
                identity_store
                    .add_identity(&identity, &IdentityMetadata(Vec::new()))
                    .await
                    .unwrap();
                let destination = Destination::builder("app").build_single(&identity).unwrap();
                let mut destination_store =
                    Box::new(persistence::in_memory::InMemoryDestinationStore::new());
                destination_store
                    .add_destination(&destination)
                    .await
                    .unwrap();
                let node = Reticulum::new(
                    vec![Arc::new(interface1)],
                    identity_store,
                    destination_store,
                )
                .unwrap();
                (identity, destination, node)
            };
            let (_identity2, _destination2, node2) = {
                let identity = Identity::new_local();
                let mut identity_store =
                    Box::new(persistence::in_memory::InMemoryIdentityStore::new());
                identity_store
                    .add_identity(&identity, &IdentityMetadata(Vec::new()))
                    .await
                    .unwrap();
                let destination = Destination::builder("app").build_single(&identity).unwrap();
                let mut destination_store =
                    Box::new(persistence::in_memory::InMemoryDestinationStore::new());
                destination_store
                    .add_destination(&destination)
                    .await
                    .unwrap();
                let node = Reticulum::new(
                    vec![Arc::new(interface2)],
                    identity_store,
                    destination_store,
                )
                .unwrap();
                (identity, destination, node)
            };

            node1.transport.force_announce_all_local().await.unwrap();
            node2.transport.force_announce_all_local().await.unwrap();
            println!("announced");
            Timer::after(Duration::from_millis(100)).await;
            // TODO: Verify that the announces were received.
        });
    }
}
