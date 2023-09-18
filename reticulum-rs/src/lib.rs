#![allow(unused_imports)]
use std::{error::Error, sync::Arc};

pub use fernet;
use identity::Identity;
use interface::{Interface, InterfaceError, Interfaces};
use persistence::{DestinationStore, IdentityStore, PersistenceError};
use transport::{Transport, TransportError};

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

pub struct Reticulum {
    identity_store: Arc<Box<dyn IdentityStore>>,
    destination_store: Arc<Box<dyn DestinationStore>>,
    transport: Transport,
}

impl Reticulum {
    pub fn new(
        interfaces: Vec<Box<dyn Interface>>,
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
