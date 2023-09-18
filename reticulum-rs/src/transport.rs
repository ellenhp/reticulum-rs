use std::{error::Error, sync::Arc, thread};

use crate::{
    interface::{InterfaceError, Interfaces},
    persistence::{DestinationStore, IdentityStore},
};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("threading error: {0}")]
    Thread(Box<dyn Error>),
    #[error("unspecified error: {0}")]
    Unspecified(Box<dyn Error>),
}

pub(crate) struct Transport {
    processing_threads: Vec<thread::JoinHandle<()>>,
    identity_store: Arc<Box<dyn IdentityStore>>,
    destination_store: Arc<Box<dyn DestinationStore>>,
}

impl Transport {
    pub fn new(
        interfaces: Interfaces,
        identity_store: Arc<Box<dyn IdentityStore>>,
        destination_store: Arc<Box<dyn DestinationStore>>,
    ) -> Result<Transport, TransportError> {
        let processing_threads = Transport::spawn_processing_threads(interfaces)?;
        Ok(Transport {
            processing_threads,
            identity_store,
            destination_store,
        })
    }

    fn spawn_processing_threads(
        interfaces: Interfaces,
    ) -> Result<Vec<thread::JoinHandle<()>>, TransportError> {
        let mut handles = Vec::new();
        for interface in interfaces {
            handles.push(
                thread::Builder::new()
                    .stack_size(4096)
                    .spawn(move || {
                        smol::block_on(async move {
                            loop {
                                let message = interface.recv().await;
                                match message {
                                    Ok(message) => {
                                        println!("received message: {:?}", message);
                                    }
                                    Err(InterfaceError::Recoverable(err)) => {
                                        println!("recoverable error receiving message: {:?}", err);
                                    }
                                    Err(err) => {
                                        println!("error receiving message: {:?}", err);
                                        break;
                                    }
                                }
                            }
                        });
                    })
                    .map_err(|err| TransportError::Thread(Box::new(err)))?,
            );
        }
        Ok(handles)
    }
}
