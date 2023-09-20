use std::{borrow::BorrowMut, cell::RefCell, sync::Arc};

use async_trait::async_trait;
use smol::{
    channel::{self, Receiver, Sender},
    lock::Mutex,
};

use super::{Interface, InterfaceError};

#[derive(Debug)]
pub struct ChannelInterface {
    senders: Arc<Mutex<Vec<Sender<Vec<u8>>>>>,
    receiver: Receiver<Vec<u8>>,
}

impl ChannelInterface {
    pub fn new() -> Self {
        let (sender, receiver) = channel::bounded(100);
        Self {
            senders: Arc::new(Mutex::new(vec![sender])),
            receiver,
        }
    }

    pub async fn clone(&self) -> Self {
        let (sender, receiver) = channel::bounded(100);
        self.senders.lock().await.push(sender);
        Self {
            senders: self.senders.clone(),
            receiver,
        }
    }
}

#[async_trait]
impl Interface for ChannelInterface {
    async fn queue_send(&self, message: &[u8]) -> Result<(), InterfaceError> {
        let senders = self.senders.lock().await;
        for sender in senders.iter() {
            let _ = sender.send(message.to_vec()).await.map_err(|err| {
                InterfaceError::Unspecified(format!(
                    "failed to queue message for sending: {:?}",
                    err
                ))
            });
        }
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, InterfaceError> {
        self.receiver.recv().await.map_err(|err| {
            InterfaceError::Unspecified(format!("failed to receive message: {:?}", err))
        })
    }
}
