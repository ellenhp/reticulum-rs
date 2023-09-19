use std::{borrow::BorrowMut, cell::RefCell, sync::Arc};

use async_trait::async_trait;
use smol::{
    channel::{self, Receiver, Sender},
    lock::Mutex,
};

use super::{Interface, InterfaceError};

#[derive(Debug)]
pub struct ChannelInterface {
    sender: Sender<Vec<u8>>,
    receiver: Arc<Mutex<Receiver<Vec<u8>>>>,
}

impl ChannelInterface {
    pub fn new() -> Self {
        let (sender, receiver) = channel::bounded(100);
        Self {
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    pub async fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            receiver: Arc::new(Mutex::new(self.receiver.lock().await.clone())),
        }
    }
}

#[async_trait]
impl Interface for ChannelInterface {
    async fn queue_send(&self, message: &[u8]) -> Result<(), InterfaceError> {
        println!("queue_send: {:?}", message);
        self.sender.send(message.to_vec()).await.map_err(|err| {
            InterfaceError::Unspecified(format!("failed to queue message for sending: {:?}", err))
        })?;
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, InterfaceError> {
        let recv = self.receiver.lock().await;
        dbg!(recv.recv().await.map_err(|err| {
            InterfaceError::Unspecified(format!("failed to receive message: {:?}", err))
        }))
    }
}
