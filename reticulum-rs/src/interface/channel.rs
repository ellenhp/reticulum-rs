#[cfg(test)]
extern crate std;

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;

use alloc::boxed::Box;
use alloc::format;
use alloc::{sync::Arc, vec::Vec};
use async_trait::async_trait;

use super::{Interface, InterfaceError};

#[derive(Debug, Clone)]
pub struct ChannelInterface {
    senders: Arc<Mutex<Vec<Sender<Vec<u8>>>>>,
    receiver: Arc<Mutex<Receiver<Vec<u8>>>>,
}

impl ChannelInterface {
    pub fn new() -> Self {
        let (sender, receiver) = channel();
        Self {
            senders: Arc::new(Mutex::new([sender].to_vec())),
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    pub async fn clone(&self) -> Self {
        let (sender, receiver) = channel();
        self.senders.lock().unwrap().push(sender);
        Self {
            senders: self.senders.clone(),
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }
}

#[async_trait]
impl Interface for ChannelInterface {
    async fn queue_send(&self, message: &[u8]) -> Result<(), InterfaceError> {
        let senders = self.senders.lock().unwrap();
        for sender in senders.iter() {
            let _ = sender.send(message.to_vec()).map_err(|err| {
                InterfaceError::Unspecified(format!(
                    "failed to queue message for sending: {:?}",
                    err
                ))
            });
        }
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, InterfaceError> {
        self.receiver.lock().unwrap().recv().map_err(|err| {
            InterfaceError::Unspecified(format!("failed to receive message: {:?}", err))
        })
    }
}
