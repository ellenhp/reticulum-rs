#[cfg(test)]
extern crate std;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;
use alloc::{sync::Arc, vec::Vec};
use async_trait::async_trait;
use tokio::sync::mpsc::channel;

use super::{ChannelData, Interface, InterfaceError};

#[derive(Debug, Clone)]
pub struct ChannelInterface {
    senders: Arc<tokio::sync::Mutex<Vec<tokio::sync::mpsc::Sender<ChannelData>>>>,
    receiver: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<ChannelData>>>,
}

impl ChannelInterface {
    pub fn new() -> Self {
        let (sender, receiver) = channel(10);
        Self {
            senders: Arc::new(tokio::sync::Mutex::new([sender].to_vec())),
            receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
        }
    }

    pub async fn clone(&self) -> Self {
        let (sender, receiver) = channel(10);
        self.senders.lock().await.push(sender);
        Self {
            senders: self.senders.clone(),
            receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
        }
    }
}

#[async_trait]
impl Interface for ChannelInterface {
    async fn queue_send(&self, message: &[u8]) -> Result<(), InterfaceError> {
        let senders = self.senders.lock().await;
        for sender in senders.iter() {
            let _ = sender
                .send(ChannelData::Message(message.to_vec()))
                .await
                .map_err(|err| {
                    InterfaceError::Unspecified(format!(
                        "failed to queue message for sending: {:?}",
                        err
                    ))
                });
        }
        Ok(())
    }

    async fn recv(&self) -> Result<ChannelData, InterfaceError> {
        let result = self.receiver.lock().await.recv().await;
        match result {
            Some(data) => Ok(data),
            None => Err(InterfaceError::Unspecified(
                "failed to receive message".to_string(),
            )),
        }
    }

    async fn close(&self) -> Result<(), InterfaceError> {
        let senders = self.senders.lock().await;
        for sender in senders.iter() {
            sender.send(ChannelData::Close).await.unwrap();
        }
        Ok(())
    }
}
