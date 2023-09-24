#[cfg(test)]
extern crate std;

use core::time::Duration;
use std::{
    net::{SocketAddr, UdpSocket},
    sync::Arc,
};

use alloc::{boxed::Box, vec::Vec};
use async_trait::async_trait;

use super::{ChannelData, Interface, InterfaceError};

#[derive(Debug, Clone)]
pub struct UdpInterface {
    socket: Arc<UdpSocket>,
    active: Arc<tokio::sync::Mutex<bool>>,
    destination: SocketAddr,
}

#[async_trait]
impl Interface for UdpInterface {
    async fn queue_send(&self, message: &[u8]) -> Result<(), InterfaceError> {
        self.socket
            .send_to(message, self.destination)
            .map_err(|err| InterfaceError::Recoverable(Box::new(err)))
            .map(|_| ())
    }

    async fn recv(&self) -> Result<ChannelData, InterfaceError> {
        {
            if !*self.active.lock().await {
                return Ok(ChannelData::Close);
            }
        }
        let mut buf = [0; 65536];
        let (len, _) = self
            .socket
            .recv_from(&mut buf)
            .map_err(|err| InterfaceError::Recoverable(Box::new(err)))?;
        Ok(ChannelData::Message(buf[..len].to_vec()))
    }

    async fn close(&self) -> Result<(), InterfaceError> {
        *self.active.lock().await = false;
        Ok(())
    }
}

impl UdpInterface {
    pub async fn new(local: SocketAddr, destination: SocketAddr) -> Self {
        let socket = UdpSocket::bind(local).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let socket = Arc::new(socket);
        Self {
            socket,
            active: Arc::new(tokio::sync::Mutex::new(true)),
            destination,
        }
    }
}
