#[cfg(test)]
extern crate std;

use std::{
    net::{SocketAddr, UdpSocket},
    sync::Arc,
};

use alloc::{boxed::Box, vec::Vec};
use async_trait::async_trait;

use super::{Interface, InterfaceError};

#[derive(Debug)]
pub struct UdpInterface {
    socket: Arc<UdpSocket>,
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

    async fn recv(&self) -> Result<Vec<u8>, InterfaceError> {
        let mut buf = [0; 65536];
        let (len, _) = self
            .socket
            .recv_from(&mut buf)
            .map_err(|err| InterfaceError::Recoverable(Box::new(err)))?;
        Ok(buf[..len].to_vec())
    }
}

impl UdpInterface {
    pub async fn new(local: SocketAddr, destination: SocketAddr) -> Self {
        let socket = Arc::new(UdpSocket::bind(local).unwrap());
        Self {
            socket,
            destination,
        }
    }
}
