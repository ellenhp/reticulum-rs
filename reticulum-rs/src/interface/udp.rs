use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use smol::net::UdpSocket;

use super::{Interface, InterfaceError, InterfaceHandle};

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
            .await
            .map_err(|err| InterfaceError::Recoverable(Box::new(err)))
            .map(|_| ())
    }

    async fn recv(&self) -> Result<Vec<u8>, InterfaceError> {
        let mut buf = [0; 65536];
        let (len, _) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|err| InterfaceError::Recoverable(Box::new(err)))?;
        Ok(buf[..len].to_vec())
    }
}

impl UdpInterface {
    pub async fn new(local: SocketAddr, destination: SocketAddr) -> Self {
        let socket = Arc::new(UdpSocket::bind(local).await.unwrap());
        Self {
            socket,
            destination,
        }
    }
}
