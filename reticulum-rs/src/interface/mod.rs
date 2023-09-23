#[cfg(all(test, feature = "interfaces"))]
pub mod channel;
#[cfg(all(test, feature = "interfaces"))]
pub mod udp;

use core::{error::Error, fmt::Debug};

use alloc::{boxed::Box, string::String, vec::Vec};
use async_trait::async_trait;

#[derive(Debug)]
pub enum InterfaceError {
    Recoverable(Box<dyn Error>),
    Unspecified(String),
}

pub type InterfaceHandle = [u8; 8];

#[async_trait]
pub trait Interface: Debug + Send + Sync + Sized {
    async fn queue_send(&self, message: &[u8]) -> Result<(), InterfaceError>;
    async fn recv(&self) -> Result<Vec<u8>, InterfaceError>;
}
