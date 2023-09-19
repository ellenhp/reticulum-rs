#[cfg(feature = "interfaces")]
pub mod channel;

use std::{error::Error, fmt::Debug, sync::Arc};

use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum InterfaceError {
    #[error("Recoverable error: {0}")]
    Recoverable(Box<dyn Error>),
    #[error("unspecified error: {0}")]
    Unspecified(String),
}

pub type InterfaceHandle = [u8; 8];

#[async_trait]
pub trait Interface: Debug + Send + Sync {
    async fn queue_send(&self, message: &[u8]) -> Result<(), InterfaceError>;
    async fn recv(&self) -> Result<Vec<u8>, InterfaceError>;
}
