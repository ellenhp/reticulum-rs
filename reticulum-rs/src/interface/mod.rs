use std::{error::Error, fmt::Debug, sync::Arc};

use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum InterfaceError {
    #[error("Recoverable error: {0}")]
    Recoverable(Box<dyn Error>),
    #[error("unspecified error: {0}")]
    Unspecified(String),
}

#[async_trait]
pub trait Interface: Debug + Send {
    fn queue_send(&self, message: &[u8]) -> Result<(), InterfaceError>;
    async fn recv(&self) -> Result<Vec<u8>, InterfaceError>;
}

pub(super) type Interfaces = Vec<Box<dyn Interface>>;
