use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum InterfaceError {
    #[error("unspecified error: {0}")]
    Unspecified(String),
}

#[async_trait]
pub trait Interface {
    async fn send(&self, message: &[u8]) -> Result<(), InterfaceError>;
    async fn recv(&self) -> Result<Vec<u8>, ()>;
}
