pub trait SignedMessage {
    fn signed_data(&self) -> &[u8];
    fn signature(&self) -> &[u8];
}

pub trait EncryptedMessage {
    fn public_key(&self) -> &[u8];
    fn encrypted_data(&self) -> &[u8];
}

pub struct Packet {}
