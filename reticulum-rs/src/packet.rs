use std::error::Error;

use packed_struct::{
    prelude::{PackedStruct, PrimitiveEnum},
    PackingError,
};
use serde::de;

use crate::{destination::Destination, identity::CryptoError, TruncatedHash};

pub trait SignedMessage {
    fn signed_data(&self) -> &[u8];
    fn signature(&self) -> &[u8];
}

pub trait EncryptedMessage {
    fn public_key(&self) -> &[u8];
    fn encrypted_data(&self) -> &[u8];
}

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("announce packets can only be constructed for 'single' destinations")]
    AnnounceDestinationNotSingle,
    #[error("crypto error: {0}")]
    CryptoError(CryptoError),
    #[error("packing error: {0}")]
    PackingError(packed_struct::PackingError),
    #[error("unspecified error: {0}")]
    Unspecified(Box<dyn Error>),
    #[error("unknown error: {0}")]
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, PackedStruct)]
#[packed_struct(bit_numbering = "msb0")]
pub struct PacketHeaderCommon {
    // First byte
    #[packed_field(bits = "1", ty = "enum")]
    header_type: HeaderType,
    #[packed_field(bits = "2..=3", ty = "enum")]
    transport_type: TransportType,
    #[packed_field(bits = "4..=5", ty = "enum")]
    destination_type: DestinationType,
    #[packed_field(bits = "6..=7", ty = "enum")]
    packet_type: PacketType,
    // Second byte: The number of hops this packet has taken.
    hops: u8,
}

#[derive(Debug, Clone, PartialEq, PackedStruct)]
#[packed_struct(bit_numbering = "msb0")]

pub struct PacketHeader1 {
    // Destination's truncated hash.
    destination_hash: [u8; 16],
    // Packet context type.
    #[packed_field(bytes = "16", ty = "enum")]
    context_type: PacketContextType,
}

#[derive(Debug, Clone, PartialEq, PackedStruct)]
#[packed_struct(bit_numbering = "msb0")]

pub struct PacketHeader2 {
    // Transport's truncated hash.
    transport_id: [u8; 16],
    // Destination's truncated hash.
    destination_hash: [u8; 16],
    // Packet context type.
    #[packed_field(bytes = "32", ty = "enum")]
    context_type: PacketContextType,
}

#[derive(PrimitiveEnum, Debug, Copy, Clone, PartialEq)]
pub enum HeaderType {
    Header1 = 0,
    Header2 = 1,
}

#[derive(PrimitiveEnum, Debug, Copy, Clone, PartialEq)]
pub enum TransportType {
    Broadcast = 0,
    Transport = 1,
    Relay = 2,
    Tunnel = 3,
}

#[derive(PrimitiveEnum, Debug, Copy, Clone, PartialEq)]
pub enum DestinationType {
    Single = 0,
    Group = 1,
    Plain = 2,
    Link = 3,
}

#[derive(PrimitiveEnum, Debug, Copy, Clone, PartialEq)]
pub enum PacketType {
    Data = 0,
    Announce = 1,
    LinkRequest = 2,
    Proof = 3,
}

#[derive(PrimitiveEnum, Debug, Copy, Clone, PartialEq)]
pub enum PacketContextType {
    None = 0x00,
    Resource = 0x01,
    ResourceAdv = 0x02,
    ResourceReq = 0x03,
    ResourceHmu = 0x04,
    ResourcePrf = 0x05,
    ResourceIcl = 0x06,
    ResourceRcl = 0x07,
    CacheRequest = 0x08,
    Request = 0x09,
    Response = 0x0A,
    PathResponse = 0x0B,
    Command = 0x0C,
    CommandStatus = 0x0D,
    Channel = 0x0E,
    Keepalive = 0xFA,
    LinkIdentify = 0xFB,
    LinkClose = 0xFC,
    LinkProof = 0xFD,
    LRRTT = 0xFE,
    LRProof = 0xFF,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PacketHeader {
    LrProof(PacketHeaderCommon, TruncatedHash),
    Header1(PacketHeaderCommon, PacketHeader1),
    Header2(PacketHeaderCommon, PacketHeader2),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    header: PacketHeader,
    payload: Vec<u8>,
}

impl Packet {
    pub fn new_lrproof(
        packet_type: PacketType,
        transport_type: TransportType,
        destination_link_hash: TruncatedHash,
        payload: Vec<u8>,
    ) -> Packet {
        let header = PacketHeader::LrProof(
            PacketHeaderCommon {
                header_type: HeaderType::Header2,
                transport_type,
                destination_type: DestinationType::Link,
                packet_type,
                hops: 0,
            },
            destination_link_hash,
        );
        debug_assert!(!Self::should_encrypt_payload(&header));
        Packet { header, payload }
    }

    pub fn new_without_transport(
        packet_type: PacketType,
        context_type: PacketContextType,
        transport_type: TransportType,
        destination: &Destination,
        payload: Vec<u8>,
    ) -> Result<Packet, PacketError> {
        let header = PacketHeader::Header1(
            PacketHeaderCommon {
                header_type: HeaderType::Header1,
                transport_type,
                destination_type: destination.destination_type(),
                packet_type,
                hops: 0,
            },
            PacketHeader1 {
                destination_hash: destination.truncated_hash(),
                context_type,
            },
        );
        let payload = if Self::should_encrypt_payload(&header) {
            destination.encrypt(payload)?
        } else {
            payload
        };
        Ok(Packet { header, payload })
    }

    pub fn new_with_transport(
        packet_type: PacketType,
        context_type: PacketContextType,
        transport_type: TransportType,
        transport_id: &Destination, // maybe an identity here?
        destination: &Destination,
        payload: Vec<u8>,
    ) -> Result<Packet, PacketError> {
        let header = PacketHeader::Header2(
            PacketHeaderCommon {
                header_type: HeaderType::Header2,
                transport_type,
                destination_type: destination.destination_type(),
                packet_type,
                hops: 0,
            },
            PacketHeader2 {
                transport_id: transport_id.truncated_hash(),
                destination_hash: destination.truncated_hash(),
                context_type,
            },
        );
        let payload = if Self::should_encrypt_payload(&header) {
            destination.encrypt(payload)?
        } else {
            payload
        };
        Ok(Packet { header, payload })
    }

    pub fn pack(&self) -> Result<Vec<u8>, PacketError> {
        let mut packed = Vec::new();
        match &self.header {
            PacketHeader::LrProof(common, destination_link_hash) => {
                packed.extend(
                    common
                        .pack()
                        .map_err(|err| PacketError::PackingError(err))?,
                );
                packed.extend(destination_link_hash.0);
            }
            PacketHeader::Header1(common, header1) => {
                packed.extend(
                    common
                        .pack()
                        .map_err(|err| PacketError::PackingError(err))?,
                );
                packed.extend(
                    header1
                        .pack()
                        .map_err(|err| PacketError::PackingError(err))?,
                );
            }
            PacketHeader::Header2(common, header2) => {
                packed.extend(
                    common
                        .pack()
                        .map_err(|err| PacketError::PackingError(err))?,
                );
                packed.extend(
                    header2
                        .pack()
                        .map_err(|err| PacketError::PackingError(err))?,
                );
            }
        }
        packed.extend(self.payload.clone());
        dbg!(packed.len());
        Ok(packed)
    }

    pub fn unpack(raw: &[u8]) -> Result<Packet, PacketError> {
        let common = PacketHeaderCommon::unpack(&[raw[0], raw[1]])
            .map_err(|err| PacketError::PackingError(err))?;
        let (header, payload) = match common.header_type {
            HeaderType::Header1 => {
                let raw_header: &[u8; 17] = raw[2..19]
                    .try_into()
                    .map_err(|_err| PacketError::Unknown("Try from slice failed".to_string()))?;
                let header1 = PacketHeader1::unpack(raw_header)
                    .map_err(|err| PacketError::PackingError(err))?;
                (PacketHeader::Header1(common, header1), &raw[19..])
            }
            HeaderType::Header2 => {
                let raw_header: &[u8; 33] = raw[2..35]
                    .try_into()
                    .map_err(|_err| PacketError::Unknown("Try from slice failed".to_string()))?;

                let header2 = PacketHeader2::unpack(raw_header)
                    .map_err(|err| PacketError::PackingError(err))?;
                (PacketHeader::Header2(common, header2), &raw[35..])
            }
        };
        Ok(Packet {
            header,
            payload: payload.to_vec(),
        })
    }

    fn should_encrypt_payload(header: &PacketHeader) -> bool {
        match header {
            PacketHeader::LrProof(_common, _destination_link_hash) => {
                return false;
            }
            PacketHeader::Header1(common, header1) => {
                let packet_type = common.packet_type;
                let context_type = header1.context_type;
                let destination_type = common.destination_type;
                if packet_type == PacketType::Announce {
                    return false;
                }
                if packet_type == PacketType::LinkRequest {
                    return false;
                }
                if packet_type == PacketType::Proof
                    && context_type == PacketContextType::ResourcePrf
                {
                    return false;
                }
                if packet_type == PacketType::Proof && destination_type == DestinationType::Link {
                    return false;
                }
                if context_type == PacketContextType::Resource {
                    return false;
                }
                if context_type == PacketContextType::Keepalive {
                    return false;
                }
                if context_type == PacketContextType::CacheRequest {
                    return false;
                }
                return true;
            }
            PacketHeader::Header2(common, _header2) => {
                let packet_type = common.packet_type;
                if packet_type == PacketType::Announce {
                    return false;
                }
                return true;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        destination::{Destination, DestinationBuilder},
        identity::{self, Identity, LocalIdentity},
        packet::{Packet, PacketContextType, PacketError, PacketType, TransportType},
    };

    #[test]
    fn test_packet() {
        let receiver = Identity::new_local();
        let destination = Destination::builder("app").build_single(&receiver).unwrap();
        let packet = Packet::new_without_transport(
            PacketType::Data,
            PacketContextType::None,
            TransportType::Transport,
            &destination,
            vec![0; 16],
        )
        .unwrap();
        let packed = packet.pack().unwrap();
        let unpacked = Packet::unpack(&packed).unwrap();
        assert_eq!(packet, unpacked);
        let decrypted = if let Identity::Local(local) = receiver {
            local.decrypt(&unpacked.payload).unwrap()
        } else {
            panic!("not a local identity");
        };
        assert_eq!(vec![0; 16], decrypted);
    }
}
