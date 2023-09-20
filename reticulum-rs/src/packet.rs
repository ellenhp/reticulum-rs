use std::{borrow::BorrowMut, error::Error, sync::Arc};

use log::warn;
use packed_struct::{
    prelude::{PackedStruct, PrimitiveEnum},
    PackingError,
};
use serde::de;
use smol::lock::Mutex;

use crate::{
    identity::{CryptoError, Identity, IdentityCommon, LocalIdentity},
    persistence::{destination::Destination, DestinationStore},
    NameHash, TruncatedHash,
};

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

impl PacketHeaderCommon {
    pub fn header_type(&self) -> HeaderType {
        self.header_type
    }
    pub fn transport_type(&self) -> TransportType {
        self.transport_type
    }
    pub fn destination_type(&self) -> DestinationType {
        self.destination_type
    }
    pub fn packet_type(&self) -> PacketType {
        self.packet_type
    }
    pub fn hops(&self) -> u8 {
        self.hops
    }
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

impl PacketHeader1 {
    pub fn destination_hash(&self) -> TruncatedHash {
        TruncatedHash(self.destination_hash)
    }
    pub fn context_type(&self) -> PacketContextType {
        self.context_type
    }
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

impl PacketHeader2 {
    pub fn transport_id(&self) -> TruncatedHash {
        TruncatedHash(self.transport_id)
    }
    pub fn destination_hash(&self) -> TruncatedHash {
        TruncatedHash(self.destination_hash)
    }
    pub fn context_type(&self) -> PacketContextType {
        self.context_type
    }
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
pub enum PacketHeaderVariable {
    LrProof(TruncatedHash),
    Header1(PacketHeader1),
    Header2(PacketHeader2),
}

#[derive(Debug, Clone, PartialEq)]
pub struct PacketHeader {
    header_common: PacketHeaderCommon,
    header_variable: PacketHeaderVariable,
}

impl PacketHeader {
    pub fn header_common(&self) -> &PacketHeaderCommon {
        &self.header_common
    }
    pub fn header_variable(&self) -> &PacketHeaderVariable {
        &self.header_variable
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WirePacket {
    header_common: PacketHeaderCommon,
    header: PacketHeader,
    payload: Vec<u8>,
}

impl WirePacket {
    pub fn new_lrproof(
        packet_type: PacketType,
        transport_type: TransportType,
        destination_link_hash: TruncatedHash,
        payload: Vec<u8>,
    ) -> WirePacket {
        let header_common = PacketHeaderCommon {
            header_type: HeaderType::Header2,
            transport_type,
            destination_type: DestinationType::Link,
            packet_type,
            hops: 0,
        };
        let header_variable = PacketHeaderVariable::LrProof(destination_link_hash);
        let header = PacketHeader {
            header_common: header_common.clone(),
            header_variable,
        };
        debug_assert!(!Self::should_encrypt_payload(&header_common, &header));
        WirePacket {
            header_common: header_common.clone(),
            header,
            payload,
        }
    }

    pub fn new_without_transport(
        packet_type: PacketType,
        context_type: PacketContextType,
        transport_type: TransportType,
        destination: &Destination,
        payload: Vec<u8>,
    ) -> Result<WirePacket, PacketError> {
        let header_common = PacketHeaderCommon {
            header_type: HeaderType::Header1,
            transport_type,
            destination_type: destination.destination_type(),
            packet_type,
            hops: 0,
        };
        let header_variable = PacketHeaderVariable::Header1(PacketHeader1 {
            destination_hash: destination.address_hash().0,
            context_type,
        });
        let header = PacketHeader {
            header_common: header_common.clone(),
            header_variable,
        };
        let payload = if Self::should_encrypt_payload(&header_common, &header) {
            destination.encrypt(payload)?
        } else {
            payload
        };
        Ok(WirePacket {
            header_common: header_common.clone(),
            header,
            payload,
        })
    }

    pub fn new_with_transport(
        packet_type: PacketType,
        context_type: PacketContextType,
        transport_type: TransportType,
        transport_id: &Destination, // maybe an identity here?
        destination: &Destination,
        payload: Vec<u8>,
    ) -> Result<WirePacket, PacketError> {
        let header_common = PacketHeaderCommon {
            header_type: HeaderType::Header2,
            transport_type,
            destination_type: destination.destination_type(),
            packet_type,
            hops: 0,
        };
        let header_variable = PacketHeaderVariable::Header2(PacketHeader2 {
            transport_id: transport_id.address_hash().0,
            destination_hash: destination.address_hash().0,
            context_type,
        });
        let header = PacketHeader {
            header_common: header_common.clone(),
            header_variable,
        };
        let payload = if Self::should_encrypt_payload(&header_common, &header) {
            destination.encrypt(payload)?
        } else {
            payload
        };
        Ok(WirePacket {
            header_common: header_common.clone(),
            header,
            payload,
        })
    }

    pub fn pack(&self) -> Result<Vec<u8>, PacketError> {
        let mut packed = Vec::new();
        packed.extend(
            self.header_common
                .pack()
                .map_err(|err| PacketError::PackingError(err))?,
        );

        match &self.header.header_variable {
            PacketHeaderVariable::LrProof(destination_link_hash) => {
                packed.extend(destination_link_hash.0);
            }
            PacketHeaderVariable::Header1(header1) => {
                packed.extend(
                    header1
                        .pack()
                        .map_err(|err| PacketError::PackingError(err))?,
                );
            }
            PacketHeaderVariable::Header2(header2) => {
                packed.extend(
                    header2
                        .pack()
                        .map_err(|err| PacketError::PackingError(err))?,
                );
            }
        }
        packed.extend(self.payload.clone());
        Ok(packed)
    }

    pub fn unpack(raw: &[u8]) -> Result<WirePacket, PacketError> {
        let header_common = PacketHeaderCommon::unpack(&[raw[0], raw[1]])
            .map_err(|err| PacketError::PackingError(err))?;
        let (header_variable, payload) = match header_common.header_type {
            HeaderType::Header1 => {
                let raw_header: &[u8; 17] = raw[2..19]
                    .try_into()
                    .map_err(|_err| PacketError::Unknown("Try from slice failed".to_string()))?;
                let header1 = PacketHeader1::unpack(raw_header)
                    .map_err(|err| PacketError::PackingError(err))?;
                (PacketHeaderVariable::Header1(header1), &raw[19..])
            }
            HeaderType::Header2 => {
                let raw_header: &[u8; 33] = raw[2..35]
                    .try_into()
                    .map_err(|_err| PacketError::Unknown("Try from slice failed".to_string()))?;

                let header2 = PacketHeader2::unpack(raw_header)
                    .map_err(|err| PacketError::PackingError(err))?;
                (PacketHeaderVariable::Header2(header2), &raw[35..])
            }
        };
        let header = PacketHeader {
            header_common: header_common.clone(),
            header_variable,
        };

        Ok(WirePacket {
            header_common: header_common.clone(),
            header,
            payload: payload.to_vec(),
        })
    }

    pub fn header(&self) -> &PacketHeader {
        &self.header
    }

    pub fn into_semantic_packet(self) -> Result<Packet, PacketError> {
        if self.header.header_common.packet_type == PacketType::Announce {
            let expected_size: usize = 64 // Public keys
                                        + 10 // Destination name hash
                                        + 10 // Random hash
                                        + 64; // Signature
            if self.payload.len() < expected_size {
                return Err(PacketError::Unknown(format!(
                    "Announce packet incorrect length: {}",
                    self.payload.len()
                )));
            }
            let identity = Identity::from_wire_repr(&self.payload[0..64])
                .map_err(|err| PacketError::CryptoError(err))?;
            let destination_name_hash = NameHash(
                self.payload[64..74]
                    .try_into()
                    .map_err(|_err| PacketError::Unknown("Try from slice failed".to_string()))?,
            );
            let random_hash = NameHash(
                self.payload[74..84]
                    .try_into()
                    .map_err(|_err| PacketError::Unknown("Try from slice failed".to_string()))?,
            );
            let signature = self.payload[84..148]
                .try_into()
                .map_err(|_err| PacketError::Unknown("Try from slice failed".to_string()))?;
            let app_data = self.payload[148..].to_vec();

            warn!("TODO: Verify signature");

            return Ok(Packet::Announce(AnnouncePacket {
                identity,
                destination_name_hash,
                random_hash,
                signature,
                app_data,
                wire_packet: self,
            }));
        }
        return Ok(Packet::Other(self));
    }

    fn should_encrypt_payload(header_common: &PacketHeaderCommon, header: &PacketHeader) -> bool {
        match &header.header_variable {
            PacketHeaderVariable::LrProof(_destination_link_hash) => {
                return false;
            }
            PacketHeaderVariable::Header1(header1) => {
                let packet_type = header_common.packet_type;
                let context_type = header1.context_type;
                let destination_type = header_common.destination_type;
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
            PacketHeaderVariable::Header2(_header2) => {
                let packet_type = header_common.packet_type;
                if packet_type == PacketType::Announce {
                    return false;
                }
                return true;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnnouncePacket {
    identity: Identity,
    destination_name_hash: NameHash,
    random_hash: NameHash,
    signature: [u8; 64],
    app_data: Vec<u8>,
    wire_packet: WirePacket,
}

impl AnnouncePacket {
    pub fn new(
        destination: Destination,
        path_context: PacketContextType,
        app_data: Vec<u8>,
    ) -> Result<AnnouncePacket, PacketError> {
        if path_context != PacketContextType::None
            && path_context != PacketContextType::PathResponse
        {
            return Err(PacketError::Unknown(
                "Announce packet path context not supported".to_string(),
            ));
        }
        let identity = destination
            .identity()
            .ok_or(PacketError::AnnounceDestinationNotSingle)?;
        let destination_name_hash = destination.name_hash();
        let random_hash = NameHash(rand::random()); // TODO: Include time? That's what the reference implementation does.
        let mut signature_material = vec![0u8; 164];
        signature_material[0..16].copy_from_slice(&destination.address_hash().0);
        signature_material[16..80].copy_from_slice(&identity.wire_repr());
        signature_material[80..90].copy_from_slice(&destination_name_hash.0);
        signature_material[90..100].copy_from_slice(&random_hash.0);
        println!(
            "signature_material: {:?}",
            hex::encode(&signature_material[0..100])
        );
        if let Identity::Local(local) = identity {
            let signature = local
                .sign(&signature_material[0..100])
                .map_err(|err| PacketError::CryptoError(err))?;
            signature_material[100..164].copy_from_slice(&signature);
        } else {
            return Err(PacketError::Unknown(
                "Announce packet identity not local".to_string(),
            ));
        }
        signature_material.extend(&app_data);
        let wire_packet = WirePacket::new_without_transport(
            PacketType::Announce,
            path_context,
            TransportType::Broadcast,
            &destination,
            signature_material[16..].to_vec(),
        )?;
        Ok(AnnouncePacket {
            identity: identity.clone(),
            destination_name_hash: destination_name_hash,
            random_hash,
            signature: signature_material[100..164]
                .try_into()
                .map_err(|_err| PacketError::Unknown("Try from slice failed".to_string()))?,
            app_data,
            wire_packet,
        })
    }
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn destination_name_hash(&self) -> &NameHash {
        &self.destination_name_hash
    }
    pub fn random_hash(&self) -> &NameHash {
        &self.random_hash
    }
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
    pub fn wire_packet(&self) -> &WirePacket {
        &self.wire_packet
    }
}

#[derive(Debug, Clone)]
pub enum Packet {
    Announce(AnnouncePacket),
    Other(WirePacket),
}

impl Packet {
    pub fn wire_packet(&self) -> &WirePacket {
        match self {
            Packet::Announce(announce) => announce.wire_packet(),
            Packet::Other(other) => other,
        }
    }

    pub(crate) async fn destination<DestStore: DestinationStore + 'static>(
        &self,
        destination_store: &Arc<Mutex<Box<DestStore>>>,
    ) -> Option<Destination> {
        match self {
            Packet::Announce(announce) => {
                let mut store = destination_store.lock().await;
                store
                    .resolve_destination(announce.destination_name_hash(), announce.identity())
                    .await
            }
            Packet::Other(other) => None,
        }
    }
}

#[cfg(test)]
mod test {
    use std::{borrow::BorrowMut, sync::Arc};

    use smol::lock::Mutex;

    use crate::{
        identity::{self, Identity, IdentityCommon, LocalIdentity},
        packet::{
            AnnouncePacket, Packet, PacketContextType, PacketError, PacketType, TransportType,
            WirePacket,
        },
        persistence::{
            destination::Destination, in_memory::InMemoryDestinationStore, DestinationStore,
        },
    };

    #[test]
    fn test_packet() {
        smol::block_on(async move {
            let store = Arc::new(Mutex::new(Box::new(InMemoryDestinationStore::new())));
            let receiver = Identity::new_local();
            let destination = Destination::builder("app")
                .build_single(&receiver, store.lock().await.as_mut())
                .await
                .unwrap();
            let packet = WirePacket::new_without_transport(
                PacketType::Data,
                PacketContextType::None,
                TransportType::Transport,
                &destination,
                vec![0; 16],
            )
            .unwrap();
            let packed = packet.pack().unwrap();
            let unpacked = WirePacket::unpack(&packed).unwrap();
            assert_eq!(packet, unpacked);
            let decrypted = if let Identity::Local(local) = receiver {
                local.decrypt(&unpacked.payload).unwrap()
            } else {
                panic!("not a local identity");
            };
            assert_eq!(vec![0; 16], decrypted);
        });
    }

    #[test]
    fn test_create_and_parse_announce_packet() {
        smol::block_on(async move {
            let store = Arc::new(Mutex::new(Box::new(InMemoryDestinationStore::new())));
            let identity = Identity::new_local();
            let destination = Destination::builder("app")
                .build_single(&identity, store.lock().await.as_mut())
                .await
                .unwrap();
            let packet =
                AnnouncePacket::new(destination.clone(), PacketContextType::None, vec![]).unwrap();
            let wire_packet = packet.wire_packet();
            let packed = wire_packet.pack().unwrap();
            let unpacked = WirePacket::unpack(&packed).unwrap();
            assert_eq!(wire_packet, &unpacked);
            let semantic = unpacked.into_semantic_packet().unwrap();
            if let Packet::Announce(announce) = semantic {
                assert_eq!(announce.identity().wire_repr(), identity.wire_repr());
                assert_eq!(announce.destination_name_hash(), &destination.name_hash());
                assert_eq!(announce.random_hash(), packet.random_hash());
                assert_eq!(announce.signature(), packet.signature());
            } else {
                panic!("not an announce packet");
            }
        });
    }
}
