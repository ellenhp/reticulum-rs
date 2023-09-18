use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::{identity::Identity, packet::Packet};

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum DestinationError {
    #[error("app_name must not be empty")]
    EmptyAppName,
    #[error("app_name must not contain a dot")]
    DotInAppName,
    #[error("aspect must not be empty")]
    EmptyAspect,
    #[error("aspect must not contain a dot")]
    DotInAspect,
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum PacketError {
    #[error("announce packets can only be constructed for 'single' destinations")]
    AnnounceDestinationNotSingle,
}

#[derive(Debug)]
pub struct Destination {
    app_name: String,
    aspects: Vec<String>,
    inner: DestinationInner,
}

#[derive(Debug)]
enum DestinationInner {
    Single(SingleDestination),
    Group(GroupDestination),
    Plain(PlainDestination),
}

impl Destination {
    fn new(
        app_name: String,
        aspects: Vec<String>,
        inner: DestinationInner,
    ) -> Result<Destination, DestinationError> {
        if app_name.is_empty() {
            return Err(DestinationError::EmptyAppName);
        }
        if app_name.contains('.') {
            return Err(DestinationError::DotInAppName);
        }
        for aspect in &aspects {
            if aspect.is_empty() {
                return Err(DestinationError::EmptyAspect);
            }
            if aspect.contains('.') {
                return Err(DestinationError::DotInAspect);
            }
        }
        Ok(Destination {
            app_name,
            aspects,
            inner,
        })
    }

    pub fn builder(app_name: String) -> DestinationBuilder {
        DestinationBuilder::new(app_name)
    }

    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    pub fn aspects(&self) -> &[String] {
        &self.aspects
    }

    /// Returns the full name of the destination according to the Reticulum spec.
    pub fn full_name(&self) -> String {
        let mut aspects = self.aspects.clone();
        // For single destinations the spec requires that we include the identity hash as an aspect.
        if let DestinationInner::Single(single) = &self.inner {
            aspects.push(single.identity.hex_hash())
        }
        [&[self.app_name.clone()], aspects.as_slice()]
            .concat()
            .join(".")
    }

    /// Returns the truncated hash of this destination according to the Reticulum spec.
    pub fn truncated_hash(&self) -> Vec<u8> {
        let name = self.full_name();
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hasher.finalize()[..16].to_vec()
    }

    /// Returns the hex representation of the truncated hash of this destination according to the Reticulum spec.
    pub fn hex_hash(&self) -> String {
        hex::encode(self.truncated_hash())
    }

    // /// Constructs an announce packet for this destination.
    // pub fn construct_announce(&mut self) -> Result<Packet, PacketError> {
    //     let single = match &self.inner {
    //         DestinationInner::Single(single) => single,
    //         _ => return Err(PacketError::AnnounceDestinationNotSingle),
    //     };
    //     let current_time = SystemTime::now();
    //     for (tag, response_time, response_data) in &mut self.path_responses {

    //     }
    //     todo!()
    // }
}

pub struct DestinationBuilder {
    app_name: String,
    aspects: Vec<String>,
}

impl DestinationBuilder {
    pub fn new(app_name: String) -> DestinationBuilder {
        DestinationBuilder {
            app_name,
            aspects: Vec::new(),
        }
    }

    pub fn aspect(mut self, aspect: String) -> DestinationBuilder {
        self.aspects.push(aspect);
        self
    }

    pub fn build_single(self, identity: Identity) -> Result<Destination, DestinationError> {
        Destination::new(
            self.app_name,
            self.aspects,
            DestinationInner::Single(SingleDestination { identity }),
        )
    }

    pub fn build_group(self) -> Result<Destination, DestinationError> {
        Destination::new(
            self.app_name,
            self.aspects,
            DestinationInner::Group(GroupDestination {}),
        )
    }

    pub fn build_plain(self) -> Result<Destination, DestinationError> {
        Destination::new(
            self.app_name,
            self.aspects,
            DestinationInner::Plain(PlainDestination {}),
        )
    }
}

#[derive(Debug)]
pub struct SingleDestination {
    identity: Identity,
}

#[derive(Debug)]
pub struct GroupDestination {}

#[derive(Debug)]
pub struct PlainDestination {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_name_single() {
        let identity = Identity::new_local();
        let hex_hash = identity.hex_hash();
        let destination = Destination::builder("app".to_string())
            .aspect("aspect1".to_string())
            .aspect("aspect2".to_string())
            .build_single(identity);
        assert!(destination.is_ok());
        let destination = destination.unwrap();
        assert_eq!(
            destination.full_name(),
            format!("app.aspect1.aspect2.{}", hex_hash)
        );
    }

    #[test]
    fn test_full_name_group() {
        let destination = Destination::builder("app".to_string())
            .aspect("aspect1".to_string())
            .aspect("aspect2".to_string())
            .build_group();
        assert!(destination.is_ok());
        let destination = destination.unwrap();
        assert_eq!(destination.full_name(), "app.aspect1.aspect2");
    }

    #[test]
    fn test_full_name_plain() {
        let destination = Destination::builder("app".to_string())
            .aspect("aspect1".to_string())
            .aspect("aspect2".to_string())
            .build_plain();
        assert!(destination.is_ok());
        let destination = destination.unwrap();
        assert_eq!(destination.full_name(), "app.aspect1.aspect2");
    }

    #[test]
    fn test_hex_hash_single() {
        let identity = Identity::new_local();
        let hex_hash = identity.hex_hash();
        let destination = Destination::builder("app".to_string())
            .aspect("aspect1".to_string())
            .aspect("aspect2".to_string())
            .build_single(identity);
        assert!(destination.is_ok());
        let destination = destination.unwrap();
        assert_eq!(
            destination.full_name(),
            format!("app.aspect1.aspect2.{}", hex_hash)
        );
        let mut hasher = Sha256::new();
        hasher.update(destination.full_name().as_bytes());
        let hash = hasher.finalize();
        assert_eq!(destination.truncated_hash(), &hash[..16]);
        assert_eq!(destination.hex_hash(), hex::encode(&hash[..16]));
    }

    #[test]
    fn test_dot_in_app_name() {
        let identity = Identity::new_local();
        let destination = Destination::builder("app.name".to_string())
            .aspect("aspect".to_string())
            .build_single(identity);
        assert!(destination.is_err());
        let err = destination.unwrap_err();
        assert_eq!(err, DestinationError::DotInAppName);
    }

    #[test]
    fn test_dot_in_aspect() {
        let identity = Identity::new_local();
        let destination = Destination::builder("app".to_string())
            .aspect("aspect.name".to_string())
            .build_single(identity);
        assert!(destination.is_err());
        let err = destination.unwrap_err();
        assert_eq!(err, DestinationError::DotInAspect);
    }
}
