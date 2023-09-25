use std::{sync::Arc, time::Duration};

use lazy_static::lazy_static;
use rand::RngCore;
use reticulum_rs::{
    identity::{Identity, IdentityCommon},
    packet::{MessagePacket, PacketContextType, WirePacket},
    persistence::{in_memory::InMemoryReticulumStore, ReticulumStore},
    Reticulum,
};
use sha2::{Digest, Sha256};
use tokio::{net::UdpSocket, spawn, sync::Mutex};

#[tokio::main]
async fn main() {
    env_logger::init();
    let mut seed = [0; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    reticulum_rs::random::init_from_seed(seed).await;

    dbg!(seed);

    let socket = UdpSocket::bind("127.0.0.1:44243").await.unwrap();

    let store: Arc<Box<dyn ReticulumStore>> = Arc::new(Box::new(InMemoryReticulumStore::new()));

    let node = Reticulum::new(store.clone()).unwrap();
    node.register_destination_prefix("reticulum-rs".to_string(), vec![])
        .await
        .unwrap();

    let node_ref = node.clone();
    spawn(async move {
        let max_packet_size = 1024;
        let mut buffer = vec![0; max_packet_size];
        loop {
            let len = socket.recv(&mut buffer).await.unwrap();
            let packet = WirePacket::unpack(&buffer[..len]).unwrap();
            match packet.clone().into_semantic_packet().unwrap() {
                reticulum_rs::packet::Packet::Announce(announce) => {
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(announce.destination_name_hash().0);
                    hasher.update(announce.identity().truncated_hash());
                    let destination_hash = hasher.finalize();
                    println!(
                        "Received announce: {:?}, {:?}, {:?}",
                        hex::encode(announce.destination_name_hash().0),
                        hex::encode(announce.identity().truncated_hash()),
                        hex::encode(destination_hash),
                    );
                }
                reticulum_rs::packet::Packet::Other(_) => {}
            }
            node_ref.process_packet(packet).await.unwrap();
        }
    });

    let local_identity = Identity::new_local().await;
    let destination = store
        .clone()
        .destination_builder("reticulum-rs")
        .build_single(&local_identity, store.as_ref())
        .await
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    loop {
        let peer_destinations = node.get_peer_destinations().await.unwrap();
        println!("Peer destinations: {:?}", peer_destinations);

        let announce_packets = node.announce_local_destinations().await.unwrap();
        for packet in announce_packets {
            socket
                .send_to(packet.pack().unwrap().as_slice(), "127.0.0.1:44242")
                .await
                .unwrap();
        }
        for peer in peer_destinations {
            println!(
                "Sending message to peer: {:?}, {:?}, {:?}",
                hex::encode(peer.name_hash().0),
                hex::encode(peer.address_hash().0),
                hex::encode(peer.identity().unwrap().truncated_hash()),
            );
            println!(
                "From identity: {:?}",
                hex::encode(destination.address_hash().0)
            );
            let message_packet =
                MessagePacket::new(&peer, PacketContextType::None, vec![0, 1, 2, 3])
                    .await
                    .unwrap();
            dbg!(socket
                .send_to(
                    message_packet.wire_packet().pack().unwrap().as_slice(),
                    "127.0.0.1:44242",
                )
                .await
                .unwrap());
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
