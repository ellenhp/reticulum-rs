use std::{
    net::{SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use reticulum_rs::{
    interface::{udp::UdpInterface, Interface},
    persistence::in_memory::{InMemoryDestinationStore, InMemoryMessageStore},
    Reticulum,
};
use smol::{block_on, lock::Mutex, Timer};

fn main() {
    env_logger::init();
    block_on(async {
        let interfaces: Vec<Arc<dyn Interface>> = vec![Arc::new(
            UdpInterface::new(
                "127.0.0.1:44243".parse().unwrap(),
                "127.0.0.1:44242".parse().unwrap(),
            )
            .await,
        )];
        let destination_store = Arc::new(Mutex::new(Box::new(InMemoryDestinationStore::new())));
        let message_store = Arc::new(Mutex::new(Box::new(InMemoryMessageStore::new())));

        let node = Reticulum::new(interfaces, destination_store, message_store).unwrap();
        node.register_destination_prefix("reticulum-rs".to_string(), vec![])
            .await
            .unwrap();
        loop {
            let peer_destinations = node.get_peer_destinations().await.unwrap();
            println!("Peer destinations: {:?}", peer_destinations);
            Timer::after(Duration::from_secs(1)).await;
        }
    });
}
