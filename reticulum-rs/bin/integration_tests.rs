// use core::{sync::Arc, time::Duration};

// use reticulum_rs::{
//     identity::Identity,
//     interface::{udp::UdpInterface, Interface},
//     persistence::{
//         in_memory::{InMemoryDestinationStore, InMemoryMessageStore},
//         DestinationStore,
//     },
//     Reticulum,
// };
// use smol::{block_on, lock::Mutex, Timer};

// fn main() {
//     env_logger::init();
//     block_on(async {
//         let interfaces: Vec<Arc<dyn Interface>> = vec![Arc::new(
//             UdpInterface::new(
//                 "127.0.0.1:44243".parse().unwrap(),
//                 "127.0.0.1:44242".parse().unwrap(),
//             )
//             .await,
//         )];
//         let destination_store = Arc::new(Mutex::new(Box::new(InMemoryDestinationStore::new())));
//         let message_store = Arc::new(Mutex::new(Box::new(InMemoryMessageStore::new())));

//         let node = Reticulum::new(interfaces, destination_store.clone(), message_store).unwrap();
//         node.register_destination_prefix("reticulum-rs".to_string(), vec![])
//             .await
//             .unwrap();

//         {
//             let mut destination_store = destination_store.lock().await;
//             destination_store
//                 .as_mut()
//                 .builder("reticulum-rs")
//                 .build_single(&Identity::new_local(), destination_store.as_mut())
//                 .await
//                 .unwrap();
//         }
//         loop {
//             let peer_destinations = node.get_peer_destinations().await.unwrap();
//             println!("Peer destinations: {:?}", peer_destinations);
//             node.force_announce_all_local().await.unwrap();
//             Timer::after(Duration::from_secs(1)).await;
//         }
//     });
// }
fn main() {}
