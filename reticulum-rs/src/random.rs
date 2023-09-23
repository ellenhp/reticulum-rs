use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

// lazy_static! {
//     pub(super) static ref RNG: Mutex<CriticalSectionRawMutex, Option<ChaCha20Rng>> =
//         Mutex::new(None);
// }

pub(super) static RNG: Mutex<CriticalSectionRawMutex, Option<ChaCha20Rng>> = Mutex::new(None);

pub(crate) async fn random_bytes(bytes: &mut [u8]) {
    let mut rng = RNG.lock().await;
    let rng = rng.as_mut().unwrap();
    rng.fill_bytes(bytes);
}

pub(crate) async fn init_from_seed(seed: [u8; 32]) {
    let mut rng = RNG.lock().await;
    *rng = Some(ChaCha20Rng::from_seed(seed));
}
