use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

// lazy_static! {
//     pub(super) static ref RNG: Mutex<CriticalSectionRawMutex, Option<ChaCha20Rng>> =
//         Mutex::new(None);
// }

#[cfg(feature = "embassy")]
pub(super) static RNG: embassy_sync::mutex::Mutex<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    Option<ChaCha20Rng>,
> = embassy_sync::mutex::Mutex::new(None);
#[cfg(feature = "tokio")]
lazy_static::lazy_static! {
    pub(crate) static ref RNG: tokio::sync::Mutex<Option<ChaCha20Rng>> = tokio::sync::Mutex::new(None);
}

pub(crate) async fn random_bytes(bytes: &mut [u8]) {
    let mut rng = RNG.lock().await;
    let rng = rng.as_mut().unwrap();
    rng.fill_bytes(bytes);
}

pub async fn init_from_seed(seed: [u8; 32]) {
    let mut rng = RNG.lock().await;
    *rng = Some(ChaCha20Rng::from_seed(seed));
}
