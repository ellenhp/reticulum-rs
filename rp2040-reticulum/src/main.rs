#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
extern crate alloc;

use alloc::boxed::Box;
use defmt::*;
use embassy_executor::Spawner;
use embassy_rp::gpio;
use embassy_sync::channel;
use embassy_time::{Duration, Timer};
use embedded_alloc::Heap;
use getrandom::register_custom_getrandom;
use gpio::{Level, Output};
use reticulum_rs::{
    identity::Identity,
    persistence::{in_memory::InMemoryReticulumStore, ReticulumStore},
};
use {defmt_rtt as _, panic_probe as _};

#[global_allocator]
static HEAP: Heap = Heap::empty();

pub fn danger_zero_random(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    for i in buf.iter_mut() {
        *i = 0;
    }
    Ok(())
}

register_custom_getrandom!(danger_zero_random);

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    {
        use core::mem::MaybeUninit;
        const HEAP_SIZE: usize = 1024 * 150;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }
    }
    reticulum_rs::random::init_from_seed([0; 32]).await;

    let p = embassy_rp::init(Default::default());
    let mut led = Output::new(p.PIN_25, Level::Low);

    let channel = channel::Channel::new();
    let store: Box<dyn ReticulumStore> = Box::new(InMemoryReticulumStore::new());
    store
        .destination_builder("app")
        .build_single(&Identity::new_local().await, &store)
        .await
        .unwrap();

    let reticulum = reticulum_rs::Reticulum::new_from_channel(&[], &store, channel, spawner)
        .await
        .unwrap();
    reticulum.force_announce_all_local().await.unwrap();

    loop {
        info!("led on!");
        led.set_high();
        Timer::after(Duration::from_secs(1)).await;

        info!("led off!");
        led.set_low();
        Timer::after(Duration::from_secs(1)).await;
    }
}
