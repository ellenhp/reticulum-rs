#![allow(unused_imports)]
pub use fernet;

pub mod destination;
pub mod identity;
pub mod interface;
pub mod packet;
pub mod transport;

pub fn do_something() {
    fernet::Fernet::generate_key();
}
