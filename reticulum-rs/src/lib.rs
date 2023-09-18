#![allow(unused_imports)]
pub use fernet;

pub mod identity;
pub mod packet;

pub fn do_something() {
    fernet::Fernet::generate_key();
}
