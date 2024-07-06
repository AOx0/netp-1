#![no_std]

pub mod eth;
pub mod ipv4;
pub mod tcp;
pub mod udp;

#[cfg(feature = "aya")]
pub mod aya;

mod ipnum;
pub use ipnum::InetProtocol;
