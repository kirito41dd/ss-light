//! Handshake related constants
//!
//! Client send proxy request to sever:
//! ```txt
//! +------+----------+----------+
//! | ATYP | DST.ADDR | DST.PORT |
//! +------+----------+----------+
//! |  1   | Variable |    2     |
//! +------+----------+----------+
//!
//! example: proxy google.com:0
//! bytes: `0x03 0x0A b`google.com` 0x00 0x00`
//!
//!```
//!

use std::{io, string::FromUtf8Error};

pub const SOCKS5_ADDR_TYPE_IPV4: u8 = 0x01;
pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
pub const SOCKS5_ADDR_TYPE_IPV6: u8 = 0x04;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    IoError(#[from] io::Error),
    #[error("unknown address type {0:#x}")]
    UnknownAddressType(u8),
    #[error("invalid domain syntax")]
    InvalidDomainSyntax(#[from] FromUtf8Error),
    #[error("copy error: {1}, {0}")]
    CopyError(io::Error, String),
    #[error("invalid package")]
    InvalidPackage,
    #[error("cipher: {0}")]
    CipherError(ring::error::Unspecified),
}

pub const MAXIMUM_UDP_PAYLOAD_SIZE: usize = 65536; // 64k, udp support max size is: 65535- IP_HEAD(20) - UDP_HEAD(8) = 65507
pub const UDP_KEEP_ALIVE_CHANNEL_SIZE: usize = 64;
pub const UDP_SEND_CHANNEL_SIZE: usize = 51200;
