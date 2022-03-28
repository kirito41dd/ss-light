//! Handshake related constants
//!
//! Client send proxy request to sever:
//! ```
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
}
