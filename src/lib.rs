//! # Examples
//! tcp relay with aes-256-gcm:
//! ```no_run
//! use tokio::net::TcpListener;
//! use std::io;
//! use ss_light::*;
//!
//! #[tokio::main]
//! async fn main() -> io::Result<()> {
//!     let pwd = "123456";
//!     let key = util::evp_bytes_to_key(pwd.as_bytes(), CipherKind::AES_256_GCM.key_len());
//!
//!     let listener = TcpListener::bind("127.0.0.1:8080").await?;
//!     let (socket, _) = listener.accept().await?;
//!
//!     // notice: one connection one task
//!     let mut ss = Stream::new_from_stream(socket, CipherKind::AES_256_GCM, &key);
//!
//!     let target_addr = Address::read_from(&mut ss).await.unwrap();
//!     let target = target_addr.connect().await.unwrap();
//!
//!     util::copy_bidirectional(ss, target).await;
//!     Ok(())
//! }
//! ```
//!
//! udp relay with aes-256-gcm:
//! ```no_run
//! use tokio::net::UdpSocket;
//! use std::{io,time};
//! use ss_light::*;
//!
//! #[tokio::main]
//! async fn main() -> io::Result<()> {
//!     let pwd = "123456";
//!     let key = util::evp_bytes_to_key(pwd.as_bytes(), CipherKind::AES_256_GCM.key_len());
//!
//!     let socket = UdpSocket::bind("127.0.0.1:8080").await?;
//!
//!     let udp_server = ss_light::UdpServer::new(
//!         socket,
//!         CipherKind::AES_256_GCM,
//!         &key,
//!         1000,
//!         time::Duration::from_secs(30),
//!     );
//!
//!     udp_server.run().await;
//!     Ok(())
//! }
//! ```
//!
//!
//!

pub mod consts;
pub use consts::Error;
pub mod crypto;
pub use crypto::kind::CipherKind;
pub use crypto::Stream;
mod handshake;
pub use handshake::Address;
mod udprelay;
pub use udprelay::UdpServer;
pub mod plugin;
pub mod util;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
