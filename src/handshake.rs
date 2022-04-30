use std::{
    fmt::{self, Formatter},
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use bytes::BufMut;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::TcpStream,
};

use crate::consts::*;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub enum Address {
    SocketAddress(SocketAddr),
    DomainNameAddress(String, u16), // domain name, port
}

impl Address {
    pub async fn read_from<R>(stream: &mut R) -> Result<Address, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut addr_type_buf = [0u8; 1];
        stream.read_exact(&mut addr_type_buf).await?;

        match addr_type_buf[0] {
            SOCKS5_ADDR_TYPE_IPV4 => {
                let mut buf = [0u8; 6];
                stream.read_exact(&mut buf).await?;
                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(
                    ip, port,
                ))))
            }
            SOCKS5_ADDR_TYPE_IPV6 => {
                let mut buf = [0u8; 18];
                stream.read_exact(&mut buf).await?;
                let ip = Ipv6Addr::from([
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
                    buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
                ]);
                let port = u16::from_be_bytes([buf[16], buf[17]]);
                Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(
                    ip, port, 0, 0,
                ))))
            }
            SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
                let mut length_buf = [0u8; 1];
                stream.read_exact(&mut length_buf).await?;
                let length = length_buf[0] as usize;

                let buf_length = length + 2; // domain + port
                let mut buf = vec![0u8; buf_length];
                stream.read_exact(&mut buf).await?;

                let port = u16::from_be_bytes([buf[length], buf[length + 1]]);
                buf.truncate(length);
                let addr = String::from_utf8(buf)?;

                Ok(Address::DomainNameAddress(addr, port))
            }
            _ => Err(Error::UnknownAddressType(addr_type_buf[0])),
        }
    }

    pub fn write_socket_addr_to_buf<B: BufMut>(addr: &SocketAddr, buf: &mut B) {
        match *addr {
            SocketAddr::V4(ref addr) => {
                buf.put_u8(SOCKS5_ADDR_TYPE_IPV4);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            SocketAddr::V6(ref addr) => {
                buf.put_u8(SOCKS5_ADDR_TYPE_IPV6);
                for seg in &addr.ip().segments() {
                    buf.put_u16(*seg);
                }
                buf.put_u16(addr.port());
            }
        }
    }

    pub fn port(&self) -> u16 {
        match *self {
            Address::SocketAddress(addr) => addr.port(),
            Address::DomainNameAddress(.., port) => port,
        }
    }

    pub fn host(&self) -> String {
        match *self {
            Address::SocketAddress(ref addr) => addr.ip().to_string(),
            Address::DomainNameAddress(ref domain, ..) => domain.to_owned(),
        }
    }

    pub async fn connect(&self) -> io::Result<TcpStream> {
        let stream = match *self {
            Address::SocketAddress(ref sa) => TcpStream::connect(sa).await?,
            Address::DomainNameAddress(ref dname, port) => {
                TcpStream::connect((dname.as_str(), port)).await?
            }
        };
        Ok(stream)
    }
}

impl fmt::Display for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}
