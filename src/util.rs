use std::{
    io::{self, Cursor},
    net::SocketAddr,
};

use bytes::BytesMut;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::{ToSocketAddrs, UdpSocket},
};

pub use crate::crypto::util::*;
use crate::Error;
use crate::{crypto::PacketCipher, Address};

/// for udp proxy
impl PacketCipher {
    /// follow shadowsocks protocol send data(socks5_address,buf) to target addr
    pub async fn send_to<A: ToSocketAddrs>(
        &self,
        socket: &UdpSocket,
        buf: &[u8],
        target: A,
        socks5_address: SocketAddr,
    ) -> Result<usize, Error> {
        let mut addr = BytesMut::new();

        Address::write_socket_addr_to_buf(&socks5_address, &mut addr);

        let data = self.encrypt_vec_slice_to(vec![&addr, buf])?;

        let n = socket.send_to(&data, target).await?;
        Ok(n)
    }

    pub async fn recv_from(
        &self,
        socket: &UdpSocket,
        buf: &mut [u8],
    ) -> Result<(usize, SocketAddr, Address), Error> {
        let (n, peer) = socket.recv_from(buf).await?;

        let data_size = self.decrypt_from(&mut buf[..n])?;

        let mut cur = Cursor::new(&mut buf[..data_size]);

        let target = Address::read_from(&mut cur).await?;

        let pos = cur.position() as usize;
        let payload = cur.into_inner();
        payload.copy_within(pos.., 0);

        Ok((payload.len() - pos, peer, target))
    }
}

pub async fn read_forever<R>(reader: &mut R) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    static mut READ_FOREVER_BUF: &mut [u8] = &mut [0u8; 1024];
    loop {
        let n = unsafe { reader.read(READ_FOREVER_BUF).await? };
        if n == 0 {
            break;
        }
    }
    Ok(())
}
