use bytes::{BufMut, Bytes, BytesMut};

use futures::ready;
use ring::aead::{Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_256_GCM};

use core::slice;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::trace;

use super::kind::CipherKind;
use super::util;

enum EncryptWriteState {
    AssemblePacket,
    Writing { pos: usize },
}

pub struct EncryptedWriter {
    sealing_key: Option<SealingKey<util::NonceSequence>>, // for encrypt
    buf: BytesMut,
    state: EncryptWriteState,
    kind: CipherKind,
}

impl EncryptedWriter {
    pub fn new(kind: CipherKind, key: &[u8], salt: &[u8]) -> Self {
        match kind {
            CipherKind::AES_256_GCM => {
                let mut buf = BytesMut::with_capacity(salt.len());
                buf.put(salt);

                // cacl sub_key
                let sub_key = util::hkdf_sha1(key, salt);

                let unbound =
                    UnboundKey::new(&AES_256_GCM, &sub_key).expect("key.len != algorithm.key_len");
                let sealing_key = SealingKey::new(unbound, util::NonceSequence::new());

                Self {
                    sealing_key: Some(sealing_key),
                    buf,
                    state: EncryptWriteState::AssemblePacket,
                    kind,
                }
            }
            _ => panic!("unsupport chipher kind"),
        }
    }

    /// Write buf to stream, return num_bytes_written
    ///
    /// An AEAD encrypted TCP stream starts with a randomly generated salt to derive the per-session subkey, followed by any number of encrypted chunks.
    /// Each chunk has the following structure:
    ///
    /// [encrypted payload length][length tag][encrypted payload][payload tag]
    ///
    /// More details in the [wiki](https://shadowsocks.org/en/wiki/AEAD-Ciphers.html)
    pub fn poll_write<S>(
        &mut self,
        cx: &mut Context,
        stream: &mut S,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        if buf.len() > self.kind.max_package_size() {
            buf = &buf[..self.kind.max_package_size()]
        }

        loop {
            match self.state {
                EncryptWriteState::AssemblePacket => {
                    // 1. append length
                    let befor_len = self.buf.len(); // salt in buf at begain
                    let length_size = 2;
                    self.buf.reserve(length_size);
                    self.buf.put_u16(buf.len() as u16);
                    let view = &mut self.buf.as_mut()[befor_len..];
                    debug_assert!(view.len() == length_size);
                    let tag = self
                        .sealing_key
                        .as_mut()
                        .unwrap()
                        .seal_in_place_separate_tag(Aad::<[u8; 0]>::empty(), view)
                        .expect("seal_in_place_separate_tag for length");
                    self.buf.extend_from_slice(tag.as_ref());

                    // 2. append data
                    let befor_len = self.buf.len(); // length data at before
                    self.buf.extend_from_slice(buf);
                    let view = &mut self.buf.as_mut()[befor_len..];
                    let tag = self
                        .sealing_key
                        .as_mut()
                        .unwrap()
                        .seal_in_place_separate_tag(Aad::<[u8; 0]>::empty(), view)
                        .expect("seal_in_place_separate_tag for data");
                    self.buf.extend_from_slice(tag.as_ref());

                    // 3. write all
                    self.state = EncryptWriteState::Writing { pos: 0 };
                }
                EncryptWriteState::Writing { ref mut pos } => {
                    while *pos < self.buf.len() {
                        let n = ready!(Pin::new(&mut *stream).poll_write(cx, &self.buf[*pos..]))?;
                        *pos += n;
                    }

                    // reset
                    self.state = EncryptWriteState::AssemblePacket;
                    self.buf.clear();
                    return Ok(buf.len()).into();
                }
            }
        }
    }
}

enum DecryptReadState {
    WaitSalt,
    ReadLength,
    ReadData { length: usize },
    BufferedData { pos: usize },
}
pub struct DecryptedReader {
    opening_key: Option<OpeningKey<util::NonceSequence>>, // for decrypt
    buf: BytesMut,
    state: DecryptReadState,
    kind: CipherKind,
    salt: Option<Bytes>,
    key: Bytes,
}

impl DecryptedReader {
    pub fn new(kind: CipherKind, key: &[u8]) -> Self {
        match kind {
            CipherKind::AES_256_GCM => Self {
                opening_key: None,
                buf: BytesMut::new(),
                state: DecryptReadState::WaitSalt,
                kind,
                salt: None,
                key: Bytes::copy_from_slice(key),
            },
            _ => panic!("unsupport chipher kind"),
        }
    }

    pub fn poll_read<S>(
        &mut self,
        cx: &mut Context,
        stream: &mut S,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        loop {
            match self.state {
                DecryptReadState::WaitSalt => {
                    let salt_len = self.kind.salt_len();
                    let n = ready!(self.poll_read_exact_or_zero(cx, stream, salt_len))?;
                    if n == 0 {
                        return Err(ErrorKind::UnexpectedEof.into()).into();
                    }
                    debug_assert!(self.buf.len() == salt_len);
                    self.salt = Some(Bytes::copy_from_slice(&self.buf));

                    // cacl sub_key
                    let sub_key = util::hkdf_sha1(&self.key, self.salt.as_ref().unwrap());
                    trace!("peer sub_key is {:?}", sub_key);

                    let unbound = UnboundKey::new(&AES_256_GCM, &sub_key)
                        .expect("key.len != algorithm.key_len");
                    let opening_key = OpeningKey::new(unbound, util::NonceSequence::new());

                    self.buf.clear();
                    self.state = DecryptReadState::ReadLength;
                    self.buf.reserve(2 + self.kind.tag_len());
                    self.opening_key = Some(opening_key);
                }
                DecryptReadState::ReadLength => {
                    let usize =
                        ready!(self.poll_read_exact_or_zero(cx, stream, 2 + self.kind.tag_len()))?;
                    if usize == 0 {
                        return Ok(()).into();
                    } else {
                        let result = self
                            .opening_key
                            .as_mut()
                            .unwrap()
                            .open_in_place(Aad::<[u8; 0]>::empty(), &mut self.buf)
                            .map_err(|_| {
                                io::Error::new(ErrorKind::Other, "ReadLength invalid tag-in")
                            })?;
                        let plen = u16::from_be_bytes([result[0], result[1]]) as usize;
                        if plen > self.kind.max_package_size() {
                            let  err = io::Error::new(
                                ErrorKind::InvalidData,
                                format!(
                                    "buffer size too large ({:#x}), AEAD encryption protocol requires buffer to be smaller than 0x3FFF, the higher two bits must be set to zero",
                                    plen
                                ),
                            );
                            return Err(err).into();
                        }
                        self.buf.clear();
                        self.state = DecryptReadState::ReadData { length: plen };
                        self.buf.reserve(plen + self.kind.tag_len())
                    }
                }
                DecryptReadState::ReadData { length } => {
                    let data_len = length + self.kind.tag_len();
                    let n = ready!(self.poll_read_exact_or_zero(cx, stream, data_len))?;
                    if n == 0 {
                        return Err(ErrorKind::UnexpectedEof.into()).into();
                    }
                    debug_assert_eq!(data_len, self.buf.len());

                    let _ = self
                        .opening_key
                        .as_mut()
                        .unwrap()
                        .open_in_place(Aad::<[u8; 0]>::empty(), &mut self.buf)
                        .map_err(|_| io::Error::new(ErrorKind::Other, "ReadData invalid tag-in"))?;

                    // remove tag
                    self.buf.truncate(length);
                    self.state = DecryptReadState::BufferedData { pos: 0 };
                }
                DecryptReadState::BufferedData { ref mut pos } => {
                    if *pos < self.buf.len() {
                        let buffered = &self.buf[*pos..];
                        let consumed = usize::min(buffered.len(), buf.remaining());
                        buf.put_slice(&buffered[..consumed]);
                        *pos += consumed;

                        return Ok(()).into();
                    }
                    self.buf.clear();
                    self.state = DecryptReadState::ReadLength;
                    self.buf.reserve(2 + self.kind.tag_len());
                }
            }
        }
    }

    fn poll_read_exact_or_zero<S>(
        &mut self,
        cx: &mut Context,
        stream: &mut S,
        size: usize,
    ) -> Poll<io::Result<usize>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        assert!(size != 0);
        while self.buf.len() < size {
            let remaing = size - self.buf.len();

            let view = &mut self.buf.chunk_mut()[..remaing];
            debug_assert_eq!(view.len(), remaing);
            let mut read_buf = ReadBuf::uninit(unsafe {
                slice::from_raw_parts_mut(view.as_mut_ptr() as *mut _, remaing)
            });

            ready!(Pin::new(&mut *stream).poll_read(cx, &mut read_buf))?;
            let n = read_buf.filled().len();

            unsafe { self.buf.advance_mut(n) }

            if n == 0 {
                if !self.buf.is_empty() {
                    return Err(ErrorKind::UnexpectedEof.into()).into();
                } else {
                    return Ok(0).into();
                }
            }
        }
        Ok(size).into()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ops::DerefMut,
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::{ready, Future};
    use tokio::io::ReadBuf;

    use crate::crypto::{aead::DecryptedReader, kind::CipherKind, util};

    use super::EncryptedWriter;

    #[tokio::test]
    async fn test_reader_writer() {
        let pwd = "123456";
        let salt = &[0u8; 32];
        let key = util::evp_bytes_to_key(pwd.as_bytes(), CipherKind::AES_256_GCM.key_len());

        struct Fut {
            r: DecryptedReader,
            w: EncryptedWriter,
            mock: Vec<u8>,
        }

        impl Future for Fut {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let content = "hello";

                let p = self.deref_mut();

                let w = &mut p.w;
                let mock = &mut p.mock;

                let n = ready!(w.poll_write(cx, mock, content.as_bytes())).unwrap();
                assert_eq!(n, content.len());

                let r = &mut p.r;
                let mut bs = [0u8; 1024];
                let mut buf = ReadBuf::new(&mut bs);
                ready!(r.poll_read(cx, &mut mock.as_slice(), &mut buf)).unwrap();

                assert_eq!(buf.filled(), content.as_bytes());

                ().into()
            }
        }

        Fut {
            r: DecryptedReader::new(CipherKind::AES_256_GCM, &key),
            w: EncryptedWriter::new(CipherKind::AES_256_GCM, &key, salt),
            mock: Vec::<u8>::new(),
        }
        .await
    }
}
