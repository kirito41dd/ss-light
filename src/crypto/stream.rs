use std::{ops::DerefMut, pin::Pin};

use rand::Fill;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::trace;

use super::{
    aead::{DecryptedReader, EncryptedWriter},
    kind::CipherKind,
};

pub struct Stream<S> {
    stream: S,
    dec: DecryptedReader,
    enc: EncryptedWriter,
    kind: CipherKind,
}

impl<S> Stream<S> {
    pub fn new_from_stream(stream: S, kind: CipherKind, key: &[u8]) -> Stream<S> {
        let mut salt = vec![0u8; kind.salt_len()];
        salt.try_fill(&mut rand::thread_rng()).unwrap();
        trace!("generated AEAD cipher salt {:?}", salt);
        Stream {
            stream,
            kind,
            dec: DecryptedReader::new(kind, key),
            enc: EncryptedWriter::new(kind, key, &salt),
        }
    }

    pub fn kind(&self) -> CipherKind {
        self.kind
    }
}

impl<S> AsyncRead for Stream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let p = self.deref_mut();
        let r = &mut p.dec;
        let stream = &mut p.stream;
        r.poll_read(cx, stream, buf)
    }
}

impl<S> AsyncWrite for Stream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let p = self.deref_mut();
        let w = &mut p.enc;
        let stream = &mut p.stream;
        w.poll_write(cx, stream, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
