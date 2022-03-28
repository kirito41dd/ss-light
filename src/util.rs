use tokio::io::{copy, AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::error;

pub use crate::crypto::util::*;
use crate::Error;

pub async fn copy_bidirectional<SA, SB>(a: SA, b: SB) -> Result<(u64, u64), Error>
where
    SA: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    SB: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    // b -> a
    let handle = tokio::spawn(async move {
        let rn = copy(&mut br, &mut aw).await;
        let result = aw.shutdown().await;
        if let Err(e) = result {
            error!("shutdown stream a err {}", e);
        }
        let n = match rn {
            Ok(n) => n,
            Err(e) => return Err(Error::CopyError(e, "b -> a".into())),
        };
        Ok::<u64, Error>(n)
    });

    // a -> b
    let rn = copy(&mut ar, &mut bw).await;
    let result = bw.shutdown().await;
    if let Err(e) = result {
        error!("shutdown stream b err {}", e);
    }

    let b2a = handle.await.unwrap()?;

    let a2b = match rn {
        Ok(n) => n,
        Err(e) => return Err(Error::CopyError(e, "a -> b".into())),
    };

    Ok((a2b, b2a))
}
