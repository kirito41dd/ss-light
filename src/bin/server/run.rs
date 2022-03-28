use std::{net::SocketAddr, sync::Arc};

use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, trace};

use crate::config::Config;

pub async fn run_server(cfg: Arc<Config>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(cfg.get_listen_ip_port()).await?;
    info!("listening on {}", cfg.get_listen_ip_port());
    loop {
        let (socket, peer) = listener.accept().await?;
        trace!("new connetion from {}", peer.to_string());
        let cfg = cfg.clone();
        tokio::spawn(async move { process(socket, peer, cfg).await });
    }
}

async fn process(socket: TcpStream, peer: SocketAddr, cfg: Arc<Config>) {
    let mut ss = ss_light::crypto::Stream::new_from_stream(socket, cfg.get_method(), cfg.get_key());
    let target_addr = match ss_light::Address::read_from(&mut ss).await {
        Ok(addr) => addr,
        Err(e) => {
            error!(
                "process peer {}, reading target addr error: {}",
                peer.ip(),
                e
            );
            return;
        }
    };
    info!("new proxy {} <-> {}", peer, target_addr);

    let target = {
        let target = match target_addr {
            ss_light::Address::SocketAddress(ref sa) => match TcpStream::connect(sa).await {
                Ok(target) => target,
                Err(e) => {
                    error!("failed to connect target {}: {}", target_addr, e);
                    return;
                }
            },
            ss_light::Address::DomainNameAddress(ref dname, port) => {
                match TcpStream::connect((dname.as_str(), port)).await {
                    Ok(target) => target,
                    Err(e) => {
                        error!("failed to connect target {}: {}", target_addr, e);
                        return;
                    }
                }
            }
        };
        trace!("success connected to target {}", target_addr);
        target
    };

    let (a2b, b2a) = match ss_light::util::copy_bidirectional(ss, target).await {
        Ok(result) => result,
        Err(e) => {
            error!("error when proxy {} <-> {}: {}", peer, target_addr, e);
            return;
        }
    };
    info!(
        "complete proxy {} <-> {}, L2R {} bytes, R2L {} bytes",
        peer, target_addr, a2b, b2a
    );
}
