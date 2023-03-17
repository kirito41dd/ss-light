use std::{io::ErrorKind, net::SocketAddr, sync::Arc};

use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    time,
};
use tracing::{debug, error, info, trace, warn};

use crate::config::Config;

pub async fn run_server(cfg: Arc<Config>) -> anyhow::Result<()> {
    // run udp
    let udp_socket = UdpSocket::bind(cfg.get_listen_ip_port()).await?;
    info!("udp server listening on {}", cfg.get_listen_ip_port());
    let cfg_for_udp = cfg.clone();
    tokio::spawn(async move { run_udp(udp_socket, cfg_for_udp).await });

    let mut tcp_listen_ip_port = cfg.get_listen_ip_port();
    // check plugin
    if let Some(plugin_cfg) = &cfg.plugin {
        let p =
            ss_light::plugin::Plugin::start(plugin_cfg, &cfg.bind_addr, &cfg.bind_port.to_string())
                .expect("start plugin");
        tcp_listen_ip_port = p.local_addr().to_string();
        tokio::spawn(async move {
            match p.join().await {
                Ok(status) => {
                    error!("plugin exited with status: {}", status);
                }
                Err(e) => {
                    error!("plugin exited with error: {}", e);
                }
            }
            std::process::exit(-1)
        });
    }

    // run tcp
    let listener = TcpListener::bind(&tcp_listen_ip_port).await?;
    info!("tcp server listening on {}", tcp_listen_ip_port);
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
        Err(ss_light::Error::IoError(ref err)) if err.kind() == ErrorKind::UnexpectedEof => {
            debug!("proxy peer tcp:{}, read target addr: unexpected eof", peer);
            return;
        }
        Err(e) => {
            // Defense active detection attack, https://gfw.report/talks/imc20/zh/
            warn!("proxy peer tcp:{}, reading target addr error: {}, read forever to defense active detection attack", peer, e);
            let res = ss_light::util::read_forever(&mut ss.into_inner()).await;
            trace!("read forever peer: {}, closing with {:?}", peer, res);
            return;
        }
    };

    trace!("proxy peer tcp:{}, read target_addr {}", peer, target_addr);

    let mut target = match time::timeout(cfg.get_timeout(), target_addr.connect()).await {
        Ok(ok) => match ok {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "proxy peer tcp:{}, connect target {} error: {}",
                    peer, target_addr, e
                );
                return;
            }
        },
        Err(_) => {
            debug!(
                "proxy peer tcp:{}, connect target {} timeout",
                peer, target_addr
            );
            return;
        }
    };

    debug!("established new tcp proxy {} <-> {}", peer, target_addr);
    let (a2b, b2a) = match tokio::io::copy_bidirectional(&mut ss, &mut target).await {
        Ok(result) => result,
        Err(e) => {
            warn!("interrupt tcp proxy {} <-> {}: {}", peer, target_addr, e);
            return;
        }
    };
    debug!(
        "complete tcp proxy {} <-> {}, L2R {} bytes, R2L {} bytes",
        peer, target_addr, a2b, b2a
    );
}

async fn run_udp(socket: UdpSocket, cfg: Arc<Config>) {
    let udp_server = ss_light::UdpServer::new(
        socket,
        cfg.get_method(),
        cfg.get_key(),
        cfg.get_udp_capacity(),
        cfg.get_udp_expiry_time(),
    );

    udp_server.run().await
}
