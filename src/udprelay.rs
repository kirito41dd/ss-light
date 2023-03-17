use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use futures::future;
use lru_time_cache::LruCache;
use tokio::{
    io,
    net::{lookup_host, UdpSocket},
    sync::mpsc,
    task::JoinHandle,
    time,
};
use tracing::{debug, error, trace, warn};

use crate::{
    consts::{MAXIMUM_UDP_PAYLOAD_SIZE, UDP_KEEP_ALIVE_CHANNEL_SIZE, UDP_SEND_CHANNEL_SIZE},
    crypto::PacketCipher,
    Address, CipherKind,
};

pub struct UdpServer {
    cipher: Arc<PacketCipher>,
    socket: Arc<UdpSocket>,
    route_table: LruCache<SocketAddr, UdpTunnelWorkerHandle>, // peer addr -> worker
    keepalive_tx: mpsc::Sender<SocketAddr>,
    keepalive_rx: mpsc::Receiver<SocketAddr>,
    time_to_live: Duration,
}

impl UdpServer {
    pub fn new(
        socket: UdpSocket,
        kind: CipherKind,
        key: &[u8],
        cap: usize,
        time_to_live: Duration,
    ) -> Self {
        let cipher = PacketCipher::new(kind, key);
        let cipher = Arc::new(cipher);
        let route_table = LruCache::with_expiry_duration_and_capacity(time_to_live, cap);
        let (keepalive_tx, keepalive_rx) = mpsc::channel(UDP_KEEP_ALIVE_CHANNEL_SIZE);
        let socket = Arc::new(socket);
        UdpServer {
            cipher,
            socket,
            route_table,
            keepalive_tx,
            keepalive_rx,
            time_to_live,
        }
    }

    pub async fn run(mut self) {
        let recv_buf = &mut [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let mut cleanup_timer = time::interval(self.time_to_live);
        loop {
            tokio::select! {
                result = self.cipher.recv_from(&self.socket, recv_buf) => {
                    match result {
                        Ok((n, peer, target)) => {
                            if n == 0 {continue;}
                            let data = &recv_buf[..n];

                            if let Err(e) = self.send_to_tunnle_worker(peer, target, data).await {
                                error!("udp proxy peer {} with {} bytes, send to tunnle worker error: {}", peer,  n, e);
                            }
                        }
                        Err(e) => {
                            error!("udp proxy recv error {}", e);
                            continue;
                        }
                    }
                }

                _ = cleanup_timer.tick() => {
                    let _ = self.route_table.iter();
                }

                peer_addr_keep_opt = self.keepalive_rx.recv() => {
                    let peer = peer_addr_keep_opt.expect("keep-alive channel closed unexpectly");
                    self.route_table.get(&peer);
                }
            }
        }
    }

    async fn send_to_tunnle_worker(
        &mut self,
        peer: SocketAddr,
        target: Address,
        data: &[u8],
    ) -> io::Result<()> {
        if let Some(worker_handle) = self.route_table.get(&peer) {
            return worker_handle.try_send_to_worker((target, Bytes::copy_from_slice(data)));
        }
        // create a new worker
        debug!("new udp proxy request {} <-> ...", peer);
        let woker_handle = UdpTunnelWorkerHandle::new(
            self.socket.clone(),
            self.keepalive_tx.clone(),
            peer,
            self.cipher.clone(),
        );

        woker_handle.try_send_to_worker((target, Bytes::copy_from_slice(data)))?;
        self.route_table.insert(peer, woker_handle);
        Ok(())
    }
}

struct UdpTunnelWorkerHandle {
    join_handle: JoinHandle<()>,
    sender: mpsc::Sender<(Address, Bytes)>,
}

impl Drop for UdpTunnelWorkerHandle {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

impl UdpTunnelWorkerHandle {
    fn new(
        server_socket: Arc<UdpSocket>,
        keepalive_tx: mpsc::Sender<SocketAddr>,
        peer_addr: SocketAddr,
        cipher: Arc<PacketCipher>,
    ) -> Self {
        let (join_handle, sender) =
            UdpTunnelWorker::create(server_socket, keepalive_tx, peer_addr, cipher);
        UdpTunnelWorkerHandle {
            join_handle,
            sender,
        }
    }
    fn try_send_to_worker(&self, data: (Address, Bytes)) -> io::Result<()> {
        if let Err(..) = self.sender.try_send(data) {
            let err = io::Error::new(io::ErrorKind::Other, "udp send channel full");
            return Err(err);
        }
        Ok(())
    }
}

struct UdpTunnelWorker {
    keepalive_tx: mpsc::Sender<SocketAddr>,
    keepalive_flag: bool,
    server_socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    outbound_ipv4_socket: Option<UdpSocket>,
    outbound_ipv6_socket: Option<UdpSocket>,
    cipher: Arc<PacketCipher>,
}

impl UdpTunnelWorker {
    fn create(
        server_socket: Arc<UdpSocket>,
        keepalive_tx: mpsc::Sender<SocketAddr>,
        peer_addr: SocketAddr,
        cipher: Arc<PacketCipher>,
    ) -> (JoinHandle<()>, mpsc::Sender<(Address, Bytes)>) {
        let (tx, rx) = mpsc::channel(UDP_SEND_CHANNEL_SIZE);

        let woker = UdpTunnelWorker {
            keepalive_tx,
            keepalive_flag: false,
            server_socket,
            peer_addr,
            outbound_ipv4_socket: None,
            outbound_ipv6_socket: None,
            cipher,
        };

        let join_handle = tokio::spawn(async move { woker.run(rx).await });

        (join_handle, tx)
    }

    async fn run(mut self, mut rx: mpsc::Receiver<(Address, Bytes)>) {
        let mut outbound_ipv4_buffer = Vec::new();
        let mut outbound_ipv6_buffer = Vec::new();
        let mut keepalive_interval = time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                recevied_opt = rx.recv() => {
                    let (target_addr, data) = match recevied_opt {
                        Some(d) => d,
                        None => {
                            trace!("udp tunnel worker for peer {} -> ... channel closed", self.peer_addr);
                            break;
                        }

                    };
                    if let Err(e) = self.send_data_to_target(&target_addr, &data).await {
                        error!("udp proxy {} <-> {}, L2R {} bytes err: {}", self.peer_addr, target_addr, data.len(), e);
                    }
                    debug!("udp proxy {} <-> {}, L2R {} bytes", self.peer_addr, target_addr, data.len())
                }

                recevied_opt = Self::recv_data_from_target(&self.outbound_ipv4_socket,&mut outbound_ipv4_buffer) => {
                    let (n, target_addr) = match recevied_opt {
                        Ok(r) => r,
                        Err(e) => {
                            error!("udp tunnel worker for peer {} <- ... failed, error: {}", self.peer_addr, e);
                            continue;
                        }
                    };
                    self.send_data_to_peer(target_addr, &outbound_ipv4_buffer[..n]).await;

                }

                recevied_opt = Self::recv_data_from_target(&self.outbound_ipv6_socket,&mut outbound_ipv6_buffer) => {
                    let (n, target_addr) = match recevied_opt {
                        Ok(r) => r,
                        Err(e) => {
                            error!("udp tunnel worker for peer {} <- ... failed, error: {}", self.peer_addr, e);
                            continue;
                        }
                    };
                    self.send_data_to_peer(target_addr, &outbound_ipv6_buffer[..n]).await;
                }

                _ = keepalive_interval.tick() => {
                    if self.keepalive_flag {
                        if let Err(..) = self.keepalive_tx.try_send(self.peer_addr) {
                            debug!("udp tunnel worker for peer {} keep-alive failed, channel full or closed", self.peer_addr);
                        } else {
                            self.keepalive_flag = false;
                        }
                    }
                }
            }
        }
    }

    async fn send_data_to_target(&mut self, target_addr: &Address, data: &[u8]) -> io::Result<()> {
        let target_sa: SocketAddr;
        match *target_addr {
            Address::SocketAddress(sa) => target_sa = sa,
            Address::DomainNameAddress(ref domain, port) => {
                match lookup_host((domain.as_str(), port)).await {
                    Ok(mut v) => {
                        match v.next() {
                            Some(sa) => target_sa = sa,
                            None => {
                                return Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("dns resolve exmpty: {}", domain),
                                ))
                            }
                        };
                    }
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("dns resolve {} error: {}", domain, e),
                        ))
                    }
                };
            }
        }

        let socket = match target_sa {
            SocketAddr::V4(..) => match self.outbound_ipv4_socket {
                Some(ref mut socket) => socket,
                None => {
                    let socket =
                        UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)).await?;
                    self.outbound_ipv4_socket.insert(socket)
                }
            },
            SocketAddr::V6(..) => match self.outbound_ipv6_socket {
                Some(ref mut socket) => socket,
                None => {
                    let socket =
                        UdpSocket::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)).await?;
                    self.outbound_ipv6_socket.insert(socket)
                }
            },
        };

        let n = socket.send_to(data, target_sa).await?;
        if n != data.len() {
            warn!(
                "udp proxy {} -> {} sent {} bytes != expected {} bytes",
                self.peer_addr,
                target_addr,
                n,
                data.len()
            );
        }
        Ok(())
    }

    async fn recv_data_from_target(
        socket: &Option<UdpSocket>,
        buf: &mut Vec<u8>,
    ) -> io::Result<(usize, SocketAddr)> {
        match *socket {
            None => future::pending().await,
            Some(ref s) => {
                if buf.is_empty() {
                    buf.resize(MAXIMUM_UDP_PAYLOAD_SIZE, 0);
                }
                s.recv_from(buf).await
            }
        }
    }

    async fn send_data_to_peer(&mut self, target: SocketAddr, data: &[u8]) {
        self.keepalive_flag = true;

        if let Err(e) = self
            .cipher
            .send_to(&self.server_socket, data, self.peer_addr, target)
            .await
        {
            warn!(
                "udp tunnel worker sendback {} bytes to peer {}, from target {}, err: {}",
                data.len(),
                self.peer_addr,
                target,
                e
            );
        } else {
            debug!(
                "udp proxy {} <-> {}, R2L {} bytes",
                self.peer_addr,
                target,
                data.len()
            );
        }
    }
}
