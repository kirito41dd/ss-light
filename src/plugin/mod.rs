//! plugin support. SIP003 [https://shadowsocks.org/en/wiki/Plugin.html](https://shadowsocks.org/en/wiki/Plugin.html)
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    process::{ExitStatus, Stdio},
};

use derivative::Derivative;
use serde::{Deserialize, Serialize};
use tokio::process::{Child, Command};
use tracing::{error, info, trace};

#[derive(Derivative, Deserialize, Serialize, Clone)]
#[derivative(Debug)]
pub struct PluginConfig {
    pub name: String,
    pub opts: Option<String>,
    pub args: Vec<String>,
}

/// server plugin: CLIENT -> PLUGIN -> SERVER -> REMOTE
///
/// plugin listen to inbound address of server
///
/// server listen to local_addr
pub struct Plugin {
    process: Child,
    local_addr: SocketAddr,
}

impl Plugin {
    // start plugin in subprocess
    pub fn start(cfg: &PluginConfig, remote_host: &str, remote_port: &str) -> io::Result<Plugin> {
        let local_addr = get_local_port(Ipv4Addr::LOCALHOST.into())?;

        trace!(
            "starting plugin {}, opts: {:?}, args: {:?} listen to {}:{}, ss will use local {}",
            cfg.name,
            cfg.opts,
            cfg.args,
            remote_host,
            remote_port,
            local_addr
        );

        let mut cmd = Command::new(&cfg.name);

        cmd.env("SS_REMOTE_HOST", remote_host)
            .env("SS_REMOTE_PORT", remote_port)
            .env("SS_LOCAL_HOST", local_addr.ip().to_string())
            .env("SS_LOCAL_PORT", local_addr.port().to_string())
            .stdin(Stdio::null())
            .kill_on_drop(true);

        if let Some(opts) = &cfg.opts {
            cmd.env("SS_PLUGIN_OPTIONS", opts);
        }

        if !cfg.args.is_empty() {
            cmd.args(&cfg.args);
        }

        match cmd.spawn() {
            Ok(process) => {
                info!(
                    "started plugin {} on {}:{} <-> {}, pid:{}",
                    cfg.name,
                    remote_host,
                    remote_port,
                    local_addr,
                    process.id().unwrap_or(0)
                );
                Ok(Plugin {
                    process,
                    local_addr,
                })
            }
            Err(e) => {
                error!("failed to start plugin {} err: {}", cfg.name, e);
                Err(e)
            }
        }
    }

    // wait plugin exits
    pub async fn join(mut self) -> io::Result<ExitStatus> {
        self.process.wait().await
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

fn get_local_port(loop_ip: IpAddr) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(SocketAddr::new(loop_ip, 0))?;
    listener.local_addr()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_local_port() {
        let local_addr = get_local_port(Ipv4Addr::LOCALHOST.into()).unwrap();
        println!("{:?}", local_addr);
    }
}
