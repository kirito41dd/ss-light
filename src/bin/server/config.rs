use std::{sync::Arc, time::Duration};

use anyhow::Context;
use clap::{Arg, Command};

use serde::{Deserialize, Serialize};

use derivative::Derivative;

#[derive(Derivative, Deserialize, Serialize)]
#[derivative(Debug)]
pub struct Config {
    pub passwd: String,
    pub bind_addr: String,
    pub bind_port: u16,
    pub method: ss_light::CipherKind,
    #[serde(default)]
    pub timeout: u32,
    #[serde(default = "default_level")]
    pub log_level: String,
    #[serde(default)]
    pub console_log: bool,
    pub file_log_dir: Option<String>,
    #[serde(skip)]
    #[derivative(Debug = "ignore")]
    pub key: Arc<Box<[u8]>>,
    pub udp_capacity: usize,
    pub udp_expiry_time: usize,
}

fn default_level() -> String {
    "info".into()
}

impl Config {
    pub fn load_from_file(file_name: &str) -> anyhow::Result<Config> {
        let s = std::fs::read_to_string(file_name)
            .with_context(|| format!("read config file {}", file_name))?;
        let c: Config =
            toml::from_str(&s).with_context(|| format!("parse config file {}", file_name))?;
        Ok(c)
    }
    pub fn get_log_level(&self) -> tracing::Level {
        match self.log_level.as_str() {
            "error" => tracing::Level::ERROR,
            "warn" => tracing::Level::WARN,
            "info" => tracing::Level::INFO,
            "debug" => tracing::Level::DEBUG,
            "trace" => tracing::Level::TRACE,
            _ => tracing::Level::INFO,
        }
    }
    pub fn get_listen_ip_port(&self) -> String {
        format!("{}:{}", self.bind_addr, self.bind_port)
    }
    pub fn get_key(&self) -> &[u8] {
        &self.key
    }
    pub fn get_method(&self) -> ss_light::CipherKind {
        self.method
    }
    pub fn get_timeout(&self) -> Duration {
        Duration::from_millis(self.timeout as u64)
    }
    pub fn get_udp_capacity(&self) -> usize {
        self.udp_capacity
    }
    pub fn get_udp_expiry_time(&self) -> Duration {
        Duration::from_secs(self.udp_expiry_time as u64)
    }
}

pub fn add_command_line_args(mut app: Command) -> Command {
    app = app
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .takes_value(true)
                .default_value("config.toml")
                .help("server cinfig path"),
        )
        .arg(
            Arg::new("passwd")
                .short('k')
                .long("passwd")
                .takes_value(true)
                .help("overrid pwd in config file"),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .takes_value(true)
                .help("overrid bind_port in config file"),
        )
        .arg(
            Arg::new("listen")
                .short('l')
                .long("listen")
                .takes_value(true)
                .help("overrid bind_addr in config file"),
        );

    app
}
