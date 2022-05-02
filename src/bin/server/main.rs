use std::{process, sync::Arc};

use clap::{ArgMatches, Command};
use config::Config;
use futures::future;

use ss_light::plugin::PluginConfig;
use tracing::{error, info, metadata::LevelFilter};
use tracing_subscriber::{
    filter, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, Layer,
};

mod config;
mod run;
use run::*;

fn main() -> anyhow::Result<()> {
    let mut app = Command::new("ss-light")
        .version(ss_light::VERSION)
        .about("A lightweight shadowsocks implementation.");
    app = config::add_command_line_args(app);

    let matches = app.get_matches();

    let config = parse_config(&matches)?;
    init_tracing_subscriber(&config);
    info!("start with {:#?}", config);

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let server = run_server(Arc::new(config));
        let sig = tokio::signal::ctrl_c();

        tokio::pin!(server, sig);

        match future::select(server, sig).await {
            future::Either::Left((result, ..)) => match result {
                Ok(()) => {}
                Err(e) => {
                    error!("exit with error: {}", e);
                    process::exit(-1)
                }
            },
            future::Either::Right(_) => {
                info!("receive exit signal")
            }
        }
    });

    Ok(())
}

fn parse_config(matches: &ArgMatches) -> anyhow::Result<Config> {
    let mut config = Config::load_from_file(matches.value_of("config").unwrap())?;

    if let Some(passwd) = matches.value_of("passwd") {
        config.passwd = passwd.into();
    }

    if let Some(listen) = matches.value_of("listen") {
        config.bind_addr = listen.into();
    }

    if let Some(port) = matches.value_of("port") {
        config.bind_port = port.parse()?;
    };

    if let Some(log_level) = matches.value_of("log-level") {
        config.log_level = log_level.into();
    }

    if let Some(plugin) = matches.value_of("plugin") {
        let plugin_cfg = config.plugin.get_or_insert(PluginConfig {
            name: "".into(),
            opts: None,
            args: vec![],
        });
        plugin_cfg.name = plugin.into();
    }

    if let Some(plugin_opts) = matches.value_of("plugin-opts") {
        let plugin_cfg = config.plugin.get_or_insert(PluginConfig {
            name: "".into(),
            opts: None,
            args: vec![],
        });
        plugin_cfg.opts = Some(plugin_opts.into());
    }

    let key = ss_light::util::evp_bytes_to_key(config.passwd.as_bytes(), config.method.key_len());
    config.key = Arc::new(key);

    Ok(config)
}

fn init_tracing_subscriber(c: &Config) {
    let formateter = tracing_subscriber::fmt::format()
        .with_level(true)
        .with_target(true);

    let file_level_filter = LevelFilter::from(c.get_log_level());
    let mut console_level_filter = file_level_filter;
    if !c.console_log {
        console_level_filter = LevelFilter::OFF;
    }

    let layer = tracing_subscriber::registry().with(
        filter::Targets::new()
            .with_target("server", console_level_filter)
            .with_target("ss_light", console_level_filter)
            .and_then(tracing_subscriber::fmt::layer().event_format(formateter.clone())),
    );

    if let Some(dir) = &c.file_log_dir {
        let file_appender = tracing_appender::rolling::daily(dir, "ss-light.log");
        layer
            .with(
                filter::Targets::new()
                    .with_target("server", file_level_filter)
                    .with_target("ss_light", file_level_filter)
                    .and_then(
                        tracing_subscriber::fmt::layer()
                            .event_format(formateter)
                            .with_writer(file_appender)
                            .with_ansi(false),
                    ),
            )
            .init();
    } else {
        layer.init();
    }
}
