## shadowsocks lightweight implementation(server side)
a proxy tool written in rust.

## build
```bash
git clone https://github.com/kirito41dd/ss-light.git
cd ss-light && cargo test
cargo build --release
./target/release/server --version
```
## usage
run with `config.toml`:
```bash
./server -c config.toml
```
```toml
passwd = "123456"
method = "aes-256-gcm"
bind_addr = "0.0.0.0"
bind_port = 6789
timeout = 2000         # ms, timeout for tcp proxy handshake and tcp connect
log_level = "info"     # error warn info debug trace
console_log = true
# file_log_dir = "applog/" # if no set, don't log to file
udp_capacity = 1000  # udp relay worker pool size, one proxy req one worker
udp_expiry_time = 30 # sec, expiration time for udp relay worker keep alive
# [plugin]
# name = "v2ray-plugin"
# opts = "server"
# args = []
```

or override config with: 
```bash
./server -c config.toml -l 127.0.0.1 -p 1080 -k <a-secure-password>
```
if without `-c`, default config file is `$pwd/config.toml`

more usage:
```bash
./server -h
```

## quick start with docker
start with default config but specify password:
```bash
docker run --rm -it -p 8888:6789/tcp -p 8888:6789/udp kirito41dd/ss-light -k passwd123
```
or start with custom config file:
1. create new config dir in home then add `config.toml` file:
    ```
    mkdir $HOME/.ss-light && cd $HOME/.ss-light
    touch config.toml
    ```
2. edit `config.toml` like [here](#usage)
3. run docker:
    ```bash
    docker run --rm -it -v $HOME/.ss-light:/app -p 8888:6789/tcp -p 8888:6789/udp kirito41dd/ss-light
    ```
use plugin:
```
docker run --rm -it -p 8888:6789/tcp -p 8888:6789/udp kirito41dd/ss-light -k passwd123 --plugin v2ray-plugin --plugin-opts server
```
use other [SIP003](https://shadowsocks.org/en/wiki/Plugin.html) plugins:
1. lick start with custom config file, download plugin to `$HOME/.ss-light`
2. start
    ```
    docker run --rm -it -v $HOME/.ss-light:/app -p 8888:6789/tcp -p 8888:6789/udp kirito41dd/ss-light --plugin=/app/<your-plugin>
    ```


> tips: use `<ctrl-p><ctrl-q>` exit container but keep it running



## feature
* Shadowsocks AEAD
    * AES_256_GCM
* TCP relay
* UDP relay
* Plugin
    * v2ray-plugin

