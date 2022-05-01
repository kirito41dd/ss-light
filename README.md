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
timeout = 2000
log_level = "info"
console_log = true
# file_log_dir = "applog/"
udp_capacity = 1000
udp_expiry_time = 300
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
docker run --rm -it -p 8888:6789/tcp -p 8888:6789/udp ss-light:latest -k passwd123
```
or start with custom config file:
1. create new config dir in home then add `config.toml` file:
    ```
    mkdir $HOME/.ss-light && cd $HOME/.ss-light
    touch config.toml
    ```
2. edit `config.toml`:
    ```toml
    passwd = "123456"
    method = "aes-256-gcm"
    bind_addr = "0.0.0.0"
    bind_port = 6789
    timeout = 2000         # ms, timeout for tcp proxy handshake and tcp connect
    log_level = "info"     # error warn info debug trace
    console_log = true
    # file_log_dir = "applog/" # if no set, don't log to file
    udp_capacity = 1000   # udp relay worker pool size, one proxy req one worker
    udp_expiry_time = 300 # sec, expiration time for udp relay worker keep alive
    ```
3. run docker:
    ```bash
    docker run --rm -it -v $HOME/.ss-light:/app -p 8888:6789/tcp -p 8888:6789/udp ss-light:latest
    ```

> tips: use `<ctrl-p><ctrl-q>` exit container but keep it running



## feature
* Shadowsocks AEAD
    * AES_256_GCM
* TCP relay
* UDP relay

