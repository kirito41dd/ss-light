FROM rust:1.59.0 AS build
WORKDIR /app
COPY . .
RUN cargo build --release && sh scripts/download_plugins.sh

FROM debian:bullseye-slim
COPY --from=build /app/target/release/server /bin/ss-light
COPY --from=build /app/v2ray-plugin /bin/v2ray-plugin
COPY --from=build /app/config.toml /app/config.toml

EXPOSE 6789/tcp
EXPOSE 6789/udp
WORKDIR /app

ENTRYPOINT ["ss-light","-c","/app/config.toml"]
