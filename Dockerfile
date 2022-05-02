FROM rust:latest AS build
WORKDIR /app
COPY . .
RUN cargo build --release && sh scripts/download_plugins.sh

FROM debian:buster-slim
COPY --from=build /app/target/release/server /ss-light
COPY --from=build /app/v2ray-plugin /v2ray-plugin
COPY --from=build /app/config.toml /app/config.toml

EXPOSE 6789/tcp
EXPOSE 6789/udp
WORKDIR /app
ENV PATH="/:$PATH"

ENTRYPOINT ["/ss-light","-c","/app/config.toml"]
