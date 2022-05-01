FROM rust:latest AS build
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:buster-slim
COPY --from=build /app/target/release/server /ss-light
COPY --from=build /app/config.toml /app/config.toml

EXPOSE 6789/tcp
EXPOSE 6789/udp
WORKDIR /app

ENTRYPOINT ["/ss-light","-c","/app/config.toml"]
