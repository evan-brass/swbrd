# Builder
FROM rust:alpine3.18
RUN apk add --no-cache musl-dev

WORKDIR /usr/src/hub
COPY --link . .
RUN cargo install --path .

# Runner
FROM scratch

COPY --from=0 /usr/local/cargo/bin/hub /bin/

EXPOSE 3478

# Use SIGINT because of Tokio::signal::ctrl_c
STOPSIGNAL SIGINT

ENTRYPOINT ["/bin/hub"]
