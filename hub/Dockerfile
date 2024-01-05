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

LABEL org.opencontainers.image.source="https://gihub.com/evan-brass/swbrd"
LABEL org.opencontainers.image.description="A pseudo-TURN server for use with switchboard WebRTC addresses."
LABEL org.opencontainers.image.license="MIT-0"

ENTRYPOINT ["/bin/hub"]
