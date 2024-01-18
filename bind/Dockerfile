# Builder
FROM rust:alpine3.18
RUN apk add --no-cache musl-dev

WORKDIR /usr/src/bind
COPY --link . .
RUN cargo install --path .

# Runner
FROM scratch

COPY --from=0 /usr/local/cargo/bin/bind /bin/
# TODO: Copy licenses for tokio and webrtc-rs

ENV RTC_CERT=generate
# TODO: Expose the udp mux port?
# EXPOSE 3478

# Use SIGINT because of Tokio::signal::ctrl_c
STOPSIGNAL SIGINT

ENTRYPOINT ["/bin/bind"]
