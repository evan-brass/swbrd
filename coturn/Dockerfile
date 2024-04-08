FROM ghcr.io/coturn/coturn:edge-alpine

COPY --link turnserver.conf /etc/coturn/turnserver.conf

EXPOSE 3478/tcp
EXPOSE 3478/udp

ENTRYPOINT ["/usr/bin/turnserver"]
CMD ["-v"]
