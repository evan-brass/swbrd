# Just for debugging to let us see what traffic is beind sent
FROM alpine

RUN apk add --no-cache tcpdump

VOLUME /var/capture

CMD ["tcpdump", "-w", "/var/capture/tcpdump.pcap"]
