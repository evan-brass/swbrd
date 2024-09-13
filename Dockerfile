FROM denoland/deno:alpine

RUN apk add libssl3

WORKDIR /swbrd
ADD . .

EXPOSE 3478/udp
VOLUME /swbrd/cert.pem

CMD deno task start
