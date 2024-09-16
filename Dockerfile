FROM denoland/deno:alpine

RUN apk add libssl3

WORKDIR /swbrd
ADD --link . .

EXPOSE 3478/udp
VOLUME /var/swbrd

CMD ["task", "start"]
