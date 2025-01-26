FROM denoland/deno

WORKDIR /swbrd
ADD --link . .

EXPOSE 3478/udp
VOLUME /var/swbrd

CMD ["task", "start"]
