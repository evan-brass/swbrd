FROM docker

COPY --link . .

CMD ["docker", "compose", "up"]
