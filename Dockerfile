FROM docker

COPY . .

CMD ["docker", "compose", "up"]
