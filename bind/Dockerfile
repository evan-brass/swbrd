# Runner
FROM alpine:3.19
RUN apk add --no-cache deno

WORKDIR /app
COPY --link . .

EXPOSE 8000

CMD ["deno", "task", "run"]
