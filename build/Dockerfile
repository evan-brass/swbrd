FROM --platform=$BUILDPLATFORM alpine AS builder
RUN apk add build-base llvm17 clang17 lld binaryen wasi-sdk
RUN apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing/ wabt

WORKDIR /build

ADD --checksum=sha256:3ecf94fcfdaacafb757786a01b7538a61750ebd85c4b024f56ff8ba1490fcd38 https://github.com/Mbed-TLS/mbedtls/releases/download/v3.6.0/mbedtls-3.6.0.tar.bz2 .
RUN mkdir mbedtls && tar -xjf mbedtls-3.6.0.tar.bz2 -C mbedtls --strip-components 1

VOLUME /build/dist

COPY --link build/Makefile .
COPY --link switch/c_src c_src

CMD ["make", "-B"]
