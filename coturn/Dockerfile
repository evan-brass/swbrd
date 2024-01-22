ARG alpine_ver=3.19
ARG git_ref=131ada68e6d0af01b4f6dba2e281b6a99e24ea2c


FROM alpine:${alpine_ver} AS builder

RUN apk update \
	&& apk add --no-cache autoconf coreutils g++ git libtool make \
	linux-headers \
	libevent-dev \
	openssl-dev

WORKDIR /build/
COPY --link broadcast.patch .

RUN git init \
	&& git fetch --depth 1 https://github.com/coturn/coturn.git ${git_ref} \
	&& git checkout FETCH_HEAD \
	# Apply our SO_BROADCAST patch
	&& git apply broadcast.patch \
	&& ./configure --prefix=/usr \
		--turndbdir=/var/lib/coturn \
		--disable-rpath \
		--sysconfdir=/etc/coturn \
		# No documentation included to keep image size smaller.
		--mandir=/tmp/coturn/man \
		--docsdir=/tmp/coturn/docs \
		--examplesdir=/tmp/coturn/examples \
	&& make \
	&& make install

FROM alpine:${alpine_ver} AS runner
RUN apk update \
	&& apk add --no-cache libevent libcrypto3
COPY --from=builder /usr/bin/turnserver /usr/bin
COPY --from=builder /build/LICENSE /usr/share/licenses/coturn/
COPY --link turnserver.conf /etc/coturn/turnserver.conf

EXPOSE 3478/tcp
EXPOSE 3478/udp

ENTRYPOINT ["/usr/bin/turnserver"]
CMD ["-v"]
