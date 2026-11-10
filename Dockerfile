FROM alpine:3.20 AS builder

RUN apk add --no-cache g++ make musl-dev

WORKDIR /src
COPY main.cpp scanner.cpp scanner.h Makefile ./
RUN make clean all

FROM alpine:3.20

RUN apk add --no-cache libstdc++ \
    && adduser -D -u 10001 scanner \
    && mkdir -p /app \
    && chown scanner:scanner /app

WORKDIR /app
COPY --from=builder /src/netscout /usr/local/bin/netscout

USER scanner
ENTRYPOINT ["/usr/local/bin/netscout"]