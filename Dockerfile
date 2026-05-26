FROM alpine:latest AS builder

RUN apk add --no-cache g++ make musl-dev

WORKDIR /app

COPY main.cpp scanner.cpp scanner.h Makefile ./

RUN make

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/netscout .

CMD ["./netscout"]