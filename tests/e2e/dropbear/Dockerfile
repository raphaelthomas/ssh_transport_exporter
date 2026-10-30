FROM alpine:3.23
RUN apk add --no-cache dropbear \
 && mkdir -p /etc/dropbear \
 && dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key
CMD ["dropbear", "-F", "-E", "-r", "/etc/dropbear/dropbear_ed25519_host_key"]
