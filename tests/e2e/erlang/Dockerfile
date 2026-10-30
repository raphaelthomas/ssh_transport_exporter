FROM erlang:28-alpine
RUN apk add --no-cache openssh-keygen \
 && mkdir -p /etc/ssh-erlang \
 && ssh-keygen -q -t ed25519 -N "" -f /etc/ssh-erlang/ssh_host_ed25519_key
WORKDIR /app
COPY server.escript ./
CMD ["escript", "server.escript"]
