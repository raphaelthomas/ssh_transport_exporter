FROM alpine:3.23
RUN apk add --no-cache openssh-server \
 && ssh-keygen -A
CMD ["/usr/sbin/sshd", "-D", "-e"]
