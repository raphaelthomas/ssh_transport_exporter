FROM alpine:3.23
RUN apk add --no-cache tinyssh busybox-extras \
 && tinysshd-makekey /etc/tinyssh/sshkeydir
# TinySSH has no listener of its own.
CMD ["busybox-extras", "tcpsvd", "0.0.0.0", "22", "tinysshd", "-v", "/etc/tinyssh/sshkeydir"]
