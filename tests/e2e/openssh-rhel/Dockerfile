ARG IMAGE=rockylinux/rockylinux:10
FROM ${IMAGE}
RUN dnf install -y openssh-server \
 && dnf clean all \
 && ssh-keygen -A
CMD ["/usr/sbin/sshd", "-D", "-e"]
