ARG IMAGE=debian:13
FROM ${IMAGE}
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && ssh-keygen -A
CMD ["/usr/sbin/sshd", "-D", "-e"]
