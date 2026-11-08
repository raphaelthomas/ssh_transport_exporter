ARG IMAGE=debian:13
FROM ${IMAGE}
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && ssh-keygen -A \
 && for k in /etc/ssh/ssh_host_*_key; do echo "HostCertificate $k-cert.pub"; done >> /etc/ssh/sshd_config
# Signed at start, not at build: a cached layer would keep an earlier run's CA.
CMD ["/bin/sh", "-c", "ssh-keygen -q -s /ca/ca -h -I e2e -n 127.0.0.1 /etc/ssh/ssh_host_*_key.pub && exec /usr/sbin/sshd -D -e"]
