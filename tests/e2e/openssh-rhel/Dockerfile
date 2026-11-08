ARG IMAGE=rockylinux/rockylinux:10
FROM ${IMAGE}
RUN sed -i -e 's/^mirrorlist=/#mirrorlist=/' -e 's/^#baseurl=/baseurl=/' /etc/yum.repos.d/*.repo \
 && dnf install -y --disablerepo='*' --enablerepo=baseos openssh-server \
 && dnf clean all \
 && ssh-keygen -A \
 && for k in /etc/ssh/ssh_host_*_key; do echo "HostCertificate $k-cert.pub"; done >> /etc/ssh/sshd_config
# Signed at start, not at build: a cached layer would keep an earlier run's CA.
CMD ["/bin/sh", "-c", "ssh-keygen -q -s /ca/ca -h -I e2e -n 127.0.0.1 /etc/ssh/ssh_host_*_key.pub && exec /usr/sbin/sshd -D -e"]
