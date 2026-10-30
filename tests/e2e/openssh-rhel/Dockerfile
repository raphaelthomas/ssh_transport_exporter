ARG IMAGE=rockylinux/rockylinux:10
FROM ${IMAGE}
RUN sed -i -e 's/^mirrorlist=/#mirrorlist=/' -e 's/^#baseurl=/baseurl=/' /etc/yum.repos.d/*.repo \
 && dnf install -y --disablerepo='*' --enablerepo=baseos openssh-server \
 && dnf clean all \
 && ssh-keygen -A
CMD ["/usr/sbin/sshd", "-D", "-e"]
