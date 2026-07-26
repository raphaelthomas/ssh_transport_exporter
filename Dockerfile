FROM scratch
ARG TARGETPLATFORM

COPY $TARGETPLATFORM/ssh_transport_exporter /bin/ssh_transport_exporter

USER 65534:65534
EXPOSE 10022
ENTRYPOINT ["/bin/ssh_transport_exporter"]
