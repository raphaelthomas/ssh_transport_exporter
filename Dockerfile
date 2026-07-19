FROM scratch
ARG TARGETPLATFORM

COPY $TARGETPLATFORM/ssh_transport_exporter /bin/ssh_transport_exporter

EXPOSE 10022
ENTRYPOINT ["/bin/ssh_transport_exporter"]
