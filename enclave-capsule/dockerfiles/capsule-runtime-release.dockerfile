FROM scratch
ARG TARGETARCH

COPY --from=artifacts ${TARGETARCH}/capsule-runtime /usr/local/bin/capsule-runtime

ENTRYPOINT ["/usr/local/bin/capsule-runtime"]