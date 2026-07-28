FROM golang:1.25.12-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/ztgotroller ./cmd/ztgotroller && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/ztgotroller-backup ./cmd/ztgotroller-backup && \
    mkdir -p /out/data && touch /out/data/.keep

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ztgotroller /usr/local/bin/ztgotroller
COPY --from=build /out/ztgotroller-backup /usr/local/bin/ztgotroller-backup
COPY --from=build --chown=65532:65532 /out/data/ /var/lib/ztgotroller/
USER 65532:65532
VOLUME ["/var/lib/ztgotroller"]
EXPOSE 9993/udp 9994/tcp
ENTRYPOINT ["/usr/local/bin/ztgotroller"]
CMD ["-identity", "/var/lib/ztgotroller/identity.secret", "-database", "/var/lib/ztgotroller/ztgotroller.db", "-listen", "0.0.0.0:9994", "-udp-listen", ":9993"]
