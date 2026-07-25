# Build du binaire `plume-collector-syslog` (Rust, recepteur syslog host-natif).
# But : EXTRAIRE le binaire vers l'hote (le VPS n'a pas cargo) — PAS une image runtime.
# meme pattern que collector-mail :
#   nerdctl build --target export --output type=local,dest=target/release .
#   -> depose ./target/release/plume-collector-syslog, que bootstrap-agent.sh installe.
# Pour le packaging k3s (Deployment + Service :514), une image RUNTIME est fournie par la cible `runtime`.
FROM rust:1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# Stage d'EXPORT : ne contient QUE le binaire -> `--output type=local` le copie tel quel sur l'hote.
FROM scratch AS export
COPY --from=build /src/target/release/plume-collector-syslog /plume-collector-syslog

# Stage RUNTIME (packaging k3s) : image minimale non-root exposant 514/udp+tcp.
# curl + ca-certificates inclus -> le MEME image sert de sidecar "shipper" (spool -> /api/ingest)
# dans le packaging pod (cf. deploy/SYSLOG.md). Une seule
# image, deux roles (receiver = entrypoint par defaut ; shipper = command override en boucle curl).
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 1000 -s /usr/sbin/nologin soc \
 && mkdir -p /var/lib/plume/spool && chown -R soc /var/lib/plume
COPY --from=build /src/target/release/plume-collector-syslog /usr/local/bin/plume-collector-syslog
USER soc
EXPOSE 514/udp
EXPOSE 514/tcp
ENV PLUME_SPOOL=/var/lib/plume/spool
ENTRYPOINT ["/usr/local/bin/plume-collector-syslog"]
