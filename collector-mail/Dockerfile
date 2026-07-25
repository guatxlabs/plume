# Build du binaire `plume-collector-mail` (Rust, collecteur mail host-native).
# But : EXTRAIRE le binaire vers l'hôte (le VPS n'a pas cargo) — PAS une image runtime.
# Construction de l'image (adaptez a votre chaine de build) :
#   nerdctl build --target export --output type=local,dest=target/release .
#   -> dépose ./target/release/plume-collector-mail, que bootstrap-agent.sh / 37 installent.
FROM rust:1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# Stage d'EXPORT : ne contient QUE le binaire -> `--output type=local` le copie tel quel sur l'hôte.
FROM scratch AS export
COPY --from=build /src/target/release/plume-collector-mail /plume-collector-mail
