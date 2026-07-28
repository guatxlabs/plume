# SOC central (daemon : ingestion + API + PWA). Les capteurs hôte/agents poussent via POST /api/ingest.
#
# CONTEXTE DE BUILD = la RACINE DE CE DÉPÔT. Le daemon résout `guatx-core` via une git-dep
#    publique (`git = "https://github.com/guatxlabs/core", tag = "v0.2.1"`, cf. daemon/Cargo.toml) —
#    core est donc récupéré depuis GitHub AU BUILD, aucun crate sibling n'est requis dans le contexte.
#    Un clone STANDALONE de ce dépôt construit directement :
#
#        docker build -t soc:latest .              # depuis la racine du dépôt
#    ou  docker compose up -d --build              # (docker-compose.yml, context: .)
#
#    L'exclusion du contexte (target/, .git/, *.db…) vit dans Dockerfile.dockerignore
#    (dockerignore par-Dockerfile, honoré par BuildKit quand -f Dockerfile).

# build
# Images de base ÉPINGLÉES PAR DIGEST (reproductibilité : un tag flottant `rust:1-bookworm` peut
# glisser sous nos pieds entre deux builds). Ré-épingler = ré-résoudre le digest de l'index multi-arch
# (`docker buildx imagetools inspect rust:1-bookworm`) et remplacer le sha ci-dessous.
FROM rust:1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS build
WORKDIR /build
# OOM-AWARE : sur une petite machine (~2 Gio de RAM), on BORNE le
# parallélisme de rustc à 2 jobs. BuildKit n'hérite PAS de l'env de l'hôte -> le cap DOIT vivre ici (un
# `CARGO_BUILD_JOBS=2` passé au script n'atteindrait jamais le `cargo` dans le conteneur). Réduit le pic
# mémoire (moins de rustc parallèles sur le graphe de deps) -> évite l'OOM du build, et sur un hôte
# partagé évite de faire évincer les charges voisines. S'applique aux DEUX builds.
ENV CARGO_BUILD_JOBS=2

# ---------------------------------------------------------------------------------------------------
# COUCHE CACHE DE DÉPENDANCES (motif « dummy-crate »). On copie D'ABORD uniquement les manifestes +
# le lockfile, avec des sources FACTICES (lib vide + `fn main(){}`), et on compile pour CACHER tout le
# graphe de deps tierces (axum/tokio/rusqlite-sqlcipher-vendored/age/…, le plus long du build). Une
# modification de SOURCE seule (le cas courant) réutilise alors cette couche -> ZÉRO recompilation des
# deps. `guatx-core` (git-dep) fait partie du graphe de deps tierces caché ici.
# ---------------------------------------------------------------------------------------------------
COPY daemon/Cargo.toml daemon/Cargo.lock ./daemon/
RUN mkdir -p daemon/src \
    && echo 'fn main() {}' > daemon/src/main.rs
WORKDIR /build/daemon
# VENDOR-AGNOSTIC (C2) — `--features ldap` DÉFAUT-ON dans l'image stock : le login LDAP/AD natif ne renvoie
# PLUS 501 (bring-your-own-directory sans rebuild). Coût mesuré : ~40 crates PUR-RUST en plus (ldap3/lber +
# asn1/x509 + url/idna/icu) ; AUCUNE nouvelle dép C — `openssl-sys` provient déjà de SQLCipher (rusqlite),
# `ring` déjà tiré par rustls/age -> pas de cc1plus/OOM (contraste avec `duckdb`, laissé opt-in). INERTE tant
# qu'aucun provider LDAP n'est configuré (aucun endpoint ouvert, aucune surface active par défaut).
# --locked : le build ÉCHOUE si Cargo.lock devait bouger (lock présent, deps figées, builds reproductibles).
RUN cargo build --release --locked --features ldap
# Purge les artefacts du crate LOCAL issu du stub (plume-daemon) pour forcer sa recompilation depuis
# les VRAIES sources — sans invalider le cache des deps tierces ci-dessus (dont guatx-core, git-dep).
RUN rm -rf target/release/deps/plume_daemon* \
           target/release/plume-daemon \
           target/release/.fingerprint/plume-daemon-*

# ---------------------------------------------------------------------------------------------------
# SOURCES RÉELLES. Reproduit l'arbo relative attendue par le daemon (`include_str!`) : db/ et docs/
# restent siblings de daemon/ sous /build.
#   /build/daemon/src -> ../../db/schema.sql            = /build/db
#   /build/daemon/src/handlers -> ../../../docs/...     = /build/docs
# guatx-core est une git-dep (récupérée au build) — pas de crate sibling à copier.
# Le dossier target/ (cache des deps) N'EST PAS dans le contexte (dockerignore) -> préservé par COPY.
# ---------------------------------------------------------------------------------------------------
WORKDIR /build
COPY daemon ./daemon
COPY db ./db
COPY config.d ./config.d
COPY docs/connector-presets ./docs/connector-presets
# soql-templates/*.json est embarqué par include_str! dans handlers/soql_meta.rs (hors daemon/) -> DOIT être
# présent dans le contexte de build AVANT cargo build, sinon la compilation échoue (gotcha include_str-hors-daemon).
COPY docs/soql-templates ./docs/soql-templates
WORKDIR /build/daemon
RUN cargo build --release --locked --features ldap

# runtime (minimal) — image de base épinglée par digest (cf. note ci-dessus).
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 soc
COPY --from=build /build/daemon/target/release/plume-daemon /usr/local/bin/plume-daemon
COPY web /usr/local/share/plume/web
# Overlay de config versionné (parseurs/règles/playbooks custom, source de vérité git) -> chargé au boot
# par load_overlays() en cache DB (managed=1). Baké comme les assets web (rootfs read-only en pod).
COPY config.d /usr/local/share/plume/config.d
# Assets web PUBLICS (servis au navigateur) : lisibles par l'uid non-root (10001) qui exécute le daemon.
# Sinon des perms restrictives du contexte de build (vu : 0660 root) -> ServeDir renvoie 404 sur l'UI
# (l'uid 10001 ne peut pas lire les fichiers). a+rX = lecture pour tous + traversée des dossiers (fonts/).
RUN chmod -R a+rX /usr/local/share/plume/web /usr/local/share/plume/config.d
RUN install -d -o soc -g soc /data /data/spool
USER soc
# LEVIER RAM (glibc arena cap) : borne le nombre d'arenas malloc à 2 (défaut = 8×CPU). Mesuré 2300→310 MiB
# sur ce process (nombreux threads : loops rollup/refresh/ingest + pool read-only) où le fragment par-arena
# domine. DÉJÀ appliqué dans le manifeste k8s (deployment.yaml) ; baké ici en DURABILITÉ (belt-and-suspenders)
# pour qu'un déploiement frais depuis CE Dockerfile n'hérite pas du défaut glibc. RUNTIME stage uniquement
# (le process daemon hérite de l'env) ; sans effet sur le comportement fonctionnel (allocateur seul).
ENV MALLOC_ARENA_MAX=2
ENV PLUME_WEB=/usr/local/share/plume/web \
    PLUME_CONFIG_DIR=/usr/local/share/plume/config.d \
    PLUME_DB=/data/soc.db \
    PLUME_SPOOL=/data/spool \
    PLUME_ADDR=0.0.0.0:7000 \
    PLUME_HOST=soc.localhost \
    PLUME_CONFIG=/nonexistent
EXPOSE 7000
VOLUME /data
# SOC_PASS_HASH doit être fourni au run :  docker run --rm soc hashpw 'monmdp'
ENTRYPOINT ["plume-daemon"]
