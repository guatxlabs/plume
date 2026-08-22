# plume-agent (#16) — matrice de build cross-OS.
#
# Cible native (Linux) : `make` / `make test`.
# Cross-compilation depuis Linux :
#   Windows  -> `cargo-xwin` (MSVC, recommandé) ou la toolchain MinGW-w64 (GNU).
#   macOS    -> `cargo-zigbuild` (Zig comme linker) + SDK Apple, ou `osxcross`.
#
# Outils (une fois) :
#   rustup target add x86_64-pc-windows-msvc x86_64-pc-windows-gnu \
#                     x86_64-apple-darwin aarch64-apple-darwin x86_64-unknown-linux-musl
#   cargo install cargo-xwin cargo-zigbuild
#   # zig requis par cargo-zigbuild : https://ziglang.org/download/
#   # SDK macOS (SDKROOT) requis pour LIER les cibles apple ; `cargo check` seul n'en a pas besoin.

CARGO ?= cargo

.PHONY: all test check-all \
        linux linux-musl \
        win-msvc win-gnu \
        mac-x64 mac-arm \
        cross-check-win cross-check-win-fim-native cross-check-mac clean

# --- natif (Linux dev box) -----------------------------------------------------------------------
all: linux
linux:
	$(CARGO) build --release

test:
	$(CARGO) test

linux-musl:
	rustup target add x86_64-unknown-linux-musl
	$(CARGO) build --release --target x86_64-unknown-linux-musl

# --- Windows -------------------------------------------------------------------------------------
# MSVC via cargo-xwin (télécharge les headers/libs MSVC, aucune VM Windows requise).
# La CRT STATIQUE est imposée par `.cargo/config.toml` (sans elle l'exe importe VCRUNTIME140.dll et
# ne démarre pas sur un Windows sans redistribuable — mesuré). NE PAS poser de RUSTFLAGS ici : la
# variable d'environnement ÉCRASERAIT le fichier de config, en silence.
win-msvc:
	$(CARGO) xwin build --release --target x86_64-pc-windows-msvc

# GNU via MinGW-w64 (paquet système `mingw-w64-gcc`).
# PRÉREQUIS VÉRIFIÉ AVANT DE LANCER LE BUILD : sans MinGW, `cargo build` part quand même, compile
# plusieurs minutes de dépendances, puis échoue au fond d'un build script sur un message que rien ne
# relie au paquet manquant. MESURÉ le 2026-08-02 sur cette machine :
#   error occurred in cc-rs: failed to find tool "x86_64-w64-mingw32-gcc": No such file or directory
#   error: error calling dlltool 'x86_64-w64-mingw32-dlltool': No such file or directory
# On teste donc l'outil AVANT et on nomme le paquet à installer.
win-gnu:
	@command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || { \
	  echo "!! MinGW-w64 absent : la cible x86_64-pc-windows-gnu ne peut pas LIER."; \
	  echo "   Installe-le (Debian/Ubuntu: apt install mingw-w64 | Arch: pacman -S mingw-w64-gcc |"; \
	  echo "   Fedora: dnf install mingw64-gcc), ou utilise la cible MSVC : make win-msvc"; \
	  echo "   (MSVC est le chemin recommandé : cargo-xwin télécharge le SDK, aucune VM requise.)"; \
	  exit 1; }
	rustup target add x86_64-pc-windows-gnu
	$(CARGO) build --release --target x86_64-pc-windows-gnu

# --- macOS ---------------------------------------------------------------------------------------
mac-x64:
	$(CARGO) zigbuild --release --target x86_64-apple-darwin
mac-arm:
	$(CARGO) zigbuild --release --target aarch64-apple-darwin

# --- cross-CHECK (valide le code cfg-gated Win/Mac depuis Linux) ----------------------------------
# NB : rustls -> ring compile du C dans son build.rs, donc un simple `cargo check --target ...` ÉCHOUE
# sans compilateur C pour la cible (mingw / cc darwin). On passe donc par les mêmes wrappers que les
# builds : cargo-xwin (clang-cl + CRT MSVC téléchargé) et cargo-zigbuild (zig cc fournit la libc cible).
# Ni MinGW ni le SDK Apple/Xcode ne sont requis. Prérequis : `cargo install cargo-xwin cargo-zigbuild`
# + `zig` dans le PATH (https://ziglang.org/download/). Ces cibles ont surfacé de vraies erreurs FFI
# (signatures windows-rs 0.58 EvtNext/EvtRender) invisibles au build Linux — d'où leur exécution en CI.
cross-check-win:
	rustup target add x86_64-pc-windows-msvc
	$(CARGO) xwin check --target x86_64-pc-windows-msvc

# La fonctionnalité `fim_windows_native` (backend FIM `ReadDirectoryChangesW`, éteinte par défaut)
# n'existe pour le compilateur que sous `cfg(all(windows, feature = "fim_windows_native"))` : le
# check ci-dessus ne la voit PAS, et une régression de compilation y resterait invisible (mesuré
# le 2026-08-21 : une erreur de type sous ce `cfg` rend rc=101 avec la fonctionnalité, rc=0 sans).
# MÊME répertoire cible, MÊME profil, aucune dépendance en plus : seul le crate de l'agent est
# re-vérifié (0,83 s mesurées le 2026-08-21 après `cross-check-win`). Ce qui N'EST PAS prouvé ici :
# le lien et l'exécution sur un hôte Windows (cf. le commentaire de la fonctionnalité dans Cargo.toml).
cross-check-win-fim-native: cross-check-win
	$(CARGO) xwin check --target x86_64-pc-windows-msvc --features fim_windows_native

cross-check-mac:
	rustup target add aarch64-apple-darwin
	$(CARGO) zigbuild --target aarch64-apple-darwin

# Tout cross-checker d'un coup (à lancer en CI).
check-all: cross-check-win-fim-native cross-check-mac
	$(CARGO) build --release
	$(CARGO) test

clean:
	$(CARGO) clean
