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
        cross-check-win cross-check-mac clean

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
win-msvc:
	$(CARGO) xwin build --release --target x86_64-pc-windows-msvc

# GNU via MinGW-w64 (paquet système `mingw-w64-gcc`).
win-gnu:
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

cross-check-mac:
	rustup target add aarch64-apple-darwin
	$(CARGO) zigbuild --target aarch64-apple-darwin

# Tout cross-checker d'un coup (à lancer en CI).
check-all: cross-check-win cross-check-mac
	$(CARGO) build --release
	$(CARGO) test

clean:
	$(CARGO) clean
