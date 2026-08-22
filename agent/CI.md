# plume-agent (#16) — CI & validation runtime cross-OS

L'agent d'endpoint est un binaire **autonome** qui tourne SUR le poste
(Linux / Windows / macOS), pas dans le pod SOC. Il lit les sources d'événements
**natives** de l'OS via du code spécifique à chaque plateforme :

| OS      | Source native            | Mécanisme                                   | Garde cfg                        |
|---------|--------------------------|---------------------------------------------|----------------------------------|
| Linux   | journald                 | sous-processus `journalctl`                 | `cfg(target_os = "linux")`       |
| Windows | Windows Event Log        | **FFI `windows`-rs 0.58** (EvtQuery/EvtNext/EvtRender/EvtCreateBookmark) + SCM | `cfg(target_os = "windows")` |
| macOS   | unified log              | sous-processus `log show` + launchd (`launchctl`) | `cfg(target_os = "macos")` |

Le code Windows/macOS est **cfg-gated** : il n'est **jamais compilé** sur un
build Linux. Un `cargo build` local sur la box de dev (Linux) ne prouve donc
**pas** que le FFI Event Log ou le lecteur unified-log compilent et lient. C'est
là que la CI GitHub Actions intervient.

## Où la validation runtime Win/Mac a lieu

**Sur GitHub Actions, une fois les repos poussés sur GitHub** (plan de lancement
Semaine 1). Les runners `windows-latest` et `macos-latest` sont de **vraies
machines** Windows et macOS — pas des émulateurs. Le workflow
[`.github/workflows/agent-ci.yml`](../.github/workflows/agent-ci.yml) lance une
**matrice** `[ubuntu-latest, windows-latest, macos-latest]` qui, sur CHAQUE OS :

1. `cargo build --release` — compile le code natif de cet OS (le FFI Event Log
   sur Windows, le lecteur unified-log sur macOS) ;
2. `cargo test` — exécute les tests (parsing + roundtrips spool/curseur) ;
3. smoke sans réseau — `plume-agent --version` / `--help` (le binaire démarre et
   parse sa CLI clap).

C'est la **validation runtime réelle** : elle ne nécessite PAS que l'opérateur possède
un Mac ou un hôte Windows.

### Comment lire la matrice

Dans l'onglet **Actions** → run `agent-ci`, trois jobs apparaissent :
`agent (ubuntu-latest)`, `agent (windows-latest)`, `agent (macos-latest)`.

- **Les 3 verts** = l'agent compile, ses tests passent et le binaire démarre sur
  les trois OS.
- **Rouge isolé sur `windows-latest`** = régression du FFI Event Log ou du SCM
  (code visible seulement de ce runner).
- **Rouge isolé sur `macos-latest`** = régression du lecteur unified-log / launchd.
- `fail-fast: false` : un OS rouge n'annule pas les autres → on voit d'un coup
  quels OS cassent.

Chaque job publie le binaire natif en artefact (`plume-agent-<OS>`).

### Companion Linux-only : `agent-cross.yml`

[`.github/workflows/agent-cross.yml`](../.github/workflows/agent-cross.yml)
donne à un contributeur **sans Mac ni Windows** un cross-CHECK depuis Linux :
`make cross-check-win` (cargo-xwin, MSVC), `make cross-check-win-fim-native`
(même cible, fonctionnalité `fim_windows_native` activée — le backend FIM
`ReadDirectoryChangesW` n'existe pour le compilateur que sous cette fonctionnalité,
aucun autre job ne le compile) et `make cross-check-mac` (cargo-zigbuild + zig,
darwin). Ça **compile/lie** le code cfg-gated Win/Mac mais ne l'**exécute pas** —
la validation runtime reste la matrice `agent-ci`. La garde
`.github/scripts/check_every_feature_is_compiled_somewhere.py` (job `shell` de
`ci.yml`) exige qu'une fonctionnalité déclarée dans un `Cargo.toml` soit activée
par au moins une commande cargo bloquante d'un workflow.

## Hypothèses des tests sur l'hôte CI (ce qui pourrait échouer sur un runner nu)

Les tests ont été écrits pour tourner sur un runner **vierge**, sans privilège ni
service. Points d'attention :

- **Parsing sur chaînes en dur** : les tests Windows (`winxml_to_event`) et macOS
  (mapping unified-log) opèrent sur des fragments XML/JSON **inline** → ils
  tournent sur les 3 OS et ne lisent **jamais** le vrai Event Log / journal.
- **Pas d'accès au journal/Event Log réel requis** : sur une cible non-native,
  `next_batch()` est un no-op (pas de FFI) ; sur la cible native le FFI n'est pas
  sollicité par les tests (seulement compilé/lié).
- **I/O disque via `std::env::temp_dir()`** (tests `buffer`/`ship`) : écrivable
  sur les 3 runners (y c. `C:\Users\...\AppData\Local\Temp` sur Windows).
- **`test-ship` EXCLU de la CI** : il charge un fichier de config et POST vers un
  endpoint d'ingest → exige config + **réseau**. Le smoke CI se limite donc à
  `--version` / `--help`. Pour un test d'intégration réseau, viser un stub HTTP
  local dans un futur job dédié (non requis aujourd'hui).
- **Aucun service installé** : les tests n'appellent ni `systemctl`, ni
  `launchctl`, ni le SCM — l'install de service n'est pas exercée en CI.

## En local

```sh
cd agent
make            # build release natif (Linux)
make test       # cargo test natif
# cross-check depuis Linux (nécessite cargo-xwin / cargo-zigbuild + zig) :
make cross-check-win
make cross-check-win-fim-native   # + feature fim_windows_native (backend FIM Windows)
make cross-check-mac
```
