# Collecteur Windows

Surveille un poste **ou serveur Windows** (perso comme entreprise) et expédie les
événements au central Plume — équivalent natif PowerShell des collecteurs Linux
(`collectors/*.sh`). Un seul fichier : [`plume-collector.ps1`](plume-collector.ps1).
Aucun agent/spool requis : il **POST directement** sur `/api/ingest` (même contrat
que `ship.sh`, `Authorization: Bearer <token>`).

## Ce qu'il collecte (chaque source dégrade proprement si indisponible)

| source Plume        | contenu                                                        | catégorie |
|---------------------|----------------------------------------------------------------|-----------|
| `windows-security`  | sessions 4624/4625, logoff 4634, privilèges 4672, verrouillage 4740, création de processus 4688, gestion de comptes | auth · process · account |
| `windows-firewall`  | connexions **bloquées** par le pare-feu (WFP 5152/5157) + état des profils | firewall |
| `windows-system`    | arrêts inattendus 6008, échecs de service 7000/7031/7034       | system |
| `windows-defender`  | détections Microsoft Defender 1006/1015/1116/1117              | malware |
| `windows-network`   | connexions TCP établies (distantes) + ports en écoute          | network |

Idempotent (filigrane par source + `dedup` côté central) : le lancer souvent ne
crée pas de doublons. Lecture seule, TLS vérifié par défaut, n'expédie que des
métadonnées d'événements.

## Prérequis

1. **PowerShell 5.1+** (intégré à Windows) — ou PowerShell 7.
2. **Exécuter en compte SYSTEM ou administrateur** (le journal *Security* l'exige).
3. **Activer les politiques d'audit** pour peupler certains événements.

> **Ce que Windows 11 audite DÉJÀ, et ce qu'il n'audite pas.** *Mesuré le 2026‑08‑02 sur un Windows 11
> Enterprise 24H2 (build 26100) fraîchement installé, avant toute modification :*
>
> | sous-catégorie | par défaut | conséquence sans les commandes ci-dessous |
> |---|---|---|
> | `Logon` | **Succès ET échec** | `4624`/`4625` arrivent **out-of-the-box** → `category=auth` est alimentée |
> | `Process Creation` | **Aucun audit** | **`category=exec` reste VIDE** — aucun `4688` n'est écrit |
> | `Filtering Platform Connection` | **Aucun audit** | **`category=firewall` ne reçoit que l'état des profils**, aucun `5152`/`5157` |
>
> Autrement dit : sans la ligne 2, la surveillance d'exécution de processus est inexistante ; sans la
> ligne 1, le pare-feu ne remonte aucun blocage. Les trois commandes ont été exécutées **telles quelles**
> et fonctionnent (`The command was successfully executed.`, 0,16 s au total).
   ```powershell
   auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:enable   # 5152/5157 (pare-feu)
   auditpol /set /subcategory:"Process Creation" /success:enable                                  # 4688
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable                             # 4624/4625
   ```

## Configuration

Créez un jeton sur le central : `plume-daemon token poste-win01`, puis renseignez
soit des variables d'environnement, soit `C:\ProgramData\plume\plume.conf` :

```ini
PLUME_CENTRAL=https://soc.central:7000
PLUME_TOKEN=<le-jeton>
# PLUME_TLS_INSECURE=1   # UNIQUEMENT pour un central en certificat auto-signé de test
```

> ### ⚠️ Ne passez JAMAIS le jeton en ligne de commande
> Le script accepte `-Central` et `-Token` en paramètres. **Ne vous en servez pas pour poser le jeton.**
> Si l'audit `Process Creation` est actif — c'est-à-dire dès que vous avez suivi les prérequis ci-dessus —
> **et** que la GPO *« Include command line in process creation events »* est activée, ou simplement que
> **Sysmon** tourne (Sysmon met la ligne de commande dans son ID 1 **sans aucune GPO**), alors le jeton
> passé en argv est écrit en clair dans le journal *Security*… **que ce collecteur expédie lui-même au
> central**. *Mesuré le 2026‑08‑02 : un jeton-appât passé via `-Token` s'est retrouvé lisible dans le SOC
> par **trois** chemins indépendants — `windows-security`/`exec` (ce script), `WinEventLog:Security`/`exec`
> (agent Rust) et `WinEventLog:Microsoft-Windows-Sysmon/Operational`/`endpoint` (Sysmon ID 1).* C'est le
> pendant Windows de la fuite `sudo` mesurée sur Ubuntu, en **plus large** : le mécanisme n'est pas
> l'outil d'élévation, c'est l'audit d'exécution lui-même. **Écrivez le jeton dans `plume.conf`, jamais
> en argv** — et si vous l'avez déjà fait, révoquez-le.

> ### Le central est en TLS : préparez la confiance AVANT le premier run
> Avec un certificat émis par une CA que le poste ne connaît pas, le run échoue sur
> `Could not establish trust relationship for the SSL/TLS secure channel` — et, faute de spool
> (voir plus bas), **le lot est perdu**. Le chemin d'entreprise est de poser la CA interne dans le
> magasin machine, une fois, avant de planifier la tâche :
> ```powershell
> Import-Certificate -FilePath C:\ProgramData\plume\ca.crt -CertStoreLocation Cert:\LocalMachine\Root
> ```
> *Mesuré : après cet import, `https://soc.central:7000/healthz` répond 200 avec la vérification TLS
> ACTIVE ; `PLUME_TLS_INSECURE=1` n'est alors plus nécessaire.* Pensez aussi à `PLUME_HOST` côté central :
> il doit lister le nom que le poste appelle, sinon la garde anti-rebinding renvoie **421** à tout
> (cf. `deploy/k3s.yaml`).

## Installation en tâche planifiée (toutes les 5 min, en SYSTEM)

```powershell
$ps  = "$PSHOME\powershell.exe"
$arg = "-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\plume\plume-collector.ps1"
# copiez plume-collector.ps1 dans C:\ProgramData\plume\ d'abord
schtasks /Create /TN "Plume Collector" /SC MINUTE /MO 5 /RU SYSTEM /RL HIGHEST `
  /TR "`"$ps`" $arg" /F
```

Test manuel (voir les événements arriver dans Plume) :
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\plume-collector.ps1
```

*La commande `schtasks` ci-dessus a été exécutée **littéralement** le 2026‑08‑02 : elle fonctionne
(`SUCCESS`, 0,14 s) et la tâche survit au redémarrage.*

## Ce que ça coûte, et en combien de temps ça remonte (mesuré le 2026‑08‑02)

*Windows 11 Enterprise 24H2 (build 26100), VM 2 vCPU / 4 Gio, central plume compilé depuis ce dépôt,
chemin réseau privé.*

| | valeur mesurée |
|---|---|
| durée d'un run complet | **35 s** (312 échantillons à 100 ms) |
| crête mémoire du run | **191,5 Mio** (`WorkingSet` du `powershell.exe`) |
| CPU d'un run | 17,4 s, soit **49 % d'un cœur pendant le run** |
| CPU **amorti** sur la période de 5 min | **5,8 % d'un cœur** |
| redémarrage → 1er événement dans le SOC | **240 s** |

**La crête de 191 Mio est le vrai chiffre à retenir** : elle est ~17× celle du collecteur Linux
(11,1 Mio) et ~20× celle de l'agent Rust sur le même poste (9,6 Mio pour un service **permanent**, à
**0,05 % d'un cœur**). C'est le prix de l'hôte PowerShell, pas celui du travail effectué. Sur un poste
bureautique c'est absorbable ; sur un serveur chargé ou une VDI dense, préférez l'agent Rust
(`agent/README.md`), qui remonte en plus **beaucoup** plus vite : **24,6 s** après le redémarrage contre
240 s ici, sur la même machine et le même boot.

> **Le 1er événement est-il de la sécurité ?** Oui, ici — contrairement à Ubuntu où le premier arrivé
> était un battement de santé. Le lot est envoyé par paquets de 400 (`BatchSize`) et le battement est
> ajouté **en dernier** : le premier POST contient donc déjà de l'`auth`. *Mesuré : premier événement
> reçu = `windows-security`/`auth` (« An account was successfully logged on. »).*
>
> **En revanche, le battement de santé n'est PAS un signal de vie à la maille de la tâche.** Son `dedup`
> est bucketé à l'**heure** (`windows-agent-health-<heure>`) : une tâche cadencée à 5 min produit donc
> **au plus un battement par heure**. *Mesuré : 6 runs consécutifs → 1 seul événement `category=health`
> stocké.* Un dead-man's-switch réglé sur « pas de battement depuis 10 min » lèverait de faux positifs.

## Limites connues, mesurées — à lire avant de déployer en flotte

1. **Aucun spool : un POST qui échoue perd le lot.** `Flush-Events` journalise un `Write-Warning` puis
   **vide le tampon**, et le filigrane de la source est avancé juste après — les événements concernés ne
   seront jamais réémis. Un central indisponible 10 minutes = 10 minutes de télémétrie **définitivement**
   perdues. Sous tâche planifiée, le `Write-Warning` ne va nulle part : la perte est **silencieuse**.
   *Non corrigé ici : y remédier demande un spool disque (c'est précisément ce que fait l'agent Rust,
   `spool_cap`, at-least-once).*
2. **Un capteur qui ne peut pas collecter ne le dit pas.** Chaque source est enveloppée dans un
   `try/catch` qui fait `return` : journal absent, accès refusé, filtre vide — les trois sont
   **indiscernables** vu du SOC, exactement le défaut que `collectors/lib.sh` interdit côté Linux avec
   `plume_unavailable` / `plume_disabled` / `plume_exit_nodata`. La garde de CI
   `.github/scripts/check_collector_exit_is_classified.py` ne balaie que `collectors/*.sh` : **ce
   fichier n'est pas dans son périmètre**, et il porte le défaut qu'elle rend non-écrivable ailleurs.
3. **L'inventaire de champs ne couvre pas ce collecteur.** `daemon/src/collected.rs` déclare 12 champs
   pour `plume-collector.ps1` ; *mesuré, ce collecteur en a réellement émis **55 distincts*** (tout
   l'`EventData` du journal : `SubjectUserName`, `NewProcessName`, `LogonType`, `CommandLine`…). L'écart
   n'est pas un oubli de déclaration : les noms viennent du XML **à l'exécution**
   (`foreach ($k in $d.Keys)`), donc l'extracteur **statique** de la garde ne peut pas les voir. La
   garde reste verte tout en sous-couvrant ce chemin — c'est une limite de méthode, pas une dérive.
4. **Sysmon n'est pas lu.** Ce script ne touche pas au canal `Microsoft-Windows-Sysmon/Operational`.
   Pour de la télémétrie Sysmon, il faut l'agent Rust (`agent/README.md`).

## Étendre

Besoin d'une source spécifique (un journal applicatif, une clé de registre, un
compteur) ? Ajoutez un appel `Collect-Log` (pour un journal d'événements) ou un
petit bloc `Add-Event` dans le script — ou, sans toucher au script, utilisez un
**scripted input** générique côté Linux qui interroge la machine Windows à distance
(cf. section « Ajouter vos sources » du README principal).
