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
3. **Activer les politiques d'audit** pour peupler certains événements :
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

## Étendre

Besoin d'une source spécifique (un journal applicatif, une clé de registre, un
compteur) ? Ajoutez un appel `Collect-Log` (pour un journal d'événements) ou un
petit bloc `Add-Event` dans le script — ou, sans toucher au script, utilisez un
**scripted input** générique côté Linux qui interroge la machine Windows à distance
(cf. section « Ajouter vos sources » du README principal).
