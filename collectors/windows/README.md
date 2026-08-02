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
>
> **Un SERVEUR n'audite PAS plus qu'un poste — mesuré, et c'est contre-intuitif.** *Le 2026‑08‑02, sur
> Windows Server 2022 Standard Évaluation (build 20348.587) fraîchement installé, les **59** sous-catégories
> rendues par `auditpol /get /category:*` ont été comparées entre **Server Core** et **Desktop Experience** :
> **aucune différence**, et les trois lignes ci-dessus valent **exactement** ce que vaut un Windows 11 —
> `Logon` = Succès et Échec, `Process Creation` = **Aucun audit**, `Filtering Platform Connection` =
> **Aucun audit**. Les trois commandes restent donc **obligatoires** sur un serveur.* Ce que le serveur
> active en plus par défaut (et qu'un poste client n'a pas été mesuré comme ayant) : `Credential Validation`,
> `Kerberos Authentication Service`, `Kerberos Service Ticket Operations`, `Directory Service Access`,
> `Computer/Security Group/User Account Management`, `Audit Policy Change` — **tous en Succès seulement**.
>
> **`category=exec` n'est pas VIDE sans la ligne 2 : elle est TROMPEUSE.** *Mesuré : audit `Process Creation`
> à « Aucun audit », Windows écrit quand même **~23 `4688` à CHAQUE démarrage** (les processus créés avant
> que LSASS n'applique la politique : `wininit`, `csrss`, `winlogon`, `services`, `lsass`…), tous avec un
> `CommandLine` **vide**, puis plus rien. Un tableau de bord qui compte les `exec` voit donc un chiffre
> non nul et stable — et ne surveille rien.*
   ```powershell
   auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:enable   # 5152/5157 (pare-feu)
   auditpol /set /subcategory:"Process Creation" /success:enable                                  # 4688
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable                             # 4624/4625
   ```

## Configuration

Créez un jeton sur le central — **avec le nom de la machine en 2ᵉ argument**, sinon le jeton n'est
lié à **aucun** hôte :

```sh
plume-daemon token poste-win01 POSTE-WIN01      # 2e argument = l'hôte AUQUEL le jeton est lié
```

> **La forme sans hôte (`plume-daemon token poste-win01`) laissait usurper n'importe quelle machine, et
> elle n'existe plus.** Elle était écrite ici jusqu'au 2026‑08‑02. *Mesuré ce jour‑là : avec le jeton
> produit par la commande sans hôte, une enveloppe portant `"host":"CONTROLEUR-DE-DOMAINE-USURPE"` est
> acceptée (**HTTP 202**) et l'événement est **stocké sous ce nom‑là**. Avec un jeton **lié**, la même
> enveloppe est acceptée mais le `host` est **réécrit** vers l'hôte du jeton (`WS22-LAB`) : le liage MORD.*
> Le liage est aussi ce qui autorise le responder à agir sur cet hôte. La portée d'un jeton est désormais
> une **déclaration** : `plume-daemon token <nom> <HOTE>` (machine) ou `plume-daemon token <nom> --relais`
> (forwarder multi-hôtes, dont l'hôte n'est **pas** attesté). La forme à deux arguments est **refusée**.
>
> *Le liage est consulté sur **toutes** les surfaces d'ingestion depuis le 2026‑08‑02. Auparavant il ne
> l'était que sur `/api/ingest` et `/loki/api/v1/push` — mesuré usurpable avec un jeton lié sur
> `/api/metrics/prom` (200), `/api/metrics/write` (204) et `/services/collector` (200). Cf. `docs/CIM.md`.*

Puis renseignez soit des variables d'environnement, soit `C:\ProgramData\plume\plume.conf` :

```ini
PLUME_CENTRAL=https://soc.central:7000
PLUME_TOKEN=<le-jeton>
# PLUME_TLS_INSECURE=1   # UNIQUEMENT pour un central en certificat auto-signé de test
```

> ### ⚠️ Le jeton ne passe JAMAIS en ligne de commande — et le paramètre a été retiré
> Le script acceptait `-Token` en paramètre, avec cette consigne de ne pas s'en servir. Une consigne
> n'est pas une garde : **le paramètre n'existe plus** (le jeton vient de `PLUME_TOKEN` ou de
> `plume.conf`). Ce qui suit explique pourquoi, et ce qui reste à votre charge.
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
>
> **Ce qui a été fermé, et ce qui ne peut pas l'être ici.** Fermé côté produit : le paramètre `-Token` de
> ce script (retiré) et le `--token <valeur>` de l'agent Rust (remplacé par `--token-stdin`, qui lit le
> jeton sur l'entrée standard). Ce qui reste ouvert, et qui ne se corrige PAS dans ce dépôt : si un
> opérateur tape lui-même un secret sur **n'importe quelle** ligne de commande, l'audit d'exécution le
> capture. C'est une propriété de Windows (Sysmon ID 1 sans GPO ; 4688 avec la GPO *« Include command
> line »*), pas de ces scripts. La contre-mesure est organisationnelle — et, si l'exposition a eu lieu,
> la révocation du jeton.

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

## Windows Server 2022 : ce que le serveur change (mesuré le 2026‑08‑02)

*Deux VM QEMU 2 vCPU / 4 Gio, Windows Server 2022 Standard Évaluation build 20348.587 : `WS22-LAB` en
**Server Core** (sans interface graphique) et `WS22-GUI` en **Desktop Experience**, promue **contrôleur de
domaine** en fin de campagne. Central plume compilé depuis ce dépôt, chemin réseau privé.*

| | Server Core | Desktop Experience | Windows 11 (fiche précédente) |
|---|---|---|---|
| installation sans TPM ni Secure Boot | **oui** — VM lancée sur OVMF nu, aucun `swtpm` | **oui** | non : `swtpm` absent = friction |
| durée d'installation sans surveillance | **216 s** (mise sous tension → 1ᵉʳ contact du harnais dans l'invité) | même ordre — **non chronométré à la même précision** (sonde relevée par intervalle : entre 250 s et 341 s) | non chiffrée |
| `auditpol` par défaut (59 sous-catégories) | *(identiques, cf. encadré des prérequis)* | **identique à Core** | identique sur les 3 lignes mesurées |
| collecteur PowerShell | **fonctionne intégralement** | fonctionne | fonctionne |
| durée d'un run | 6,7 s à 11,2 s | **9,3 s** | 35 s |
| crête mémoire du run | **177,3 Mio** | **176,8 Mio** | 191,5 Mio |
| CPU d'un run | 9,5 s (141 % d'un cœur : PowerShell est multi-thread) | 8,4 s (90 %) | 17,4 s (49 %) |
| agent Rust en service | **7,9 Mio** | 7,8 Mio | 9,6 Mio |
| mise sous tension → 1ᵉʳ event, agent Rust | **8,6 s** (2ᵉ mesure : 11,1 s) | — | 24,6 s *(convention non consignée)* |
| mise sous tension → 1ᵉʳ event, collecteur ps1 | **138,4 s** | — | 240,2 s *(idem)* |

> **Convention de la ligne « mise sous tension »** : t0 = **lancement de la VM, machine éteinte avant**.
> Un premier essai chronométré depuis l'**ordre de redémarrage** a donné 17,6 s / 112,9 s — chiffres
> **écartés** : l'arrêt propre de Windows produit des événements que l'agent expédie *pendant* l'extinction,
> donc ils ne mesurent pas le délai de reprise. La fiche Windows 11 ne consigne pas laquelle des deux
> conventions elle emploie : les 24,6 s / 240,2 s ne sont **pas** directement comparables aux chiffres
> ci-dessus, seul l'ordre de grandeur et le rapport agent/collecteur le sont.
>
> **Le 1ᵉʳ événement du serveur n'est ni de la santé, ni catégorisé.** *Mesuré : le premier événement de
> l'agent après mise sous tension vient du canal `Application` (Core) et arrive avec une catégorie
> **VIDE** — voir plus bas les 36,7 % d'événements sans catégorie. Le premier événement du collecteur
> PowerShell, lui, est bien `windows-security`/`auth`, comme sur Windows 11.*

**Server Core ne coûte RIEN au collecteur.** *Mesuré : `Import-Certificate` (0,41 s), `schtasks /Create`
(0,06 s), `Get-NetFirewallProfile`, `Get-MpComputerStatus` (Defender **est** présent et actif par défaut),
`Get-WinEvent`, `Expand-Archive` — tout répond sur Core. L'agent Rust y installe et démarre son service SCM
(`install` → `Running`), et `test-ship` répond **202**.* Aucune dépendance à l'interface graphique n'a été
trouvée, dans le collecteur comme dans l'agent.

> ### Sur un contrôleur de domaine, le collecteur PowerShell est AVEUGLE à Kerberos
> *Mesuré après promotion de `WS22-GUI` en contrôleur du domaine `lab.plume`
> (`Install-WindowsFeature AD-Domain-Services` **43,4 s**, `Install-ADDSForest` **54,9 s**, +1 redémarrage,
> DC opérationnel **70 s** après) : la création d'un compte et deux authentifications ont produit **2 × 4768**
> (ticket TGT) et **8 × 4769** (ticket de service) dans le journal `Security`. Côté SOC, ces événements
> n'existent QUE par l'agent Rust (`WinEventLog:Security`, `category=auth`) : le collecteur PowerShell en a
> remonté **0**, parce que sa liste d'identifiants ne contient ni `4768`, ni `4769`, ni `4771`, ni `4776`.*
> Sur un DC — c'est-à-dire là où se joue l'authentification de tout le parc — **utilisez l'agent Rust**, ou
> ajoutez ces identifiants à l'appel `Collect-Log` du journal Security.
>
> **La promotion en DC n'ajoute AUCUNE couverture d'audit.** *Mesuré : les 59 sous-catégories avant/après
> `dcpromo` ne diffèrent que des 2 lignes activées à la main par les commandes des prérequis. La stratégie
> « Default Domain Controllers » ne réveille donc rien de ce que Plume attend — et, bonne nouvelle
> symétrique, elle n'écrase pas non plus les réglages `auditpol` posés avant la promotion.*

> ### Sysmon sur un serveur : 2 s à installer, 11 Mio — et il rend la ligne de commande sans AUCUNE GPO
> *Mesuré : `Sysmon64.exe -accepteula -i` (v15.21) = **2,11 s** sur Core, **1,6 s** sur Desktop
> (désinstallation `-u` : 3,5 s) ; le service tourne à **11,0 Mio** et 0,03 s de CPU cumulé après démarrage.
> Sur `WS22-LAB`, machine dont **aucune** politique d'audit n'a jamais été touchée (`Process Creation` =
> « Aucun audit », GPO ligne de commande **absente**), l'appât `APPAT-CORE-SYSMON-…` passé en argv d'un
> `cmd.exe` n'a produit **aucun** `4688` — mais **2 événements Sysmon ID 1 le portant en clair**.*
> Autrement dit : **installer Sysmon suffit à faire remonter toutes les lignes de commande au SOC**, secrets
> en argv compris, sans qu'aucun réglage d'audit n'ait été fait. Avec la GPO *« Include command line… »*
> activée (et `gpupdate /force` — *mesuré : sans lui le réglage ne mord pas*), l'appât est ressorti par
> **deux** chemins indépendants : `windows-security`/`exec` (ce script) et `WinEventLog:Security`/`exec`
> (agent Rust) ; sans elle, **0** des `4688` portait une ligne de commande non vide.
>
> ⚠️ **Sysmon installé APRÈS l'agent** : ses événements sont bien lus (le canal est dans la liste par
> défaut de l'agent, et le signet l'inclut dès le run suivant) — c'est le piège de flotte ci-dessous, et
> non un problème de canal, qui les faisait disparaître.

> ### Le piège de la FLOTTE : deux serveurs se volaient leurs événements (corrigé le 2026‑08‑02)
> `event.dedup` est **UNIQUE au niveau de la base** du central, pas de l'hôte, et les identifiants
> d'enregistrement du journal Windows **repartent de 1 sur chaque machine**. Les clés produites ici
> (`windows-security-<record_id>`, `windows-agent-health-<heure>`, `windows-fwprofile-<profil>-<heure>`…)
> ne portaient **pas** le nom de l'hôte : la 2ᵉ machine enrôlée voyait ses événements écartés **en silence**
> par l'`INSERT OR IGNORE` du central.
> *Mesuré avec deux serveurs sur un même central : sur les **311** enregistrements du canal Sysmon de
> `WS22-LAB`, **266 sont arrivés et 45 ont disparu** — exactement les 45 que `WS22-GUI` avait déjà expédiés ;
> et le battement de santé horaire de `WS22-GUI` n'a **jamais** été stocké, la clé étant déjà prise.*
> **Correctif (1er temps, côté émetteur)** : le nom de l'hôte est préfixé une fois pour toutes dans
> `Add-Event` (et dans `winxml_to_event` côté agent) — impossible d'oublier l'hôte en ajoutant une source.
>
> **Correctif (2e temps, côté central — 2026‑08‑02)** : le piège n'était pas windowsien. Mesuré côté
> Linux le même jour, en faisant tourner les **36 capteurs livrés** sur deux hôtes auxquels il manque les
> mêmes prérequis : **36 clés produites par machine, dont 26 identiques**, et à l'ingestion **78
> événements envoyés → 52 stockés, 26 perdus**, tous sur la 2ᵉ machine (39 lignes pour la 1ʳᵉ, **13** pour
> la 2ᵉ). Corriger émetteur par émetteur n'était donc pas une correction : 40 clés fabriquées dans 30
> fichiers livrés, 5 langages, plus les capteurs qu'écriront les clients. Le central **cloisonne
> désormais `event.dedup` par l'hôte de la ligne** à l'écriture (`dedup_scoped_by_host`,
> `daemon/src/ingest/store.rs`) : deux lignes dont la colonne `host` diffère ne peuvent plus se supprimer
> l'une l'autre, quelle que soit la clé fabriquée par l'émetteur. Les préfixes posés ici deviennent
> **redondants et sont conservés** (un collecteur doit rester correct face à un central plus ancien).
> *Vérifié APRÈS correctif, sur les mêmes machines : `WS22-LAB` porte désormais **323 clés Sysmon
> continues de 1 à 323** (plus aucun trou), et `WS22-GUI` a enfin son battement
> (`WS22-GUI-windows-agent-health-…`).* **Conséquence de mise à jour** : les clés changent de forme, donc
> le premier run après mise à jour ré-expédie une fois les événements encore dans la fenêtre du filigrane
> (doublons ponctuels, jamais de perte).
> ⚠️ **Le même piège vaut pour tout émetteur** dont la clé n'inclut pas l'hôte : c'est une propriété du
> central, pas du collecteur Windows. *Lecture de code (NON mesurée) : plusieurs collecteurs Linux
> (`update-<image>-<digest>`, `ban-<jail>-<ip>-<heure>`, `clamav-<fichier>-<signature>`…) forment des clés
> identiques d'une machine à l'autre et sont donc exposés au même effacement silencieux — à vérifier par la
> mesure avant de conclure.*

## Limites connues, mesurées — à lire avant de déployer en flotte

1. ~~**Aucun spool : un POST qui échoue perd le lot.**~~ **CORRIGÉ le 2026‑08‑02.** Le défaut était réel et
   mesuré : `Flush-Events` attrapait l'échec, écrivait un `Write-Warning` (qui, sous tâche planifiée, ne va
   **nulle part**), vidait le tampon **inconditionnellement**, et `Set-Watermark` avait **déjà** avancé le
   filigrane. *Mesuré (harnais pwsh exécutant ce script TEL QUEL, journal Windows et central simulés) :
   central indisponible pendant UN run, **42** événements éligibles → **0 arrivés**, filigrane avancé quand
   même → **42 perdus DÉFINITIVEMENT**, 0 rattrapé au rétablissement. Même harnais, central disponible :
   0 perdu / 42 arrivés.*
   **Ce qui change** : le filigrane n'est plus écrit là où il est calculé — il est **mis en attente**
   (`Stage-Watermark`) et n'est **commis** qu'après un POST **acquitté**, par `Complete-Run`, seul endroit
   du fichier qui écrive sur le disque d'état. **Le journal Windows EST le spool** : tant que le filigrane
   ne bouge pas, le run suivant relit exactement ce qui n'est pas passé (at‑least‑once ; les réémissions
   sont absorbées par le `dedup`, cloisonné par hôte côté central). *Re‑mesuré après correctif, même
   scénario : **0 perdu, 42 rattrapés**.*
   > ⚠️ **Changement de comportement à connaître avant de déployer** : un POST non acquitté **LÈVE** et le
   > run sort **non nul** (le `Write-Warning` muet a disparu). Sous `schtasks`, cela remonte dans
   > `LastTaskResult` — un central indisponible devient **visible** au lieu d'être silencieux. C'est
   > voulu : c'est le seul canal qui subsiste quand le central est injoignable.
   >
   > **Ce qui n'est PAS rejoué** : les ÉCHANTILLONS d'un run perdu (profils pare‑feu, instantané réseau,
   > battement) ne sont pas dans un journal — ils sont **recalculés** au run suivant. Aucune HISTOIRE
   > n'est perdue ; un point d'échantillonnage l'est. Pour un spool disque en bonne et due forme,
   > l'agent Rust reste la réponse (`spool_cap`, at‑least‑once sur disque).
2. ~~**Un capteur qui ne peut pas collecter ne le dit pas.**~~ **CORRIGÉ le 2026‑08‑02.** *Mesuré avant :
   journal `Security` en **accès refusé** (le cas du technicien qui lance le script hors SYSTEM) → **12**
   événements attendus, **0 arrivé, 0 aveu**, code de retour **0**, et le battement de santé annonçait
   quand même « plume windows collector ok ».*
   Le script porte désormais le miroir PowerShell de la partition fermée de `collectors/lib.sh` :
   `Plume-Unavailable` (incapacité) · `Plume-Disabled` (coupé par l'opérateur) · `Plume-NoData` (rien de
   neuf — silence **légitime**, aucun octet). Le discriminant entre « rien de neuf » et « aveugle » est le
   `FullyQualifiedErrorId` de `Get-WinEvent`, **jamais** le message : les messages Windows sont
   **localisés**, et un test sur le texte classerait une vraie cécité en « calme » dès que la machine
   n'est pas anglophone. La partition penche du côté sûr : **seul** `NoMatchingEventsFound` vaut silence.
   *Re‑mesuré après correctif, même scénario : **5 aveux** `collect_status=unavailable`
   (3 × `windows-security`, 1 × `windows-firewall`, 1 × `windows-defender`).*
   Les aveux ont le format de `plume_report_availability` (`category=config`,
   `collect_status=unavailable`, `reason` du **même vocabulaire fermé** que les capteurs shell), donc la
   règle **existante** `config.d/rules/catalog/de-collector-unavailable.json` les couvre sans être touchée.
   Voir qui est aveugle : `search category=config collect_status=unavailable | table host, source, reason, detail`.
   **Garde de CI** : `.github/scripts/check_windows_collector_is_honest.py` (AST PowerShell réel) exige que
   tout `catch` classe ou relève, qu'aucune erreur ne soit avalée (`-ErrorAction SilentlyContinue` interdit),
   et qu'aucun filigrane ne s'écrive avant un envoi acquitté. *Prouvée par mutation : 11 mutations, 11 rouges.*
3. **L'inventaire de champs ne couvre pas ce collecteur.** `daemon/src/collected.rs` déclare 12 champs
   pour `plume-collector.ps1` ; *mesuré, ce collecteur en a réellement émis **55 distincts*** (tout
   l'`EventData` du journal : `SubjectUserName`, `NewProcessName`, `LogonType`, `CommandLine`…). L'écart
   n'est pas un oubli de déclaration : les noms viennent du XML **à l'exécution**
   (`foreach ($k in $d.Keys)`), donc l'extracteur **statique** de la garde ne peut pas les voir. La
   garde reste verte tout en sous-couvrant ce chemin — c'est une limite de méthode, pas une dérive.
4. **Sysmon n'est pas lu.** Ce script ne touche pas au canal `Microsoft-Windows-Sysmon/Operational`.
   Pour de la télémétrie Sysmon, il faut l'agent Rust (`agent/README.md`).
5. **Le champ CIM `action` n'est JAMAIS posé.** *Mesuré le 2026‑08‑02 sur les deux Windows Server 2022 :
   **0 des 1 505** événements de ce collecteur porte `action` — comme les **0 / 6 962** de l'agent Rust
   (`docs/CIM.md` §4c en fait pourtant le vocabulaire neutre de composition).* En revanche ce collecteur
   pose **toujours** une `category` (**0 / 1 505** sans catégorie), là où l'agent en laisse 36,7 % vides :
   sur ce point précis, le collecteur PowerShell est le plus complet des deux.
6. **Kerberos manque sur un contrôleur de domaine** (`4768`/`4769`/`4771`/`4776` absents de la liste
   d'identifiants) — mesuré, cf. la section Windows Server 2022 ci-dessus.

## Étendre

Besoin d'une source spécifique (un journal applicatif, une clé de registre, un
compteur) ? Ajoutez un appel `Collect-Log` (pour un journal d'événements) ou un
petit bloc `Add-Event` dans le script — ou, sans toucher au script, utilisez un
**scripted input** générique côté Linux qui interroge la machine Windows à distance
(cf. section « Ajouter vos sources » du README principal).
