# collector-mail — detection mail host-native

Le SOC traite le mail comme **un collecteur de plus** (agent collecte -> SOC ingere), au lieu d'un
service a part. `collector-mail` lit le **maildir sur le FS de l'hote**, applique des **patterns
curates** (IOC / phishing / URL), et emet des **events MINIMAUX** (compte, dossier, sujet/exp.,
message-id, sample IOC/URL) -> spool -> `ship.sh` -> SOC central (`source=mail` + FTS).

**JAMAIS de body en clair** dans le spool / la DB SOC (minimisation = "securite >= existant").
Le **body complet** reste un **pull gate `role=admin` + audite**, capacite agent-side **distincte**
— PAS dans ce binaire (cf. la sous-commande `body` plus bas).

## Ou tourne-t-il
Host-natif (pas in-cluster) : le maildir est sur le **FS du node** (PVC local-path), donc lisible
directement. Meme modele que `audit.sh` / `falco.sh` / `pod-logs.sh`.

## Config `/etc/plume/mail.conf`
```sh
PLUME_MAIL_ROOT=/var/lib/<provisioner>/<pvc>_<ns>_<claim>-0   # chemin du volume = /var/mail dans le pod
PLUME_MAIL_DOMAIN=example.tld          # pour le layout PLAT (mono-domaine) -> construit user@domaine
PLUME_MAIL_FOLDER=*                  # tous les dossiers (defaut)
PLUME_MAIL_LIMIT=2000               # plafond messages/compte au 1er passage (incremental ensuite)
PLUME_MAIL_MAX_EVENTS=1000          # cap d'alertes par run (anti-flood)
# PLUME_MAIL_PATTERNS=/etc/plume/mail-patterns.json   # surcharge du jeu par defaut (optionnel)
# PLUME_MAIL_STATE=/var/lib/plume/spool/.mail-seen    # etat incremental (defaut)
```
> Le defaut du provisioner local-path de k3s est `/var/lib/rancher/k3s/storage` ; si ton cluster le
> monte ailleurs, mets le VRAI chemin ici **et** regle `PLUME_K3S_STORAGE` (collector kube-state) sur
> le meme chemin, sinon la metrique storage% est muette.

## Activation (OPT-IN, regle d'or)
Installe mais **non active** par defaut. Quand tu le veux :
```sh
sudo systemctl enable --now plume-collector-mail.timer
```
Etat incremental : chaque message n'est scanne qu'une fois (`.mail-seen`) ; le `dedup` cote SOC
(`mail:<compte>:<dossier>:<fileid>`) garantit l'idempotence meme si l'enveloppe est re-shippee.

## Patterns par defaut
`phishing-account-action` (sujet), `phishing-urgent` (sujet), `raw-ip-url`, `punycode-url`,
`credential-url`, `executable-link`, `decoded-credential` (params base64 decodes). Moteur `regex`
(automate fini = temps lineaire, pas de ReDoS) + cap longueur/taille compilee. Surcharge possible
via `PLUME_MAIL_PATTERNS` (JSON `[{id,category,severity,target,regex}]` ;
target = subject|from|text_body|html_body|url|decoded_url|headers).

## Body-fetch complet (gate + audite) — sous-commande `body`
Lecture du **mail complet** d'UN message, a la demande (forensic). C'est le SEUL chemin qui retourne
le body ; il reste **gate + audite**, et vit agent-side (pas de body en clair shippe par le scan).
```sh
PLUME_MAIL_ROOT=... PLUME_ACTOR=<qui> plume-collector-mail body <account> <id> [folder]
# -> stdout : JSON {account,folder,subject,from,to,date,headers,text,html}
```
- **Gate** : l'invocation est reservee au central (acces agent/SSH via le role agent) ; le central
  verifie `role=admin` AVANT d'appeler, et passe `PLUME_ACTOR` (qui declenche).
- **Audit** : chaque lecture ecrit un event `source=mail-audit` ("body read: acct/folder/id by actor")
  dans le spool -> SOC (cherchable + chaine d'integrite cote central).
- **Rendu** : le central affiche le `html` dans un `<iframe sandbox>` + CSP `default-src 'none'`
  (anti-XSS + anti-tracking).
- Le binaire NE sert PAS d'HTTP en continu (pas de surface permanente) : appel a la demande.

## Parite avant retrait (NON negociable)
Si tu as deja un scanner mail (service dedie, onglet d'une console existante), **ne le retire pas**
tant que la recherche mail du SOC n'a pas atteint la **parite** (cf. `deploy/K8S.md`, « Ordre de
bascule »). Sequence : construire -> verifier parite -> puis retirer.
