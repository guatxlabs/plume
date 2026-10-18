# collector-mail — detection mail host-native

Le SOC traite le mail comme **un collecteur de plus** (agent collecte -> SOC ingere), au lieu d'un
service a part. `collector-mail` lit le **maildir sur le FS de l'hote**, applique des **patterns
curates** (IOC / phishing / URL), et emet des **events MINIMAUX** (compte, dossier, domaine de
l'expediteur, message-id, sample IOC/URL) -> spool -> `ship.sh` -> SOC central (`source=mail` + FTS).
Le sample d'une URL n'en garde que schema, hote, port et chemin (requete, fragment et identifiants
coupes, et la coupure est dite) ; un parametre decode sort par son NOM ; une partie locale d'adresse
sort `*@domaine`. L'objet ne sort que sur `PLUME_MAIL_EMIT_SUBJECT=1`, borne a 80 caracteres.

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
# PLUME_MAIL_EMIT_SUBJECT=0          # 1 = emet l'objet (80 caracteres) ; 0 ou rien = non ; autre = refus
# PLUME_MAIL_STATE=/var/lib/plume/spool/.mail-seen    # etat incremental (defaut)
# PLUME_MAIL_EXCLURE_COMPTES=          # comptes JAMAIS ouverts (vide = tous lus) ; cf. ci-dessous
```
> Le defaut du provisioner local-path de k3s est `/var/lib/rancher/k3s/storage` ; si ton cluster le
> monte ailleurs, mets le VRAI chemin ici **et** regle `PLUME_K3S_STORAGE` (collector kube-state) sur
> le meme chemin, sinon la metrique storage% est muette.

## Retirer une boite du balayage — `PLUME_MAIL_EXCLURE_COMPTES`
Une boite hebergee qui ne doit pas etre analysee se nomme ici ; le collecteur ne l'ouvre JAMAIS : ni
`stat` dans son repertoire, ni `read_dir`, ni lecture de message, ni ligne dans l'etat incremental, et
la sous-commande `body` refuse de la lire (voir plus bas ce qu'elle lit pour le savoir). Le « ni
`stat` » tient a l'ordre du code (la decision sur le nom precede toute sonde) ; les temoins
(`collector-mail/tests/compte_exclu_jamais_ouvert.rs`, boites en droits 000) voient un `read_dir` ou
une lecture, pas un `stat` isole.
- **Forme** : entrees separees par des virgules et/ou des blancs. Avec un `@` (`alice@example.test`) :
  l'adresse complete, ce compte-la seulement. Sans `@` (`alice`) : la partie locale, dans **chaque**
  domaine du maildir (layout plat : le domaine est `PLUME_MAIL_DOMAIN` ; imbrique : celui du repertoire).
- **Comparaison EXACTE** du nom tel que le layout le donne, apres passage en minuscules ASCII des deux
  cotes : `alice` n'exclut ni `alic` ni `alicex`. Un nom de compte non ASCII n'egale aucune entree.
- **Refus** : une entree vide (`a,,b`, virgule finale), un motif (`*?[]{}`), un caractere hors classe
  (partie locale `a-z 0-9 . _ + -`, domaine `a-z 0-9 . -`) ou une adresse mal formee ARRETE le
  passage avant toute lecture ; l'aveu (sortie d'erreur + `collect_status=unavailable` dans le spool)
  nomme le RANG de l'entree et la cause, jamais sa valeur.
- **Ce que le passage en dit** : le battement (`journalctl -u plume-collector-mail`) porte
  `N compte(s) dont M ouvert(s), K exclu(s) par PLUME_MAIL_EXCLURE_COMPTES` — un COMPTE, jamais un nom.
  `0 exclu(s)` alors qu'une liste est posee : l'entree ne vise aucun compte (faute de frappe ?).
- **Layout imbrique** : un repertoire de premier niveau dont le nom egale une entree (partie locale, ou
  `<nom>@PLUME_MAIL_DOMAIN`) est retire entier, sans etre sonde pour savoir s'il est un compte ou un
  domaine.
- **Trois modes** : le collecteur tourne sur l'HOTE dans les trois (le maildir est sur son disque) ; le
  reglage se pose dans `/etc/plume/mail.conf` (lu par `plume-collector-mail.service`), que le serveur
  mail soit natif, en conteneur Docker ou dans k3s. Lance a la main, la variable de l'environnement
  s'ajoute a la liste du fichier (elle ne la remplace pas).
- **Le balayage et `body` relisent `mail.conf` eux-memes, avec UNE seule regle** : `body`, lance par le
  demon (`PLUME_MAIL_BODY_CMD`), herite de l'environnement du DEMON, qui ne charge pas ce fichier. Les
  deux chemins lisent donc `/etc/plume/mail.conf` (autre chemin : `PLUME_MAIL_CONF`) par la meme
  fonction :
  - la liste du fichier est JOINTE a celle de l'environnement (une entree de l'un OU de l'autre exclut) ;
  - le domaine du layout plat suit la precedence du service (`EnvironmentFile=` l'emporte) : le fichier
    qui PORTE `PLUME_MAIL_DOMAIN` decide, meme d'une valeur vide (qui vaut alors `localhost`, comme pour
    le service) ; sinon l'environnement ; sinon `localhost` ;
  - fichier ABSENT : l'environnement seul ;
  - fichier present mais ILLISIBLE pour l'utilisateur qui lance la commande : REFUS, au balayage (aveu
    `collect_status=unavailable`) comme a `body`, que l'environnement porte une liste ou non, et meme si
    aucune liste n'est posee — la liste du fichier n'est pas jugeable. **Consequence a connaitre** :
    `body` lance sous un utilisateur qui ne lit pas `mail.conf` (`root:soc 0640` par
    `bootstrap-agent.sh`) ne rend plus rien ; le lancer sous l'utilisateur du balayage (root), qui lit
    deja le maildir et ce fichier.
- **Un dossier ne sort pas du compte** : le `folder` de `body` (et `PLUME_MAIL_FOLDER`) est refuse s'il
  est vide, porte `/`, `\`, `..` ou un caractere de controle ; un dossier ou un `cur/`/`new/` en lien qui
  resout hors du compte est refuse sans y entrer. Avant, `Sent/../../bob` lisait la boite `bob`.
- **`body` juge la boite, pas l'adresse ecrite** : le chemin que l'adresse resout (liens et `.`
  suivis) decide. En layout plat, `alice@autre.test` ou `alice@example.test.` ouvrent la meme boite
  `alice` : elles sont refusees comme `alice@example.test`. Un dossier d'un compte retire
  (`.Sent@alice`) l'est aussi ; un chemin qui sort de la racine, ou qui ne designe aucun compte que
  le balayage nomme, est refuse des qu'une liste est posee.
- **Ce qui n'est pas efface** : les lignes de l'etat incremental ecrites AVANT l'exclusion restent dans
  `.mail-seen` (identifiants de fichiers, aucun contenu).

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
# relit /etc/plume/mail.conf (ou PLUME_MAIL_CONF) comme le balayage (liste ET domaine, meme regle) :
# un compte retire du balayage est refuse ici aussi, avant toute recherche du message
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

## Le capteur de journal `collectors/mail.sh` : d'ou il lit (`PLUME_MAIL_SRC`)
A ne pas confondre avec `collector-mail` (le maildir, ci-dessus) : `mail.sh` lit le JOURNAL du serveur
mail (`mail.log`, ClamAV). Il vaut dans les **trois modes** de deploiement, et sa source se regle ou se
detecte :
- **Posee** (`PLUME_MAIL_SRC=k3s|docker|file`) : prise telle quelle, **prioritaire**, jamais devinee et
  sans aucune sonde. `k3s` lit par `kubectl exec` (ou `k3s kubectl`) dans le pod de `PLUME_MAIL_SELECTOR`
  (defaut `app=mailserver`) du namespace `PLUME_MAIL_NS` (defaut `mail`) ; `docker` par `docker exec` dans
  le conteneur `PLUME_MAIL_CONTAINER` (defaut `mailserver`) ; `file` lit `PLUME_MAIL_LOG` sur l'hote
  (defaut `/var/log/mail/mail.log`). Si l'outil manque, l'echec de lecture est avoue, rien n'est tente
  a la place.
- **Non posee** : detection, dans cet ordre, chaque sonde en lecture seule et bornee par `timeout`
  (`PLUME_MAIL_DETECTION_DELAI`, 5 s par defaut ; un entier >= 1 sans zero en tete, `0`/`00` couperaient la
  borne : pose et illisible, il est avoue `unreadable-config` et c'est 5 qui s'applique) : (a) `k3s` si `kubectl` ou `k3s` est present ET qu'un pod
  du selecteur existe dans le namespace ; (b) `docker` si `docker` est present ET que le conteneur nomme
  est en marche (`docker inspect`) ; (c) `file` si `PLUME_MAIL_LOG` est un fichier lisible. Hote natif
  (systemd, journal local) : (c) ; serveur mail en conteneur Docker : (b) ; dans k3s : (a).
- **Aucune** : aveu `collect_status=unavailable`, `reason=missing-source`, qui dit ce qui a ete essaye et
  qu'il faut poser `PLUME_MAIL_SRC` ; rien n'est acquitte.
- **Sous une unite contrainte** (`plume-mail.service` : `CPUQuota=25%`, `HOME=/tmp` en `PrivateTmp`, donc le
  cache de decouverte de `k3s kubectl` repart a froid a chaque passage) : une sonde k3s qui depasse le delai
  fait un passage aveugle (avoue `missing-source`, rien d'acquitte). **Poser** `PLUME_MAIL_SRC` dans
  `/etc/plume/plume.conf` quand la source est connue ; la detection est le repli, pas le reglage d'exploitation.

La source RETENUE et son origine sont dites dans l'enveloppe de config du capteur (evenement
`source=mail category=config`, `type=collection-reducing`, sous `filters` : `source`, et `source_origine`
qui vaut `posee` ou `detectee`). Temoin : `.github/scripts/check_mail_sensor_reads_sender_checks_outbound_queue_and_clamav.py`.
