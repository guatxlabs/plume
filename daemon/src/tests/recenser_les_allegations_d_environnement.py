#!/usr/bin/env python3
"""Recensement des allégations d'environnement écrites dans les commentaires Rust — instrument de `S29`.

POURQUOI CET INSTRUMENT EXISTE, ET POURQUOI IL EST ÉCRIT
--------------------------------------------------------
Le recensement de `S29` avait un critère ÉCRIT mais aucun script ne l'avait gardé : le chiffre (258
phrases qui affirment, 24 qui nomment un fichier du dépôt) n'était pas rejouable. Un recensement sans
instrument n'est pas une mesure, c'est un souvenir. Ce script EST le critère ; tout chiffre qu'il rend
se compare à un chiffre rendu par lui, jamais à un chiffre rendu par un autre critère.

LE CRITÈRE, DANS L'ORDRE OÙ IL EST APPLIQUÉ
------------------------------------------
1. CORPUS : tout `*.rs` sous la racine du dépôt, hors tout répertoire `target/` et `.git/`.
2. UNITÉ : le BLOC de commentaire. Une machine à états parcourt chaque fichier caractère par caractère,
   retire les chaînes littérales (`"…"`, `r"…"`, `r#"…"#`), traite les littéraux de caractère (`'"'`
   ne doit PAS ouvrir une chaîne), et isole les commentaires : des lignes `//` / `///` / `//!`
   CONSÉCUTIVES et seules sur leur ligne forment un bloc ; un commentaire en fin de ligne de code est
   un bloc à lui seul ; un `/* … */` (imbriqué ou non) est un bloc.
3. CANDIDAT : un bloc qui porte au moins un terme de BAC À SABLE, de SYSTÈME DE FICHIERS ou de NOYAU
   pris DANS SON SENS OS. Les faux amis mesurés sont exclus par construction, et la liste est publiée
   ci-dessous (`FAUX_AMIS`) : `kernel`/`noyau` est le noyau VECTORISÉ dans `cold_store/` et partout où
   il est suivi de « vectorisé / SIMD / de calcul » ; `atomique` est une transaction SQL ou un entier
   atomique, sauf adossé à un renommage de fichier ; `namespace`/`espace de noms` n'est OS que près de
   « processus / montage / réseau / utilisateur / conteneur / cgroup » ; `OOM` n'est retenu qu'en
   « tueur / killer / oom_score / tué », jamais en « anti-OOM » (une borne de conception) ; `signal`
   n'est retenu que comme signal POSIX nommé ; `audit`, `auditd`, `ufw`, `conntrack` sont des NOMS DE
   SOURCE d'événements, jamais des termes ; `lecture seule` est une connexion ou une route, OS seulement
   comme montage ; `disque` n'est OS que plein ou partitionné ; `PID` et l'`ordonnanceur` sont ceux de
   plume ; `processus` n'est OS que tué, signalé, cloisonné ou lu dans `/proc`.
4. PHRASE QUI AFFIRME : les lignes du bloc sont jointes, le texte est découpé en phrases sur `. ; ! ?`.
   Une phrase est retenue si (a) elle porte elle-même un terme candidat, (b) elle compte au moins cinq
   mots, (c) elle n'est pas interrogative, (d) elle n'est pas conditionnelle ou hypothétique (elle ne
   commence pas par « si / quand / lorsque / if / when / unless » et ne porte aucun conditionnel :
   « serait / pourrait / devrait / aurait / would / could / might / should »), et (e) elle porte un
   verbe d'affirmation au présent (liste `VERBES_D_AFFIRMATION`). Ce dernier point est la part la plus
   heuristique du critère ; il est publié pour être contesté, pas pour être cru.
5. DATÉE : la phrase porte une date ISO `AAAA-MM-JJ`.
6. FAISEUR DE VÉRITÉ : une phrase NOMME UN FICHIER DE CE DÉPÔT si elle contient un chemin relatif qui
   existe sous la racine (`collectors/integrity.sh`), un répertoire du dépôt ou un glob dessus
   (`systemd/`, `collectors/*`), ou un nom de fichier à extension connue qui existe dans le dépôt
   (`integrity.sh`, `seeds.rs`, `Cargo.toml`). Un chemin ABSOLU (`/etc/…`, `/proc/…`)
   désigne l'HÔTE, jamais le dépôt — SAUF quand il est CITÉ et non pris pour sujet (`CHEMIN_CITE`,
   faux amis mesurés côté hôte) : la phrase dit où CE CODE nomme, écrit ou touche le chemin, ou qu'une
   suite n'en dépend pas (« le seul endroit qui écrit dans `/proc` », « valables sur un hôte sans
   `/proc` ») -> faiseur `arbre`, se tient par une recherche sur l'arbre, pas par une mesure sur
   l'hôte ; ou le chemin est une VALEUR D'EXEMPLE — un jeton de recherche (« `/usr/bin/dash` …
   étaient des erreurs FTS5 »), une algèbre de chemins (« `/homeless-binary` n'est pas sous `/home` »),
   une comparaison (« comme `/dev/zero` ») -> faiseur `exemple`, rien à vérifier nulle part. Mesuré le
   2026-08-22 : 78 phrases classées hôte, dont 8 `arbre` et 7 `exemple` ; 63 restent hôte.
   Le reste (ni fichier du dépôt, ni chemin d'hôte) est laissé SANS faiseur nommé : c'est la case
   qu'aucune garde de source ne peut tenir.

CE QUE CET INSTRUMENT NE FAIT PAS
---------------------------------
Il ne juge pas la vérité d'une phrase, et il ne la tient pas. Il rend une LISTE, avec `fichier:ligne`,
pour qu'un lecteur aille lire le fichier que chaque phrase prend à témoin. Il ne remplace donc aucune
garde de `allegations_d_environnement.rs` ; il dit où chercher.

USAGE
-----
    recenser_les_allegations_d_environnement.py                 résumé + phrases qui nomment un fichier
    recenser_les_allegations_d_environnement.py --toutes        toutes les phrases qui affirment
    recenser_les_allegations_d_environnement.py --hote          celles dont le faiseur est un chemin d'hôte
    recenser_les_allegations_d_environnement.py --arbre         chemin cité : où ce code le nomme (recherche sur l'arbre)
    recenser_les_allegations_d_environnement.py --exemple       chemin cité comme valeur d'exemple (rien à vérifier)
    recenser_les_allegations_d_environnement.py --json          sortie machine (une ligne JSON par phrase)
    recenser_les_allegations_d_environnement.py --sans FICHIER  exclut un fichier du corpus (répétable)
"""

import json
import os
import re
import sys

RACINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# --- 3. Les termes, par famille, dans leur sens OS. Bornés par `\b` quand le mot est latin. -------
TERMES = {
    "bac-a-sable": [
        r"bac à sable", r"bac a sable", r"\bsandbox", r"\bsystemd\b(?![.:]\w)", r"\bseccomp\b", r"\bchroot\b",
        r"\bsetuid\b", r"\bcapabilit(?:y|ies|é|és)\b", r"\bCAP_[A-Z_]+\b", r"\bprivil[èe]ge", r"\bcgroup",
        r"groupe de contr[ôo]le", r"\bconteneur", r"\bcontainer", r"\bdocker\b", r"\bpodman\b", r"\bk3s\b",
        r"\bkubernetes\b", r"\bunit[ée] systemd", r"\bfichier d'unit[ée]", r"\.service\b", r"\.timer\b",
        r"\b(?:Protect(?:System|Home|Kernel\w*|ControlGroups|Clock|Proc|Hostname)|Private(?:Tmp|Devices|Network|Users|Mounts)"
        r"|ReadWritePaths|ReadOnlyPaths|InaccessiblePaths|NoNewPrivileges|CapabilityBoundingSet|AmbientCapabilities"
        r"|DynamicUser|StateDirectory|RuntimeDirectory|LogsDirectory|CacheDirectory|ConfigurationDirectory"
        r"|TemporaryFileSystem|RestrictAddressFamilies|RestrictNamespaces|RestrictSUIDSGID|LockPersonality"
        r"|MemoryDenyWriteExecute|SystemCallFilter|SystemCallArchitectures|UMask|EnvironmentFile|MemoryMax"
        r"|MemoryHigh|TasksMax|CPUQuota|BindPaths|BindReadOnlyPaths|ExecStart|ExecStartPre|WorkingDirectory)\b",
        r"\bnamespace", r"espace de noms",
    ],
    "systeme-de-fichiers": [
        r"syst[èe]me de fichiers", r"\bfilesystem\b", r"point de montage", r"\bmontage\b", r"\bmount(?:ed|s)?\b",
        r"\btmpfs\b", r"\boverlayfs\b", r"\bext4\b", r"\bxfs\b", r"\bbtrfs\b", r"\bf(?:data)?sync\b",
        r"\bO_(?:DIRECT|EXCL|CREAT|APPEND|NOFOLLOW|TRUNC)\b", r"\binode", r"lien symbolique", r"\bsymlink",
        r"\bhardlink", r"\bchmod\b", r"\bchown\b", r"\bumask\b", r"\b0[0-7]{3}\b",
        r"(?<![\w/.])/(?:etc|proc|sys|run|var|tmp|dev|usr|opt|home|root|srv|mnt|boot)(?:/[\w.\-*]+)*",
        r"disque plein", r"\bE(?:NOSPC|ACCES|PERM|NOENT|ROFS|EXIST|BUSY|MFILE|NFILE|DQUOT|IO)\b",
        r"lecture seule", r"read-only", r"\bread only\b", r"renommage atomique", r"\batomic rename\b",
        r"\brename\(2\)", r"fichier temporaire", r"\btemp_store\b", r"\bdisque\b", r"\bdisk\b",
        r"\bpartition\b",
    ],
    "noyau": [
        r"\bnoyau\b", r"\bkernel\b", r"\boom[_ -]?(?:killer|kill|score|tueur)", r"tueur (?:de )?oom",
        r"\btué par (?:le )?(?:noyau|oom)", r"\bovercommit", r"\bpage cache\b", r"cache de pages",
        r"\bmmap\b", r"\bmadvise\b", r"\bulimit\b", r"\brlimit", r"\bRLIMIT_\w+", r"\bnofile\b",
        r"\bSIG(?:TERM|KILL|HUP|INT|PIPE|USR1|USR2|CHLD|STOP|CONT|ABRT|SEGV)\b", r"\bepoll\b", r"\binotify\b",
        r"\bfanotify\b", r"\bsysctl\b", r"\bio_uring\b", r"\bswap\b", r"\bzram\b", r"\bdmesg\b",
        r"\be?bpf\b",
        r"socket unix", r"unix socket", r"\bAF_UNIX\b", r"m[ée]moire r[ée]sidente", r"\bRSS\b",
        r"\bhugepage", r"\bTHP\b", r"\bNUMA\b", r"\bordonnanceur\b", r"\bscheduler\b",
        r"\bprocessus\b", r"\bprocess\b", r"\bfork\b", r"\bexecve?\b",
    ],
}
TERMES_COMPILES = {fam: [re.compile(t, re.IGNORECASE) for t in ts] for fam, ts in TERMES.items()}

# --- 3 bis. Les faux amis : (motif, condition qui RÉTABLIT le sens OS). Une occurrence du motif qui
# ne satisfait pas la condition n'est pas un terme. `None` = le motif n'est JAMAIS un terme OS.
FAUX_AMIS = [
    (re.compile(r"\b(?:kernel|noyau)\b\s*(?:vectoris|simd|de calcul|colonnaire|d'ex[ée]cution vectoris)", re.I), None),
    (re.compile(r"\banti-?oom\b", re.I), None),
    (re.compile(r"\batomi(?:que|c)\b", re.I), re.compile(r"renomm|rename|fsync|disque|fichier", re.I)),
    (re.compile(r"\bnamespace|espace de noms", re.I),
     re.compile(r"processus|\bpid\b|montage|mount|r[ée]seau|network|utilisateur|\buser\b|conteneur|container|cgroup", re.I)),
    (re.compile(r"\bsignal\b", re.I), re.compile(r"\bSIG[A-Z]+\b|posix|\bkill\b", re.I)),
    (re.compile(r"\baudit\b", re.I), re.compile(r"\bauditd\b", re.I)),
    (re.compile(r"\bpartition\b", re.I), re.compile(r"disque|disk|montage|mount|/dev/", re.I)),
    # « processus » n'est OS que comme objet du noyau : tué, signalé, forké, cloisonné, lu dans /proc.
    (re.compile(r"\bprocess(?:us)?\b", re.I),
     re.compile(r"/proc\b|tué|tue\b|\bkill|\bSIG[A-Z]+\b|\bfork|\bexec(?:ve)?\b|cgroup|\boom\b|environnement du processus|espace de noms|namespace|setuid|privil", re.I)),
    # « disque » est un support de stockage ; seul « disque plein / espace disque / partition » est un fait de FS.
    (re.compile(r"\bdisque\b|\bdisk\b", re.I), re.compile(r"plein|\bfull\b|espace disque|disk space|ENOSPC|partition|montage|mount|tmpfs|/dev/", re.I)),
    # « lecture seule » est le plus souvent une connexion SQLite ou une route ; OS seulement comme montage.
    (re.compile(r"lecture seule|read-?only|read only", re.I),
     re.compile(r"syst[èe]me de fichiers|filesystem|montage|mount|ProtectSystem|ReadOnlyPaths|EROFS|/etc\b|/usr\b|/run\b|/var\b|\bumask|chmod|0[0-7]{3}\b|conteneur|container|docker", re.I)),
    # l'ordonnanceur de plume n'est pas celui du noyau.
    (re.compile(r"\bordonnanceur\b|\bscheduler\b", re.I), re.compile(r"noyau|kernel|\bCFS\b|\bcpu\b|cœur|coeur|thread", re.I)),
    # RSS est une mesure ; elle n'est un fait d'environnement que rapportée au noyau qui la rend.
    (re.compile(r"\bRSS\b|m[ée]moire r[ée]sidente", re.I), re.compile(r"/proc\b|VmHWM|noyau|kernel|cgroup|\boom", re.I)),
    # dans `cold_store/`, « montage » est celui d'une VUE SQL (ATTACH), pas d'un système de fichiers.
    (re.compile(r"\bmontage\b|\bmont[ée]e?s?\b", re.I),
     re.compile(r"/proc\b|\bmount|tmpfs|syst[èe]me de fichiers|point de montage|volume|PVC|conteneur|container|ProtectSystem|ProtectHome|ReadOnlyPaths|bind|/etc\b|/var\b|/run\b|secret", re.I)),
    # un nombre octal n'est un MODE que s'il est dit tel ; `0000..` est un compteur zéro-paddé.
    (re.compile(r"\b0[0-7]{3}\b"), re.compile(r"\bmode\b|droits?|permission|perms?\b|chmod|umask|r[ée]pertoire|\bdir\b|fichier|\.conf\b|\bconf\b", re.I)),
]
# `auditd`, `ufw`, `conntrack`, `iptables`, `k8s`… sont ici des NOMS DE SOURCE d'événements (31 + 13 phrases
# mesurées), jamais une propriété de l'hôte qui exécute plume : ils ne sont pas des termes.
# Dans `cold_store/`, `kernel`/`noyau` est TOUJOURS le noyau vectorisé (86 blocs mesurés).
CHEMINS_NOYAU_VECTORISE = ("cold_store/",)
MOTIF_NOYAU = re.compile(r"\b(?:kernel|noyau)\b", re.I)

# --- 4. Ce qui fait d'une phrase une affirmation. ----------------------------------------------------
VERBES_D_AFFIRMATION = re.compile(
    r"(?:\b(?:est|sont|n'est|ne sont|existe|existent|porte|portent|rend|rendent|tient|tiennent|expose|exposent"
    r"|masque|masquent|refuse|refusent|garantit|garantissent|interdit|interdisent|lit|lisent|écrit|ecrit|écrivent"
    r"|monte|montent|hache|surveille|surveillent|fournit|fournissent|impose|imposent|remplace|remplacent|tue|tuent"
    r"|chiffre|reste|restent|vaut|valent|suffit|contient|contiennent|protège|protege|empêche|empeche|bloque|bloquent"
    r"|passe|passent|échoue|echoue|réussit|reussit|tourne|tournent|démarre|demarre|vit|vivent|appartient|dépend|depend"
    r"|s'applique|s'appliquent|compte|comptent|ignore|ignorent|absorbe|perd|perdent|laisse|laissent|voit|voient"
    r"|s'exécute|s'execute|partage|partagent|s'arrête|s'arrete|a|ont|n'a|n'ont|n'existe|toujours|jamais|aucun|aucune"
    r"|is|are|isn't|aren't|does|doesn't|do|don't|has|have|hasn't|never|always|exists|runs|mounts|reads|writes"
    r"|kills|cannot|can't|holds|keeps|remains|owns|lacks|no)\b)",
    re.I,
)
HYPOTHESE = re.compile(
    r"\b(?:serai(?:t|ent)|pourrai(?:t|ent)|devrai(?:t|ent)|aurai(?:t|ent)|faudrait|would|could|might|should)\b", re.I
)
DEBUT_CONDITIONNEL = re.compile(r"^\W*(?:si|s'il|s'ils|quand|lorsque|lorsqu'|if|when|unless|et si|même si|meme si)\b", re.I)
DATE_ISO = re.compile(r"\b20\d\d-\d\d-\d\d\b")
CHEMIN_RELATIF = re.compile(r"(?<![\w/.])(?:[A-Za-z0-9_.\-]+/)+[A-Za-z0-9_.\-*|]*")
NOM_DE_FICHIER = re.compile(
    r"(?<![\w/.\-])(?:[A-Za-z0-9_\-]+\.(?:rs|sh|service|timer|py|ps1|toml|sql|ya?ml|conf|json|env|example|md|html|js|input|lock)"
    r"|Dockerfile|docker-compose\.yml)(?![\w/\-])"
)
CHEMIN_ABSOLU = re.compile(r"(?<![\w/.])/(?:etc|proc|sys|run|var|tmp|dev|usr|opt|home|root|srv|mnt|boot)(?:/[\w.\-*]+)*")

# --- 6 bis. Les faux amis CÔTÉ HÔTE : un chemin absolu CITÉ n'est pas un chemin pris pour sujet.
# (motif, faiseur rendu à la place de `hote`). Chaque motif porte l'exemple mesuré qui l'a fait écrire.
CHEMIN_CITE = [
    # « Le seul endroit du module qui nomme `/proc` », « Aucune des fonctions de lecture ne nomme `/proc` »,
    # « C'est le seul endroit qui écrit dans `/proc` », « Seuls les tests d'INSTRUMENT touchent `/proc` » :
    # la phrase parle de CE CODE ; son faiseur est une recherche sur l'arbre.
    (re.compile(r"\b(?:seuls?|seules?|aucune?)\b[^.;:]{0,60}\b(?:endroit|fonction|test|site|module)s?\b[^.;:]{0,60}"
                r"\b(?:nomme|nomment|écri|ecri|lit|lisent|touche|touchent|cite|citent|dépend|depend)", re.I), "arbre"),
    # « valables sur un hôte sans `/proc` comme sur un autre », « y compris une machine sans `/proc` » :
    # une suite qui dit ne pas dépendre de l'hôte — se tient en lisant la suite.
    (re.compile(r"\b(?:hôte|hote|machine)s? sans `?/", re.I), "arbre"),
    # « `/usr/bin/dash` … étaient tous des erreurs FTS5 », « cinq saisies … à `MATCH` », « 4 racines … GXQL » :
    # le chemin est un JETON de langage de requête.
    (re.compile(r"\bFTS5?\b|\bMATCH\b|\bGXQL\b|\bsaisies?\b", re.I), "exemple"),
    # « `/homeless-binary` n'est PAS sous `/home` » (`Path::starts_with`) : une algèbre de chemins.
    (re.compile(r"starts_with|\bcomposants?\b", re.I), "exemple"),
    # « (ou `/dev/zero`-like) », « (comme /dev/zero, un fichier qui grossit…) » : une comparaison.
    (re.compile(r"`?/[\w/.\-]+`?-like|\bcomme `?/", re.I), "exemple"),
]


def fichiers_du_depot():
    """Tous les chemins relatifs du dépôt (hors `target/`, `.git/`), et l'index basename -> chemins."""
    relatifs, par_nom = set(), {}
    for dossier, sous, noms in os.walk(RACINE):
        sous[:] = [s for s in sous if s not in ("target", ".git", "__pycache__", "node_modules")]
        for n in noms:
            rel = os.path.relpath(os.path.join(dossier, n), RACINE)
            relatifs.add(rel)
            par_nom.setdefault(n, []).append(rel)
    return relatifs, par_nom


def corpus_rs(exclus):
    out = []
    for dossier, sous, noms in os.walk(RACINE):
        sous[:] = [s for s in sous if s not in ("target", ".git")]
        for n in noms:
            if n.endswith(".rs"):
                rel = os.path.relpath(os.path.join(dossier, n), RACINE)
                if rel not in exclus and n not in exclus:
                    out.append(rel)
    return sorted(out)


def blocs_de_commentaire(src):
    """Machine à états : rend [(ligne_de_debut, texte)] — le texte sans ses marqueurs `//`, `/*`."""
    o = src
    n = len(o)
    i = 0
    ligne = 1
    blocs = []
    courant = None  # (ligne_de_debut, [lignes]) d'un bloc de commentaires-lignes en cours
    derniere_ligne_commentee = -1
    code_sur_la_ligne = False  # du code a-t-il été vu sur la ligne courante avant ce commentaire ?

    def clore():
        nonlocal courant
        if courant is not None:
            blocs.append((courant[0], "\n".join(courant[1])))
            courant = None

    while i < n:
        c = o[i]
        if c == "\n":
            ligne += 1
            code_sur_la_ligne = False
            i += 1
            continue
        # chaîne brute r"…" / r#"…"#
        if c == "r" and (i == 0 or not (o[i - 1].isalnum() or o[i - 1] == "_")) and i + 1 < n and o[i + 1] in '"#':
            j = i + 1
            d = 0
            while j < n and o[j] == "#":
                d += 1
                j += 1
            if j < n and o[j] == '"':
                j += 1
                while j < n:
                    if o[j] == '"' and o[j + 1 : j + 1 + d] == "#" * d:
                        j += 1 + d
                        break
                    j += 1
                ligne += o[i:j].count("\n")
                i = j
                code_sur_la_ligne = True
                continue
        if c == '"':
            j = i + 1
            while j < n:
                if o[j] == "\\":
                    j += 2
                    continue
                if o[j] == '"':
                    j += 1
                    break
                j += 1
            ligne += o[i:j].count("\n")
            i = j
            code_sur_la_ligne = True
            continue
        if c == "'":
            if i + 2 < n and o[i + 2] == "'":
                i += 3
                code_sur_la_ligne = True
                continue
            if i + 3 < n and o[i + 1] == "\\" and o[i + 3] == "'":
                i += 4
                code_sur_la_ligne = True
                continue
            i += 1
            code_sur_la_ligne = True
            continue
        if c == "/" and i + 1 < n and o[i + 1] == "/":
            j = i
            while j < n and o[j] != "\n":
                j += 1
            texte = o[i:j].lstrip("/").lstrip("!")
            if texte.startswith(" "):
                texte = texte[1:]
            if code_sur_la_ligne:
                clore()
                blocs.append((ligne, texte))
            elif courant is not None and derniere_ligne_commentee == ligne - 1:
                courant[1].append(texte)
            else:
                clore()
                courant = (ligne, [texte])
            derniere_ligne_commentee = ligne
            i = j
            continue
        if c == "/" and i + 1 < n and o[i + 1] == "*":
            clore()
            j = i + 2
            prof = 1
            while j + 1 < n and prof > 0:
                if o[j] == "/" and o[j + 1] == "*":
                    prof += 1
                    j += 2
                    continue
                if o[j] == "*" and o[j + 1] == "/":
                    prof -= 1
                    j += 2
                    continue
                j += 1
            texte = o[i + 2 : max(i + 2, j - 2)]
            blocs.append((ligne, "\n".join(l.strip().lstrip("*").strip() for l in texte.split("\n"))))
            ligne += o[i:j].count("\n")
            i = j
            continue
        if not c.isspace():
            code_sur_la_ligne = True
            if courant is not None:
                clore()
        i += 1
    clore()
    return blocs


def termes_dans(texte, chemin):
    """Les familles de termes présentes dans `texte` AU SENS OS — faux amis retirés."""
    t = texte
    for motif, rattrape in FAUX_AMIS:
        if rattrape is None or not rattrape.search(t):
            t = motif.sub(" ", t)
    if any(p in chemin for p in CHEMINS_NOYAU_VECTORISE):
        t = MOTIF_NOYAU.sub(" ", t)
    familles = []
    for fam, motifs in TERMES_COMPILES.items():
        if any(m.search(t) for m in motifs):
            familles.append(fam)
    return familles


def phrases(texte):
    joint = re.sub(r"\s+", " ", texte.replace("\n", " ")).strip()
    morceaux = re.split(r"(?<=[.;!?])\s+(?=[^\s])", joint)
    return [m.strip() for m in morceaux if m.strip()]


def affirme(phrase):
    if phrase.endswith("?") or "?" in phrase:
        return False
    if len(phrase.split()) < 5:
        return False
    if DEBUT_CONDITIONNEL.search(phrase) or HYPOTHESE.search(phrase):
        return False
    return bool(VERBES_D_AFFIRMATION.search(phrase))


def faiseur_de_verite(phrase, relatifs, par_nom, chemin_source):
    """Rend ('depot', [fichiers]) | ('hote', [chemins]) | ('aucun', [])."""
    nommes = []
    for m in CHEMIN_RELATIF.finditer(phrase):
        cand = m.group(0).strip(".")
        if cand.startswith("/"):
            continue
        # `systemd/`, `collectors/*`, `systemd/*.service|*.timer` nomment un RÉPERTOIRE du dépôt
        if "*" in cand or cand.endswith("/"):
            dossier = cand.split("*")[0].rstrip("/")
            if dossier and os.path.isdir(os.path.join(RACINE, dossier)):
                nommes.append(dossier + "/")
            continue
        if cand in relatifs:
            nommes.append(cand)
        elif "daemon/" + cand in relatifs:
            nommes.append("daemon/" + cand)
        elif "daemon/src/" + cand in relatifs:
            nommes.append("daemon/src/" + cand)
        elif "agent/src/" + cand in relatifs:
            nommes.append("agent/src/" + cand)
    for m in NOM_DE_FICHIER.finditer(phrase):
        nom = m.group(0)
        if nom in par_nom and not any(x.endswith("/" + nom) or x == nom for x in nommes):
            cibles = par_nom[nom]
            # un basename ambigu (`mod.rs`, `main.rs`) ne nomme rien de précis ; on préfère celui du
            # même crate si c'est le seul, sinon on ne tranche pas
            if len(cibles) == 1:
                nommes.append(cibles[0])
            else:
                meme_crate = [x for x in cibles if x.split("/")[0] == chemin_source.split("/")[0]]
                if len(meme_crate) == 1:
                    nommes.append(meme_crate[0])
    # une phrase qui ne nomme qu'ELLE-MÊME (le fichier où elle est écrite) ne nomme pas de témoin
    nommes = sorted(set(x for x in nommes if x != chemin_source))
    if nommes:
        return "depot", nommes
    hote = sorted(set(m.group(0) for m in CHEMIN_ABSOLU.finditer(phrase)))
    if hote:
        for motif, faiseur in CHEMIN_CITE:
            if motif.search(phrase):
                return faiseur, hote
        return "hote", hote
    return "aucun", []


def recenser(exclus):
    relatifs, par_nom = fichiers_du_depot()
    fichiers = corpus_rs(exclus)
    total_blocs = candidats = 0
    resultats = []
    for rel in fichiers:
        with open(os.path.join(RACINE, rel), encoding="utf-8", errors="replace") as f:
            src = f.read()
        blocs = blocs_de_commentaire(src)
        total_blocs += len(blocs)
        for ligne, texte in blocs:
            if not termes_dans(texte, rel):
                continue
            candidats += 1
            for ph in phrases(texte):
                fam = termes_dans(ph, rel)
                if not fam or not affirme(ph):
                    continue
                faiseur, nommes = faiseur_de_verite(ph, relatifs, par_nom, rel)
                resultats.append(
                    {
                        "fichier": rel,
                        "ligne": ligne,
                        "familles": fam,
                        "datee": bool(DATE_ISO.search(ph)),
                        "faiseur": faiseur,
                        "nomme": nommes,
                        "phrase": ph,
                    }
                )
    return {"fichiers": len(fichiers), "blocs": total_blocs, "candidats": candidats, "phrases": resultats}


def main(argv):
    exclus = set()
    mode = "depot"
    en_json = False
    it = iter(argv)
    for a in it:
        if a == "--toutes":
            mode = "toutes"
        elif a == "--hote":
            mode = "hote"
        elif a == "--arbre":
            mode = "arbre"
        elif a == "--exemple":
            mode = "exemple"
        elif a == "--json":
            en_json = True
        elif a == "--sans":
            exclus.add(next(it))
        else:
            sys.stderr.write(f"argument inconnu : {a}\n")
            return 2
    r = recenser(exclus)
    ph = r["phrases"]
    n_dat = sum(1 for p in ph if p["datee"])
    n_dep = sum(1 for p in ph if p["faiseur"] == "depot")
    n_hot = sum(1 for p in ph if p["faiseur"] == "hote")
    n_arb = sum(1 for p in ph if p["faiseur"] == "arbre")
    n_exe = sum(1 for p in ph if p["faiseur"] == "exemple")
    if not en_json:
        print(
            f"corpus : {r['fichiers']} fichiers .rs · {r['blocs']} blocs de commentaire · "
            f"{r['candidats']} blocs candidats · {len(ph)} phrases qui AFFIRMENT · {n_dat} datées "
            f"({(100 * n_dat // len(ph)) if ph else 0} %) · faiseur = fichier du dépôt : {n_dep} · "
            f"faiseur = chemin d'hôte : {n_hot} · chemin cité (arbre) : {n_arb} · chemin d'exemple : {n_exe} · "
            f"sans faiseur nommé : {len(ph) - n_dep - n_hot - n_arb - n_exe}"
        )
        if exclus:
            print(f"exclus du corpus : {sorted(exclus)}")
    choisies = [p for p in ph if mode == "toutes" or p["faiseur"] == mode]
    for p in choisies:
        if en_json:
            print(json.dumps(p, ensure_ascii=False))
        else:
            marque = "D" if p["datee"] else "-"
            cible = " -> " + ", ".join(p["nomme"]) if p["nomme"] else ""
            print(f"{p['fichier']}:{p['ligne']} [{marque}] [{'/'.join(p['familles'])}]{cible}\n    {p['phrase']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
