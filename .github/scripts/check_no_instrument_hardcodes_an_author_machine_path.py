#!/usr/bin/env python3
r"""Un instrument qui porte le chemin absolu de la machine où il a été écrit est vert par construction.

LE DÉFAUT, MESURÉ LE 2026-08-30 (clé `P8.9-k`, ouverte en fermant un rouge d'intégration).
Une garde neuve portait, en dur, le chemin absolu du poste où elle avait été écrite. Sur ce poste
le chemin EXISTE : la garde y balayait le bon arbre, ne trouvait rien, et rendait 0. Ailleurs — sur
un clone frais, dans un `git worktree`, sur le coureur d'intégration — le chemin n'existe pas et
elle a JETÉ à sa toute première exécution. Les deux verdicts sont faux de la même façon : aucun des
deux ne dit quoi que ce soit du code. Le vert local était le plus dangereux des deux, parce qu'il
se lit comme une garantie.

CE QUI REND CE CONSTAT PARTICULIER — LE SAVOIR ÉTAIT DÉJÀ LÀ, MAL PLACÉ.
`verifier-message-de-commit.sh` refuse DÉJÀ `/home/<compte>` — mais dans un MESSAGE DE COMMIT, où
un chemin machine n'est qu'un bruit de lecture. Rien ne le refusait dans les INSTRUMENTS, où le
même littéral change le VERDICT. La propriété n'était pas absente du dépôt : elle était appliquée
à l'endroit où elle coûte le moins.

POURQUOI UNE GARDE À ELLE ET PAS UNE JAMBE DE `P8.9-i`.
`check_every_guard_written_is_a_guard_wired.py` a le bon corpus — le RÉPERTOIRE, et pour la même
raison qu'ici : un instrument neuf existe sur le disque AVANT d'être suivi, et c'est exactement à
cet instant qu'il porte encore le chemin de son auteur. Mais sa propriété est « cet instrument
s'exécute-t-il », pas « cet instrument est-il portable ». Y ajouter cette jambe rendrait son nom
faux. Le corpus est repris ; le fichier, non.

LA RÈGLE, ET POURQUOI ELLE N'EST PAS CELLE QU'ON ÉCRIT D'ABORD
--------------------------------------------------------------
Le balayage naïf — « toute occurrence de `/home/` » — rend DEUX occurrences dans ce dépôt au
2026-08-30, et TOUTES DEUX SONT LÉGITIMES :

  1. `check_fim_coverage_is_reachable.py:220` — `/home/*/.ssh/authorized_keys`, un motif du système
     SURVEILLÉ, cité dans un commentaire ;
  2. `verifier-message-de-commit.sh:79` — `/home/[a-z][a-z0-9_-]*`, LA RÈGLE elle-même, et
     `/home/<compte>` dans le texte du refus.

Une garde qui les accuse est PIRE que l'angle mort qu'elle comble : elle apprend à passer outre.

DEUX RESSERREMENTS ONT ÉTÉ ESSAYÉS, PUIS ÉCARTÉS, MESURE À L'APPUI (2026-08-30) :

  · BORNER AUX INSTRUMENTS EXÉCUTABLES. Écarté parce qu'il est FAUX ici et COÛTEUX partout.
    `verifier-message-de-commit.sh` est en mode 100755 : la borne ne l'écarte PAS, et le cas 2
    resterait accusé. Elle écarte en revanche 42 des 56 instruments de `.github/scripts/` — dont
    `check_fim_coverage_is_reachable.py`, en 100644 — que l'intégration exécute pourtant par
    `python3 <chemin>`. Le bit d'exécution ne dit rien de ce qui s'exécute.

  · DÉPOUILLER LES COMMENTAIRES AVANT DE JUGER. Écarté parce qu'il est INUTILE ici et RÉTRÉCIT le
    canal. Le cas 1 tombe déjà par la règle ci-dessous, sans dépouillement ; le cas 2 n'est pas un
    commentaire et n'en tomberait pas. Le dépouillement n'acquitte donc rien qui ne soit déjà
    acquitté, et il rendrait ÉCRIVABLE un chemin d'auteur en commentaire — lequel nomme toujours un
    compte réel et vieillit tout aussi mal.

CE QUI SÉPARE VRAIMENT LE DÉFAUT DES DEUX CAS LÉGITIMES N'EST NI LE FICHIER NI LA LIGNE : c'est le
SEGMENT DE COMPTE. Un chemin machine porte un compte CONCRET (`/home/<nom>`) ; un motif porte, à sa
place, un caractère qui ne peut PAS commencer un nom de compte POSIX — `*`, `[`, `<`, `$`, `{`, `?`,
`%`, `.`, `(`, `+`, `\`. La distinction est STRUCTURELLE et dérivée, pas une liste de fichiers
tolérés ni une liste de mots-bouchons : un compte d'apparence bouchon reste ACCUSÉ — voir le
témoin positif « compte à l'allure de bouchon » plus bas. C'est voulu : un faux chemin
d'apparence concrète se fait prendre pour un vrai à la relecture suivante.

Sont accusées les quatre formes de répertoire d'utilisateur : `/home/<compte>`, `/Users/<compte>`,
`/root` (le répertoire EST le compte, sans segment) et `C:\\Users\\<compte>`. `~` et `$HOME` ne le sont pas :
ils sont PORTABLES, c'est-à-dire exactement le geste qu'on veut voir à la place.

CETTE GARDE EST SOUMISE À SA PROPRE RÈGLE. Ses témoins fabriqués sont assemblés par morceaux
(`_h()` plus bas) : le littéral accusable n'apparaît donc NULLE PART dans ce fichier. Aucune
exemption ne la vise — s'exempter soi-même est le contournement que la prochaine garde recopierait.

Corpus : `.github/scripts/` (instruments), `.githooks/` (les crochets, où le même littéral est tout
aussi mortel), `.github/*.sh` et `.github/workflows/` (un `run:` porte un chemin comme un script).
Le RÉPERTOIRE, pas l'index — voir plus haut. Il s'ARRÊTE là, et c'est MESURÉ, pas frileux :
appliquer la même règle à `collectors/`, `agent/` et `systemd/` rend 13 accusations dans 3
fichiers au 2026-08-30, TOUTES légitimes — un collecteur d'intégrité NOMME le répertoire de clés de l'administrateur parce
que c'est son SUJET, et un durcissement systemd nomme les répertoires qu'il protège. Là-bas un
chemin d'utilisateur est la matière ; ici il est un défaut. La borne de corpus EST le critère.

Sorties : 0 = sain · 1 = VIOLATION · 2 = REFUS DE CONCLURE (corpus illisible ou témoins en défaut).
"""
import os
import re
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))

# Répertoires balayés, relatifs à la racine, et suffixes d'instrument. Un fichier sans suffixe est
# retenu dans `.githooks/` : les crochets git n'en portent pas, et ce sont des instruments.
CORPUS = (
    (os.path.join(".github", "scripts"), (".py", ".sh", ".mjs", ".ps1")),
    (".githooks", None),
    (".github", (".sh",)),
    # Les FLUX DE TRAVAIL sont des instruments au même titre : un `run:` qui porte un chemin
    # absolu est le même défaut, et le coureur d'intégration en offre une variante propre —
    # `/home/<coureur>/work/…` est le répertoire de travail d'UN type de coureur, faux sur un
    # coureur auto-hébergé et sur macOS, où le compte vit sous `/Users`. La forme portable est
    # `$GITHUB_WORKSPACE`. MESURÉ le 2026-08-30 : les 4 flux du dépôt n'en portent aucun,
    # l'extension du corpus ne coûte donc aucune accusation aujourd'hui.
    (os.path.join(".github", "workflows"), (".yml", ".yaml")),
)

# Un nom de compte POSIX commence par une lettre ou un souligné. Tout ce qui n'en est pas un à
# cette position est un MOTIF (joker, classe d'expression régulière, bouchon, variable), pas un
# compte. `(?<![\w/])` empêche `/var/backups/home/x` et `/homelab/` de se faire prendre pour un
# répertoire d'utilisateur : le segment doit ouvrir le chemin, pas s'y trouver enfoui.
COMPTE = r"[A-Za-z_][A-Za-z0-9_.-]*"
MOTIFS = (
    ("répertoire d'utilisateur POSIX", re.compile(r"(?<![\w/])/home/(" + COMPTE + r")")),
    ("répertoire d'utilisateur macOS", re.compile(r"(?<![\w/])/Users/(" + COMPTE + r")")),
    ("répertoire de l'administrateur", re.compile(r"(?<![\w/])/(root)/")),
    ("répertoire d'utilisateur Windows", re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+(" + COMPTE + r")")),
)


def accusations(ligne):
    """Les segments de compte CONCRETS portés par une ligne. Vide = la ligne est admissible."""
    trouve = []
    for quoi, motif in MOTIFS:
        for m in motif.finditer(ligne):
            trouve.append((quoi, m.group(0)))
    return trouve


# Les témoins sont assemblés pour que ce fichier ne porte lui-même aucun littéral accusable.
def _h(*parts):
    return "/".join(("",) + parts)


def _w(*parts):
    return "".join(chr(92) + p for p in parts)


def epreuves():
    """Témoins FABRIQUÉS — positifs ET négatifs. Aucun ne lit le disque."""
    doivent_accuser = [
        ("racine en dur d'un poste", 'RACINE = "' + _h("home", "guat", "GUATX", "plume") + '"'),
        ("chemin macOS en dur", "cd " + _h("Users", "hugo", "dev", "plume")),
        ("chemin Windows en dur", "p = \"C:" + _w("Users", "Hugo", "plume") + "\""),
        ("répertoire de l'administrateur", "cle = " + _h("root", ".ssh", "id_ed25519")),
        ("compte du coureur d'intégration", "cd " + _h("home", "runner", "work", "plume-oss")),
        ("compte à l'allure de bouchon", "ex : " + _h("home", "user", "projet")),
        ("chemin en fin de ligne sans barre finale", "cd " + _h("home", "guat")),
    ]
    ne_doivent_pas_accuser = [
        # Les DEUX cas légitimes réellement présents dans le dépôt au 2026-08-30, reproduits par
        # leur FORME et non recopiés : c'est la forme qui doit être acquittée, pas ces lignes-là.
        ("motif du système surveillé (joker)", "# " + _h("home", "*", ".ssh") + "/authorized_keys"),
        ("la règle elle-même (classe régulière)", 'grep -qE "' + _h("home", "[a-z][a-z0-9_-]*") + '"'),
        ("bouchon entre chevrons", 'ajoute "chemin machine (' + _h("home", "<compte>") + ')"'),
        ("chemin portable par tilde", "~/.ssh/authorized_keys"),
        ("chemin portable par variable", '"$HOME/.config/plume"'),
        ("bouchon en accolades", _h("home", "{user}", "projet")),
        ("joker interrogatif", _h("home", "?", "x")),
        ("répertoire système, pas d'utilisateur", "/etc/ssh/ssh_host_ed25519_key"),
        ("répertoire d'état, pas d'utilisateur", "/var/lib/plume/plume.db"),
        ("le mot home enfoui dans un chemin", "/var/backups/home/plume.tar"),
        ("un mot qui commence par home", "/homelab/inventaire.yml"),
        ("expansion portable", 'os.path.expanduser("~")'),
        ("segment vide", _h("home", "")),
    ]
    for nom, ligne in doivent_accuser:
        if not accusations(ligne):
            return f"témoin POSITIF « {nom} » non accusé — la garde laisserait passer le défaut"
    for nom, ligne in ne_doivent_pas_accuser:
        vu = accusations(ligne)
        if vu:
            return f"témoin NÉGATIF « {nom} » accusé à tort ({vu[0][1]}) — une garde qui accuse à tort apprend à passer outre"
    return None


def instruments():
    """Les instruments présents sur le DISQUE. None = corpus illisible."""
    vus = []
    for rel, suffixes in CORPUS:
        rep = os.path.join(RACINE, rel)
        if not os.path.isdir(rep):
            continue
        try:
            noms = sorted(os.listdir(rep))
        except OSError:
            return None
        for nom in noms:
            chemin = os.path.join(rep, nom)
            if not os.path.isfile(chemin):
                continue
            if suffixes is not None and not nom.endswith(suffixes):
                continue
            vus.append((os.path.join(rel, nom), chemin))
    return vus


def main():
    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2

    corpus = instruments()
    if corpus is None:
        print("::error::corpus illisible : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    if len(corpus) < 10:
        print(f"::error::corpus de {len(corpus)} instrument(s) — trop peu pour être l'arbre attendu ; "
              "la garde REFUSE DE CONCLURE plutôt que de rendre un vert vide", file=sys.stderr)
        return 2

    fautifs = 0
    lues = 0
    for rel, chemin in corpus:
        try:
            with open(chemin, encoding="utf-8", errors="replace") as fh:
                lignes = fh.readlines()
        except OSError:
            print(f"::error file={rel}::instrument illisible : la garde REFUSE DE CONCLURE", file=sys.stderr)
            return 2
        lues += 1
        for n, ligne in enumerate(lignes, 1):
            for quoi, extrait in accusations(ligne):
                fautifs += 1
                print(f"::error file={rel},line={n}::chemin absolu de machine « {extrait} » "
                      f"({quoi}) — cet instrument est lié au poste où il a été écrit : il y est vert "
                      "par construction et jette ailleurs. Écrire un chemin RELATIF à ce fichier "
                      "(`os.path.dirname(__file__)`, `git rev-parse --show-toplevel`) ou, si le "
                      "chemin décrit le système SURVEILLÉ, le laisser en MOTIF "
                      "(joker, classe, bouchon) plutôt qu'en compte concret.", file=sys.stderr)

    if fautifs:
        print(f"\n{fautifs} chemin(s) de machine dans {lues} instrument(s). Un instrument qui porte "
              "le chemin du poste où il a été écrit rend DEUX verdicts également faux : vert chez "
              "son auteur, où le chemin existe et où il balaie le bon arbre sans rien trouver ; "
              "jeté partout ailleurs. Le vert est le plus dangereux — il se lit comme une garantie. "
              "Ce dépôt refuse déjà ce littéral dans un MESSAGE DE COMMIT "
              "(verifier-message-de-commit.sh) ; il le refuse désormais là où il change un VERDICT.",
              file=sys.stderr)
        return 1

    print(f"check_no_instrument_hardcodes_an_author_machine_path : {lues} instrument(s) lus dans "
          ".github/scripts, .githooks, .github et .github/workflows — aucun ne porte de chemin absolu sous un "
          "répertoire d'utilisateur (/home, /Users, /root, C:\\Users) avec un segment de compte "
          "CONCRET. Le corpus est le RÉPERTOIRE et non l'index : un instrument neuf est vu dès "
          "qu'il existe sur le disque, ce qui est précisément le moment où il porte encore le "
          "chemin de son auteur.\n"
          "CE QU'ELLE NE TIENT PAS : un chemin machine ASSEMBLÉ à l'exécution (concaténation, "
          "`os.environ['HOME'] + '/guat/...'`, variable lue ailleurs) lui échappe entièrement — "
          "elle juge des LITTÉRAUX, ligne par ligne, et n'exécute rien. Elle ne juge pas la "
          "PORTABILITÉ au-delà de ce littéral : un chemin relatif faux, un `cd` implicite, une "
          "dépendance à un binaire absent restent invisibles. Elle ne couvre ni `daemon/`, ni "
          "`web/`, ni `docs/` — d'autres corpus, d'autres gardes. Un segment de compte qui ouvre "
          "par un caractère de motif est acquitté SANS vérifier que le motif est correct : "
          "`/home/[a-z` mal formé passe. Et elle ne dit rien du chemin d'un instrument NON SUIVI "
          "qui vivrait hors de ces quatre répertoires.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
