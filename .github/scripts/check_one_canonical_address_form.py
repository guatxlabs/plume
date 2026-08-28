#!/usr/bin/env python3
"""`P4.7-j` — IL N'EXISTE QU'UNE CANONICALISATION D'ADRESSE, ET C'EST CELLE QUI REPLIE LA FORME MAPPÉE.

LE DÉFAUT, MESURÉ LE 2026-08-28. Le démon portait TROIS canonicalisations aux verdicts DIFFÉRENTS sur
`::ffff:a.b.c.d` : `ssrf_norm_ip` (qui REPLIE, `to_ipv4_mapped`), `parse::<IpAddr>() + to_string()`
(qui ne replie PAS — mesuré : `::ffff:cb00:7107` et `0:0:0:0:0:ffff:203.0.113.7` en ressortent tous
deux `::ffff:203.0.113.7`), et `ipaddress`/`.compressed` côté hôte (qui ne replie pas non plus).
La deuxième était employée SIX fois — sur ce qui clé le store `net_ban`, sur l'IP réelle du client,
sur le pair TCP — et elle CONVERGEAIT les écritures exotiques VERS la forme qui traversait la
protection, au lieu de converger vers la VALEUR.

LA POPULATION EST DÉCOUVERTE, JAMAIS ÉNUMÉRÉE : c'est l'ensemble des endroits où l'arbre transforme
une adresse en CHAÎNE après l'avoir obtenue comme valeur. Un site écrit demain est couvert sans être
nommé, et aucune liste de fichiers n'a besoin d'être tenue à jour.

RÈGLE (Rust) : une telle région doit vivre dans le module qui PORTE le canonicaliseur unique, ou
NOMMER `ssrf_norm_ip`. Rien d'autre.
RÈGLE (shell) : la canonicalisation d'hôte ne peut PAS appeler le canonicaliseur du démon (langages
différents, processus différents). Elle doit donc porter un AVEU ÉCRIT à son site, qui nomme la
divergence — un troisième verdict silencieux est exactement ce que cette clé poursuit.

CE QUE CETTE GARDE NE PROUVE PAS, ÉCRIT DANS SON PROPRE EN-TÊTE :
  * RIEN sur les comparaisons SQL (`LEFT JOIN banned_ip ON b.src_ip=a.src_ip`, `GROUP BY src_ip`,
    `COUNT(DISTINCT src_ip)`, entité RBA, `ti_lookup_key`) : la corrélation et la détection tranchent
    toujours l'identité sur la chaîne, et c'est hors de ce lot ;
  * RIEN hors de ce dépôt — `guatx-core::ti::normalize_ioc` porte une SIXIÈME définition de « ceci
    est une adresse », épinglée dans `daemon/Cargo.lock` ;
  * RIEN sur ce que `nft`, `cscli` ou `fail2ban-client` font d'un littéral donné.

Codes de sortie : 0 conforme · 1 violation · 2 l'instrument REFUSE DE CONCLURE.
"""
import os, re, sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))

# Le canonicaliseur UNIQUE, reconnu par ce qu'il FAIT (le repli de la forme mappée), pas par un chemin.
DEF_CANON = re.compile(r"fn\s+ssrf_norm_ip\s*\(")
REPLI = re.compile(r"to_ipv4_mapped\s*\(")
NOM_CANON = re.compile(r"\bssrf_norm_ip\s*\(")

# (i) OBTENIR une adresse comme VALEUR ; (ii) la rendre en CHAÎNE. Les deux dans la même région.
# `ssrf_norm_ip(` est DANS la population À DESSEIN : la garde doit VOIR les sites conformes, sinon
# elle n'apparie plus rien le jour où le dernier site fautif disparaît, et son vert ne dit plus rien.
ACQUISITION = re.compile(r"parse::<[^>]*IpAddr[^>]*>\s*\(\s*\)"
                         r"|:\s*(?:std::net::)?IpAddr\s*=[^;]*\.parse\s*\(\s*\)"
                         r"|ConnectInfo<[^>]*SocketAddr[^>]*>"
                         r"|\bssrf_norm_ip\s*\(")
RENDU = re.compile(r"\.to_string\s*\(\s*\)")
FENETRE = 3  # lignes : une canonicalisation tient dans une expression, au plus un `let` + son usage

AVEU_SHELL = "CANONICALISATION HORS DÉMON"
SHELL_CANON = re.compile(r"\bipaddress\b|\.compressed\b")
# L'aveu couvre SON voisinage, jamais le fichier entier : un SECOND canonicaliseur divergent écrit
# ailleurs dans le même fichier doit nommer SA divergence, pas hériter de celle du premier.
FENETRE_AVEU = 40


def sans_bruit(ligne):
    """Retire les littéraux de chaîne (le SQL y vit) et les commentaires de ligne."""
    l = re.sub(r'"(?:[^"\\]|\\.)*"', ' "" ', ligne)
    l = re.sub(r"//.*$", "", l)
    return l


def sans_bruit_shell(ligne):
    """MOITIÉ SHELL : une PHRASE ne peuple pas la population (correction du 2026-08-29).

    MESURÉ : `SHELL_CANON` était appliqué aux lignes BRUTES, sans aucun débruitage. Le seul
    commentaire d'en-tête « IPv4/IPv6 canonique via python-ipaddress » suffisait donc (a) à faire
    croire à la garde qu'elle regardait du code, (b) à satisfaire son auto-invalidation
    `shell_vus == 0 -> REFUSE DE CONCLURE`. Quelqu'un pouvait supprimer TOUT le bloc python de
    canonicalisation en laissant la phrase : la garde imprimait « 1 site shell, tous avoués » et
    rendait VERT sans avoir lu une ligne de code. Trois des sept sites « trouvés » étaient de la
    prose, dont un À L'INTÉRIEUR de l'aveu lui-même."""
    l = re.sub(r"^\s*#.*$", "", ligne)
    l = re.sub(r"(\s)#.*$", r"\1", l)
    return l


def sites_shell(lignes):
    """Indices des lignes où un script d'hôte CANONICALISE réellement une adresse (prose exclue)."""
    return [i for i, l in enumerate(lignes) if SHELL_CANON.search(sans_bruit_shell(l))]


def sites_shell_muets(lignes):
    """Sites SANS aveu dans LEUR fenêtre. L'aveu est cherché autour de CHAQUE site, jamais autour du
    premier seulement : ancré sur `premiers[0] - 30`, il était accepté n'importe où entre la ligne 0
    et la ligne ~260 du fichier, et un second canonicaliseur ajouté n'importe où dans cet intervalle
    héritait de l'aveu du premier sans qu'un mot soit écrit sur SA divergence."""
    muets = []
    for i in sites_shell(lignes):
        deb, fin = max(0, i - FENETRE_AVEU), min(len(lignes), i + 5)
        if AVEU_SHELL not in "\n".join(lignes[deb:fin]):
            muets.append(i)
    return muets


def fichiers_rust():
    """Production seulement : un test a le droit d'analyser une adresse comme il veut."""
    out = []
    for base, _, noms in os.walk(os.path.join(RACINE, "daemon", "src")):
        rel = os.path.relpath(base, RACINE)
        if os.sep + "tests" in os.sep + rel:
            continue
        for n in sorted(noms):
            if n.endswith(".rs") and n != "tests.rs":
                out.append(os.path.join(base, n))
    return sorted(out)


def regions_de_canonicalisation(lignes):
    """Régions (début, fin) où une adresse est OBTENUE puis RENDUE en chaîne, sur <= FENETRE lignes."""
    propres = [sans_bruit(l) for l in lignes]
    trouvees = []
    for i, l in enumerate(propres):
        if not ACQUISITION.search(l):
            continue
        fin = min(len(propres), i + FENETRE)
        bloc = "\n".join(propres[i:fin])
        if RENDU.search(bloc):
            trouvees.append((i, fin, bloc))
    return trouvees


def epreuves():
    """TÉMOINS POSITIF ET NÉGATIF SUR L'APPARIEUR, hors du disque. Une garde qui n'apparie rien
    rendrait vert en ne regardant rien, et son silence se lirait comme une garantie."""
    doit_apparier = [
        'let canon = target.trim().parse::<std::net::IpAddr>().map(|i| i.to_string()).unwrap();',
        'let parsed: std::net::IpAddr = ip.trim().parse().map_err(|_| "x")?;\n    let canon = parsed.to_string();',
        'let valid = |v: &str| v.trim().parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string());',
    ]
    doit_apparier.append('let canon = ssrf_norm_ip(t).map(|i| i.to_string()).unwrap_or_default();')
    ne_doit_pas = [
        'let ok = c.parse::<std::net::IpAddr>().is_ok();',
        'let s = format!("{a}").to_string();',
        'if base.parse::<std::net::IpAddr>().is_err() { return Err(e); }',
    ]
    for src in doit_apparier:
        if not regions_de_canonicalisation(src.split("\n")):
            return f"témoin POSITIF manqué : {src!r} n'est pas vu comme une canonicalisation"
    for src in ne_doit_pas:
        if regions_de_canonicalisation(src.split("\n")):
            return f"témoin NÉGATIF manqué : {src!r} est vu comme une canonicalisation alors qu'il n'en est pas une"
    # Le SQL ne doit jamais entrer dans la population : il vit dans des littéraux.
    if regions_de_canonicalisation(['let q = "SELECT ip.parse::<IpAddr>() , to_string()";']):
        return "témoin NÉGATIF manqué : un littéral de chaîne entre dans la population"

    # --- LA MOITIÉ SHELL A DÉSORMAIS SES PROPRES ÉPREUVES (la règle du dépôt vaut des DEUX côtés :
    # --- témoin positif ET négatif avant de croire un instrument).
    if sites_shell(["# IPv4/IPv6 canonique via python-ipaddress", "echo bonjour"]):
        return "témoin NÉGATIF (shell) manqué : une PHRASE de commentaire peuple la population"
    if sites_shell(["  print(x)   # rend net.compressed"]):
        return "témoin NÉGATIF (shell) manqué : un commentaire de FIN de ligne peuple la population"
    if not sites_shell(["python3 - <<'PY'", "import sys, ipaddress", "print(net.compressed)", "PY"]):
        return "témoin POSITIF (shell) manqué : un vrai canonicaliseur d'hôte n'est pas apparié"
    if not sites_shell(["    net = ipaddress.ip_network(c, strict=False)   # bits hôte masqués"]):
        return "témoin POSITIF (shell) manqué : du code suivi d'un commentaire n'est plus apparié"
    if sites_shell_muets([f"# {AVEU_SHELL} : la divergence est ici", "import ipaddress"]):
        return "témoin POSITIF (shell) manqué : un aveu écrit À SON SITE n'est pas reconnu"
    loin = [f"# {AVEU_SHELL}"] + ["true"] * (FENETRE_AVEU + 10) + ["import ipaddress"]
    if not sites_shell_muets(loin):
        return ("témoin NÉGATIF (shell) manqué : un aveu situé à plus de "
                f"{FENETRE_AVEU} lignes couvre un site qu'il ne nomme pas")
    return None


def main():
    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2

    # --- VALIDATION DE L'INSTRUMENT SUR L'ARBRE : le canonicaliseur unique doit être TROUVÉ, et il
    # --- doit REPLIER. S'il a disparu ou cessé de replier, cette garde ne garde plus rien.
    porteur = None
    for f in fichiers_rust():
        texte = open(f, encoding="utf-8").read()
        if DEF_CANON.search(texte):
            if not REPLI.search(texte):
                print(f"::error::{os.path.relpath(f, RACINE)} définit `ssrf_norm_ip` mais ne REPLIE plus la "
                      f"forme mappée (`to_ipv4_mapped` absent) — la garde REFUSE DE CONCLURE", file=sys.stderr)
                return 2
            porteur = f
            break
    if porteur is None:
        print("::error::`ssrf_norm_ip` introuvable dans daemon/src : le canonicaliseur unique a disparu, "
              "la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    violations, vues = [], 0
    for f in fichiers_rust():
        lignes = open(f, encoding="utf-8").read().split("\n")
        for (i, fin, bloc) in regions_de_canonicalisation(lignes):
            vues += 1
            if f == porteur or NOM_CANON.search(bloc):
                continue
            violations.append((os.path.relpath(f, RACINE), i + 1, lignes[i].strip()[:120]))
    if vues == 0:
        print("::error::AUCUNE canonicalisation d'adresse trouvée dans daemon/src — l'apparieur n'apparie "
              "plus rien, la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    # --- MOITIÉ SHELL : elle ne PEUT pas appeler le canonicaliseur du démon ; elle doit l'AVOUER.
    shell_vus, shell_muets = 0, []
    rep_col = os.path.join(RACINE, "collectors")
    for n in sorted(os.listdir(rep_col)) if os.path.isdir(rep_col) else []:
        if not n.endswith(".sh"):
            continue
        chemin = os.path.join(rep_col, n)
        lignes = open(chemin, encoding="utf-8").read().split("\n")
        vus_ici = sites_shell(lignes)
        if not vus_ici:
            continue
        shell_vus += len(vus_ici)
        # L'aveu est exigé AUTOUR DE CHAQUE SITE, jamais autour du premier seulement.
        for i in sites_shell_muets(lignes):
            shell_muets.append((os.path.relpath(chemin, RACINE), i + 1))
    if shell_vus == 0:
        print("::error::AUCUNE canonicalisation d'adresse trouvée dans collectors/*.sh — l'apparieur shell "
              "n'apparie plus rien, la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    if violations or shell_muets:
        for (rel, ligne, txt) in violations:
            print(f"::error file={rel},line={ligne}::canonicalisation d'adresse HORS du canonicaliseur unique "
                  f"et sans passer par `ssrf_norm_ip` : {txt}", file=sys.stderr)
        for (rel, ligne) in shell_muets:
            print(f"::error file={rel},line={ligne}::canonicalisation d'adresse d'hôte SANS aveu écrit — "
                  f"ajouter « {AVEU_SHELL} » et NOMMER la divergence avec le canonicaliseur du démon",
                  file=sys.stderr)
        print(f"une seule forme canonique : {len(violations)} site(s) Rust hors voie unique, "
              f"{len(shell_muets)} site(s) shell muet(s) — sur {vues} région(s) Rust et {shell_vus} site(s) shell",
              file=sys.stderr)
        return 1

    print(f"une seule forme canonique : OK — {vues} région(s) de canonicalisation Rust "
          f"(toutes dans {os.path.relpath(porteur, RACINE)} ou via `ssrf_norm_ip`), "
          f"{shell_vus} site(s) shell, tous avoués.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
