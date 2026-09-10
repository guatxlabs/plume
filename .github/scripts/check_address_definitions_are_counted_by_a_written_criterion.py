#!/usr/bin/env python3
"""`P4.7-j` — CE QUI COMPTE COMME « DÉFINITION D'ADRESSE » EST ÉCRIT, ET LE COMPTE EST DÉRIVÉ, PUIS AVOUÉ.

LE DÉFAUT, MESURÉ LE 2026-09-03 : la cellule annonçait « au moins six » définitions de « ceci est une
adresse » dans l'arbre, un recensement en rendait jusqu'à treize, et le chiffre allait de six à treize
selon ce qu'on acceptait d'appeler définition — un sélecteur de champ, une clé de recherche de
renseignement et un site qui délègue à un normaliseur existant étaient comptés sous une lecture,
écartés sous une autre. Aucune population n'était mesurable, et une garde posée sur un compte
indécidable aurait été une rançon.

LE CRITÈRE, FERMÉ, ÉCRIT UNE FOIS. Est une définition d'adresse toute UNITÉ NOMMÉE du dépôt — fonction
Rust, fonction shell — dont le corps, commentaires dépouillés et littéraux CONSERVÉS (les expressions
rationnelles y vivent), porte au moins :
  (a) une ANALYSE DE TYPE d'adresse — `parse::<IpAddr>` et ses variantes, `IpAddr::from_str`, une
      liaison `: IpAddr = ….parse()`, `ipaddress.ip_network(…)` ;
  ou (b) un TEST DE FORME LITTÉRAL — une expression rationnelle à octet IPv4 (`\\d{1,3}` ou
      `[0-9]{1,3}`), ou un test d'alphabet hexadécimal assorti du séparateur `.` ou `:`.
Ce que le critère ÉCARTE, à dessein et non par oubli :
  * une canonicalisation sur une valeur DÉJÀ TYPÉE (`to_ipv4_mapped` sans analyse dans la même
    unité) : elle ne décide pas qu'une chaîne est une adresse, elle transforme une adresse ;
  * un découpage par séparateur sans test d'alphabet (le préfixe textuel de l'exclusion d'affichage) :
    il rend un préfixe de chaîne, jamais un verdict d'adressité ;
  * un sélecteur de champ (`src_ip` avant `rhost`) : une précédence de NOM, pas une forme ;
  * une normalisation d'indicateur qui ignore le type (`trim` + minuscules) ;
  * une unité qui DÉLÈGUE le verdict (elle appelle `ssrf_norm_ip` et ne teste rien elle-même) : elle
    n'entre pas dans la population parce qu'elle ne porte ni (a) ni (b) ;
  * tout ce qui vit hors de ce dépôt (`guatx-core::ti::normalize_ioc`, épinglé dans `daemon/Cargo.lock`) ;
  * les comparaisons SQL sur la chaîne (`ON b.src_ip=a.src_ip`, `GROUP BY src_ip`) — la moitié
    détection, tenue par `P4.7-l`, pas par cette garde.

LA POPULATION EST DÉRIVÉE, JAMAIS ÉNUMÉRÉE : chaque unité est trouvée par son corps. L'AVEU, lui, est
écrit — une ligne par définition, avec sa catégorie et son consommateur — parce que le nombre n'est pas
ce qui compte : c'est que chaque définition ait un NOM et un consommateur connu. Une définition neuve
que l'aveu ne nomme pas est refusée (l'avouer ici, ou la rallier au canonicaliseur unique) ; un aveu
qui ne correspond plus à l'arbre est refusé aussi (retirer la ligne : le compte descend).

CE QUE CETTE GARDE NE PROUVE PAS, ÉCRIT DANS SON PROPRE EN-TÊTE :
  * que deux définitions rendent le MÊME verdict sur la même chaîne — c'est `check_one_canonical_address_form.py`
    qui tient la forme canonique, et seulement sous `daemon/src` et `collectors/*.sh` ; une définition
    de l'agent qui recopie le repli de la forme mappée sans le nommer est COMPTÉE ici, pas jugée ;
  * la détection et la corrélation, qui tranchent l'identité sur la chaîne ;
  * l'attribution d'une fonction imbriquée : le corps est attribué à l'unité la plus INTÉRIEURE qui le
    contient, selon l'indentation que rustfmt tient sur tout ce dépôt.

Codes de sortie : 0 conforme · 1 violation · 2 l'instrument REFUSE DE CONCLURE.
Option `--deriver` : imprime la population dérivée sans juger l'aveu.
"""
import os, re, sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))

# La surface : les caisses Rust hors répertoires de tests, et les capteurs shell.
SURFACE_RUST = ["daemon/src", "agent/src", "collector-mail/src", "collector-syslog/src"]
SURFACE_SHELL = ["collectors"]

# (a) ANALYSE DE TYPE.
ANALYSE_DE_TYPE = re.compile(
    r"parse::<\s*(?:std::net::)?(?:IpAddr|Ipv4Addr|Ipv6Addr|SocketAddr|IpNet)\s*>"
    r"|\b(?:IpAddr|Ipv4Addr|Ipv6Addr)::from_str\b"
    r"|:\s*(?:std::net::)?(?:IpAddr|Ipv4Addr|Ipv6Addr)\s*=[^;]*\.parse\s*\("
    r"|\bipaddress\.(?:ip_network|ip_address|ip_interface)\s*\("
)
# (b) TEST DE FORME LITTÉRAL : un octet IPv4 en expression rationnelle, ou l'alphabet hexadécimal
# assorti d'un séparateur d'adresse sur la même ligne.
OCTET_IPV4 = re.compile(r"\\d\{1,3\}|\[0-9\]\{1,3\}")
ALPHABET_HEX = re.compile(r"is_ascii_hexdigit\s*\(\s*\)")
SEPARATEUR = re.compile(r"'\.'|':'")

# La forme d'une unité : fonction Rust (toute indentation), fonction shell (colonne 0).
FN_RUST = re.compile(r"^(?P<indent>\s*)(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(?P<nom>\w+)")
FN_SHELL = re.compile(r"^(?P<nom>\w+)\s*\(\)\s*\{")
CFG_TEST = re.compile(r"^\s*#\[cfg\(test\)\]")

# L'AVEU : (chemin, unité, catégorie, consommateur). Une ligne par définition ; l'ordre est celui de la
# dérivation (chemin puis unité). Le compte est ce que l'aveu porte — le lire ici, jamais le recopier.
AVEU = [
    ("agent/src/source/windows.rs", "valeur_exploitable", "a", "ingestion (src_ip/dst_ip Windows) — recopie le repli de la forme mappée sans nommer ssrf_norm_ip : hors du regard de la garde de forme canonique"),
    ("collector-mail/src/patterns.rs", "defaults", "b", "détection (motif raw-ip-url, IPv4 pointée seule)"),
    ("collector-syslog/src/main.rs", "parse_cidr", "a", "enforcement du collecteur syslog (liste d'admission des émetteurs, CIDR ou adresse nue)"),
    ("collectors/engagement-adapter.sh", "canon_or_reject", "a", "enforcement d'hôte (périmètre d'engagement poussé vers nft) — divergence de repli avouée au site"),
    ("collectors/respond.sh", "is_ip", "b", "enforcement d'hôte (cible d'un geste, liste d'épargne) — IPv4 pointée ou hexadécimal à deux-points, sans repli ni zone"),
    ("daemon/src/handlers/actions.rs", "cible_de_levee_acceptee", "b", "enforcement (levée de ban) — alphabet hexadécimal, un point, 45 caractères au plus"),
    ("daemon/src/handlers/actions.rs", "ressemble_a_une_adresse", "b", "refus (une liste d'arrêt de service qui porterait l'autre politique) — alphabet hexadécimal et un séparateur, sans borne"),
    ("daemon/src/handlers/engagement.rs", "validate_engagement_scope", "a", "enforcement (exemption de pentest) — analyse indépendante avant de rappeler parse_protected_item"),
    ("daemon/src/ingest/mod.rs", "extract_src_ip", "b", "ingestion (src_ip d'une ligne de journal) — dénude port et CIDR, alphabet hexadécimal et un séparateur"),
    ("daemon/src/ledger.rs", "parse_ssrf_allow", "a", "enforcement (liste d'autorisation d'égress) — CIDR, adresse nue ou nom d'hôte ; ne replie pas à l'analyse"),
    ("daemon/src/ledger.rs", "protected_item_reseau", "a", "enforcement (adresses protégées, jamais bannies) — CIDR, adresse nue ou joker sur frontière d'octet ; replie la forme mappée"),
    ("daemon/src/ledger.rs", "ssrf_norm_ip", "a", "LE canonicaliseur unique — enforcement, authentification, engagement ; replie la forme mappée"),
    ("daemon/src/migrate.rs", "migrate_v23", "b", "analyse (motifs sshd semés : rhost IPv4 uniquement)"),
]

PLANCHER_DE_POPULATION = 8  # en dessous, l'instrument ne voit plus l'arbre : refus de conclure


def sans_commentaires(texte, rust):
    """Retire les commentaires de ligne en CONSERVANT les littéraux : un `//` ou un `#` n'ouvre un
    commentaire que s'il est précédé d'un blanc (ou en tête) et qu'un nombre PAIR de guillemets le
    précède sur la ligne — `r"https?://\\d{1,3}…"` reste entier."""
    marque = "//" if rust else "#"
    out = []
    for l in texte.split("\n"):
        d = l.lstrip()
        if d.startswith(marque):
            out.append("")
            continue
        i = 0
        coupe = None
        while True:
            j = l.find(marque, i)
            if j < 0:
                break
            avant = l[:j]
            precede_d_un_blanc = j == 0 or avant[-1] in " \t"
            guillemets = avant.count('"') + (0 if rust else avant.count("'"))
            if precede_d_un_blanc and guillemets % 2 == 0:
                coupe = j
                break
            i = j + len(marque)
        out.append(l if coupe is None else l[:coupe])
    return "\n".join(out)


def sans_cfg_test(lignes):
    """Retire tout item annoté `#[cfg(test)]` jusqu'à son accolade fermante à la même indentation."""
    out = []
    i = 0
    while i < len(lignes):
        if CFG_TEST.match(lignes[i]):
            indent = len(lignes[i]) - len(lignes[i].lstrip())
            j = i + 1
            while j < len(lignes) and not (lignes[j].strip() == "}" and len(lignes[j]) - len(lignes[j].lstrip()) == indent):
                j += 1
            out.extend([""] * (j - i + 1))
            i = j + 1
            continue
        out.append(lignes[i])
        i += 1
    return out


def unites(lignes, rust):
    """Les unités nommées d'un fichier : (nom, début, fin) ; fin = accolade fermante à la même indentation
    (rustfmt / shell en colonne 0), ou la ligne elle-même pour une fonction sur une ligne."""
    res = []
    for i, l in enumerate(lignes):
        m = (FN_RUST if rust else FN_SHELL).match(l)
        if not m:
            continue
        indent = m.group("indent") if rust else ""
        ouvre = l.find("{")
        if ouvre >= 0 and l.count("{") == l.count("}") and l.count("{") > 0:
            res.append((m.group("nom"), i, i))
            continue
        if rust and ouvre < 0 and l.rstrip().endswith(";"):
            continue  # une déclaration sans corps (trait)
        j = i + 1
        while j < len(lignes) and lignes[j] != indent + "}":
            j += 1
        res.append((m.group("nom"), i, j))
    return res


def unite_la_plus_interieure(us, ligne):
    """L'unité au début le plus tardif qui contient la ligne."""
    cand = [u for u in us if u[1] <= ligne <= u[2]]
    return max(cand, key=lambda u: u[1])[0] if cand else None


def categories_d_une_ligne(l):
    cats = set()
    if ANALYSE_DE_TYPE.search(l):
        cats.add("a")
    if OCTET_IPV4.search(l) or (ALPHABET_HEX.search(l) and SEPARATEUR.search(l)):
        cats.add("b")
    return cats


def deriver_un_texte(texte, rust):
    """{unité: catégories} pour un texte source ; les lignes hors de toute unité sont rendues sous `None`."""
    lignes = sans_commentaires(texte, rust).split("\n")
    if rust:
        lignes = sans_cfg_test(lignes)
    us = unites(lignes, rust)
    trouve = {}
    for i, l in enumerate(lignes):
        cats = categories_d_une_ligne(l)
        if not cats:
            continue
        u = unite_la_plus_interieure(us, i)
        trouve.setdefault(u, set()).update(cats)
    return trouve


def fichiers():
    out = []
    for s in SURFACE_RUST:
        for d, dirs, fs in os.walk(os.path.join(RACINE, s)):
            dirs[:] = [x for x in dirs if x != "tests"]
            for f in fs:
                if f.endswith(".rs") and f != "tests.rs":
                    out.append((os.path.relpath(os.path.join(d, f), RACINE), True))
    for s in SURFACE_SHELL:
        for d, _, fs in os.walk(os.path.join(RACINE, s)):
            for f in fs:
                if f.endswith(".sh"):
                    out.append((os.path.relpath(os.path.join(d, f), RACINE), False))
    return sorted(out)


def deriver():
    """[(chemin, unité, catégories)] sur l'arbre, plus les lignes hors unité (à dire, jamais à taire)."""
    population, hors_unite = [], []
    for rel, rust in fichiers():
        with open(os.path.join(RACINE, rel), encoding="utf-8", errors="replace") as fh:
            texte = fh.read()
        for u, cats in deriver_un_texte(texte, rust).items():
            if u is None:
                hors_unite.append(rel)
            else:
                population.append((rel, u, "".join(sorted(cats))))
    return sorted(population), hors_unite


# ---- L'INSTRUMENT, VALIDÉ DANS LES DEUX SENS SUR DES CORPUS FABRIQUÉS ----
CORPUS_RUST = '''\
/// Une doc qui cite parse::<IpAddr>() ne compte pas.
pub(crate) fn comptee_par_analyse(s: &str) -> Option<IpAddr> {
    // un commentaire avec [0-9]{1,3} ne compte pas non plus
    s.trim().parse::<IpAddr>().ok()
}
fn comptee_par_forme(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
}
fn comptee_par_motif() -> &'static str {
    r"https?://\\d{1,3}(\\.\\d{1,3}){3}"
}
fn delegue(s: &str) -> Option<String> {
    ssrf_norm_ip(s).map(|ip| ip.to_string())
}
fn typee_seulement(ip: IpAddr) -> IpAddr {
    match ip { IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip), v4 => v4 }
}
fn externe() {
    fn interne(s: &str) -> bool { s.parse::<Ipv4Addr>().is_ok() }
    interne("x");
}
#[cfg(test)]
mod tests {
    fn dans_les_tests(s: &str) -> bool { s.parse::<IpAddr>().is_ok() }
}
'''
CORPUS_SHELL = '''\
#!/bin/sh
# is_ip() { grep -qE '^([0-9]{1,3}\\.){3}' ; } — un commentaire ne compte pas
is_ip() { printf '%s' "$1" | grep -qE '^([0-9]{1,3}\\.){3}[0-9]{1,3}$'; }
canon() {
  python3 - "$1" <<'PY'
import ipaddress
net = ipaddress.ip_network(c, strict=False)   # commentaire
PY
}
rien() {
  echo "pas une adresse"
}
'''


def instrument():
    attendu_rust = {"comptee_par_analyse": "a", "comptee_par_forme": "b", "comptee_par_motif": "b", "interne": "a"}
    vu = {u: "".join(sorted(c)) for u, c in deriver_un_texte(CORPUS_RUST, True).items()}
    if vu != attendu_rust:
        return f"corpus Rust : attendu {attendu_rust}, vu {vu}"
    attendu_shell = {"is_ip": "b", "canon": "a"}
    vu = {u: "".join(sorted(c)) for u, c in deriver_un_texte(CORPUS_SHELL, False).items()}
    if vu != attendu_shell:
        return f"corpus shell : attendu {attendu_shell}, vu {vu}"
    return None


def main():
    faute = instrument()
    if faute:
        print(f"::error::[definitions-d-adresse] INSTRUMENT : {faute} — la dérivation ne rend plus ce qu'un corpus connu impose, aucun verdict.")
        return 2
    population, hors_unite = deriver()
    if "--deriver" in sys.argv:
        for rel, u, c in population:
            print(f"  {c}  {rel} :: {u}")
        for rel in hors_unite:
            print(f"  ?  {rel} :: (hors de toute unité nommée)")
        print(f"[definitions-d-adresse] {len(population)} définition(s) dérivée(s), {len(hors_unite)} ligne(s) hors unité.")
        return 0
    if len(population) < PLANCHER_DE_POPULATION:
        print(f"::error::[definitions-d-adresse] {len(population)} définition(s) dérivée(s) sous le plancher de {PLANCHER_DE_POPULATION} : l'instrument ne voit plus l'arbre, aucun verdict.")
        return 2
    derivees = {(rel, u): c for rel, u, c in population}
    avouees = {(rel, u): (c, qui) for rel, u, c, qui in AVEU}
    rc = 0
    for (rel, u), c in sorted(derivees.items()):
        if (rel, u) not in avouees:
            print(f"::error file={rel}::[definitions-d-adresse] DÉFINITION NEUVE non avouée : `{u}` (catégorie {c}). L'avouer dans AVEU avec sa catégorie et son consommateur, ou la rallier au canonicaliseur unique (`ssrf_norm_ip`).")
            rc = 1
        elif avouees[(rel, u)][0] != c:
            print(f"::error file={rel}::[definitions-d-adresse] `{u}` : catégorie avouée « {avouees[(rel, u)][0]} », dérivée « {c} » — l'aveu ne décrit plus l'unité.")
            rc = 1
    for (rel, u), (c, _) in sorted(avouees.items()):
        if (rel, u) not in derivees:
            print(f"::error file={rel}::[definitions-d-adresse] AVEU SANS OBJET : `{u}` n'est plus une définition d'adresse (ou n'existe plus). Retirer la ligne : le compte descend.")
            rc = 1
    for rel in hors_unite:
        print(f"::error file={rel}::[definitions-d-adresse] une analyse ou un test de forme vit HORS de toute unité nommée : le critère ne sait pas à qui l'attribuer.")
        rc = 1
    print(f"[definitions-d-adresse] {len(derivees)} définition(s) d'adresse dérivée(s) par le critère écrit, {len(avouees)} avouée(s) : "
          + ", ".join(f"{u} ({c})" for (_, u), c in sorted(derivees.items())))
    print("[definitions-d-adresse] ÉCARTÉ PAR LE CRITÈRE, DIT : les canonicalisations sur valeur typée, le préfixe textuel d'exclusion d'affichage, "
          "les sélecteurs de champ, la clé de renseignement, les unités qui délèguent, le cœur épinglé, et les comparaisons SQL (P4.7-l).")
    return rc


if __name__ == "__main__":
    sys.exit(main())
