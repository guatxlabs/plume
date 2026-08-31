#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`P11.21-n` — LA LANGUE DÉCLARÉE PAR LE DOCUMENT EST CELLE QU'IL PEINT.

LE CONSTAT, ET IL A ÉTÉ NOMMÉ AVANT D'ÊTRE CORRIGÉ. La garde voisine
`check_an_admission_is_painted_where_it_is_read.py` écrit, dans sa propre liste de ce
qu'elle NE TIENT PAS : « `web/index.html` déclare `lang="fr"` en dur et AUCUN module ne
pose jamais `document.documentElement.lang` […] Une console rendue en anglais annonce
donc le français à `:lang()` et aux technologies d'assistance. C'est un défaut de
`web/`, il est NOMMÉ ici et pas corrigé ici. » Ce fichier est la moitié qui le tient.

MESURÉ LE 2026-08-31 SUR L'ARBRE D'ALORS, dans un vrai moteur, sur la VRAIE page : avec
`soc_lang='en'` en stockage de site, la console peint « Overview », « Search », « Sign
in », « Password », « Run » — et `document.documentElement.getAttribute('lang')` rend
`"fr"`. La page CONNAÎT la bonne réponse (elle s'en sert pour chaque libellé qu'elle
rend) et en PUBLIE une autre. Un lecteur d'écran y prononce donc l'anglais avec une
phonétique française.

LE CORRECTIF TENU ICI est d'une ligne, dans `web/core.js`, à l'endroit MÊME où la langue
est décidée (`LANG`, lu du stockage à l'évaluation du module) et sous la MÊME condition
que la locale de dates `LOC`. `web/index.html` garde `lang="fr"` dans son balisage,
et c'est juste : tant que le graphe ES n'est pas lié, la seule chose affichable est
l'aveu `#init-echec`, écrit en français quoi qu'il arrive.

=====================================================================================
LA FORME DE CETTE GARDE, ET POURQUOI CELLE-CI PLUTÔT QUE L'AUTRE
=====================================================================================
Deux voies existaient. Le choix n'est pas une préférence : il est MESURÉ, par deux des
mutations que ce fichier joue.

  · UNE GARDE DE TEXTE aurait dérivé de la source que l'attribut est posé là où la
    langue est décidée. Elle prouve la PRÉSENCE D'UN GESTE, jamais son EFFET. Deux des
    cinq mutations jouées plus bas la laisseraient VERTE, et ce ne sont pas des cas
    d'école :
      - `figer-sur-le-francais` : la ligne est là, à la bonne place, sous la bonne
        condition — mais la valeur posée est constante. Toute grammaire qui accepte
        « un attribut de langue est posé dans `core.js` » accepte celle-là.
      - `ecraser-plus-tard` : la ligne de `core.js` est INTACTE et un AUTRE module
        (`app.js`, évalué APRÈS) repose l'attribut. Aucune lecture de `core.js` ne peut
        voir ça ; il faudrait lire TOUS les modules, et ce serait redevenu une liste.
    C'est très exactement le défaut que la garde voisine poursuit — un instrument vert
    là où il ne mesure plus rien.

  · UNE GARDE QUI RENVOIE LA PAGE DANS UN MOTEUR lit l'attribut RÉELLEMENT posé après
    que la langue a été appliquée. Elle ne connaît ni la ligne, ni le module, ni la
    forme du geste : elle connaît l'ÉTAT FINAL du document. C'est celle-ci.

SON COÛT EST CONNU ET IL EST BAS — mesuré le 2026-08-31 sur ce poste (Google Chrome
151.0.7922.169) : SIX rendus, ~3,9 s chacun, ~24 s en tout. C'est MOINS que la garde
voisine (25 rendus, ~31 s) pour une raison mesurée : les trois cellules de langue
tiennent dans UN SEUL rendu. Le stockage de site est propre à l'ORIGINE, pas au
document ; la coquille sème donc `soc_lang`, charge la VRAIE `/index.html` dans un
cadre, lit, jette le cadre, sème la valeur suivante et recommence. Chaque cadre est un
réalisme neuf, donc une carte de modules neuve, donc une RÉÉVALUATION de `core.js` —
vérifié le 2026-08-31 en rejouant `fr` APRÈS `en` : la langue rebascule, ce n'est pas
un verrou à sens unique.

ET CE QUI REND CETTE VOIE POSSIBLE ICI, LÀ OÙ LA GARDE VOISINE A DÛ DÉRIVER UN BALISAGE :
la propriété jugée ici ne demande AUCUN démon. `web/core.js` n'importe que deux feuillets
(`state.js`, `recherche_de_liste.js`, zéro import chacun) et ne porte AUCUN appel au
niveau supérieur. La VRAIE `web/index.html`, avec son VRAI graphe `/app.js`, se lie donc
seule : mesuré le 2026-08-31, elle atteint `html.app-ready` en 1,7 s sans qu'aucune API
ne réponde. Ce fichier ne juge donc pas une fiction dérivée — il juge la page.

=====================================================================================
CE QUE CETTE GARDE JUGE
=====================================================================================
TROIS CELLULES, et la troisième n'est pas un ornement :
  · `absent` — aucun choix en stockage. C'est le PREMIER visiteur, et cette cellule est
    ce qui interdit à un correctif de déplacer la langue par défaut d'une console
    existante : elle exige `fr` peint ET `fr` déclaré.
  · `fr` — choix explicite du français.
  · `en` — choix explicite de l'anglais. C'est la cellule qui était ROUGE.

LA LANGUE PEINTE N'EST PAS DEVINÉE, ET SURTOUT ELLE N'EST PAS ÉCRITE ICI. Aucun mot
français ni anglais ne figure dans ce fichier comme critère. Le vocabulaire est DÉRIVÉ
de `web/i18n.js` — le dictionnaire FR->EN que la console emploie réellement — puis
RÉDUIT à ce que les deux rendus de référence démontrent être un DISCRIMINANT :

  une paire (clé française, valeur anglaise) n'est retenue que si le rendu français
  peint la clé et PAS la valeur, ET que le rendu anglais peint la valeur et PAS la clé.

Cette réduction n'est pas une commodité, elle retire un BRUIT MESURÉ (2026-08-31) :
sur 1 679 paires où la clé diffère de la valeur, `('événement', 'event')` vote anglais
dans le rendu FRANÇAIS — parce que `event` y est peint comme nom de table, pas comme
libellé — et `('Tester', 'Test')` voit ses DEUX faces peintes. Un seuil (« 95 % des
sondes ») aurait noyé ces deux-là ; la réduction les ÉLIMINE, et le verdict reste sans
seuil : une cellule dont les deux camps ont des voix, ou aucune, ne rend pas vert — elle
REFUSE.

LE VERDICT, PAR CELLULE : la langue peinte (dérivée comme ci-dessus) et la langue
déclarée (`document.documentElement.getAttribute('lang')`) doivent être la MÊME. Un
attribut ABSENT ou VIDE est un manquement, pas une excuse : une console qui peint
l'anglais sans rien déclarer laisse le lecteur d'écran sur le réglage de l'agent.

CE QUI EST TAUTOLOGIQUE ICI, ÉCRIT PLUTÔT QUE CACHÉ : les discriminants sont choisis à
l'aide des rendus `fr` et `en` de l'arbre intact ; que ces deux rendus-là peignent bien
le français et l'anglais est donc VRAI PAR CONSTRUCTION. Ce n'est pas un vice, parce que
ce n'est PAS la moitié jugée : la langue DÉCLARÉE reste une variable libre, lue
séparément, et c'est elle que les trois cellules et les cinq mutations mettent à
l'épreuve. La cellule `absent` et les cinq rendus mutés, eux, voient leur langue peinte
déterminée sans tautologie, contre un vocabulaire fixé ailleurs.

L'INSTRUMENT EST VALIDÉ AVANT TOUT VERDICT, ET DANS LES DEUX SENS. Cinq mutations sont
SERVIES (jamais écrites dans l'arbre : la couche HTTP substitue le module, le dépôt n'est
pas touché), chacune jugée dans les TROIS cellules avec une attente PAR CELLULE. La
moitié VERTE de ces attentes est ce qui démontre que la garde n'est pas rouge par
construction :

  mutation                  | absent | fr    | en
  --------------------------|--------|-------|-------
  figer-sur-le-francais     | VERT   | VERT  | ROUGE   <- reproduit l'état d'AVANT le correctif
  figer-sur-l-anglais       | ROUGE  | ROUGE | VERT
  inverser                  | ROUGE  | ROUGE | ROUGE
  effacer-l-attribut        | ROUGE  | ROUGE | ROUGE
  ecraser-plus-tard         | VERT   | VERT  | ROUGE   <- `core.js` INTACT, `app.js` clobbe après

Une mutation qui n'est pas attrapée EXACTEMENT comme annoncé — un rouge attendu qui
verdit, un vert attendu qui rougit — sort en 2. Un instrument aveugle ne rend pas vert.

CE QUE CETTE GARDE NE TIENT PAS — écrit ici plutôt que découvert plus tard :
  · ELLE NE JUGE QUE LA RACINE. `document.documentElement.lang` couvre le document
    entier ; un fragment de langue AUTRE à l'intérieur (une citation anglaise dans une
    console française, le bloc `#parsers-intro` que `i18n_observer.js` réécrit en
    anglais) devrait porter son propre `lang` et N'EST PAS vu ici. La propriété tenue
    est « la racine ne ment pas », pas « chaque nœud dit sa langue ».
  · ELLE NE JUGE QUE DEUX LANGUES, parce que la console n'en offre que deux
    (`web/index.html` : `<option value="fr">`, `<option value="en">`). Une troisième
    langue ajoutée sans toucher ce fichier ferait REFUSER (aucun discriminant pour
    elle), pas verdir — c'est le bon sens de l'échec, mais c'est du travail à faire.
  · ELLE NE TIENT PAS LE CHANGEMENT SANS RECHARGEMENT, et c'est parce qu'il N'EXISTE
    PAS — mesuré, pas supposé (2026-08-31). `LANG` est lu UNE fois, du stockage, à
    l'évaluation de `core.js` ; le sélecteur `#lang` de `web/app.js` écrit le stockage
    puis appelle `location.reload()`, et si l'écriture échoue il REFUSE le changement et
    remet la liste sur la langue réelle (clé `P4.13-b`, commentée sur place). Il n'y a
    donc aucun chemin en mémoire qui change la langue, donc rien à réappliquer. Le jour
    où un tel chemin existerait, cette garde deviendrait INSUFFISANTE sans rougir : elle
    ne rend qu'au chargement. C'est la limite la plus importante de ce fichier.
  · ELLE NE MESURE PAS CE QU'UN LECTEUR D'ÉCRAN PRONONCE. Elle tient que l'attribut
    nomme la bonne langue ; que telle synthèse vocale l'honore est hors de portée.
  · ELLE NE JUGE QU'UN SEUL GABARIT (1600x1200). C'est délibéré et mesuré : aucune règle
    `:lang()` ni `[lang]`, ni `quotes`/`hyphens`, n'existe dans `web/style.css` ni dans
    `web/index.html` (vérifié le 2026-08-31), donc l'attribut ne change AUCUNE peinture
    et la largeur ne peut rien y faire. Si un tel sélecteur apparaissait un jour, la
    largeur redeviendrait pertinente et ce fichier ne le verrait pas.
  · LE STOCKAGE EST SEMÉ PAR LA COQUILLE, pas par un vrai clic sur `#lang`. Ce qui est
    tenu est donc « une console dont le stockage porte cette langue déclare cette
    langue » ; que le sélecteur écrive bien cette clé-là est tenu par la source
    (`ecrireDansLeStockageDuSite('soc_lang', …)` dans `web/app.js`) et non ici.
  · AUCUNE API NE RÉPOND pendant le rendu : la console atteint `app-ready` par le chemin
    401 de `login.js`. Une vue qui ne se peint QUE derrière un démon vivant n'est donc
    pas dans le document jugé — mais la propriété est portée par la RACINE, que toutes
    les vues partagent.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# LA RACINE SE DÉRIVE DE LA POSITION DE CE FICHIER, JAMAIS D'UN CHEMIN ÉCRIT : un chemin
# de machine d'auteur en dur a déjà coûté une intégration continue rouge, et la garde
# `check_no_instrument_hardcodes_an_author_machine_path.py` tient cette propriété.
RACINE = Path(__file__).resolve().parents[2]
WEB = RACINE / "web"

CODE_OK, CODE_VIOLATION, CODE_REFUS = 0, 1, 2

# Les trois cellules : (nom, valeur semée dans `soc_lang`, langue ATTENDUE).
# `None` = la clé est RETIRÉE du stockage, donc le premier visiteur.
CELLULES = (("absent", None, "fr"), ("fr", "fr", "fr"), ("en", "en", "en"))

NOMS_DE_MOTEUR = ("google-chrome-stable", "google-chrome", "chromium",
                  "chromium-browser", "chrome", "headless_shell")
VARIABLE_DE_MOTEUR = "PLUME_NAVIGATEUR"

# Le verdict sort par un NŒUD, pas par un marqueur textuel : `--dump-dom` recrache aussi
# le SOURCE du script, où tout marqueur littéral se retrouverait — et la garde lirait sa
# propre question au lieu de la réponse.
ID_VERDICT = "verdict-p11-21-n"

# Planchers de REFUS. Ils ne pondèrent aucun verdict : ils disent à partir de quand ce
# fichier accepte de conclure. Mesuré le 2026-08-31 : 1 679 paires, 681 discriminants.
PLANCHER_PAIRES, PLANCHER_DISCRIMINANTS = 100, 50


def refuser(motif: str) -> None:
    """Code 2 — canal DISTINCT d'une propriété violée. Un instrument qui ne mesure pas
    ne rend pas vert : il se tait bruyamment."""
    print(f"::error::(2-refus) {motif}", file=sys.stderr)
    print("REFUS DE CONCLURE — cette garde n'a rien mesuré ; ce n'est PAS un vert.",
          file=sys.stderr)
    sys.exit(CODE_REFUS)


# =====================================================================================
# 1. LE MOTEUR — DÉRIVÉ, JAMAIS SUPPOSÉ
# =====================================================================================
def trouver_le_moteur() -> str:
    impose = os.environ.get(VARIABLE_DE_MOTEUR, "").strip()
    if impose:
        if not (os.path.isfile(impose) and os.access(impose, os.X_OK)):
            refuser(f"`{VARIABLE_DE_MOTEUR}={impose}` ne désigne aucun exécutable : la "
                    "garde ne se replie pas en silence sur un autre moteur.")
        return impose
    for nom in NOMS_DE_MOTEUR:
        chemin = shutil.which(nom)
        if chemin:
            return chemin
    refuser(
        "AUCUN MOTEUR DE RENDU SANS TÊTE sur le chemin. Cherchés : "
        + ", ".join(NOMS_DE_MOTEUR)
        + f" ; porte d'entrée `{VARIABLE_DE_MOTEUR}=<chemin>`. La langue DÉCLARÉE par un "
        "document ne se lit qu'après application de la langue RENDUE — une lecture de la "
        "source prouverait la présence d'un geste, pas son effet. L'image de coureur "
        "`ubuntu-24.04` publiait Google Chrome installé par défaut le 2026-08-30 : si ce "
        "refus paraît en intégration continue, c'est l'image qui a changé."
    )
    raise AssertionError("inatteignable")


# =====================================================================================
# 2. LE VOCABULAIRE — DÉRIVÉ DU DICTIONNAIRE QUE LA CONSOLE EMPLOIE
#    Aucun mot n'est écrit ici. Si `web/i18n.js` change de forme, ce bloc REFUSE au lieu
#    de verdir sur un vocabulaire vide.
# =====================================================================================
# UN LITTÉRAL DE CHAÎNE JAVASCRIPT, ET PAS UNE CLASSE DE CARACTÈRES : une classe
# `["']([^"']*)["']` COUPE au premier guillemet INTÉRIEUR et fabrique de faux littéraux
# faits de CODE pris entre deux chaînes — la garde voisine s'est fait prendre exactement
# là (sa « quatrième faute d'instrument », 2026-08-31). Ce motif ferme sur le MÊME
# délimiteur que celui qui ouvre, échappements compris.
_LITTERAL = r"""(?:'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)")"""
_PAIRE = re.compile(_LITTERAL + r"\s*:\s*" + _LITTERAL)
_OUVERTURE = "const I18N_EN = {"


def sans_commentaires(source: str) -> str:
    """Retire `//…` et `/*…*/` SANS toucher à ce qui vit dans une chaîne. Un simple
    `re.sub` sur `//.*` couperait au milieu d'une URL (`http://…`) présente dans un
    libellé et fabriquerait des paires tronquées."""
    sortie, i, n = [], 0, len(source)
    while i < n:
        c = source[i]
        if c in "'\"`":
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == c:
                    j += 1
                    break
                j += 1
            sortie.append(source[i:j])
            i = j
            continue
        if c == "/" and i + 1 < n and source[i + 1] == "/":
            j = source.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and i + 1 < n and source[i + 1] == "*":
            j = source.find("*/", i)
            i = n if j < 0 else j + 2
            continue
        sortie.append(c)
        i += 1
    return "".join(sortie)


def deriver_le_vocabulaire() -> list:
    chemin = WEB / "i18n.js"
    if not chemin.is_file():
        refuser(f"`{chemin}` est introuvable : le dictionnaire dont ce fichier DÉRIVE "
                "son vocabulaire n'existe plus, il n'y a plus rien à mesurer.")
    source = chemin.read_text(encoding="utf-8")
    debut = source.find(_OUVERTURE)
    if debut < 0:
        refuser(f"`web/i18n.js` ne porte plus `{_OUVERTURE}` : le dictionnaire a changé "
                "de forme. Cette garde REFUSE plutôt que de juger avec un vocabulaire "
                "vide — un vert obtenu sans sonde serait un mensonge.")
    fin = source.find("\n};", debut)
    if fin < 0:
        refuser("le dictionnaire de `web/i18n.js` ne se referme pas sur `\\n};` : la "
                "dérivation ne sait pas où il s'arrête.")
    bloc = sans_commentaires(source[debut:fin])
    paires, vues = [], set()
    for m in _PAIRE.finditer(bloc):
        cle = m.group(1) if m.group(1) is not None else m.group(2)
        val = m.group(3) if m.group(3) is not None else m.group(4)
        # Une paire dont les deux faces sont IDENTIQUES ne discrimine rien : « Dashboards »,
        # « Firewall », « CSV » sont le MÊME mot dans les deux langues. Les retenir aurait
        # fait voter les deux camps à la fois, donc REFUSER, sur une console pourtant saine.
        if cle and val and cle != val and cle not in vues:
            vues.add(cle)
            paires.append((cle, val))
    if len(paires) < PLANCHER_PAIRES:
        refuser(f"seulement {len(paires)} paire(s) FR->EN dérivées de `web/i18n.js` "
                f"(plancher {PLANCHER_PAIRES}) : la dérivation s'est effondrée. Juger la "
                "langue peinte avec ce vocabulaire-là ne mesurerait presque rien.")
    return paires


# =====================================================================================
# 3. LA COQUILLE — LES TROIS CELLULES DANS UN SEUL RENDU
#    Le stockage de site est propre à l'ORIGINE : semer, charger la VRAIE `/index.html`
#    dans un cadre, lire, jeter le cadre, semer la valeur suivante. Chaque cadre est un
#    réalisme neuf, donc une carte de modules neuve, donc une réévaluation de `core.js`.
#    La coquille MESURE et ne juge rien : elle rapporte l'attribut posé et, pour chaque
#    paire du vocabulaire, laquelle de ses deux faces est peinte. Tout le jugement est en
#    Python, où il est relisible.
# =====================================================================================
def batir_la_coquille(paires: list) -> str:
    return """<!doctype html><html><head><meta charset="utf-8"><title>banc</title>
<style>html,body{margin:0;padding:0;background:#000} iframe{border:0;display:block}</style>
</head><body>
<script>
(async function () {
  const CELLULES = __CELLULES__, PAIRES = __PAIRES__, ID = __ID__, ATTENTE = __ATTENTE__;
  const resultat = {}; let ecrit = false;
  const ecrire = (fatal) => {
    if (ecrit) return; ecrit = true;
    const pre = document.createElement('pre'); pre.id = ID;
    pre.textContent = JSON.stringify({ cellules: resultat, fatal: fatal || null });
    document.body.appendChild(pre);
  };
  // FILET : si une cellule ne rend jamais, la coquille écrit quand même ce qu'elle tient.
  // La garde refuse alors en NOMMANT la manquante, au lieu de refuser sur un silence.
  setTimeout(() => ecrire('delai'), 60000);
  // Tout ce que la marche d'i18n peut traduire : les nœuds TEXTE et les quatre attributs
  // AFFICHÉS que `i18n_observer.js` surveille. Rien d'autre n'est un libellé.
  const ATTRS = ['title', 'placeholder', 'aria-label', 'label'];
  const peints = (d) => {
    const vus = new Set();
    const w = d.createTreeWalker(d.documentElement, NodeFilter.SHOW_TEXT);
    for (let n = w.nextNode(); n; n = w.nextNode()) {
      const t = (n.nodeValue || '').trim(); if (t) vus.add(t);
    }
    for (const el of d.querySelectorAll('[title],[placeholder],[aria-label],[label]'))
      for (const a of ATTRS) {
        const v = el.getAttribute(a); if (v && v.trim()) vus.add(v.trim());
      }
    return vus;
  };
  const charger = () => new Promise((res, rej) => {
    const f = document.createElement('iframe');
    f.width = '1600'; f.height = '1200';
    f.onload = () => setTimeout(() => res(f), ATTENTE);
    f.onerror = () => rej(new Error('cadre'));
    f.src = '/index.html';
    document.body.appendChild(f);
  });
  try {
    for (const c of CELLULES) {
      try {
        if (c.valeur === null) localStorage.removeItem('soc_lang');
        else localStorage.setItem('soc_lang', c.valeur);
      } catch (e) { ecrire('stockage-refuse'); return; }
      const f = await charger();
      const d = f.contentDocument;
      if (!d) { ecrire('cadre-illisible:' + c.nom); return; }
      // Le masque : un chiffre par paire. bit 1 = la face FRANÇAISE est peinte,
      // bit 2 = la face ANGLAISE l'est. Deux bits par paire suffisent au jugement, et
      // renvoyer les milliers de chaînes peintes coûterait cent fois plus.
      const vus = peints(d);
      let masque = '';
      for (const p of PAIRES) masque += String((vus.has(p[0]) ? 1 : 0) + (vus.has(p[1]) ? 2 : 0));
      resultat[c.nom] = {
        declaree: d.documentElement.getAttribute('lang'),
        pret: d.documentElement.classList.contains('app-ready'),
        masque: masque
      };
      f.remove();
    }
    ecrire(null);
  } catch (e) { ecrire('exception:' + (e && e.message)); }
})();
</script>
</body></html>""".replace("__CELLULES__", json.dumps(
        [{"nom": n, "valeur": v} for (n, v, _a) in CELLULES], ensure_ascii=False)) \
        .replace("__PAIRES__", json.dumps(paires, ensure_ascii=False)) \
        .replace("__ID__", json.dumps(ID_VERDICT)) \
        .replace("__ATTENTE__", "1200")


# =====================================================================================
# 4. L'ORIGINE HTTP LOCALE — la page est servie DEPUIS `web/`, donc `/style.css`,
#    `/app.js`, `/fonts/*` et tout chemin absolu résolvent comme en production. Sous
#    `file://` le graphe de modules ne se lierait même pas.
#    C'est AUSSI la couche où les mutations sont servies : substituer un module ici ne
#    touche pas un octet du dépôt.
# =====================================================================================
class Serveur(SimpleHTTPRequestHandler):
    pages = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        chemin = self.path.split("?", 1)[0]
        if chemin in self.pages:
            corps, mime = self.pages[chemin]
            octets = corps.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", mime + "; charset=utf-8")
            self.send_header("Content-Length", str(len(octets)))
            self.end_headers()
            self.wfile.write(octets)
            return
        super().do_GET()


def rendre(moteur: str, coquille: str, substitutions: dict) -> dict:
    """Rend les trois cellules en UN passage et rapporte ce que le moteur a peint.
    Tout ce qui n'est pas un relevé complet est un REFUS, jamais un vert."""
    Serveur.pages = {"/__banc__.html": (coquille, "text/html")}
    for chemin, corps in substitutions.items():
        # `text/javascript` est OBLIGATOIRE : servi sous un autre type, un module ES est
        # REJETÉ par le moteur, la page ne se lierait pas et la mutation ne mordrait
        # jamais — elle passerait pour « non attrapée » et ferait refuser à tort.
        Serveur.pages[chemin] = (corps, "text/javascript")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), partial(Serveur, directory=str(WEB)))
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="banc-p11-21-n-") as profil:
            try:
                r = subprocess.run(
                    [moteur, "--headless", "--no-sandbox", "--disable-gpu",
                     "--disable-dev-shm-usage", "--hide-scrollbars",
                     "--force-device-scale-factor=1", "--window-size=1600,1200",
                     "--virtual-time-budget=60000", f"--user-data-dir={profil}",
                     "--dump-dom", f"http://127.0.0.1:{port}/__banc__.html"],
                    capture_output=True, text=True, timeout=300,
                )
            except FileNotFoundError:
                refuser(f"le moteur `{moteur}` a disparu entre sa découverte et son appel.")
            except subprocess.TimeoutExpired:
                refuser(f"le moteur `{moteur}` n'a pas rendu la page en 300 s : rien n'a "
                        "été mesuré, et un vert ici serait un mensonge.")
    finally:
        httpd.shutdown()
        httpd.server_close()

    dom = r.stdout or ""
    trouve = re.search(rf'<pre id="{ID_VERDICT}">([\s\S]*?)</pre>', dom)
    if not trouve:
        refuser(f"le moteur `{moteur}` n'a rendu AUCUN relevé (code {r.returncode}, "
                f"{len(dom)} octets de DOM) : le nœud `#{ID_VERDICT}` est absent, donc la "
                "page n'a pas exécuté sa mesure. Il n'y a rien à conclure, ni rouge ni "
                "vert.\n--- stderr ---\n" + (r.stderr or "")[-2000:])
    brut = (trouve.group(1).replace("&quot;", '"').replace("&lt;", "<")
            .replace("&gt;", ">").replace("&amp;", "&"))
    try:
        releve = json.loads(brut)
    except json.JSONDecodeError as e:
        refuser(f"le relevé rendu par la page n'est pas lisible ({e}) : {brut[:400]!r}")
        raise AssertionError("inatteignable")
    if releve.get("fatal"):
        refuser(f"la coquille s'est arrêtée sur `{releve['fatal']}` : les cellules n'ont "
                "pas toutes été mesurées.")
    cellules = releve.get("cellules") or {}
    absentes = [n for (n, _v, _a) in CELLULES if n not in cellules]
    if absentes:
        refuser(f"la coquille n'a pas rendu {len(absentes)} cellule(s) sur "
                f"{len(CELLULES)} : {', '.join(absentes)}.")
    for nom, v in cellules.items():
        if not v.get("pret"):
            refuser(f"la cellule `{nom}` n'a jamais atteint `html.app-ready` : le graphe "
                    "de modules ne s'est pas lié, donc la langue n'a jamais été "
                    "appliquée et il n'y a rien à comparer.")
    return cellules


# =====================================================================================
# 5. LE JUGEMENT — SANS SEUIL, ET SANS UN SEUL MOT ÉCRIT ICI
# =====================================================================================
def discriminants(cellules: dict) -> list:
    """Les indices de paires dont les DEUX rendus de référence démontrent qu'elles
    basculent : française seule sous `fr`, anglaise seule sous `en`. Tout le reste est du
    bruit — un nom de table anglais peint en français, un mot dont les deux faces
    coexistent — et il est ÉLIMINÉ, pas noyé sous un seuil."""
    mfr, men = cellules["fr"]["masque"], cellules["en"]["masque"]
    return [i for i in range(len(mfr)) if mfr[i] == "1" and men[i] == "2"]


def langue_peinte(masque: str, indices: list) -> tuple:
    """Rend (langue, voix_fr, voix_en). `None` = indécidable : les deux camps ont des
    voix, ou aucun n'en a. La garde REFUSE alors — elle ne choisit pas la majorité."""
    vfr = sum(1 for i in indices if masque[i] in ("1", "3"))
    ven = sum(1 for i in indices if masque[i] in ("2", "3"))
    if vfr and not ven:
        return "fr", vfr, ven
    if ven and not vfr:
        return "en", vfr, ven
    return None, vfr, ven


def juger(cellules: dict, indices: list) -> dict:
    """Rend {cellule: manquement|None}. Un manquement est une PHRASE, pas un booléen."""
    verdict = {}
    for (nom, valeur, attendue) in CELLULES:
        v = cellules[nom]
        peinte, vfr, ven = langue_peinte(v["masque"], indices)
        declaree = v.get("declaree")
        semis = "aucune clé `soc_lang`" if valeur is None else f"`soc_lang={valeur}`"
        if peinte is None:
            refuser(
                f"cellule `{nom}` ({semis}) : la langue PEINTE est indécidable "
                f"({vfr} voix française(s), {ven} anglaise(s) sur {len(indices)} "
                "discriminants). Une console à moitié traduite ne se déclare ni dans une "
                "langue ni dans l'autre, et conclure ici serait inventer une réponse.")
        if peinte != attendue:
            refuser(
                f"cellule `{nom}` ({semis}) : la console peint `{peinte}` là où ce banc "
                f"attendait `{attendue}`. Ce n'est PAS la propriété jugée ici (la "
                "traduction elle-même est tenue par "
                "`check_i18n_lexicon_covers_displayed_strings.py`) : ce banc ne sait plus "
                "quelle langue il met à l'épreuve, donc il ne conclut pas.")
        if not declaree:
            verdict[nom] = (
                f"la console peint `{peinte}` et NE DÉCLARE RIEN "
                f"(`lang={declaree!r}`) : le lecteur d'écran reste sur le réglage de "
                "l'agent, qui n'a aucune raison d'être celui-ci.")
        elif declaree != peinte:
            verdict[nom] = (
                f"la console peint `{peinte}` et DÉCLARE `{declaree}` "
                f"({len(indices)} discriminants, {vfr} voix française(s), {ven} "
                "anglaise(s)) : une synthèse vocale prononcera les libellés avec la "
                "phonétique de la mauvaise langue.")
        else:
            verdict[nom] = None
    return verdict


# =====================================================================================
# 6. LES MUTATIONS — SERVIES, JAMAIS ÉCRITES DANS L'ARBRE
#    Chacune est un AJOUT en fin de module : aucune ne cherche la ligne du correctif dans
#    la source, donc aucune ne devient muette parce qu'on l'a reformulée. Une mutation
#    ajoutée en fin de `core.js` s'exécute APRÈS le geste ; en fin de `app.js`, APRÈS tout
#    le graphe.
# =====================================================================================
def mutations() -> list:
    core = (WEB / "core.js").read_text(encoding="utf-8")
    app = (WEB / "app.js").read_text(encoding="utf-8")
    R, V = "rouge", "vert"

    def sur_core(js):
        return {"/core.js": core + "\n" + js + "\n"}

    return [
        # LA MUTATION QUI COMPTE POUR LE CHOIX DE FORME : le geste EXISTE, il est au bon
        # endroit, il pose bien un attribut de langue — mais sur une constante. Une garde
        # de texte dérivée de `core.js` la laisserait VERTE.
        ("figer-sur-le-francais", sur_core("document.documentElement.lang = 'fr';"),
         {"absent": V, "fr": V, "en": R},
         "reproduit exactement l'état d'AVANT le correctif : le balisage l'emporte."),
        ("figer-sur-l-anglais", sur_core("document.documentElement.lang = 'en';"),
         {"absent": R, "fr": R, "en": V},
         "le miroir : deux cellules rougissent et la troisième reste verte, donc le "
         "verdict lit bien la VALEUR et pas la présence d'un attribut."),
        # UNE MUTATION SE CALCULE SUR LE SEMIS, JAMAIS SUR L'ATTRIBUT DÉJÀ POSÉ — ET CE
        # N'EST PAS UN DÉTAIL DE STYLE : ATTRAPÉ LE 2026-08-31 PAR LA MUTATION DE L'ARBRE,
        # PAS PAR RELECTURE. Écrite d'abord `lang = (lang === 'en' ? 'fr' : 'en')`, elle
        # LISAIT l'état laissé par le correctif. Correctif retiré, l'attribut valait `fr`
        # (le balisage), l'inversion le portait donc à `en` — ce qui est JUSTE dans la
        # cellule anglaise : la mutation n'y mordait plus, et la garde REFUSAIT (code 2) au
        # lieu d'ACCUSER (code 1) très exactement le défaut pour lequel elle a été écrite.
        # Un verdict qui passe d'« accuse » à « refuse de conclure » est le signal d'alerte.
        # Le semis du stockage, lui, ne dépend pas du correctif : l'inversion mord toujours.
        ("inverser", sur_core(
            "document.documentElement.lang = "
            "((function(){try{return localStorage.getItem('soc_lang');}catch(e){return null;}})()"
            " === 'en' ? 'fr' : 'en');"),
         {"absent": R, "fr": R, "en": R},
         "les trois cellules mentent à la fois."),
        ("effacer-l-attribut", sur_core("document.documentElement.removeAttribute('lang');"),
         {"absent": R, "fr": R, "en": R},
         "ne rien déclarer n'est pas une excuse : c'est un manquement, pas un vert."),
        # LA SECONDE MUTATION QUI DÉCIDE DE LA FORME : `core.js` est INTACT. Le défaut vit
        # dans un AUTRE module, évalué plus tard. Aucune lecture de `core.js` ne peut le
        # voir ; seul l'ÉTAT FINAL du document le montre.
        ("ecraser-plus-tard", {"/app.js": app + "\ndocument.documentElement.lang = 'fr';\n"},
         {"absent": V, "fr": V, "en": R},
         "`core.js` intact, `app.js` repose l'attribut après coup : le cas qu'une garde "
         "de texte ne peut pas exprimer sans relire TOUS les modules."),
    ]


def main() -> int:
    moteur = trouver_le_moteur()
    paires = deriver_le_vocabulaire()
    coquille = batir_la_coquille(paires)

    # --- L'ARBRE INTACT, D'ABORD : il fixe le vocabulaire discriminant. Le VERDICT qu'il
    #     porte n'est imprimé qu'APRÈS la validation de l'instrument.
    intact = rendre(moteur, coquille, {})
    indices = discriminants(intact)
    if len(indices) < PLANCHER_DISCRIMINANTS:
        refuser(
            f"seulement {len(indices)} discriminant(s) de langue sur {len(paires)} paires "
            f"(plancher {PLANCHER_DISCRIMINANTS}). Un discriminant est une paire dont le "
            "rendu français peint la seule face française et le rendu anglais la seule "
            "face anglaise. En dessous de ce plancher, la « langue peinte » ne serait plus "
            "une mesure — et un vert obtenu ainsi ne vaudrait rien.")
    verdict_intact = juger(intact, indices)

    # --- L'INSTRUMENT, VALIDÉ DANS LES DEUX SENS ET AVANT TOUT VERDICT.
    #     Chaque mutation est jugée dans LES TROIS cellules. La moitié VERTE des attentes
    #     est ce qui démontre que la garde n'est pas rouge par construction.
    joues = []
    for (nom, subs, attendu, raison) in mutations():
        obtenu = juger(rendre(moteur, coquille, subs), indices)
        ecarts = []
        for (cell, _v, _a) in CELLULES:
            veut_rouge = attendu[cell] == "rouge"
            a_rougi = obtenu[cell] is not None
            if veut_rouge and not a_rougi:
                ecarts.append(f"`{cell}` devait ROUGIR et est restée VERTE")
            elif not veut_rouge and a_rougi:
                ecarts.append(f"`{cell}` devait rester VERTE et a rougi ({obtenu[cell]})")
        if ecarts:
            refuser(
                f"MUTATION NON ATTRAPÉE COMME ANNONCÉ — `{nom}` ({raison}) : "
                + " ; ".join(ecarts)
                + ". Cette garde est donc AVEUGLE à ce défaut-là. Un instrument qui ne "
                "voit pas la panne qu'il prétend voir ne rend pas vert.")
        joues.append(nom)

    # --- LE VERDICT, ENFIN, SUR L'ARBRE INTACT.
    manquements = [(c, m) for (c, m) in verdict_intact.items() if m]
    if manquements:
        for (cell, motif) in manquements:
            print(f"::error::[P11.21-n] cellule `{cell}` — {motif}", file=sys.stderr)
        print(f"\nROUGE — {len(manquements)} cellule(s) sur {len(CELLULES)} déclarent une "
              "langue qui n'est pas celle qu'elles peignent.\n"
              "Le geste manquant tient en une ligne, à l'endroit où la langue est DÉCIDÉE "
              "(`web/core.js`, à côté de `LANG` et `LOC`) :\n"
              "    document.documentElement.lang = LANG === 'en' ? 'en' : 'fr';\n"
              "Ne pas le corriger dans `web/index.html` : la valeur du balisage est "
              "l'AMORÇAGE (l'aveu `#init-echec` est français quoi qu'il arrive), et y "
              "écrire une autre constante ne ferait que déplacer le mensonge.",
              file=sys.stderr)
        return CODE_VIOLATION

    print(f"[P11.21-n] VERT — {len(CELLULES)} cellules de langue "
          f"({', '.join(n for (n, _v, _a) in CELLULES)}) rendues dans un vrai moteur : "
          "chacune DÉCLARE la langue qu'elle PEINT.")
    print(f"  · vocabulaire DÉRIVÉ de `web/i18n.js` : {len(paires)} paires FR->EN dont "
          f"les deux faces diffèrent, réduites à {len(indices)} discriminants prouvés par "
          "les deux rendus de référence. Aucun mot n'est écrit dans cette garde.")
    print(f"  · instrument validé AVANT le verdict par {len(joues)} mutations SERVIES "
          f"(le dépôt n'est pas touché) : {', '.join(joues)} — chacune jugée dans les "
          "trois cellules, rouges ET verts attendus.")
    print("  · CE QUE CE VERT NE DIT PAS : il ne tient que la RACINE du document (un "
          "fragment de langue autre à l'intérieur n'est pas vu), il ne rend qu'AU "
          "CHARGEMENT (mesuré : la console n'offre aucun changement de langue sans "
          "rechargement — `web/app.js` écrit le stockage puis recharge), et il ne dit "
          "rien de ce qu'une synthèse vocale fait de cet attribut.")
    return CODE_OK


if __name__ == "__main__":
    sys.exit(main())
