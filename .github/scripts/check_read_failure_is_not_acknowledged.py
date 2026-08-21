#!/usr/bin/env python3
"""Une lecture qui ÉCHOUE ne doit rien acquitter — garde de CI (`S36`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`S30` a posé l'invariant des capteurs incrémentaux : PUBLIER d'abord, ACQUITTER ensuite, pour qu'une
coupure produise un rejeu et non une perte. Elle s'appuyait sur une HYPOTHÈSE ÉCRITE, et cette
hypothèse n'était vraie que sur une moitié du domaine :

    « sortir par `plume_exit_nodata` veut dire qu'AUCUNE enveloppe n'a été publiée,
      donc les marqueurs en attente n'acquittent RIEN. »

VRAI quand le marqueur est CALCULÉ À PARTIR DE CE QUI A ÉTÉ LU — un curseur journald tiré de la
dernière ligne obtenue n'existe pas tant que la lecture n'a pas abouti, donc il n'y a rien à écrire.
FAUX quand le marqueur ne doit RIEN à la lecture : un offset pris sur la TAILLE du fichier, un repère
daté, l'instant du passage. Celui-là est en attente AVANT que la lecture n'aboutisse. Si elle échoue,
le capteur n'a effectivement rien à signaler, il sort par la porte propre, et cette sortie ACQUITTE
une tranche que personne n'a jamais publiée. Le passage suivant repart APRÈS elle : les événements ne
reviendront jamais, et rien ne les compte, puisque rien ne compte ce qui manque. C'est mot pour mot
la perte silencieuse que `S30` existait pour empêcher, réintroduite par la porte de sortie.

CE QUI REND LE DÉFAUT INVISIBLE À LA RELECTURE, ET C'EST LE CŒUR
---------------------------------------------------------------
Le mot d'une lecture qui a échoué et le mot d'une source réellement calme sont LE MÊME MOT : la
chaîne vide. `cmd 2>/dev/null || true` efface le seul élément qui les distinguait — le code de
retour. Et un TUBE aggrave la chose au lieu de la révéler : `journalctl … | grep MOTIF` rend le
verdict du `grep`, pour qui « aucune correspondance » vaut 1, c'est-à-dire le cas NORMAL. Le verdict
de la lecture ne survit donc pas au premier filtre placé derrière elle.

LA RÈGLE, ÉCRITE COMME UNE ALTERNATIVE À DEUX PREUVES
----------------------------------------------------
Tout capteur qui MET UN MARQUEUR EN ATTENTE doit rendre l'une des deux preuves suivantes :
  (i)  il NOMME ce qui arrive quand sa lecture échoue — `plume_lecture_echouee` (jeter, avouer,
       sortir) ou `plume_lecture_partielle` (avouer, continuer, sans mettre le marqueur en attente) ;
  (ii) AUCUNE mise en attente n'apparaît avant une sortie propre : le marqueur n'existe que sur le
       chemin qui PUBLIE, donc aucune sortie propre ne peut acquitter quoi que ce soit.
La découverte se fait sur le MOTIF — « ce fichier met-il un marqueur en attente ? » — jamais sur une
liste de capteurs : un capteur écrit demain est couvert par construction, et devra choisir sa preuve.

DEUX JAMBES, PARCE QU'UNE GARDE STATIQUE NE PROUVE QUE LA FORME
--------------------------------------------------------------
1. STATIQUE : la règle ci-dessus, sur la population découverte, avec un PLANCHER de non-dégénérescence
   (sous ce plancher la garde REFUSE DE CONCLURE au lieu de rendre vert en étant aveugle).
2. EXÉCUTÉE : la bibliothèque et de VRAIS capteurs sont lancés, avec la lecture RELAYÉE pour qu'elle
   échoue au moment exact où le marqueur est en attente. Deux témoins vont en SENS INVERSE, et le
   second est indispensable :
     (a) LECTURE EN ÉCHEC — le marqueur ne bouge PAS, l'incapacité est AVOUÉE, et le passage suivant
         REJOUE la tranche ;
     (b) SOURCE LUE, RIEN À SIGNALER — le marqueur avance NORMALEMENT et rien n'est avoué. Sans ce
         témoin-là, un capteur qui n'acquitterait plus JAMAIS rien passerait (a) brillamment tout en
         re-scannant la même tranche indéfiniment : on aurait échangé une perte silencieuse contre
         un rejeu permanent, et le fonctionnement normal aurait disparu. Ce témoin ne se contente
         PAS d'une source inchangée — le marqueur y porterait déjà la bonne valeur du passage
         précédent, et la régression passerait inaperçue : il ajoute une ligne que le capteur LIT
         et n'expédie pas, seul état où la sortie propre DOIT écrire le marqueur.

CE QUE LA JAMBE EXÉCUTÉE PROUVE, ET CE QU'ELLE NE PROUVE PAS
------------------------------------------------------------
Elle prouve que le capteur DISTINGUE les deux situations et que la distinction change ce qui est
écrit sur le disque — c'est le piège central, et il est mesuré, pas supposé. Elle NE PROUVE PAS
qu'AUCUNE lecture d'aucun capteur ne puisse échouer silencieusement ailleurs : la jambe statique
exige qu'un chemin d'échec soit NOMMÉ, elle ne peut pas vérifier qu'il est branché sur CHAQUE lecture.
Cette part-là tient à la relecture, et elle est écrite ici plutôt que sous-entendue.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

LIB = "collectors/lib.sh"
STAGE = re.compile(r"\bstate_stage(?:_append|_file)?\b")
NODATA = re.compile(r"\bplume_exit_nodata\b")
NOMME = re.compile(r"\bplume_lecture_(?:echouee|partielle)\b")

# PLANCHER, pas un compte exact : ajouter un capteur incrémental est une opération de routine.
# Le plancher ferme le seul mode de panne réel de la découverte — un motif cassé qui ne trouve RIEN
# et rapporte un vert joyeux. MESURÉ le 2026-08-21 : 22 capteurs mettent un marqueur en attente.
PLANCHER_POPULATION = 20

erreurs = []


def echec(msg):
    print(f"::error::{msg}")
    sys.exit(1)


def sans_commentaire(ligne):
    """Retire le `#` de commentaire en respectant les quotes (un `#` dans "..." n'en ouvre pas un)."""
    out, quote, i = [], None, 0
    while i < len(ligne):
        c = ligne[i]
        if quote:
            if c == "\\" and quote == '"':
                out.append(c)
                i += 1
                if i < len(ligne):
                    out.append(ligne[i])
            elif c == quote:
                quote = None
            else:
                out.append(c)
        else:
            if c == "#":
                break
            if c in "'\"":
                quote = c
            else:
                out.append(c)
        i += 1
    return "".join(out)


def lignes_de_code(chemin):
    with open(chemin, encoding="utf-8") as f:
        return [sans_commentaire(l) for l in f.read().split("\n")]


def verdict(lignes):
    """(met_en_attente, sort_proprement, nomme_l_echec, mise_en_attente_avant_une_sortie_propre)."""
    stage = [i for i, l in enumerate(lignes) if STAGE.search(l)]
    nodata = [i for i, l in enumerate(lignes) if NODATA.search(l)]
    nomme = any(NOMME.search(l) for l in lignes)
    avant = any(s < n for s in stage for n in nodata)
    return bool(stage), bool(nodata), nomme, avant


def population():
    suivis = subprocess.run(
        ["git", "ls-files", "collectors/*.sh"], capture_output=True, text=True, check=True
    ).stdout.split()
    trouves = []
    for chemin in suivis:
        if chemin == LIB:
            continue
        lignes = lignes_de_code(chemin)
        met, sort, nomme, avant = verdict(lignes)
        if met:
            trouves.append((chemin, sort, nomme, avant))
    return trouves


# =================================================================================================
# VALIDATION DE L'INSTRUMENT — avant de croire un verdict, on lui montre les deux cas
# =================================================================================================
FAUTIF = """#!/bin/sh
. "${PLUME_LIB:-lib.sh}"
size=$(wc -c < "$LOG")
new=$(tail -c "+$((last + 1))" "$LOG" 2>/dev/null || true)
state_stage "$OFF" "$size"
[ -z "$new" ] && plume_exit_nodata
spool_write_then_ack "x-$ts.json" "$events"
"""
CORRIGE_PAR_NOM = FAUTIF.replace(
    '|| true)', ') || plume_lecture_echouee x source_illisible "$LOG"'
)
CORRIGE_PAR_ORDRE = """#!/bin/sh
. "${PLUME_LIB:-lib.sh}"
[ -z "$events" ] && plume_exit_nodata
state_stage "$OFF" "$size"
spool_write_then_ack "x-$ts.json" "$events"
"""


def valider_l_instrument():
    """Un témoin POSITIF et un témoin NÉGATIF : sans les deux, un verdict ne se croit pas."""
    cas = [
        ("capteur fautif", FAUTIF, True),
        ("capteur corrigé en NOMMANT l'échec", CORRIGE_PAR_NOM, False),
        ("capteur corrigé par l'ORDRE de mise en attente", CORRIGE_PAR_ORDRE, False),
    ]
    for nom, texte, doit_rougir in cas:
        lignes = [sans_commentaire(l) for l in texte.split("\n")]
        met, sort, nomme, avant = verdict(lignes)
        if not met:
            echec(f"INSTRUMENT : le motif ne voit plus la mise en attente dans « {nom} »")
        rouge = sort and avant and not nomme
        if rouge != doit_rougir:
            echec(
                f"INSTRUMENT : « {nom} » devrait {'ROUGIR' if doit_rougir else 'PASSER'} et ne le "
                f"fait pas — la règle ne mesure pas ce qu'elle annonce, aucun de ses verts ne vaut."
            )


# =================================================================================================
# JAMBE STATIQUE
# =================================================================================================
def jambe_statique(trouves):
    for chemin, sort, nomme, avant in trouves:
        if sort and avant and not nomme:
            erreurs.append(
                f"{chemin}: met un marqueur EN ATTENTE avant une sortie `plume_exit_nodata`, sans "
                f"jamais NOMMER ce qui arrive quand la lecture échoue.\n"
                f"      Une lecture ratée rend le MÊME mot qu'une source vide — la chaîne vide — "
                f"donc cette sortie propre acquitte une tranche jamais publiée, et elle est perdue "
                f"en silence.\n"
                f"      Deux façons de fermer ça, au choix :\n"
                f"        1. lire le code de retour de la lecture (le SORTIR du tube : un `grep` "
                f"derrière rend 1 quand il ne trouve rien, ce qui est le cas NORMAL) puis\n"
                f"           `|| plume_lecture_echouee <capteur> \"$(plume_cause_lecture <chemin>)\" "
                f'"<détail>"` — ou `plume_lecture_partielle` si le capteur a autre chose à publier ;\n'
                f"        2. ne mettre le marqueur en attente que sur le chemin qui PUBLIE."
            )
    if len(trouves) < PLANCHER_POPULATION:
        erreurs.append(
            f"seulement {len(trouves)} capteurs à marqueur découverts, plancher "
            f"{PLANCHER_POPULATION} : soit le motif est cassé (cette garde ne vérifierait alors "
            f"RIEN), soit des capteurs ont légitimement disparu — dans ce cas baissez le plancher "
            f"depuis votre propre compte."
        )


# =================================================================================================
# JAMBE EXÉCUTÉE
# =================================================================================================
class Bac:
    """Un bac à sable : spool, état, relais d'outils, gabarit — rien de la machine n'y entre."""

    def __init__(self, base, nom):
        self.racine = os.path.join(base, nom)
        self.spool = os.path.join(self.racine, "spool")
        self.etat = os.path.join(self.racine, "state")
        self.binz = os.path.join(self.racine, "bin")
        self.gab = os.path.join(self.racine, "gabarit")
        for d in (self.spool, self.etat, self.binz, self.gab):
            os.makedirs(d)

    def relais_lecture_qui_echoue(self, outil):
        """Remplace <outil> par un relais qui ÉCHOUE sans rien écrire — la lecture ratée, simulée.

        Le relais est VALIDÉ avant d'être cru : sans le drapeau il doit rendre l'outil réel, avec le
        drapeau il doit échouer. Un relais qui ne relaierait pas ferait passer le témoin (a) pour
        vert sans qu'il ait rien mesuré.
        """
        reel = shutil.which(outil)
        if reel is None:
            echec(f"INSTRUMENT : `{outil}` absent — le relais de lecture ne peut pas être validé")
        chemin = os.path.join(self.binz, outil)
        with open(chemin, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/sh\n"
                'if [ -n "${PLUME_RELAIS_LECTURE_KO:-}" ]; then exit 1; fi\n'
                f'exec {reel} "$@"\n'
            )
        os.chmod(chemin, 0o755)
        for drapeau, attendu in (("", 0), ("1", 1)):
            r = subprocess.run(
                ["sh", "-c", f"{outil} -c +1 /dev/null"],
                env=self.env({"PLUME_RELAIS_LECTURE_KO": drapeau}),
                capture_output=True,
                text=True,
            )
            if r.returncode != attendu:
                echec(
                    f"INSTRUMENT : le relais de `{outil}` rend {r.returncode} au lieu de {attendu} "
                    f"(drapeau={drapeau!r}) — le témoin d'échec de lecture ne mesurerait rien."
                )

    def env(self, sup=None):
        e = dict(
            os.environ,
            PATH=self.binz + os.pathsep + os.environ.get("PATH", ""),
            PLUME_SPOOL=self.spool,
            PLUME_STATE=self.etat,
            PLUME_LIB=os.path.abspath(LIB),
        )
        e.update(sup or {})
        return e

    def vider_spool(self):
        for n in os.listdir(self.spool):
            os.remove(os.path.join(self.spool, n))

    def passage(self, capteur, sup=None, lecture_ko=False):
        env = self.env(sup)
        env["PLUME_RELAIS_LECTURE_KO"] = "1" if lecture_ko else ""
        subprocess.run(
            ["sh", os.path.abspath(capteur)], env=env, capture_output=True, text=True
        )
        return sorted(os.listdir(self.spool))

    def aveu_present(self):
        return any(n.startswith("config-availability-") for n in os.listdir(self.spool))

    def marqueur(self, nom):
        chemin = os.path.join(self.etat, nom)
        try:
            with open(chemin, encoding="utf-8") as f:
                return f.read()
        except OSError:
            return None


def ecrire(chemin, texte, mode="w"):
    os.makedirs(os.path.dirname(chemin), exist_ok=True)
    with open(chemin, mode, encoding="utf-8") as f:
        f.write(texte)


FALCO = (
    '{{"time":"2026-08-21T10:0{n}:00.12345678{n}Z","rule":"Regle {n}","priority":"Warning",'
    '"output":"detection numero {n}","output_fields":{{"proc.name":"sh"}}}}\n'
)
SURICATA = (
    '{{"timestamp":"2026-08-21T10:0{n}:00.12345{n}+0000","flow_id":100{n},"event_type":"alert",'
    '"src_ip":"198.51.100.{n}","dest_ip":"203.0.113.1","alert":{{"signature":"IDS regle {n}",'
    '"severity":1,"signature_id":200{n}}}}}\n'
)
KAUDIT = (
    '{{"kind":"Event","stage":"ResponseComplete","verb":"delete","user":{{"username":"u{n}"}},'
    '"objectRef":{{"resource":"secrets","namespace":"ns{n}","name":"s{n}"}},'
    '"responseStatus":{{"code":200}},"sourceIPs":["198.51.100.{n}"]}}\n'
)

# LE « BRUIT » EST CE QUI REND LE TÉMOIN (b) CAPABLE DE MESURER QUELQUE CHOSE : une ligne que le
# capteur LIT et n'expédie pas. Elle place le capteur dans le seul état où la sortie propre DOIT
# écrire le marqueur — la lecture a abouti, et il n'y a rien à publier. Une source simplement
# inchangée ne prouverait rien : le marqueur y porte déjà la bonne valeur du passage précédent, si
# bien qu'une sortie propre qui n'acquitterait PLUS JAMAIS rien passerait le témoin sans être vue.
BRUIT = {
    "falco": '{"time":"2026-08-21T10:09:00.000000000Z","rule":"sans priorite"}\n',
    "suricata": '{"timestamp":"2026-08-21T10:09:00.000000+0000","event_type":"stats"}\n',
    "kube-audit": '{"kind":"Event","stage":"ResponseComplete","auditID":"sans-verbe"}\n',
}

SCENARIOS = [
    # (nom, capteur, nom du fichier de gabarit, gabarit, marqueur, variable d'environnement)
    ("falco", "collectors/falco.sh", "falco.txt", FALCO, "falco.offset", "PLUME_FALCO_LOG"),
    ("suricata", "collectors/suricata.sh", "eve.json", SURICATA, "suricata.offset", "PLUME_SURICATA_EVE"),
    ("kube-audit", "collectors/kube-audit.sh", "audit.log", KAUDIT, "kube-audit.offset", "PLUME_KUBE_AUDIT_LOG"),
]


def temoins(base, nom, capteur, fichier, gabarit, marqueur, variable):
    bac = Bac(base, nom)
    source = os.path.join(bac.gab, fichier)
    sup = {variable: source}
    bac.relais_lecture_qui_echoue("tail")

    # --- passage 1 : la source porte trois enregistrements, tout se passe bien -------------------
    ecrire(source, "".join(gabarit.format(n=i) for i in (1, 2, 3)))
    bac.vider_spool()
    bac.passage(capteur, sup)
    apres_1 = bac.marqueur(marqueur)
    if apres_1 is None or int(apres_1) != os.path.getsize(source):
        erreurs.append(
            f"[{nom}] le marqueur n'a pas été écrit après une collecte NORMALE "
            f"({apres_1!r}) — la mesure suivante ne prouverait rien."
        )
        return
    if bac.aveu_present():
        erreurs.append(f"[{nom}] une collecte normale a produit un aveu d'indisponibilité")

    # --- TÉMOIN (a) : la source grossit, mais la LECTURE ÉCHOUE ---------------------------------
    ecrire(source, gabarit.format(n=4), mode="a")
    taille_2 = os.path.getsize(source)
    bac.vider_spool()
    bac.passage(capteur, sup, lecture_ko=True)
    apres_ko = bac.marqueur(marqueur)
    if apres_ko is not None and int(apres_ko) == taille_2:
        erreurs.append(
            f"[{nom}] TÉMOIN (a) : la lecture a ÉCHOUÉ et le marqueur a tout de même avancé à "
            f"{taille_2} — la tranche non lue est ACQUITTÉE, donc perdue en silence. C'est le "
            f"défaut que `S30` fermait, revenu par la sortie propre."
        )
    if not bac.aveu_present():
        erreurs.append(
            f"[{nom}] TÉMOIN (a) : la lecture a échoué et RIEN ne le dit — pas d'aveu "
            f"d'indisponibilité dans le spool. Un capteur aveugle est indiscernable d'un capteur calme."
        )

    # --- le passage suivant REJOUE la tranche : c'est ce que « ne pas acquitter » veut dire ------
    bac.vider_spool()
    noms = bac.passage(capteur, sup)
    if not any(n.startswith(nom.replace("kube-audit", "kubeaudit")) for n in noms):
        erreurs.append(
            f"[{nom}] TÉMOIN (a) : après l'échec de lecture, le passage suivant n'a RIEN republié "
            f"({noms}) — la tranche n'a pas été rejouée, elle est bel et bien perdue."
        )

    # --- TÉMOIN (b) : la source est LUE et n'a RIEN à signaler -----------------------------------
    # Sans ce témoin, un capteur qui n'acquitterait plus jamais rien passerait (a) brillamment tout
    # en re-scannant la même tranche à l'infini : on aurait échangé une perte silencieuse contre un
    # rejeu permanent, et le fonctionnement NORMAL aurait disparu. Le bruit est une ligne que le
    # capteur lit et n'expédie pas — le seul état où la sortie propre DOIT écrire le marqueur.
    avant_b = bac.marqueur(marqueur)
    ecrire(source, BRUIT[nom], mode="a")
    taille_b = os.path.getsize(source)
    bac.vider_spool()
    bac.passage(capteur, sup)
    apres_b = bac.marqueur(marqueur)
    if apres_b is None or int(apres_b) != taille_b:
        erreurs.append(
            f"[{nom}] TÉMOIN (b) : la source a été LUE, elle n'avait rien à signaler, et le marqueur "
            f"n'a PAS avancé ({avant_b!r} -> {apres_b!r}, attendu {taille_b}) — le capteur relira la "
            f"même tranche indéfiniment. La perte silencieuse aurait été troquée contre un rejeu "
            f"permanent, ce qui n'est pas un progrès."
        )
    if bac.aveu_present():
        erreurs.append(
            f"[{nom}] TÉMOIN (b) : une source lue sans rien à signaler a produit un aveu "
            f"d'indisponibilité — le calme normal serait rapporté comme une panne."
        )


def temoins_bibliotheque(base):
    """La bibliothèque, seule : c'est elle qui porte la distinction, les capteurs ne font que choisir."""
    bac = Bac(base, "bibliotheque")
    script = os.path.join(bac.racine, "sonde.sh")
    ecrire(
        script,
        'set -eu\n. "$PLUME_LIB"\nplume_init\n'
        'state_stage "$STATE/marqueur" 4242\n'
        '_t=$(mktemp "$STATE/.b.XXXXXX"); printf base > "$_t"\n'
        'state_stage_file "$_t" "$STATE/reference"\n'
        'case "$1" in\n'
        '  vide) plume_exit_nodata ;;\n'
        '  echec) plume_lecture_echouee sonde source_illisible "temoin" ;;\n'
        "esac\n",
    )
    for cas, marqueur_attendu, aveu_attendu in (("vide", "4242", False), ("echec", None, True)):
        for n in os.listdir(bac.etat):
            os.remove(os.path.join(bac.etat, n))
        bac.vider_spool()
        subprocess.run(
            ["sh", script, cas], env=bac.env(), capture_output=True, text=True
        )
        vu = bac.marqueur("marqueur")
        if vu != marqueur_attendu:
            erreurs.append(
                f"[bibliothèque/{cas}] marqueur = {vu!r}, attendu {marqueur_attendu!r} — "
                f"`plume_exit_nodata` doit acquitter, `plume_lecture_echouee` ne doit RIEN acquitter."
            )
        if bac.aveu_present() != aveu_attendu:
            erreurs.append(
                f"[bibliothèque/{cas}] aveu d'indisponibilité "
                f"{'absent' if aveu_attendu else 'présent'} — un échec de lecture se DIT, une source "
                f"vide ne se dit pas."
            )
        reste = [n for n in os.listdir(bac.etat) if n.startswith(".b.")]
        if cas == "echec" and reste:
            erreurs.append(
                f"[bibliothèque/echec] le temporaire mis en attente n'a pas été jeté ({reste})"
            )


def jambe_executee():
    with tempfile.TemporaryDirectory() as base:
        temoins_bibliotheque(base)
        for scenario in SCENARIOS:
            temoins(base, *scenario)


def main():
    valider_l_instrument()
    trouves = population()
    jambe_statique(trouves)
    jambe_executee()
    if erreurs:
        for e in erreurs:
            print(f"::error::{e}")
        print(f"\n{len(erreurs)} défaut(s) : une lecture qui échoue acquitte, ou se tait.")
        return 1
    nommants = sum(1 for _, _, nomme, _ in trouves if nomme)
    print(
        f"{len(trouves)} capteurs mettent un marqueur en attente ; {nommants} NOMMENT le chemin "
        f"d'échec de lecture, les autres ne mettent en attente que sur le chemin qui publie."
    )
    print(
        f"{len(SCENARIOS)} capteurs exercés pour de vrai + la bibliothèque : lecture en échec -> "
        f"marqueur figé, aveu émis, tranche rejouée ; source vide -> marqueur écrit, aucun aveu."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
