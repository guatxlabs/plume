//! OÙ PARTENT LES OCTETS DE LA BASE — la ventilation par objet (clé P10.2-a).
//!
//! POURQUOI CE MODULE EXISTE. plume doit tenir sous 2 Gio, et jusqu'ici **il ne savait pas dire ce
//! qui remplit sa propre base**. `db-stats` rendait un TOTAL et une freelist ; toute décision
//! d'optimisation du stockage se prenait donc sur une estimation. Mesuré le 2026-08-05, l'écart
//! entre ce qu'on croyait et ce qui est :
//!   * la référence « base 2 518 Mio / ~9,8 M événements » de la roadmap valait en réalité
//!     **1 239,6 Mio / 1 473 271 événements** ;
//!   * une freelist annoncée à **44,3 %** (profil vieux de 6 jours) valait **0,0 %** ;
//!   * et sur le banc, **32,8 % du fichier sont des INDEX** — le plus gros poste après les données,
//!     alors que personne ne le regardait.
//! Un instrument absent ne rend pas prudent : il rend confiant à tort.
//!
//! CE QUE LE DUMP NE TRANSPORTE PAS, ET POURQUOI C'EST LE SUJET. La sauvegarde `--compress` est un
//! dump LOGIQUE : elle écrit les lignes des tables, le DDL des index, et un marqueur de
//! reconstruction FTS. Elle **exclut par construction** le contenu des index, les tables shadow
//! FTS5 et les pages libres. Comparer sa taille au fichier entier compare donc une PARTIE à un
//! TOUT — c'est ce qui a produit un « ×81 » qui mélangeait trois effets distincts. Cette
//! ventilation existe pour que la comparaison redevienne honnête.
//!
//! LA CLASSIFICATION EST DÉRIVÉE DU SCHÉMA, JAMAIS ÉNUMÉRÉE. On ne liste pas les noms connus
//! (`event_fts_data`, `idx_event_ts`…) : une table ajoutée demain échapperait à la liste et
//! serait comptée dans la mauvaise case, en silence. On dérive :
//!   * `sqlite_master.type = 'index'`            -> INDEX (y compris les `sqlite_autoindex_*`) ;
//!   * table dont le nom préfixe `<vtab>_`, où `<vtab>` est une TABLE VIRTUELLE du schéma -> FTS
//!     (les tables shadow d'une vtable portent son nom en préfixe : `_data`, `_idx`, `_docsize`,
//!     `_config`, `_content`…) ;
//!   * toute autre table                          -> DONNÉES.
//! Un nouveau backend FTS ou un nouvel index sont donc classés correctement sans qu'on y pense.
//!
//! LE COÛT EST RÉEL, DONC LA VENTILATION EST OPT-IN. `dbstat` PARCOURT TOUTES LES PAGES : mesuré
//! ~49 s sur 3,9 Gio au banc (12,6 s/Gio, base NON chiffrée), et **35,4 s sur 1 586,8 Mio en
//! production le 2026-08-09, soit 22,9 s/Gio** — le banc sous-estimait de moitié, parce que la
//! production déchiffre chaque page (SQLCipher) sur un pod limité à 2 cœurs. Le `db-stats` par défaut
//! — celui qu'un exploitant lance en production pour décider d'un reclaim — reste donc INCHANGÉ et
//! instantané (1,3 s mesurées au même moment). La ventilation s'obtient par `db-stats --par-objet`,
//! et le message le dit.
//!
//! UN RELEVÉ NE FAIT PAS UNE SÉRIE. Ce module rend UN POINT, à l'instant où on le lui demande — et
//! trois erreurs coûteuses sont venues de là (une carte de leviers bâtie sur une ventilation de banc,
//! 17 chiffres de roadmap périmés, une hausse du FTS prise pour de la croissance alors que c'était
//! l'aging). `ventilation_serie` prend la MÊME mesure — `mesurer`, pas une seconde implémentation —
//! sur un tick lent, et l'écrit dans `metric` : `metric plume_db_poste_bytes by poste | timechart
//! span=1d avg(value)` répond « la part FTS5 a-t-elle baissé ? » sans relever quoi que ce soit.

use crate::*;

/// Un poste de la ventilation. `Autre` n'est pas un fourre-tout de confort : il capture ce que la
/// dérivation n'a PAS su classer, et il est IMPRIMÉ. Un octet non classé qu'on ne montre pas est un
/// octet qu'on croit avoir compris.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub(crate) enum Poste {
    Donnees,
    Index,
    Fts,
    Autre,
}

/// TOUS les postes, DANS L'ORDRE DE PUBLICATION. Une seule liste : le rendu texte l'itère et la série
/// temporelle la publie. Elle ne peut pas se désynchroniser de l'énumération — `rang()` est un `match`
/// EXHAUSTIF, donc une 5ᵉ variante ne compile pas tant qu'elle n'a pas son rang, et
/// `tous_les_postes_sont_publies` refuse un rang qui ne serait pas couvert par `TOUS`.
pub(crate) const TOUS: [Poste; 4] = [Poste::Donnees, Poste::Index, Poste::Fts, Poste::Autre];

impl Poste {
    pub(crate) fn libelle(self) -> &'static str {
        match self {
            Poste::Donnees => "données (tables)",
            Poste::Index => "index b-tree",
            Poste::Fts => "FTS5 (shadow)",
            Poste::Autre => "NON CLASSÉ",
        }
    }

    /// Rang DENSE dans `TOUS`. C'est le SEUL endroit qui énumère les variantes, et il est exhaustif
    /// (E0004) : ajouter un poste sans lui donner de rang ne compile pas.
    pub(crate) fn rang(self) -> usize {
        match self {
            Poste::Donnees => 0,
            Poste::Index => 1,
            Poste::Fts => 2,
            Poste::Autre => 3,
        }
    }

    /// CLÉ STABLE d'étiquette de série — jamais `libelle()`. Le libellé est un texte d'affichage : il
    /// porte des espaces, des parenthèses, une casse, et il suivrait une traduction. Une série dont
    /// l'étiquette bouge n'est pas la même série : le mois d'historique serait coupé en deux sans que
    /// rien ne rougisse.
    pub(crate) fn cle(self) -> &'static str {
        match self {
            Poste::Donnees => "donnees",
            Poste::Index => "index",
            Poste::Fts => "fts",
            Poste::Autre => "non_classe",
        }
    }
}

/// Classe UN objet à partir du schéma. `virtuelles` est l'ensemble DÉRIVÉ des tables virtuelles.
/// PURE : testable sans base.
pub(crate) fn classer(nom: &str, type_sql: Option<&str>, virtuelles: &[String]) -> Poste {
    match type_sql {
        Some("index") => Poste::Index,
        Some("table") => {
            // Une shadow porte le nom de sa vtable en PRÉFIXE suivi d'un `_`. On exclut la vtable
            // elle-même (elle n'occupe pas de page : son contenu vit dans ses shadows).
            if virtuelles.iter().any(|v| nom != v && nom.starts_with(&format!("{v}_"))) {
                Poste::Fts
            } else {
                Poste::Donnees
            }
        }
        _ => Poste::Autre,
    }
}

/// La CLÉ du 5ᵉ seau publié : les pages libres. Elles ne sont pas un `Poste` (elles ne sortent pas de
/// `classer` : `dbstat` ne les voit pas), mais elles font partie de la somme qui ferme la comptabilité,
/// donc elles font partie de la série. Nommée ici, à côté des autres clés, pour qu'il n'y ait qu'un
/// vocabulaire.
pub(crate) const CLE_LIBRES: &str = "libres";

/// LA VENTILATION MESURÉE — des NOMBRES, pas un tableau. C'est la valeur dont le rapport texte de
/// `db-stats --par-objet` ET la série temporelle sont deux RENDUS : il n'y a qu'un seul calcul, donc
/// les deux ne peuvent pas diverger (le défaut qu'on paie ailleurs quand un chiffre est recopié).
pub(crate) struct Ventilation {
    /// Octets par poste, INDEXÉ PAR `Poste::rang()` — jamais une `HashMap` dont une clé absente se
    /// lirait « zéro octet » alors qu'elle veut dire « ce poste n'existe pas dans cette base ». Ici un
    /// poste sans objet vaut réellement 0 octet, et la comptabilité le prouve.
    pub(crate) octets: [i64; TOUS.len()],
    pages: [i64; TOUS.len()],
    pub(crate) libres_octets: i64,
    pub(crate) total_octets: i64,
    freelist_pages: i64,
    pages_vues: i64,
    lock_byte: i64,
    page_count: i64,
    top: Vec<(String, i64)>,
}

/// POURQUOI LA MESURE N'A PAS PU ÊTRE PRISE. Il n'existe pas de variante « autre » : chaque cause porte
/// un nom, donc chaque cause est PUBLIABLE dans la série (`cause()`) au lieu de se traduire en zéro.
pub(crate) enum Echec {
    /// Le schéma n'a pas pu être lu. Sans la liste des tables virtuelles, les shadows FTS tomberaient
    /// dans « données » : la ventilation serait publiable mais FAUSSE. On refuse.
    LectureSchema(String),
    /// `dbstat` a refusé — vtable absente du binaire, ou parcours interrompu.
    Dbstat(String),
    /// La somme ne tombe pas juste : un tableau qui ne somme pas au fichier ferait croire à une mesure.
    ComptabiliteNonFermee { pages_vues: i64, freelist: i64, lock_byte: i64, page_count: i64 },
}

impl Echec {
    /// La cause, en CLÉ STABLE d'étiquette de série (même contrat que `Poste::cle` : pas de texte
    /// d'affichage dans une étiquette). Cardinalité bornée par l'énumération, aucune donnée variable.
    pub(crate) fn cause(&self) -> &'static str {
        match self {
            Echec::LectureSchema(_) => "lecture_schema",
            Echec::Dbstat(_) => "dbstat_indisponible",
            Echec::ComptabiliteNonFermee { .. } => "comptabilite_non_fermee",
        }
    }

    /// La phrase pour un humain — celle que `db-stats --par-objet` imprimait déjà, au mot près.
    pub(crate) fn phrase(&self) -> String {
        match self {
            Echec::LectureSchema(e) => format!("lecture des tables virtuelles : {e}"),
            Echec::Dbstat(e) => e.clone(),
            Echec::ComptabiliteNonFermee { pages_vues, freelist, lock_byte, page_count } => format!(
                "COMPTABILITÉ NON FERMÉE : dbstat {pages_vues} + freelist {freelist} + lock-byte {lock_byte} = {} \
                 pages, alors que page_count = {page_count}. Écart de {} page(s). La ventilation N'EST PAS publiée : \
                 un tableau qui ne somme pas au fichier ferait croire à une mesure.",
                pages_vues + freelist + lock_byte,
                (page_count - (pages_vues + freelist + lock_byte)).abs()
            ),
        }
    }
}

/// LA MESURE. Rend `Err` si la COMPTABILITÉ NE FERME PAS — une ventilation qui ne somme pas au fichier
/// n'est pas une mesure, c'est un tableau plausible. Mieux vaut refuser que publier un total faux.
///
/// COÛT : `dbstat` PARCOURT TOUTES LES PAGES. MESURÉ le 2026-08-09 sur la production (1 586,8 Mio,
/// SQLCipher, pod limité à 2 cœurs) : **35,4 s, soit 22,9 s/Gio** — et 35,9 s au premier appel contre
/// 35,4 s au second, donc le coût est CPU (déchiffrement des pages), pas disque. Le contournement
/// naturel a été essayé et MESURÉ le même jour sur une base locale de 319,5 Mio (sqlite3 3.53.4, non
/// chiffrée) : retirer la sous-requête corrélée sur `sqlite_master` (1,85 s -> 1,49 s) ou passer au
/// `dbstat(main,1)` agrégé (1,49 s) ne change RIEN — c'est le parcours des pages qui coûte, pas la
/// forme de la requête. Il n'y a donc pas de version « pas chère » de cette mesure : elle se paie sur
/// un tick lent, jamais au moment d'un scrape.
pub(crate) fn mesurer(conn: &Connection, page_size: i64, page_count: i64, freelist: i64) -> Result<Ventilation, Echec> {
    let mut virtuelles: Vec<String> = Vec::new();
    {
        let mut st = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND sql LIKE 'CREATE VIRTUAL TABLE%'")
            .map_err(|e| Echec::LectureSchema(e.to_string()))?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| Echec::LectureSchema(e.to_string()))?;
        for v in rows.flatten() {
            virtuelles.push(v);
        }
    }

    let mut octets = [0i64; TOUS.len()];
    let mut pages = [0i64; TOUS.len()];
    let mut top: Vec<(String, i64)> = Vec::new();
    let mut pages_vues = 0i64;
    {
        // `dbstat` PARCOURT toutes les pages : c'est le coût annoncé de cette sous-commande.
        let mut st = conn
            .prepare(
                "SELECT d.name, SUM(d.pgsize), COUNT(*), (SELECT m.type FROM sqlite_master m WHERE m.name = d.name) \
                 FROM dbstat d GROUP BY d.name",
            )
            .map_err(|e| {
                Echec::Dbstat(format!("dbstat indisponible ({e}) — la vtable DBSTAT n'est pas compilée dans ce binaire"))
            })?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            })
            .map_err(|e| Echec::Dbstat(format!("parcours dbstat : {e}")))?;
        for (nom, o, pg, ty) in rows.flatten() {
            let r = classer(&nom, ty.as_deref(), &virtuelles).rang();
            octets[r] += o;
            pages[r] += pg;
            pages_vues += pg;
            top.push((nom, o));
        }
    }

    let total = page_size * page_count;
    // La page « lock-byte » (offset 1 Gio) n'est JAMAIS allouée : elle n'apparaît ni dans dbstat ni
    // dans la freelist. On l'attend donc, plutôt que de la découvrir comme un trou inexpliqué.
    let lock_byte = if total > 1_073_741_824 { 1 } else { 0 };
    if pages_vues + freelist + lock_byte != page_count {
        return Err(Echec::ComptabiliteNonFermee { pages_vues, freelist, lock_byte, page_count });
    }

    top.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(Ventilation {
        octets,
        pages,
        libres_octets: page_size * freelist,
        total_octets: total,
        freelist_pages: freelist,
        pages_vues,
        lock_byte,
        page_count,
        top,
    })
}

/// Le RAPPORT TEXTE de `db-stats --par-objet`, dérivé de la mesure. Rien n'est recalculé ici.
pub(crate) fn rendre_texte(v: &Ventilation) -> String {
    let mib = |b: i64| b as f64 / (1024.0 * 1024.0);
    let pct = |b: i64| if v.total_octets > 0 { b as f64 * 100.0 / v.total_octets as f64 } else { 0.0 };
    let mut out = String::new();
    out.push_str("  ventilation (dbstat — parcours COMPLET des pages) :\n");
    for p in TOUS {
        let (o, pg) = (v.octets[p.rang()], v.pages[p.rang()]);
        if o == 0 && p == Poste::Autre {
            continue; // rien de non classé : on ne montre pas une ligne vide qui inquiéterait pour rien
        }
        out.push_str(&format!("    {:<18} {:>9.1} MiB  {:>5.1} %   ({pg} pages)\n", p.libelle(), mib(o), pct(o)));
    }
    out.push_str(&format!(
        "    {:<18} {:>9.1} MiB  {:>5.1} %   ({} pages)\n",
        "pages libres",
        mib(v.libres_octets),
        pct(v.libres_octets),
        v.freelist_pages
    ));

    out.push_str("  10 plus gros objets :\n");
    for (nom, o) in v.top.iter().take(10) {
        out.push_str(&format!("    {:<34} {:>9.1} MiB  {:>5.1} %\n", nom, mib(*o), pct(*o)));
    }
    out.push_str(&format!(
        "  comptabilité : {} + {} libre(s) + {} lock-byte = {} pages ✓\n",
        v.pages_vues, v.freelist_pages, v.lock_byte, v.page_count
    ));
    out
}

/// La ventilation complète, RENDUE EN TEXTE — l'usage historique (`db-stats --par-objet`). Sortie
/// inchangée au caractère près : `mesurer` fait le calcul, `rendre_texte` le met en forme.
pub(crate) fn ventiler(conn: &Connection, page_size: i64, page_count: i64, freelist: i64) -> Result<String, String> {
    mesurer(conn, page_size, page_count, freelist).map(|v| rendre_texte(&v)).map_err(|e| e.phrase())
}

#[cfg(test)]
mod ventilation_tests {
    use super::*;

    /// LA CLASSIFICATION EST DÉRIVÉE : une table shadow d'une vtable inconnue aujourd'hui est
    /// classée FTS parce qu'elle PRÉFIXE une table virtuelle, pas parce que son nom figure dans une
    /// liste. C'est la propriété qui empêche un objet ajouté demain d'être compté dans la mauvaise
    /// case en silence.
    ///
    /// MUTATION : remplacer la dérivation par une liste en dur (`nom.ends_with("_data")`) ⇒ la
    /// 4e assertion, qui utilise une vtable au nom inventé, passe au ROUGE.
    #[test]
    fn la_classification_est_derivee_du_schema() {
        let virt = vec!["event_fts".to_string(), "vtable_inventee_demain".to_string()];
        assert!(matches!(classer("idx_event_ts", Some("index"), &virt), Poste::Index));
        assert!(matches!(classer("sqlite_autoindex_event_1", Some("index"), &virt), Poste::Index));
        assert!(matches!(classer("event", Some("table"), &virt), Poste::Donnees));
        assert!(matches!(classer("event_fts_data", Some("table"), &virt), Poste::Fts));
        assert!(
            matches!(classer("vtable_inventee_demain_idx", Some("table"), &virt), Poste::Fts),
            "une shadow d'une vtable INCONNUE doit être classée par DÉRIVATION, pas par liste de noms"
        );
    }

    /// La vtable elle-même n'est pas sa propre shadow : elle n'occupe aucune page, son contenu vit
    /// dans ses shadows. La compter en FTS fausserait le total de zéro, mais la ligne serait fausse.
    #[test]
    fn la_vtable_nest_pas_sa_propre_shadow() {
        let virt = vec!["event_fts".to_string()];
        assert!(matches!(classer("event_fts", Some("table"), &virt), Poste::Donnees));
    }

    /// CE QUI N'EST PAS CLASSÉ EST DIT. Un objet absent de `sqlite_master` (type `None`) tombe dans
    /// `Autre` et sera IMPRIMÉ — on ne le range pas d'office dans « données » pour faire joli.
    #[test]
    fn linconnu_est_montre_pas_masque() {
        let virt: Vec<String> = vec![];
        assert!(matches!(classer("objet_mysterieux", None, &virt), Poste::Autre));
    }

    /// `TOUS` ET `rang()` NE PEUVENT PAS DIVERGER — sinon un poste existerait sans jamais être publié
    /// dans la série, et la somme des séries ne ferait plus le fichier SANS que rien ne rougisse.
    ///
    /// MUTATION : retirer une variante de `TOUS` (par exemple `Poste::Fts`) ⇒ son rang n'est plus
    /// atteint, `couverts` reste `false` à cet indice, et l'assertion nomme le poste manquant.
    #[test]
    fn tous_les_postes_sont_publies() {
        let mut couverts = [false; TOUS.len()];
        for p in TOUS {
            couverts[p.rang()] = true;
        }
        for (i, ok) in couverts.iter().enumerate() {
            assert!(*ok, "le poste de rang {i} n'est pas dans TOUS -> il ne serait JAMAIS publié dans la série");
        }
    }

    /// LES CLÉS D'ÉTIQUETTE SONT DISTINCTES ET STABLES. Deux postes qui partageraient une clé
    /// s'additionneraient en silence dans la série ; une clé qui collisionnerait avec celle des pages
    /// libres ferait la même chose.
    #[test]
    fn les_cles_de_serie_sont_distinctes() {
        let mut cles: Vec<&str> = TOUS.iter().map(|p| p.cle()).collect();
        cles.push(CLE_LIBRES);
        let n = cles.len();
        cles.sort_unstable();
        cles.dedup();
        assert_eq!(cles.len(), n, "deux seaux publiés partagent une clé -> ils s'additionneraient en silence");
        // Une clé d'étiquette n'est PAS un libellé d'affichage : ni espace, ni majuscule, ni accent.
        for c in &cles {
            assert!(
                c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "clé d'étiquette instable : {c:?} (une étiquette qui suit la traduction coupe la série en deux)"
            );
        }
    }
}
