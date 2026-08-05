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
//! ~49 s sur 3,9 Gio. Le `db-stats` par défaut — celui qu'un exploitant lance en production pour
//! décider d'un reclaim — reste donc INCHANGÉ et instantané. La ventilation s'obtient par
//! `db-stats --par-objet`, et le message le dit.

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

impl Poste {
    pub(crate) fn libelle(self) -> &'static str {
        match self {
            Poste::Donnees => "données (tables)",
            Poste::Index => "index b-tree",
            Poste::Fts => "FTS5 (shadow)",
            Poste::Autre => "NON CLASSÉ",
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

/// La ventilation complète. Rend `Err` si la COMPTABILITÉ NE FERME PAS — une ventilation qui ne
/// somme pas au fichier n'est pas une mesure, c'est un tableau plausible. Mieux vaut refuser que
/// publier un total faux.
pub(crate) fn ventiler(conn: &Connection, page_size: i64, page_count: i64, freelist: i64) -> Result<String, String> {
    let mut virtuelles: Vec<String> = Vec::new();
    {
        let mut st = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND sql LIKE 'CREATE VIRTUAL TABLE%'")
            .map_err(|e| format!("lecture des tables virtuelles : {e}"))?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| format!("lecture des tables virtuelles : {e}"))?;
        for v in rows.flatten() {
            virtuelles.push(v);
        }
    }

    let mut par_poste: std::collections::HashMap<Poste, (i64, i64)> = std::collections::HashMap::new();
    let mut top: Vec<(String, i64)> = Vec::new();
    let mut pages_vues = 0i64;
    {
        // `dbstat` PARCOURT toutes les pages : c'est le coût annoncé de cette sous-commande.
        let mut st = conn
            .prepare(
                "SELECT d.name, SUM(d.pgsize), COUNT(*), (SELECT m.type FROM sqlite_master m WHERE m.name = d.name) \
                 FROM dbstat d GROUP BY d.name",
            )
            .map_err(|e| format!("dbstat indisponible ({e}) — la vtable DBSTAT n'est pas compilée dans ce binaire"))?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            })
            .map_err(|e| format!("parcours dbstat : {e}"))?;
        for (nom, octets, pages, ty) in rows.flatten() {
            let p = classer(&nom, ty.as_deref(), &virtuelles);
            let e = par_poste.entry(p).or_insert((0, 0));
            e.0 += octets;
            e.1 += pages;
            pages_vues += pages;
            top.push((nom, octets));
        }
    }

    let total = page_size * page_count;
    let libres = page_size * freelist;
    // La page « lock-byte » (offset 1 Gio) n'est JAMAIS allouée : elle n'apparaît ni dans dbstat ni
    // dans la freelist. On l'attend donc, plutôt que de la découvrir comme un trou inexpliqué.
    let lock_byte = if total > 1_073_741_824 { 1 } else { 0 };
    let attendu = pages_vues + freelist + lock_byte;
    if attendu != page_count {
        return Err(format!(
            "COMPTABILITÉ NON FERMÉE : dbstat {pages_vues} + freelist {freelist} + lock-byte {lock_byte} = {attendu} \
             pages, alors que page_count = {page_count}. Écart de {} page(s). La ventilation N'EST PAS publiée : \
             un tableau qui ne somme pas au fichier ferait croire à une mesure.",
            (page_count - attendu).abs()
        ));
    }

    let mib = |b: i64| b as f64 / (1024.0 * 1024.0);
    let pct = |b: i64| if total > 0 { b as f64 * 100.0 / total as f64 } else { 0.0 };
    let mut out = String::new();
    out.push_str("  ventilation (dbstat — parcours COMPLET des pages) :\n");
    for p in [Poste::Donnees, Poste::Index, Poste::Fts, Poste::Autre] {
        let (o, pg) = par_poste.get(&p).copied().unwrap_or((0, 0));
        if o == 0 && p == Poste::Autre {
            continue; // rien de non classé : on ne montre pas une ligne vide qui inquiéterait pour rien
        }
        out.push_str(&format!("    {:<18} {:>9.1} MiB  {:>5.1} %   ({pg} pages)\n", p.libelle(), mib(o), pct(o)));
    }
    out.push_str(&format!("    {:<18} {:>9.1} MiB  {:>5.1} %   ({freelist} pages)\n", "pages libres", mib(libres), pct(libres)));

    top.sort_by(|a, b| b.1.cmp(&a.1));
    out.push_str("  10 plus gros objets :\n");
    for (nom, o) in top.iter().take(10) {
        out.push_str(&format!("    {:<34} {:>9.1} MiB  {:>5.1} %\n", nom, mib(*o), pct(*o)));
    }
    out.push_str(&format!(
        "  comptabilité : {pages_vues} + {freelist} libre(s) + {lock_byte} lock-byte = {page_count} pages ✓\n"
    ));
    Ok(out)
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
}
