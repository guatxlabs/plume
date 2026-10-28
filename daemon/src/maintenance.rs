//! Réconciliation d'état d'index + tâches de fond (le vrai kill-switch env-driven, idempotent). Détection
//! version SQLite (`sqlite_runtime_version`), pilotage FTS-fields (`reconcile_fts_fields` + DDL vtable/
//! triggers) et index expression (`EXPR_INDEX_FIELDS`/`reconcile_expr_indexes_*`/`reconcile_index_state`),
//! CREATE lourds en tâche de fond post-bind (`ensure_*_index_background`/`analyze_full_background`/
//! `fts_backfill_background`) et `host_self`. Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// =====================================================================================
// RÉCONCILIATION D'ÉTAT D'INDEX (le VRAI kill-switch, env-driven, IDEMPOTENT).
//
// Les migrations v40/v41 ne font QUE bumper schema_version (cf. supra). Tout le pilotage d'état
// (créer/dropper la vtable+triggers FTS et les index expression, UN par entrée d'EXPR_INDEX_FIELDS)
// vit ICI et est appelé À CHAQUE
// boot après migrate(). Conséquence : poser PLUME_FTS_FIELDS=0 (resp. PLUME_EXPRINDEX=0) + redeploy
// APPLIQUE réellement le DROP (pas de fuite, pas de coût ingest résiduel), et =1 re-crée si absent.
// Idempotent : CREATE/DROP ... IF [NOT] EXISTS -> re-jouable sans erreur.
// =====================================================================================

/// Les champs chauds indexés par index expression partiel (7 Phase 2 v41 + 3 v49 + 2 v50 : dir,risk).
/// Source unique de vérité partagée par reconcile_index_state, le background CREATE et la doc (= HOT_FIELDS).
///
/// C'EST UN ALIAS, PAS UNE COPIE — et c'est la propriété qui compte : ajouter un champ à `HOT_FIELDS`
/// (`soql_glue.rs`) SUFFIT à faire naître son `idx_ev_f_{champ}` en tâche de fond au boot suivant, et à
/// le soumettre au même kill-switch `PLUME_EXPRINDEX`. Il n'y a RIEN à synchroniser ici, donc rien qui
/// puisse dériver. Corollaire à ne pas perdre : la liste indexée et la liste que le compilateur GXQL
/// considère comme « chaude » sont LA MÊME — un champ ne peut pas être indexé sans que le compilateur
/// le sache (ce qui casserait l'appariement de l'index), ni l'inverse.
const EXPR_INDEX_FIELDS: &[&str] = HOT_FIELDS;

/// LE PRÉFIXE DE LA FAMILLE — et c'est le SEUL critère qui SURVIT au retrait d'un champ de la liste
/// chaude. Tant qu'un champ est déclaré, son index se nomme depuis la liste ; le jour où il en sort,
/// la liste ne peut plus le nommer, et seul le préfixe désigne encore ce qui reste sur la base.
/// C'est de lui que `drop_orphan_expr_field_indexes` dérive son périmètre.
///
/// CE QUI EMPÊCHE CE PRÉFIXE DE DÉRIVER DE LA DDL QUI CRÉE, alors que rien ici ne relit la source du
/// produit. La garde `P6.8-e` fabrique son orphelin avec le préfixe que le produit CRÉE, et exige
/// qu'il DISPARAISSE : un renommage de la famille qui oublierait cette constante-ci ferait chercher
/// la purge sous un préfixe que plus rien ne porte — un no-op parfaitement silencieux — et fait donc
/// tomber deux témoins de cette garde. La confrontation qui l'accompagne (le préfixe attendu par la
/// garde est bien celui des index créés, ces derniers étant retrouvés par l'EXPRESSION qu'ils
/// portent et jamais par leur nom, faute de quoi elle serait circulaire) ne remplace pas ces deux
/// témoins : elle NOMME la cause au lieu de laisser lire un orphelin qui survit.
const PREFIXE_INDEX_CHAMP_CHAUD: &str = "idx_ev_f_";

/// `P10.20-b` (tranche entretien) — CE QU'UNE TÂCHE D'ENTRETIEN A DIT, RENDU À SON APPELANT.
///
/// AVANT : les gestes de cette passe (DDL du kill-switch, présences au catalogue, `ANALYZE`, jalons, watermark du
/// backfill) lisaient par `.ok()`, `.is_ok()`, `unwrap_or(0)` ou écrivaient en `let _` : une lecture RATÉE valait
/// « absent » ou « zéro » — elle déclenchait un geste lourd (un `ANALYZE` complet, un backfill entier) ou en sautait un
/// (un `DROP` différé sans raison dite), et une écriture REFUSÉE était suivie de la ligne de succès. DÉSORMAIS : absent,
/// non lu et zéro sont trois issues distinctes ; une lecture ratée ne déclenche ni ne saute aucun geste en silence (le
/// geste est différé au démarrage suivant, et la ligne le dit) ; une écriture refusée est dite et comptée, jamais suivie
/// de la ligne de succès.
///
/// Les lignes sont CELLES qui partent sur la sortie d'erreur (même valeur, imprimée par `dire`), de sorte qu'un témoin
/// juge la ligne imprimée et non une reconstruction voisine. Les appelants de fond (`server/travaux_sur_la_base.rs`)
/// n'ont rien à en faire de plus : la ligne est déjà au journal, et la tâche sera rejouée au démarrage suivant.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct CompteRenduDEntretien {
    /// Les lignes parties sur la sortie d'erreur, dans l'ordre.
    pub(crate) lignes: Vec<String>,
    /// Les lectures RATÉES (moteur en erreur, valeur illisible) : chacune a différé le geste qu'elle décidait.
    pub(crate) lectures_non_faites: usize,
    /// Les écritures (DDL, `ANALYZE`, jalon, watermark) que le moteur a refusées ou qui n'ont rien écrit.
    pub(crate) ecritures_refusees: usize,
}

impl CompteRenduDEntretien {
    /// Une ligne au journal, sans compte : un fait établi (succès, absence légitime).
    fn dire(&mut self, ligne: String) {
        eprintln!("{ligne}");
        self.lignes.push(ligne);
    }

    /// Une lecture ratée : comptée, puis dite.
    fn lecture_non_faite(&mut self, ligne: String) {
        self.lectures_non_faites += 1;
        self.dire(ligne);
    }

    /// Une écriture refusée : comptée, puis dite.
    fn ecriture_refusee(&mut self, ligne: String) {
        self.ecritures_refusees += 1;
        self.dire(ligne);
    }

    /// Verse le compte rendu d'une sous-tâche dans celui-ci (lignes dans l'ordre, comptes additionnés).
    fn verser(&mut self, autre: CompteRenduDEntretien) {
        self.lignes.extend(autre.lignes);
        self.lectures_non_faites += autre.lectures_non_faites;
        self.ecritures_refusees += autre.ecritures_refusees;
    }
}

/// `P10.20-b` (tranche entretien) — LA PRÉSENCE D'UN OBJET AU CATALOGUE, EN TROIS ISSUES : `Ok(true)` présent,
/// `Ok(false)` absent, `Err` NON LU. Remplace les `.is_ok()` qui rangeaient une lecture ratée sous « absent » (un
/// `CREATE` tenté ou un `DROP` sauté sans un mot).
fn objet_present_au_catalogue(conn: &Connection, genre: &str, nom: &str) -> rusqlite::Result<bool> {
    use rusqlite::OptionalExtension as _;
    conn.query_row("SELECT 1 FROM sqlite_master WHERE type=?1 AND name=?2", params![genre, nom], |_| Ok(()))
        .optional()
        .map(|vu| vu.is_some())
}

/// La présence d'un INDEX (`type='index'`), en trois issues (`objet_present_au_catalogue`).
fn index_present_au_catalogue(conn: &Connection, nom: &str) -> rusqlite::Result<bool> {
    objet_present_au_catalogue(conn, "index", nom)
}

/// Version d'exécution réelle de la SQLite liée (SQLCipher vendoré). On la lit au lieu
/// de supposer : le crate `libsqlite3-sys` 0.28 vendore SQLite 3.39.4 (< 3.43) -> `contentless_delete=1`
/// (ajouté en 3.43) N'EST PAS disponible. On vérifie donc à l'exécution et on documente le chemin pris.
///
/// `P10.20-b` (tranche entretien) — AVANT : une lecture ratée valait « 0.0.0 » (et un morceau non numérique, 0), et la
/// ligne de succès FTS ON affichait « SQLite 0.0 », une version inventée. DÉSORMAIS une lecture ratée ou une forme
/// inattendue rend `Err` avec la cause, et la ligne dit « version SQLite non lue (<cause>) ». Elle n'est PAS comptée
/// dans `lectures_non_faites` : la version ne décide d'aucun geste, elle n'est qu'une information du journal.
fn sqlite_runtime_version(conn: &Connection) -> Result<(i64, i64, i64), String> {
    let v: String = conn.query_row("SELECT sqlite_version()", [], |r| r.get(0)).map_err(|e| e.to_string())?;
    let mut it = v.split('.').map(|p| p.parse::<i64>().ok());
    match (it.next().flatten(), it.next().flatten(), it.next().flatten(), it.next()) {
        (Some(maj), Some(min), Some(rev), None) => Ok((maj, min, rev)),
        _ => Err(format!("forme inattendue « {v} »")),
    }
}

/// DDL de la vtable FTS5 contentless sur les valeurs aplaties de `fields` (1 colonne `v`). Inchangé
/// (partie VALIDÉE : contentless 1 colonne, tokenizer identités/chemins/IP/emails). `contentless_delete=1`
/// N'EST PAS ajouté car la SQLite liée est 3.39.4 (< 3.43) — cf. sqlite_runtime_version.
pub(crate) const FTS_FIELDS_VTABLE_DDL: &str = "CREATE VIRTUAL TABLE IF NOT EXISTS event_fields_fts USING fts5(\
     v, content='', tokenize=\"unicode61 remove_diacritics 2 tokenchars '_-.:/@'\", prefix='2 3')";

/// Trigger AFTER INSERT : 1 doc FTS par event = group_concat des valeurs scalaires de `fields`.
/// (partie VALIDÉE, inchangée). PAS de trigger AU : `event` est append-only.
const FTS_FIELDS_AI_TRIGGER_DDL: &str = "CREATE TRIGGER IF NOT EXISTS event_ff_ai AFTER INSERT ON event \
     WHEN new.fields IS NOT NULL AND json_valid(new.fields) BEGIN \
       INSERT INTO event_fields_fts(rowid, v) \
       SELECT new.id, group_concat(je.value, ' ') \
         FROM json_each(new.fields) je \
        WHERE je.value IS NOT NULL AND je.type IN ('text','integer','real'); \
     END";

/// Trigger AFTER DELETE qui fait un VRAI delete FTS5 sur table contentless.
/// AVANT : `VALUES('delete', old.id, '')` -> sur une vtable contentless, la commande 'delete' DOIT
/// recevoir les MÊMES tokens que ceux insérés (FTS5 ne stocke pas le contenu, il ne peut décrémenter
/// les postings que si on les lui re-fournit). Passer '' ne décrémentait RIEN -> postings orphelins ->
/// event_fields_fts grossissait indéfiniment à chaque DELETE de retention_run (fuite disque).
/// APRÈS : on RECONSTRUIT le flat depuis old.fields (group_concat IDENTIQUE au trigger AI) et on le
/// passe à 'delete' -> FTS5 décrémente exactement les bons postings -> pas de fuite. Chemin FALLBACK
/// (valide pour toute version FTS5 ; pas besoin de contentless_delete=1, indisponible en 3.39.4).
const FTS_FIELDS_AD_TRIGGER_DDL: &str = "CREATE TRIGGER IF NOT EXISTS event_ff_ad AFTER DELETE ON event \
     WHEN old.fields IS NOT NULL AND json_valid(old.fields) BEGIN \
       INSERT INTO event_fields_fts(event_fields_fts, rowid, v) \
       SELECT 'delete', old.id, group_concat(je.value, ' ') \
         FROM json_each(old.fields) je \
        WHERE je.value IS NOT NULL AND je.type IN ('text','integer','real'); \
     END";

/// Réconcilie l'INFRA FTS-fields (vtable + triggers) avec l'env, à CHAQUE boot.
/// PLUME_FTS_FIELDS=1 -> s'assure que vtable+triggers existent (CREATE IF NOT EXISTS) ;
/// =0 -> DROP triggers PUIS vtable (kill-switch dur : supprime le coût ingest ET la fuite H1).
/// Instantané (DDL pur, aucun scan) -> sûr au boot synchrone. Idempotent.
///
/// `P10.20-b` (tranche entretien) — AVANT : chaque DDL en `let _`, puis la ligne « présents » ou « DROPPÉS (kill-switch
/// appliqué) » quoi qu'il arrive. Un trigger AD non recréé rouvre la fuite disque de `retention_run`, un DROP refusé
/// laisse le coût d'ingestion que le levier prétend retirer : les deux étaient annoncés comme faits. DÉSORMAIS chaque
/// DDL refusé est dit et compté, tous les DDL sont tentés (aucun n'est sauté parce qu'un précédent a échoué), et la
/// ligne de succès n'est imprimée que si AUCUN n'a été refusé ; sinon la ligne dit « INCOMPLET » avec le compte.
fn reconcile_fts_fields(conn: &Connection, conf: &HashMap<String, String>) -> CompteRenduDEntretien {
    let mut cr = CompteRenduDEntretien::default();
    if cfg(conf, "PLUME_FTS_FIELDS", "0") == "1" {
        let version = match sqlite_runtime_version(conn) {
            Ok((maj, min, _)) => format!("SQLite {maj}.{min}"),
            Err(cause) => format!("version SQLite non lue ({cause})"),
        };
        // Le trigger AD a CHANGÉ -> on le RECRÉE inconditionnellement (DROP puis CREATE) pour remplacer
        // l'ancienne forme buggée ('delete',id,'') qui aurait pu être posée par un boot antérieur.
        let gestes: [(&str, &str); 4] = [
            ("CREATE de la vtable event_fields_fts", FTS_FIELDS_VTABLE_DDL),
            ("CREATE du trigger event_ff_ai", FTS_FIELDS_AI_TRIGGER_DDL),
            ("DROP du trigger event_ff_ad", "DROP TRIGGER IF EXISTS event_ff_ad"),
            ("CREATE du trigger event_ff_ad", FTS_FIELDS_AD_TRIGGER_DDL),
        ];
        let mut refus = 0usize;
        for (quoi, ddl) in gestes {
            if let Err(e) = conn.execute(ddl, []) {
                refus += 1;
                cr.ecriture_refusee(format!("[reconcile] FTS-fields ON : {quoi} REFUSÉ ({e}) — retry au prochain boot"));
            }
        }
        if refus > 0 {
            cr.dire(format!(
                "[reconcile] FTS-fields ON INCOMPLET : {refus} DDL refusé(s) sur {} — event_fields_fts et ses triggers ne sont PAS tous en place ; retry au prochain boot",
                gestes.len()
            ));
        } else {
            cr.dire(format!(
                "[reconcile] FTS-fields ON : event_fields_fts + triggers présents ({version} ; delete FTS par reconstruction des tokens — pas de fuite disque)"
            ));
        }
    } else {
        // OFF : kill-switch effectif. DROP triggers d'abord (dépendent de la vtable) puis la vtable.
        let gestes: [(&str, &str); 3] = [
            ("DROP du trigger event_ff_ai", "DROP TRIGGER IF EXISTS event_ff_ai"),
            ("DROP du trigger event_ff_ad", "DROP TRIGGER IF EXISTS event_ff_ad"),
            ("DROP de la vtable event_fields_fts", "DROP TABLE IF EXISTS event_fields_fts"),
        ];
        let mut refus = 0usize;
        for (quoi, ddl) in gestes {
            if let Err(e) = conn.execute(ddl, []) {
                refus += 1;
                cr.ecriture_refusee(format!("[reconcile] FTS-fields OFF : {quoi} REFUSÉ ({e}) — retry au prochain boot"));
            }
        }
        if refus > 0 {
            cr.dire(format!(
                "[reconcile] FTS-fields OFF INCOMPLET (PLUME_FTS_FIELDS!=1) : {refus} DROP refusé(s) sur {} — kill-switch NON appliqué en entier ; retry au prochain boot",
                gestes.len()
            ));
        } else {
            cr.dire("[reconcile] FTS-fields OFF (PLUME_FTS_FIELDS!=1) : vtable + triggers DROPPÉS (kill-switch appliqué)".to_string());
        }
    }
    cr
}

/// LA TABLE QUE CES INDEX COUVRENT. Elle n'était nulle part hors de la DDL qui crée, et c'est ce qui
/// rendait le constat de présence aveugle : un index d'expression est utile parce qu'il est posé sur
/// CETTE table-là et sur CETTE expression-là, pas parce qu'il en porte le nom.
const TABLE_DES_INDEX_DE_CHAMP_CHAUD: &str = "event";

/// LE FRAGMENT DE DÉFINITION QUI IDENTIFIE L'EXPRESSION INDEXÉE — le chemin JSON du champ, tel que la
/// DDL de la passe l'écrit. C'est le geste déjà employé par la confrontation de `P6.8-e`, qui retrouve
/// les index de la famille par l'EXPRESSION qu'ils portent et jamais par leur nom, faute de quoi elle
/// serait circulaire ; il est repris ici plutôt qu'une seconde lecture du catalogue.
fn chemin_json_du_champ(champ: &str) -> String {
    format!("'$.{champ}'")
}

/// CE QUE LE CATALOGUE DIT DU NOM ATTENDU — trois cas EXCLUSIFS, d'où un type et des `match` EXHAUSTIFS
/// (aucun bras `_`) : un quatrième cas ajouté demain ne compile pas tant que sa phrase n'est pas écrite.
enum ConstatAuCatalogue {
    /// Un index de ce nom existe, il est posé sur la BONNE TABLE, et sa définition porte le chemin JSON
    /// du champ. Seul ce cas compte comme présent.
    Fidele,
    /// AUCUN objet de type index ne porte ce nom.
    Absent,
    /// Un objet de type index porte ce nom, mais sa DÉFINITION n'est pas celle attendue. Porte de quoi
    /// le dire à l'exploitant : ce n'est pas « manquant », c'est « occupé par autre chose ».
    MalPose(String),
    /// `P10.20-b` (tranche entretien) — le catalogue n'a PAS PU être lu pour ce nom (cause du moteur portée). Ni
    /// présent ni absent : la passe tente la création (sens sûr, `IF NOT EXISTS`), et le compte rendu le NOMME à part
    /// au lieu de le ranger sous « manquent ».
    NonLu(String),
}

/// LE CONSTAT D'UN CHAMP, LU DANS LA DÉFINITION ET PAS DANS L'ÉTIQUETTE (`P6.8-g`).
///
/// CE QUE LA COMPARAISON REGARDE, ET POURQUOI CES DEUX FAITS-LÀ. La définition qu'un moteur rend est
/// normalisée à sa façon — espaces, casse des mots-clés, guillemets d'identifiants — donc une égalité
/// de texte avec la DDL du produit virerait au ROUGE à la première reformulation, ce qui serait pire
/// que le défaut qu'elle prétend fermer. On compare donc ce qui est STABLE :
///   * `tbl_name`, une COLONNE du catalogue et non du texte : la table sur laquelle l'index est posé ;
///   * la présence du chemin JSON `'$.<champ>'` dans le texte de la définition — un littéral de chaîne,
///     que SQLite conserve tel qu'il a été écrit, et que la reformulation d'un DDL ne touche pas.
/// La recherche est faite EN RUST et non par un `LIKE` : `LIKE` est insensible à la casse sur l'ASCII,
/// or un chemin JSON ne l'est pas — `'$.ACTION'` désigne un autre champ que `'$.action'` et serait
/// accepté à tort.
///
/// CE QU'ELLE NE SAIT PAS DISTINGUER, ÉCRIT ICI PLUTÔT QUE LAISSÉ À DEVINER :
///   * un index posé sur `event` et portant bien `'$.<champ>'` mais d'une AUTRE FORME — composite,
///     non partiel, ou dont le prédicat diffère — est compté PRÉSENT. Il indexe le bon champ de la
///     bonne table ; il peut néanmoins ne pas servir les mêmes plans. C'est la limite assumée d'une
///     comparaison qui refuse de dépendre du texte exact du DDL ;
///   * inversement, un DDL qui écrirait le même chemin AUTREMENT (guillemets doubles, chemin cité
///     `'$."<champ>"'`) serait déclaré mal posé alors qu'il est équivalent. Ce n'est pas un silence :
///     la passe le NOMME, et le nommer est le comportement recherché ;
///   * elle ne dit RIEN de l'état de l'index (à jour, utilisable par le planner) : c'est une lecture
///     de catalogue, pas une vérification de contenu.
///
/// UNE ERREUR DE LECTURE N'EST NI PRÉSENT NI ABSENT (`P10.20-b`, tranche entretien) : elle rend `NonLu`, qui
/// n'entre jamais dans les présents — la passe tentera donc la création, idempotente (`IF NOT EXISTS`), le sens
/// SÛR —, et le compte rendu la nomme sous son propre marqueur. AVANT, elle était rangée sous `Absent` par `.ok()` :
/// le compte rendu accusait « manquent » un index qu'il n'avait pas su lire.
fn constat_au_catalogue(conn: &Connection, champ: &str) -> ConstatAuCatalogue {
    use rusqlite::OptionalExtension as _;
    let nom = format!("{PREFIXE_INDEX_CHAMP_CHAUD}{champ}");
    let lu: rusqlite::Result<Option<(String, Option<String>)>> = conn
        .query_row(
            "SELECT tbl_name, sql FROM sqlite_master WHERE type='index' AND name=?1",
            params![nom],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional();
    let (table, definition) = match lu {
        Ok(None) => return ConstatAuCatalogue::Absent,
        Ok(Some((table, definition))) => (table, definition),
        Err(e) => return ConstatAuCatalogue::NonLu(format!("{nom} ({e})")),
    };
    if table != TABLE_DES_INDEX_DE_CHAMP_CHAUD {
        return ConstatAuCatalogue::MalPose(format!(
            "{nom} est posé sur « {table} » et non sur « {TABLE_DES_INDEX_DE_CHAMP_CHAUD} »"
        ));
    }
    match definition {
        None => ConstatAuCatalogue::MalPose(format!(
            "{nom} n'a aucune définition au catalogue (auto-index d'une contrainte, jamais un index d'expression)"
        )),
        Some(d) if d.contains(&chemin_json_du_champ(champ)) => ConstatAuCatalogue::Fidele,
        Some(_) => ConstatAuCatalogue::MalPose(format!(
            "{nom} est posé sur « {TABLE_DES_INDEX_DE_CHAMP_CHAUD} » mais sa définition ne porte pas {}",
            chemin_json_du_champ(champ)
        )),
    }
}

/// LE CONSTAT AU CATALOGUE, ÉCRIT UNE SEULE FOIS — pour chaque champ DÉCLARÉ, son index d'expression
/// est-il RÉELLEMENT là ? Trois listes, dans l'ordre de la déclaration. Lecture de `sqlite_master`,
/// aucun scan de table.
///
/// POURQUOI CE POINT EST UNIQUE. Le court-circuit de la passe de fond et le compte rendu de sa fin
/// répondent à LA MÊME question ; deux lectures recopiées finiraient par répondre autrement l'une que
/// l'autre. C'est exactement l'écart « déclaré vs constaté » qui a produit le défaut `P6.8-f` : le
/// court-circuit, lui, lisait bien le catalogue, tandis que le compte rendu récitait la déclaration.
///
/// ET POURQUOI IL NE SUFFIT PAS QU'IL LISE LE CATALOGUE (`P6.8-g`). Il l'interrogeait sur le seul NOM.
/// Un objet de type index portant le nom attendu mais posé sur une AUTRE table — ou sur une autre
/// expression — était donc compté présent : le court-circuit sortait sans rien faire et le vrai index
/// n'était JAMAIS créé, sans une ligne ni une alerte. Un homonyme mal posé est désormais NOMMÉ comme
/// tel et n'entre jamais dans les présents.
struct ConstatDesIndex {
    /// Les champs dont l'index est là ET conforme.
    presents: Vec<&'static str>,
    /// Les champs dont AUCUN index ne porte le nom attendu.
    absents: Vec<&'static str>,
    /// Les champs dont le nom attendu est OCCUPÉ par un index qui n'est pas le leur, avec la raison.
    mal_poses: Vec<String>,
    /// `P10.20-b` — les noms dont le catalogue n'a pas pu être lu, avec la cause du moteur.
    non_lus: Vec<String>,
}

impl ConstatDesIndex {
    /// Tous les champs déclarés ont leur index CONFORME. C'est la condition du court-circuit : un
    /// homonyme mal posé ne l'ouvre plus, une présence non lue non plus.
    fn complet(&self) -> bool {
        self.absents.is_empty() && self.mal_poses.is_empty() && self.non_lus.is_empty()
    }
}

fn expr_indexes_constates(conn: &Connection) -> ConstatDesIndex {
    let mut c = ConstatDesIndex { presents: Vec::new(), absents: Vec::new(), mal_poses: Vec::new(), non_lus: Vec::new() };
    for champ in EXPR_INDEX_FIELDS {
        match constat_au_catalogue(conn, champ) {
            ConstatAuCatalogue::Fidele => c.presents.push(*champ),
            ConstatAuCatalogue::Absent => c.absents.push(*champ),
            ConstatAuCatalogue::MalPose(raison) => c.mal_poses.push(raison),
            ConstatAuCatalogue::NonLu(cause) => c.non_lus.push(cause),
        }
    }
    c
}

/// Les index expression partiels (EXPR_INDEX_FIELDS) existent-ils déjà tous, ET conformes ? DÉRIVÉ du
/// constat ci-dessus — pas une seconde lecture du catalogue.
fn expr_indexes_all_present(conn: &Connection) -> bool {
    expr_indexes_constates(conn).complet()
}

/// Le marqueur qui introduit, dans le compte rendu de la passe, la liste des index qui MANQUENT.
/// Écrit une fois : la garde `P6.8-f` lit la liste ANNONCÉE à partir de lui au lieu de deviner la
/// forme de la ligne, et une reformulation qui l'emporterait la rendrait rouge plutôt qu'aveugle.
pub(crate) const MARQUEUR_INDEX_MANQUANTS: &str = "MANQUENT :";

/// Le marqueur qui introduit la liste des noms attendus OCCUPÉS PAR UN INDEX POSÉ SUR AUTRE CHOSE
/// (`P6.8-g`). Écrit une fois, pour la même raison que son voisin : la garde le lit au lieu de deviner
/// la forme de la phrase. Il est DISTINCT de `MARQUEUR_INDEX_MANQUANTS` et n'en contient pas le texte —
/// sans quoi la lecture de l'un attraperait la liste de l'autre.
pub(crate) const MARQUEUR_INDEX_MAL_POSES: &str = "POSÉS SUR AUTRE CHOSE :";

/// `P10.20-b` (tranche entretien) — le marqueur qui introduit la liste des noms dont le catalogue n'a PAS PU être
/// lu. Distinct des deux autres et n'en contient pas le texte ; son accusation précède les deux autres, pour que la
/// liste de `MARQUEUR_INDEX_MANQUANTS` reste la fin de la ligne.
pub(crate) const MARQUEUR_INDEX_NON_LUS: &str = "NON LUS AU CATALOGUE :";

/// LE COMPTE RENDU DE LA PASSE — CONSTATÉ AU CATALOGUE, JAMAIS DÉDUIT DE LA DÉCLARATION (`P6.8-f`).
///
/// CE QU'IL REMPLACE. Cette ligne annonçait `EXPR_INDEX_FIELDS.len()` index « présents » : la
/// longueur de la liste DÉCLARÉE. Un démarrage où trois créations échouaient journalisait donc le
/// compte complet — alors que la passe avait capturé chacune de ces erreurs et les avait écrites
/// juste au-dessus. Le composant SAVAIT son résultat incomplet et le présentait comme complet.
///
/// ET IL NE POUVAIT SE TROMPER QU'AU MOMENT UTILE. Le court-circuit de la passe sort AVANT toute
/// création dès que tous les index sont là : cette ligne ne s'imprime donc QUE lorsque la passe
/// travaille pour de bon, c'est-à-dire exactement quand une création peut échouer. Un verdict qui ne
/// peut rendre qu'un succès ne renseigne sur rien.
///
/// ET IL DIT DÉSORMAIS DEUX MANQUES DIFFÉRENTS (`P6.8-g`). « Aucun index de ce nom » et « ce nom est
/// occupé par un index posé sur autre chose » n'appellent pas le même geste : le premier se répare tout
/// seul au démarrage suivant, le second JAMAIS — la création est idempotente sur le NOM, donc elle
/// n'écrase pas l'occupant et se retire en silence. L'homonyme mal posé est donc nommé à part, avec la
/// raison, et l'accusation des mal posés PRÉCÈDE celle des manquants pour que la liste introduite par
/// `MARQUEUR_INDEX_MANQUANTS` reste la fin de la ligne.
fn compte_rendu_de_la_passe(conn: &Connection) -> String {
    let c = expr_indexes_constates(conn);
    let attendus = EXPR_INDEX_FIELDS.len();
    if c.complet() {
        return format!(
            "[reconcile-bg] {}/{attendus} index expression partiels CONSTATÉS au catalogue ({}) — créés en fond, boot non bloqué",
            c.presents.len(),
            c.presents.join(",")
        );
    }
    let mut accusations = Vec::new();
    if !c.non_lus.is_empty() {
        accusations.push(format!("{MARQUEUR_INDEX_NON_LUS} {}", c.non_lus.join(" ; ")));
    }
    if !c.mal_poses.is_empty() {
        accusations.push(format!("{MARQUEUR_INDEX_MAL_POSES} {}", c.mal_poses.join(" ; ")));
    }
    if !c.absents.is_empty() {
        accusations.push(format!("{MARQUEUR_INDEX_MANQUANTS} {}", c.absents.join(",")));
    }
    format!(
        "[reconcile-bg] {}/{attendus} index expression partiels CONSTATÉS au catalogue — la passe n'a pas abouti pour tous, retry au prochain boot ; {}",
        c.presents.len(),
        accusations.join(" ; ")
    )
}

/// Réconcilie les INDEX EXPRESSION (EXPR_INDEX_FIELDS) avec l'env. Partie INSTANTANÉE seulement :
/// PLUME_EXPRINDEX=0 -> DROP tous (instantané, kill-switch dur). PLUME_EXPRINDEX=1 -> NE crée RIEN ici
/// (un CREATE INDEX sur une table volumineuse bloquerait le bind) ; la création est faite EN FOND par
/// reconcile_expr_indexes_background après le bind. Idempotent.
///
/// `P10.20-b` (tranche entretien) — AVANT : chaque `DROP` en `let _`, puis « {n} index DROPPÉS (kill-switch appliqué) »
/// avec `n` = la longueur de la DÉCLARATION. DÉSORMAIS un `DROP` refusé est dit et compté, les suivants sont tentés, et
/// la ligne de succès n'est imprimée que si aucun n'a été refusé.
fn reconcile_expr_indexes_fast(conn: &Connection, conf: &HashMap<String, String>) -> CompteRenduDEntretien {
    let mut cr = CompteRenduDEntretien::default();
    if cfg(conf, "PLUME_EXPRINDEX", "1") == "1" {
        // ON : on ne crée pas ici (anti-crashloop M1). Le background s'en charge. No-op synchrone.
    } else {
        let mut refus = 0usize;
        for c in EXPR_INDEX_FIELDS {
            if let Err(e) = conn.execute(&format!("DROP INDEX IF EXISTS idx_ev_f_{c}"), []) {
                refus += 1;
                cr.ecriture_refusee(format!("[reconcile] index expression OFF : DROP INDEX idx_ev_f_{c} REFUSÉ ({e}) — retry au prochain boot"));
            }
        }
        if refus > 0 {
            cr.dire(format!(
                "[reconcile] index expression OFF INCOMPLET (PLUME_EXPRINDEX!=1) : {refus} DROP refusé(s) sur {} — kill-switch NON appliqué en entier ; retry au prochain boot",
                EXPR_INDEX_FIELDS.len()
            ));
        } else {
            cr.dire(format!("[reconcile] index expression OFF (PLUME_EXPRINDEX!=1) : {} index DROPPÉS (kill-switch appliqué ; full-scan json_extract)", EXPR_INDEX_FIELDS.len()));
        }
    }
    cr
}

/// Point d'entrée IDEMPOTENT appelé à CHAQUE boot APRÈS migrate(), AVANT le bind.
/// Ne contient QUE des opérations INSTANTANÉES (DDL pur, aucun scan de table) -> ne retarde pas le bind.
/// Le travail LOURD (CREATE INDEX sur l'historique) est délégué à reconcile_expr_indexes_background,
/// lancé en tâche de fond après le bind. C'est le vrai kill-switch : toggle env + redeploy => effet réel.
/// Rend le compte rendu des deux étapes (`P10.20-b`), dans l'ordre : FTS-fields puis index d'expression.
pub(crate) fn reconcile_index_state(conn: &Connection, conf: &HashMap<String, String>) -> CompteRenduDEntretien {
    let mut cr = reconcile_fts_fields(conn, conf);
    cr.verser(reconcile_expr_indexes_fast(conn, conf));
    cr
}

/// CREATE des index expression (EXPR_INDEX_FIELDS) EN TÂCHE DE FOND (jamais au boot synchrone). Modèle
/// analyze_full_background : spawn après le bind, sleep initial laissant passer bind + liveness probe.
/// No-op si PLUME_EXPRINDEX!=1 (le DROP est déjà fait synchrone par reconcile_expr_indexes_fast). Chaque
/// CREATE INDEX partiel est borné (1 seul à la fois, jamais en boucle/churn) ; il tient le lock writer LE
/// TEMPS d'UN index (one-time, partiel WHERE expr IS NOT NULL -> petit), puis le relâche entre chaque ->
/// l'ingest respire. IF NOT EXISTS -> idempotent (no-op si déjà créés au boot précédent).
///
/// REND LA LIGNE ANNONCÉE — celle-là même qui part sur la sortie d'erreur — ou `None` quand la passe
/// n'annonce rien : levier éteint, ou court-circuit parce que tout était déjà au catalogue. Ce retour
/// n'est pas décoratif : il rend le compte rendu EXERÇABLE, de sorte qu'une garde assère LA valeur
/// imprimée et non une reconstruction voisine qui pourrait en diverger (`P6.8-f`).
pub(crate) fn reconcile_expr_indexes_background(db: &Arc<Mutex<Connection>>) -> Option<String> {
    // RÉCONCILIER, C'EST CONVERGER DANS LES DEUX SENS. Avant de créer ce que la déclaration promet,
    // on retire ce que plus personne ne sait nommer — et AVANT de lire le levier, donc dans les deux
    // régimes (la décision est motivée sur `drop_orphan_expr_field_indexes`, `P6.8-e`).
    drop_orphan_expr_field_indexes(&db.lock());
    let conf = load_config();
    if cfg(&conf, "PLUME_EXPRINDEX", "1") != "1" {
        return None; // OFF : rien à créer (le drop est synchrone au boot).
    }
    // Court-circuit : si tout est déjà là, on évite même de prendre le lock writer.
    {
        let conn = db.lock();
        if expr_indexes_all_present(&conn) {
            return None;
        }
    }
    for c in EXPR_INDEX_FIELDS {
        // 1 SEUL CREATE INDEX à la fois, lock writer pris/relâché PAR index (borné, one-time) -> pas de
        // lock O(lignes) non borné tenu sur tout le lot. Partiel (WHERE expr IS NOT NULL) -> index minuscule.
        {
            let conn = db.lock();
            let r = conn.execute(
                &format!(
                    "CREATE INDEX IF NOT EXISTS idx_ev_f_{c} ON event(json_extract(fields,'$.{c}')) \
                     WHERE json_extract(fields,'$.{c}') IS NOT NULL"
                ),
                [],
            );
            if let Err(e) = r {
                eprintln!("[reconcile-bg] CREATE INDEX idx_ev_f_{c} ÉCHEC ({e}) — retry au prochain boot");
                // on continue avec les suivants ; l'idempotence (IF NOT EXISTS) rattrape au boot suivant.
            }
        }
        // respiration entre deux index : laisse l'ingest et les lectures passer (anti-famine writer).
        std::thread::sleep(Duration::from_millis(200));
    }
    // LE COMPTE RENDU EST RELU AU CATALOGUE, jamais récité depuis la déclaration : la passe vient
    // d'avaler ses propres échecs (chacun nommé ci-dessus), c'est donc le seul moment où annoncer un
    // compte complet serait un mensonge (`P6.8-f`).
    let ligne = {
        let conn = db.lock();
        compte_rendu_de_la_passe(&conn)
    };
    eprintln!("{ligne}");
    Some(ligne)
}

/// P6.8-e — DROP des index de champ chaud ORPHELINS : ceux dont le CHAMP a quitté la liste chaude.
/// Rend les noms effectivement retirés (pour que le geste soit exerçable, pas seulement journalisé).
///
/// LE MODE D'ÉCHEC, QUI EST CELUI QU'UN VOISIN A DÉJÀ DÉCRIT. `reconcile_expr_indexes_fast` ne droppe
/// que les noms qu'il DÉRIVE de la liste COURANTE. Retirer un champ de `HOT_FIELDS` retire donc, du
/// même geste, la seule chose qui savait NOMMER son index : celui-ci reste sur toute base déjà
/// déployée, payé en disque ET en écriture d'arbre PAR LIGNE INGÉRÉE, et même l'interrupteur qui
/// éteint la famille entière ne l'atteint pas, puisqu'il énumère lui aussi depuis la liste courante.
/// C'est mot pour mot le mode d'échec que `drop_orphan_auto_field_indexes_background` a été écrit
/// pour fermer sur la famille voisine `idx_ev_auto_*` ; ceci en est le symétrique pour `idx_ev_f_*`.
///
/// LE CRITÈRE EST LE PRÉFIXE, PAS LA LISTE. On n'écrit aucun nom : on DEMANDE au catalogue les index
/// de la famille, et on retire ceux dont le champ — le nom, privé de son préfixe — n'est PLUS
/// déclaré. Un champ retiré demain est donc nettoyé au démarrage suivant sans que personne ait à
/// inscrire son index quelque part. Dériver, ne pas énumérer.
///
/// TOURNE-T-IL QUAND LE LEVIER EST ÉTEINT ? OUI, ET C'EST TRANCHÉ ICI. Un retrait qui n'aurait lieu
/// que sous levier ARMÉ abandonnerait à jamais les orphelins d'une installation qui a ÉTEINT la
/// famille — or c'est précisément celle qui ne veut plus payer un seul de ces index, et son levier
/// éteint ne sait pas davantage les nommer. Le retrait est donc INCONDITIONNEL, et il est appelé
/// AVANT la lecture du levier. Sa prudence ne vient pas d'un drapeau mais de son CRITÈRE, qui ne
/// désigne QUE des objets que plus rien ne réclame :
///   - `type='index'` — un objet homonyme d'un AUTRE type (table, vue) n'est jamais touché ;
///   - le champ ne doit PLUS être déclaré — sous levier armé, aucun index déclaré n'entre donc dans
///     le périmètre (le voir recréé juste après serait le signe d'une purge trop large) ; sous levier
///     éteint, les index déclarés ont déjà été droppés par le réconciliateur synchrone, et il ne
///     reste que ceux que personne d'autre ne sait nommer ;
///   - un nom réduit au seul préfixe est LAISSÉ : le produit n'en crée jamais (il appose toujours un
///     champ non vide), donc il ne vient pas de cette famille ;
///   - le nom passe enfin le prédicat d'identifiant du produit, comme chez le voisin.
///
/// LA CONSÉQUENCE ASSUMÉE, ET ELLE EST NOMMÉE. Un binaire qui REVIENT en arrière (retour à une
/// version dont la liste chaude est plus courte) retirera les index des champs que la version
/// suivante avait ajoutés. C'est réparable par construction, et sans intervention : re-déployer la
/// version récente les recrée en tâche de fond. Le coût d'un aller-retour est donc une re-création
/// d'index, à comparer à un orphelin permanent que plus aucun code ne peut retirer.
///
/// SÛR EN TÂCHE DE FOND, contrairement à un CREATE : `DROP INDEX` rend au freelist les pages du btree
/// sans LIRE ni DÉCHIFFRER `event` (cf. `drop_subsumed_index`). Idempotent — au démarrage suivant il
/// n'y a plus rien à voir — et non fatal : un échec est NOMMÉ et retenté au boot suivant.
pub(crate) fn drop_orphan_expr_field_indexes(conn: &Connection) -> Vec<String> {
    retirer_les_index_de_champ_chaud_orphelins(conn).retires
}

/// `P10.20-b` (tranche entretien) — CE QUE LE RETRAIT DES ORPHELINS A FAIT, ET CE QU'IL A DIT.
pub(crate) struct RetraitDesOrphelins {
    /// Les noms effectivement retirés.
    pub(crate) retires: Vec<String>,
    /// Les lignes dites (retraits, refus, énumération non faite) et leurs comptes. Hors test, seule la sortie
    /// d'erreur les porte : l'appelant de fond (`drop_orphan_expr_field_indexes`) ne rend que les noms retirés.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) compte_rendu: CompteRenduDEntretien,
}

/// `P10.20-b` (tranche entretien) — LES NOMS D'UNE FAMILLE D'INDEX, LUS AU CATALOGUE EN ENTIER OU PAS DU TOUT.
/// AVANT : `rows.flatten()` laissait tomber une ligne en erreur (pas interrompu, ligne illisible) et rendait une
/// liste PLUS COURTE prise pour complète — l'orphelin non lu restait sans un mot. DÉSORMAIS la première erreur
/// (préparation, liaison ou pas) rend `Err`, et l'appelant ne retire RIEN ce démarrage, en le disant.
fn noms_lus_au_catalogue<P: rusqlite::Params>(conn: &Connection, sql: &str, p: P) -> rusqlite::Result<Vec<String>> {
    let mut st = conn.prepare(sql)?;
    let rows = st.query_map(p, |r| r.get::<_, String>(0))?;
    rows.collect()
}

/// Le corps de `drop_orphan_expr_field_indexes`, qui rend aussi ce qu'il a dit (`P10.20-b`).
pub(crate) fn retirer_les_index_de_champ_chaud_orphelins(conn: &Connection) -> RetraitDesOrphelins {
    let mut cr = CompteRenduDEntretien::default();
    // `ESCAPE '\'` n'est pas décoratif : dans un motif LIKE, `_` signifie « un caractère quelconque »
    // — sans échappement le motif attraperait aussi des noms d'AUTRES familles.
    let motif = format!("{}%", PREFIXE_INDEX_CHAMP_CHAUD.replace('_', "\\_"));
    let famille: Vec<String> = match noms_lus_au_catalogue(
        conn,
        "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE ?1 ESCAPE '\\' ORDER BY name",
        params![motif],
    ) {
        Ok(noms) => noms,
        Err(e) => {
            cr.lecture_non_faite(format!(
                "[reconcile-bg] énumération des index de champ chaud ÉCHEC ({e}) — aucun retrait ce boot, retry au prochain boot"
            ));
            return RetraitDesOrphelins { retires: Vec::new(), compte_rendu: cr };
        }
    };
    let mut retires = Vec::new();
    for nom in famille {
        // Le champ est DÉRIVÉ du nom, jamais l'inverse : c'est ce qui rend le geste possible pour un
        // champ que la déclaration ne porte plus.
        let champ = match nom.strip_prefix(PREFIXE_INDEX_CHAMP_CHAUD) {
            Some(c) if !c.is_empty() => c,
            _ => continue, // nom réduit au préfixe : le produit n'en crée pas -> pas à nous de le retirer
        };
        if EXPR_INDEX_FIELDS.contains(&champ) {
            continue; // champ DÉCLARÉ -> ce n'est pas un orphelin, quel que soit l'état du levier
        }
        // Le nom vient de sqlite_master (jamais d'une entrée utilisateur) ; il est EN OUTRE re-validé
        // par le même prédicat d'identifiant que partout ailleurs -> aucune interpolation non contrôlée.
        if !soql_ident_ok(&nom) {
            continue;
        }
        match conn.execute(&format!("DROP INDEX IF EXISTS {nom}"), []) {
            Ok(_) => {
                cr.dire(format!(
                    "[reconcile-bg] {nom} DROPPÉ (index de champ chaud ORPHELIN : « {champ} » n'est \
                     plus dans la liste chaude, plus rien ne savait le nommer — ni le kill-switch, ni \
                     la purge voisine ; P6.8-e)"
                ));
                retires.push(nom);
            }
            Err(e) => cr.ecriture_refusee(format!("[reconcile-bg] DROP INDEX {nom} ÉCHEC ({e}) — retry au prochain boot")),
        }
    }
    RetraitDesOrphelins { retires, compte_rendu: cr }
}

/// Crée l'index MANQUANT idx_event_category EN TÂCHE DE FOND (jamais synchrone au boot :
/// un CREATE INDEX sur 2,39M lignes chiffrées bloquerait le bind -> liveness k8s -> CrashLoopBackOff).
/// Modèle reconcile_expr_indexes_background : court-circuit si déjà présent (pas de lock writer inutile),
/// sinon UN CREATE one-shot sous lock writer borné (one-time). IF NOT EXISTS -> idempotent (no-op au boot
/// suivant). L'index sert le filtre courant `category=auth` (sinon full-scan déchiffré). Le re-ANALYZE
/// (analyze_full_background, ré-armé par le bump v47) fait connaître l'index au planner.
///
/// `P10.20-b` (tranche entretien) — la présence se lit en trois issues : non lue, le `CREATE` n'est PAS tenté ce
/// démarrage et la ligne le dit (avant : `.is_ok()` la rangeait sous « absent ») ; un `CREATE` refusé est compté.
pub(crate) fn ensure_event_category_index_background(db: &Arc<Mutex<Connection>>) -> CompteRenduDEntretien {
    let mut cr = CompteRenduDEntretien::default();
    // court-circuit : déjà là -> on évite même de prendre le lock writer.
    {
        let conn = db.lock();
        match index_present_au_catalogue(&conn, "idx_event_category") {
            Ok(true) => return cr,
            Ok(false) => {}
            Err(e) => {
                cr.lecture_non_faite(phrase_presence_non_lue("idx_event_category", &e));
                return cr;
            }
        }
    }
    let conn = db.lock();
    match conn.execute("CREATE INDEX IF NOT EXISTS idx_event_category ON event(category)", []) {
        Ok(_) => cr.dire("[reconcile-bg] idx_event_category créé en fond (filtre category=... ne full-scanne plus ; boot non bloqué)".to_string()),
        Err(e) => cr.ecriture_refusee(format!("[reconcile-bg] CREATE INDEX idx_event_category ÉCHEC ({e}) — retry au prochain boot")),
    }
    cr
}

/// `P10.20-b` (tranche entretien) — LA PHRASE D'UNE PRÉSENCE D'INDEX NON LUE, écrite une fois pour les tâches qui
/// CRÉENT : le geste n'est ni tenté ni tenu pour inutile, il est différé.
fn phrase_presence_non_lue(nom: &str, e: &rusqlite::Error) -> String {
    format!("[reconcile-bg] présence de {nom} NON LUE au catalogue ({e}) — CREATE non tenté ce boot, retry au prochain boot")
}

/// v110 (ALLÈGEMENT INDEX HOT — P5) — DROP EN TÂCHE DE FOND des deux index REDONDANTS de `event`, sur la base
/// LIVE (une base neuve ne les crée plus : `db/schema.sql` ne les DÉCLARE PLUS). REMPLACE l'ancien
/// `ensure_event_source_index_background` (CHANGE 4 v103) qui CRÉAIT idx_event_src : ce source-seul était un
/// contournement du planner (qui ignorait alors (source, src_ip) pour un `source=X` pur), rendu OBSOLÈTE par
/// idx_event_src_ts(source, ts) de v108 — que le planner CHOISIT pour `source=X` (prouvé EXPLAIN QUERY PLAN).
/// Chaque index retiré est le PRÉFIXE STRICT d'un composite qui le subsume -> le retrait n'introduit AUCUN
/// full-scan (le seek garde la même colonne de tête). DROP INDEX = cheap (libère les pages du btree, NE
/// déchiffre PAS la table grasse) -> SÛR en fond, contrairement à un CREATE INDEX (doctrine anti-crashloop
/// non applicable). Idempotent (court-circuit si déjà droppés) ; gardé par la présence du remplaçant.
///
///   1) idx_event_sev(severity) ⊂ idx_event_sev_srcip(severity, src_ip) [migrate_v31, garanti sur toute base
///      ayant passé v31] -> DROP INCONDITIONNEL (le composite sert tout seek severity).
///   2) idx_event_src(source)   ⊂ idx_event_src_ts(source, ts) [v108] -> DROP UNIQUEMENT si idx_event_src_ts
///      est CONFIRMÉ présent (jamais avant que son remplaçant existe -> ZÉRO fenêtre de scan ; si src_ts pas
///      encore créé par ensure_event_src_ts_index_background, on laisse source-seul et on retentera au boot
///      suivant). idx_event_src_srcip(source, src_ip) reste un filet supplémentaire de toute façon.
pub(crate) fn drop_redundant_event_indexes_background(db: &Arc<Mutex<Connection>>) -> CompteRenduDEntretien {
    let conn = db.lock();
    let mut cr = CompteRenduDEntretien::default();
    // 1) severity-seul : subsumé INCONDITIONNELLEMENT par le composite (severity, src_ip) [v31].
    drop_subsumed_index(&conn, "idx_event_sev", Subsumant::ParConstruction("idx_event_sev_srcip(severity, src_ip) [v31]"), "P5 v110", &mut cr);
    // 2) source-seul : droppé SEULEMENT si le remplaçant (source, ts) existe -> zéro fenêtre de scan.
    drop_subsumed_index(&conn, "idx_event_src", Subsumant::Explicite("idx_event_src_ts"), "P5 v110", &mut cr);
    cr
}

/// CE QUI SUBSUME un index redondant — et, par là, CE QU'IL FAUT VÉRIFIER AVANT DE LE DROPPER. La
/// distinction n'est pas cosmétique : elle décide s'il existe ou non une FENÊTRE pendant laquelle la
/// base n'aurait plus AUCUN index de tête sur la colonne.
enum Subsumant<'a> {
    /// Le subsumant existe PAR CONSTRUCTION, donc rien à confirmer. Deux cas :
    ///  - l'AUTO-INDEX d'une contrainte `UNIQUE(...)` / `PRIMARY KEY(...)` : SQLite le crée AVEC la table
    ///    (`sqlite_autoindex_<table>_N`) et il ne peut pas en être séparé — si la table est là, il est là ;
    ///  - un index explicite posé par une migration ANTÉRIEURE et donc garanti sur toute base ayant passé
    ///    cette version (cas idx_event_sev_srcip / v31).
    /// Le `&str` porté est la DESCRIPTION lisible du subsumant, pour le journal — jamais un nom à chercher.
    ParConstruction(&'a str),
    /// Le subsumant est un index EXPLICITE dont la présence n'est PAS garantie à cet instant (il peut être
    /// créé par une autre tâche de fond, elle-même retentée au boot suivant). Le `&str` est son NOM, et il
    /// est CONFIRMÉ dans `sqlite_master` avant tout DROP — doctrine v110 : « jamais droppé avant que son
    /// remplaçant existe » -> ZÉRO fenêtre de scan sur les gros flux.
    Explicite(&'a str),
}

/// UN retrait d'index redondant, avec sa garde et son journal. Mécanique COMMUNE aux droppers de fond
/// (`drop_redundant_event_indexes_background` v110 et `drop_prefix_subsumed_indexes_background`) : elle est
/// EXTRAITE plutôt que recopiée, pour que la règle « on confirme le subsumant explicite, jamais l'auto-index »
/// n'existe qu'à UN endroit.
///
/// POURQUOI UN DROP EST SÛR EN TÂCHE DE FOND ALORS QU'UN CREATE NE L'EST PAS. `DROP INDEX` ne fait que rendre
/// au freelist les pages du btree de l'index : il NE LIT NI NE DÉCHIFFRE la table (aucune page de `event` /
/// `alert` n'est touchée), donc son coût ne dépend PAS du volume de lignes. `CREATE INDEX`, lui, doit
/// DÉCHIFFRER et trier la totalité de la table SQLCipher : sur des millions de lignes (auditd ~4M) il tient le
/// verrou d'écriture assez longtemps pour retarder le bind -> la liveness probe k8s échoue -> CrashLoopBackOff
/// (leçon idx_event_category / idx_event_src_ts). La doctrine anti-crashloop qui interdit un CREATE synchrone
/// ne s'applique donc PAS à un DROP.
///
/// Idempotent : court-circuit si l'index n'est plus là (aucune prise du writer inutile), `IF EXISTS` sinon.
/// Un échec n'est jamais fatal — il est NOMMÉ et retenté au boot suivant.
///
/// `P10.20-b` (tranche entretien) — les deux présences se lisent en trois issues. AVANT, `.is_ok()` : une lecture
/// ratée du redondant valait « déjà droppé » (retour muet), une lecture ratée du subsumant valait « pas encore
/// présent » (la ligne affirmait une absence qu'elle n'avait pas lue). DÉSORMAIS une présence non lue CONSERVE le
/// redondant ce démarrage (zéro fenêtre de scan tenue) et le dit sous sa propre phrase ; un `DROP` refusé est compté.
fn drop_subsumed_index(conn: &Connection, redondant: &str, subsumant: Subsumant<'_>, origine: &str, cr: &mut CompteRenduDEntretien) {
    match index_present_au_catalogue(conn, redondant) {
        Ok(true) => {}
        Ok(false) => return, // déjà droppé (ou base neuve : plus aucune migration ne le crée) -> rien à faire
        Err(e) => {
            cr.lecture_non_faite(format!(
                "[reconcile-bg] présence de {redondant} NON LUE au catalogue ({e}) — DROP non tenté ce boot, retry au prochain boot"
            ));
            return;
        }
    }
    let quoi = match subsumant {
        Subsumant::ParConstruction(desc) => desc,
        Subsumant::Explicite(nom) => match index_present_au_catalogue(conn, nom) {
            Ok(true) => nom,
            Ok(false) => {
                cr.dire(format!(
                    "[reconcile-bg] {redondant} CONSERVÉ ce boot : son subsumant {nom} n'est pas encore \
                     présent (drop différé -> zéro fenêtre de scan ; retry au prochain boot)"
                ));
                return;
            }
            Err(e) => {
                cr.lecture_non_faite(format!(
                    "[reconcile-bg] {redondant} CONSERVÉ ce boot : la présence de son subsumant {nom} n'a PAS pu être \
                     lue ({e}) (drop différé -> zéro fenêtre de scan ; retry au prochain boot)"
                ));
                return;
            }
        },
    };
    match conn.execute(&format!("DROP INDEX IF EXISTS {redondant}"), []) {
        Ok(_) => cr.dire(format!("[reconcile-bg] {redondant} DROPPÉ (subsumé par {quoi} ; seek préservé sur la colonne de tête ; {origine})")),
        Err(e) => cr.ecriture_refusee(format!("[reconcile-bg] DROP INDEX {redondant} ÉCHEC ({e}) — retry au prochain boot")),
    }
}

/// P10.2-d (ALLÈGEMENT INDEX, SUITE) — DROP EN TÂCHE DE FOND des NEUF index redondants que le schéma migré
/// posait encore, sur la base LIVE qui les porte déjà (une base neuve ne les crée plus : les `CREATE INDEX`
/// ont été RETIRÉS de `migrate.rs` à leur source, cf. les notes « P10.2-d » qui y sont laissées).
///
/// POURQUOI UNE FONCTION VOISINE ET PAS UNE EXTENSION DE `drop_redundant_event_indexes_background`. Ce nom-là
/// dit « event_indexes », et SEPT de ces neuf index ne sont PAS sur `event` (ils sont sur `alert`, `banned_ip`,
/// `case_link`, `dashboard_snapshot`, `data_model_field`, `data_model_object`, `net_ban`, `ueba_baseline_obs`,
/// `event_rollup`). Y verser neuf entrées aurait fabriqué exactement la classe fourre-tout que la règle du
/// dépôt interdit, et rendu FAUX un nom qui est aujourd'hui EXACT pour les deux index de v110. La règle
/// « extraire plutôt qu'allonger » est appliquée à la MÉCANIQUE, pas à la liste : le `has_index` + DROP +
/// journal + garde vit désormais dans `drop_subsumed_index`, et les DEUX droppers l'appellent. Chacun garde
/// un nom qui décrit exactement son périmètre, et la campagne v110 garde son identité (son marqueur, son
/// rollback documenté). ASSUMÉ : deux fonctions, zéro mécanique dupliquée.
///
/// LE CRITÈRE, UNIFORME : chaque index retiré est un PRÉFIXE (au sens SQLite : mêmes colonnes, dans le MÊME
/// ORDRE, en tête) d'un index qui le subsume -> tout seek que le redondant servait, le subsumant le sert avec
/// la MÊME colonne de tête. Le doublon EXACT est le cas dégénéré du préfixe (une liste est un préfixe
/// d'elle-même). AUCUNE requête ne change de RÉSULTAT (un index ne détermine qu'un PLAN) ; prouvé par mutation
/// (2026-08-05) : après DROP, aucun passage en SCAN et le planificateur NOMME l'index subsumant.
///
/// 1) DOUBLONS EXACTS d'une contrainte — l'auto-index existe PAR CONSTRUCTION avec la table -> INCONDITIONNEL :
///      idx_dashboard_snapshot_tok(token)                = UNIQUE(token) de dashboard_snapshot [v90]
///      idx_baseline_obs(baseline_id, entity, bucket)    = PRIMARY KEY(baseline_id, entity, bucket) [v84]
/// 2) PRÉFIXES STRICTS d'un auto-index de contrainte — même garantie de construction -> INCONDITIONNEL :
///      idx_banned_ip_srcip(src_ip)   ⊂ PK(src_ip, source)                          de banned_ip        [v52]
///      idx_case_link_src(src_id)     ⊂ UNIQUE(src_id, dst_id, kind)                de case_link        [v28]
///      idx_dm_field_object(object_id)⊂ UNIQUE(object_id, name)                     de data_model_field [v45]
///      idx_dm_object_model(model_id) ⊂ UNIQUE(model_id, name)                      de data_model_object[v45]
///      idx_event_rollup(bucket)      ⊂ PK(bucket, source, severity, action, src_ip, host, env_id)      [v33/v67]
///      idx_net_ban_ip(ip)            ⊂ PK(ip, env_id)                              de net_ban          [v111]
/// 3) PRÉFIXE STRICT d'un index EXPLICITE — le SEUL cas gardé, car son subsumant peut manquer sur une base
///    donnée (il vient d'une migration, pas d'une contrainte) :
///      idx_alert_mitre(mitre) ⊂ idx_alert_mitre_ts(mitre, ts) [v72] -> DROP UNIQUEMENT si idx_alert_mitre_ts
///      est CONFIRMÉ présent dans sqlite_master. Sinon on CONSERVE mitre-seul ce boot et on retente au suivant :
///      `/api/alerts?mitre=` et `coverage_detections` ne doivent jamais traverser une fenêtre sans index de tête
///      sur `mitre`.
///
/// NE SONT PAS ICI, et c'est délibéré : les index PARTIELS (`idx_event_health_beat` WHERE category='health',
/// `idx_incident_active`, `idx_incident_notmerged`). Un index partiel n'est JAMAIS subsumé par un index plein
/// de mêmes colonnes de tête — il est plus petit et sert un prédicat que l'autre ne porte pas. La garde dérivée
/// (`tests/index_redondance.rs`) les EXCLUT par la colonne `partial` de `PRAGMA index_list`, pour la même raison.
pub(crate) fn drop_prefix_subsumed_indexes_background(db: &Arc<Mutex<Connection>>) -> CompteRenduDEntretien {
    let conn = db.lock();
    let mut cr = CompteRenduDEntretien::default();
    for (redondant, contrainte) in [
        ("idx_dashboard_snapshot_tok", "l'auto-index de UNIQUE(token) de dashboard_snapshot"),
        ("idx_baseline_obs", "l'auto-index de PRIMARY KEY(baseline_id, entity, bucket) de ueba_baseline_obs"),
        ("idx_banned_ip_srcip", "l'auto-index de PRIMARY KEY(src_ip, source) de banned_ip"),
        ("idx_case_link_src", "l'auto-index de UNIQUE(src_id, dst_id, kind) de case_link"),
        ("idx_dm_field_object", "l'auto-index de UNIQUE(object_id, name) de data_model_field"),
        ("idx_dm_object_model", "l'auto-index de UNIQUE(model_id, name) de data_model_object"),
        ("idx_event_rollup", "l'auto-index de PRIMARY KEY(bucket, source, severity, action, src_ip, host, env_id) de event_rollup"),
        ("idx_net_ban_ip", "l'auto-index de PRIMARY KEY(ip, env_id) de net_ban"),
    ] {
        drop_subsumed_index(&conn, redondant, Subsumant::ParConstruction(contrainte), "P10.2-d", &mut cr);
    }
    // Le SEUL dont le subsumant est un index EXPLICITE (v72) et non un auto-index -> garde obligatoire.
    drop_subsumed_index(&conn, "idx_alert_mitre", Subsumant::Explicite("idx_alert_mitre_ts"), "P10.2-d", &mut cr);
    cr
}

/// P6.8-b — DROP EN TÂCHE DE FOND des index `idx_ev_auto_*` ORPHELINS laissés par le mécanisme
/// d'auto-index adaptatif RETIRÉ.
///
/// POURQUOI CETTE FONCTION EXISTE. Le mécanisme (registre `autoindex` de v42, mainteneur de fond, tampon
/// de chaleur, promotion d'un `idx_ev_auto_<champ>`) était INERTE — il n'a JAMAIS promu un seul index, sa
/// chaîne de collecte étant coupée par une frontière de crate, et le compilateur le disait. Il a été
/// supprimé. Mais SON MAINTENEUR ÉTAIT LE SEUL CODE QUI SAVAIT DROPPER CES INDEX : le réconciliateur
/// d'index ne connaît que la famille `idx_ev_f_*` (`EXPR_INDEX_FIELDS`), et les deux droppers voisins ne
/// connaissent que des noms figés. Sans cette fonction, un `idx_ev_auto_*` présent sur une base live
/// deviendrait un ORPHELIN PERMANENT : il continuerait à coûter du disque ET un insert btree PAR LIGNE
/// INGÉRÉE, et plus personne ne pourrait le retirer. Retirer le mainteneur sans le remplacer ici
/// laisserait la base dans un état PIRE qu'avant le retrait.
///
/// POURQUOI EN TÂCHE DE FOND ET PAS EN MIGRATION — c'est le point qui a été tranché, et il ne l'a pas été
/// pour des raisons d'élégance. Une migration exige de bumper `CODE_SCHEMA_MAX` ; or `schema_downgrade_guard`
/// REFUSE d'ouvrir une base dont la version dépasse celle du binaire (`db_open.rs` ->
/// `PlusRecenteQueCeBinaire`), et la migration tourne AVANT le bind. La séquence « nouveau build -> base
/// estampillée v115 -> la porte de déploiement échoue pour une raison quelconque -> rollback automatique
/// vers l'image précédente (max=114) -> ce binaire REFUSE la base » met la production à terre ET tue le
/// chemin de secours. On ne brûle pas le rollback pour de l'hygiène d'index. Le motif ÉTABLI du dépôt est
/// exactement celui-ci : v110 et P10.2-d droppent des index en fond, APRÈS le bind, sans aucun bump.
///
/// LA TABLE `autoindex` N'EST PAS DROPPÉE, ET C'EST DÉLIBÉRÉ. Le contrat de démarrage compare la forme de
/// RÉFÉRENCE (construite en mémoire par CE binaire : `db/schema.sql` + toute la chaîne de migrations, donc
/// `migrate_v42` INCLUSE, qui crée la table) à la base réelle, et il le fait dans UN SEUL SENS : ce qui
/// MANQUE à la base. Dropper la table à l'exécution ferait donc MANQUER à toute base live un objet que la
/// référence déclare -> gap -> refus de démarrer (fail-closed). La retirer proprement suppose de la retirer
/// AUSSI de la référence, donc une migration, donc le bump à sens unique ci-dessus. Une table VIDE de
/// quelques kilo-octets ne justifie pas ça. Elle est donc VESTIGIALE et ASSUMÉE : plus une ligne de code ne
/// la lit ni ne l'écrit, elle pourra partir dans un futur lot où un bump de schéma est de toute façon
/// justifié pour d'autres raisons.
///
/// LA LISTE N'EST PAS ÉCRITE ICI : ELLE EST DEMANDÉE À SQLITE. On ne SAIT PAS quels `idx_ev_auto_*`
/// existent — mesuré sur une base réelle le 2026-08-05, aucun n'apparaît dans les 10 plus gros objets, mais
/// cet instrument a un plancher (la taille du 10e objet, des dizaines de Mio). On ÉNUMÈRE donc depuis
/// `sqlite_master` et on droppe ce qui est
/// LÀ. `ESCAPE '\'` n'est pas décoratif : dans un motif LIKE, `_` signifie « un caractère quelconque » —
/// sans échappement le motif attraperait aussi `idxXevXautoX…`, donc des index d'AUTRES familles.
/// Idempotent (au boot suivant il n'y a plus rien à voir), non fatal, retenté à chaque boot.
///
/// `P10.20-b` (tranche entretien) — l'énumération se lit en entier ou pas du tout (`noms_lus_au_catalogue`) : avant,
/// `rows.flatten()` laissait tomber une ligne en erreur et l'orphelin non lu restait sans un mot.
pub(crate) fn drop_orphan_auto_field_indexes_background(db: &Arc<Mutex<Connection>>) -> CompteRenduDEntretien {
    let conn = db.lock();
    let mut cr = CompteRenduDEntretien::default();
    let orphelins: Vec<String> = match noms_lus_au_catalogue(
        &conn,
        "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx\\_ev\\_auto\\_%' ESCAPE '\\'",
        [],
    ) {
        Ok(noms) => noms,
        Err(e) => {
            cr.lecture_non_faite(format!(
                "[reconcile-bg] énumération des idx_ev_auto_* ÉCHEC ({e}) — aucun retrait ce boot, retry au prochain boot"
            ));
            return cr;
        }
    };
    for nom in &orphelins {
        // Le nom vient de sqlite_master (jamais d'une entrée utilisateur) ; il est EN OUTRE re-validé par
        // le même prédicat d'identifiant que partout ailleurs -> aucune interpolation non contrôlée.
        if !soql_ident_ok(nom) {
            continue;
        }
        match conn.execute(&format!("DROP INDEX IF EXISTS {nom}"), []) {
            Ok(_) => cr.dire(format!(
                "[reconcile-bg] {nom} DROPPÉ (orphelin du mécanisme d'auto-index adaptatif retiré ; plus \
                 aucun code ne le maintenait ni ne pouvait le retirer ; P6.8-b)"
            )),
            Err(e) => cr.ecriture_refusee(format!("[reconcile-bg] DROP INDEX {nom} ÉCHEC ({e}) — retry au prochain boot")),
        }
    }
    cr
}

/// v108 (PERF recherche raw haut-volume) — crée l'index COMPOSITE MANQUANT idx_event_src_ts(source, ts) EN
/// TÂCHE DE FOND sur la base MIGRÉE. La recherche brute `search source=X earliest=-Nd` compile en `... FROM event
/// WHERE source=? AND ts>=?` : idx_event_src (source-seul) SEEK source mais doit LIRE chaque ligne pour ts, et le
/// COUNT de pagination non borné déchiffrait TOUTE la table grasse (message/fields) -> budget 60s dépassé. Le
/// COMPOSITE couvre source+ts -> le COUNT BORNÉ (query.rs) devient un balayage INDEX-ONLY plafonné (zéro
/// déchiffrement de table) et la page range-prune sur ts. `db/schema.sql` le déclare (bases NEUVES l'ont, table
/// vide) mais AUCUNE migration ne peut le créer synchrone : un CREATE INDEX sur des MILLIONS de lignes chiffrées
/// (auditd ~4M) bloquerait le bind -> liveness k8s -> CrashLoopBackOff (cf. idx_event_category/idx_event_src). MÊME
/// nom que schema.sql -> sur base neuve le court-circuit no-op (pas de btree en double), sur la base live on comble
/// le trou. Modèle EXACT de ensure_event_source_index_background : court-circuit si présent, sinon UN CREATE
/// one-shot IF NOT EXISTS (idempotent). Le re-ANALYZE (bump v108) fait connaître l'index au planner. `source` =
/// TEXT faible cardinalité (~35) -> btree petit, disque, RAM négligeable (budget 2 Go). PURE optimisation.
///
/// `P10.20-b` (tranche entretien) — présence en trois issues (non lue : `CREATE` différé et dit), refus compté.
pub(crate) fn ensure_event_src_ts_index_background(db: &Arc<Mutex<Connection>>) -> CompteRenduDEntretien {
    let mut cr = CompteRenduDEntretien::default();
    // court-circuit : déjà là (base neuve via schema.sql, ou déjà créé) -> on évite même de prendre le lock writer.
    {
        let conn = db.lock();
        match index_present_au_catalogue(&conn, "idx_event_src_ts") {
            Ok(true) => return cr,
            Ok(false) => {}
            Err(e) => {
                cr.lecture_non_faite(phrase_presence_non_lue("idx_event_src_ts", &e));
                return cr;
            }
        }
    }
    let conn = db.lock();
    match conn.execute("CREATE INDEX IF NOT EXISTS idx_event_src_ts ON event(source, ts)", []) {
        Ok(_) => cr.dire(format!("[reconcile-bg] idx_event_src_ts(source,ts) créé en fond (recherche raw source=X sur fenêtre longue : COUNT pagination index-only borné + page range-prune ts ; boot non bloqué, v108)")),
        Err(e) => cr.ecriture_refusee(format!("[reconcile-bg] CREATE INDEX idx_event_src_ts ÉCHEC ({e}) — retry au prochain boot")),
    }
    cr
}

/// P3.7-a (PERF INGEST — les sondes dead-man's-switch rendaient l'ingestion quadratique) — crée EN TÂCHE
/// DE FOND l'index PARTIEL `idx_event_health_beat(source, ts) WHERE category='health'` sur la base MIGRÉE.
///
/// CE QU'IL FERME. Les 8 sondes `Sonde::EventBattementSante` de `COLLECTORS` tournent DANS
/// `check_heartbeats`, SOUS LE VERROU D'ÉCRITURE, tous les 20 s. Leur `MAX(ts) WHERE source=? AND
/// category='health'` ne peut pas être servi par idx_event_src_ts(source, ts) : `category` n'y est pas,
/// donc SQLite SEEK la source puis REMONTE sa plage en lisant la LIGNE de chaque candidat jusqu'à trouver
/// un battement. MESURÉ le 2026-08-03 (compteur VM_STEP, déterministe) : `VM steps = 5 x (lignes de la
/// source postérieures au dernier battement) + c`, la PENTE valant EXACTEMENT 5 sur 5 points (`c` = petite
/// constante, 13 à 20 selon l'implémentation SQLite ; le 6e point, 0 ligne, est le cas dégénéré = coût
/// constant). À volume x4 les sondes dont la source n'a jamais battu passent EXACTEMENT x4, confirmé sur
/// DEUX implémentations SQLite indépendantes (CLI 3.53 et le SQLCipher embarqué : 2 014 -> 8 014 sans
/// l'index, 13 constant avec). Une sonde dead-man's-switch devient donc la plus
/// chère précisément quand le collecteur qu'elle surveille est MORT — panne AUTO-AMPLIFIANTE, et ce qu'elle
/// consomme sous le verrou, l'ingestion ne l'a pas.
///
/// POURQUOI PARTIEL et pas (source, category, ts) : MESURÉ sur banc, le composite plein coûte 25,5 o/LIGNE
/// INGÉRÉE, soit quelques dizaines de Mio EXTRAPOLÉS au million et demi de lignes d'une base réelle (volume
/// relevé le 2026-08-05 par `db-stats --par-objet`) + un insert btree sur le CHEMIN D'INGEST CHAUD ; le
/// partiel coûte 21,8 o/LIGNE DE BATTEMENT (~1,5 Mio pour 8 collecteurs battant toutes les 5 min sur 30 j)
/// + un insert toutes les ~37 s. 26x moins de disque — l'écart de disque SUIT LE VOLUME (il valait 166x
/// sous l'hypothèse, réfutée, d'une base six fois plus grosse, et pèse 2,0 % du budget 2 Go au lieu de 12,5 %),
/// tandis que l'écart d'INSERTIONS n'en dépend pas. L'objection d'amplification d'écriture qui avait fait
/// écarter le correctif (cf. handlers/freshness.rs) ne porte que sur le composite plein.
///
/// JAMAIS SYNCHRONE AU BOOT : un CREATE INDEX sur des millions de lignes chiffrées SQLCipher bloquerait le
/// bind -> liveness k8s -> CrashLoopBackOff (leçon idx_event_category / idx_event_src_ts). Modèle EXACT de
/// `ensure_event_src_ts_index_background` : court-circuit si présent (base neuve via schema.sql, ou déjà
/// créé), sinon UN CREATE one-shot IF NOT EXISTS (idempotent, MÊME nom que schema.sql -> aucun btree en
/// double). Le re-ANALYZE (bump v114) fait connaître l'index au planner. La DDL n'est PAS réécrite ici :
/// elle vient de `sondes::DDL_IDX_BATTEMENT_SANTE`, à côté des sondes qui en dépendent (zéro dérive).
/// ADDITIF, mode 0 byte-identique : l'index ne change AUCUNE valeur rendue, seulement le chemin d'accès.
///
/// `P10.20-b` (tranche entretien) — présence en trois issues (non lue : `CREATE` différé et dit), refus compté.
pub(crate) fn ensure_event_health_beat_index_background(db: &Arc<Mutex<Connection>>) -> CompteRenduDEntretien {
    let mut cr = CompteRenduDEntretien::default();
    // court-circuit : déjà là -> on évite même de prendre le lock writer.
    {
        let conn = db.lock();
        match index_present_au_catalogue(&conn, IDX_BATTEMENT_SANTE) {
            Ok(true) => return cr,
            Ok(false) => {}
            Err(e) => {
                cr.lecture_non_faite(phrase_presence_non_lue(IDX_BATTEMENT_SANTE, &e));
                return cr;
            }
        }
    }
    let conn = db.lock();
    match conn.execute(DDL_IDX_BATTEMENT_SANTE, []) {
        Ok(_) => cr.dire(format!(
            "[reconcile-bg] {IDX_BATTEMENT_SANTE}(source,ts) WHERE category='health' créé en fond \
             (les 8 sondes dead-man's-switch cessent de remonter la plage de leur source sous le verrou d'écriture ; P3.7-a)"
        )),
        Err(e) => cr.ecriture_refusee(format!("[reconcile-bg] CREATE INDEX {IDX_BATTEMENT_SANTE} ÉCHEC ({e}) — retry au prochain boot")),
    }
    cr
}

/// ANTI FULL-SCAN (rollup_hosts sur metric/snapshot) — crée EN TÂCHE DE FOND les index ts-leading
/// idx_metric_ts / idx_snapshot_ts. `metric` n'a que idx_metric(name,ts) et `snapshot` idx_snapshot(kind,ts) :
/// ts n'y est PAS colonne de tête, donc le prédicat borné `ts >= recent` de rollup_hosts (chaque tick, sous le
/// lock writer) NE peut PAS range-pruner -> full-scan + déchiffrement SQLCipher de TOUTE la table metric/snapshot
/// -> famine de l'ingest (même lock) + le `MAX(ts)` par-requête de pipeline_is_fresh (integrations/fleet) qui
/// scannait pareil. Avec ces index : les fenêtres du rollup deviennent des range-scans indexés (O(lignes de la
/// fenêtre)) et `MAX(ts)` devient un simple max indexé O(1). JAMAIS synchrone au boot : un CREATE INDEX sur ~2M
/// lignes metric chiffrées bloquerait le bind -> liveness k8s -> CrashLoopBackOff (cf. idx_event_category). One-shot,
/// idempotent (IF NOT EXISTS + court-circuit), 1 index à la fois, lock writer pris/relâché PAR index (l'ingest
/// respire entre deux). PURE optimisation (aucune sémantique changée) — « optimiser, pas augmenter les ressources ».
///
/// `P10.20-b` (tranche entretien) — présence en trois issues PAR INDEX : une présence non lue diffère CET index (dit)
/// et la boucle passe au suivant ; un refus est compté.
pub(crate) fn ensure_host_rollup_scan_indexes_background(db: &Arc<Mutex<Connection>>) -> CompteRenduDEntretien {
    let mut cr = CompteRenduDEntretien::default();
    for (name, ddl) in [
        ("idx_metric_ts",   "CREATE INDEX IF NOT EXISTS idx_metric_ts ON metric(ts)"),
        ("idx_snapshot_ts", "CREATE INDEX IF NOT EXISTS idx_snapshot_ts ON snapshot(ts)"),
    ] {
        // court-circuit : déjà là -> on évite même de prendre le lock writer.
        {
            let conn = db.lock();
            match index_present_au_catalogue(&conn, name) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => {
                    cr.lecture_non_faite(phrase_presence_non_lue(name, &e));
                    continue;
                }
            }
        }
        {
            let conn = db.lock();
            match conn.execute(ddl, []) {
                Ok(_) => cr.dire(format!("[reconcile-bg] {name} créé en fond (rollup_hosts range-prune metric/snapshot au lieu de full-scan ; MAX(ts) freshness = max indexé ; boot non bloqué)")),
                Err(e) => cr.ecriture_refusee(format!("[reconcile-bg] CREATE INDEX {name} ÉCHEC ({e}) — retry au prochain boot")),
            }
        }
        // respiration entre deux index : laisse l'ingest et les lectures passer (anti-famine writer).
        std::thread::sleep(Duration::from_millis(200));
    }
    cr
}

/// Ajoute (idempotent) les panneaux « Sévérité >=3 par src_ip » et « Volume par host » au dashboard
/// « Vue d'ensemble (rapide) » s'ils manquent. Garde par (dashboard_id, titre) -> jamais de
/// doublon, et ne touche pas les dashboards utilisateurs. Réutilisable (migration v37 + filet au boot).
/// GÉNÉRIQUE SUR `SqlExec` (cf. migrate.rs) : `&Connection` depuis le boot (historique inchangé),
/// `&MigTx` depuis la migration v37 -> écritures SOUS le garde de l'étape.
///
/// `P10.28-l` (vague AP) — AVANT : la présence du panneau lue par `.is_ok()` (une lecture RATÉE valait absence : le
/// panneau était écrit EN DOUBLE) puis l'`INSERT` en `let _` (refusé, ou `Ok(0)` d'un `RAISE(IGNORE)` : rien n'était
/// dit). DÉSORMAIS : présence en trois issues (`.optional()`) — présent, absent, non lu ; non lu n'écrit rien et le dit ;
/// l'`INSERT` doit écrire UNE ligne (`une_ligne_ecrite`), sinon le refus est dit. Une ligne de journal par panneau non
/// ajouté ; le démarrage suivant (filet de `server/mod.rs`, `seed_tenant_content`) le retente. Sous `MigTx` (v37), un
/// refus de classe B fait toujours échouer l'étape (le garde le note) ; les autres laissent l'étape validée sans ce
/// panneau, comme avant, mais dits.
pub(crate) fn ensure_rollup_srcip_host_panels<C: SqlExec>(conn: &C) {
    use rusqlite::OptionalExtension as _;
    // `P10.28-l` (vague AR) — LE TABLEAU EN TROIS ISSUES. Avant : `Err(_) => return` confondait « absent » (install
    // pré-semis : `seed_rollup_dashboard` s'en charge, silence légitime) et « lecture ratée » (retour muet : les deux
    // panneaux n'étaient ni vérifiés ni ajoutés, et rien ne le disait). Non lu : rien n'est écrit, une ligne `[seed]`.
    let did: i64 = match conn
        .query_row("SELECT id FROM dashboard WHERE name='Vue d''ensemble (rapide)'", [], |r| r.get(0))
        .optional()
    {
        Ok(Some(d)) => d,
        Ok(None) => return, // dashboard absent (install pré-seed) -> seed_rollup_dashboard s'en chargera
        Err(e) => {
            eprintln!("[seed] panneaux rapides de « Vue d'ensemble (rapide) » NON vérifiés : le tableau n'a pas pu être lu ({e}) — rien n'est écrit, retenté au prochain démarrage");
            return;
        }
    };
    let extra: [(&str, &str, &str); 2] = [
        ("Sévérité >=3 par src_ip", "SELECT src_ip, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ AND severity>=3 AND src_ip<>'' GROUP BY src_ip ORDER BY n DESC LIMIT 20", "bar"),
        ("Volume par host", "SELECT host, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ AND host<>'' GROUP BY host ORDER BY n DESC LIMIT 20", "bar"),
    ];
    for (title, q, viz) in extra {
        let present = conn
            .query_row("SELECT 1 FROM panel WHERE dashboard_id=?1 AND title=?2", params![did, title], |_| Ok(()))
            .optional();
        match present {
            Ok(Some(())) => continue,
            Ok(None) => {}
            Err(e) => {
                eprintln!("[seed] panneau « {title} » de « Vue d'ensemble (rapide) » NON ajouté : sa présence n'a pas pu être lue ({e}) — rien n'est écrit, retenté au prochain démarrage");
                continue;
            }
        }
        let ecrit = conn
            .execute(
                "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) \
                 VALUES(?1,?2,?3,0,?4,(SELECT COALESCE(MAX(position),-1)+1 FROM panel WHERE dashboard_id=?1),2)",
                params![did, title, q, viz],
            )
            .and_then(une_ligne_ecrite);
        if let Err(e) = ecrit {
            eprintln!("[seed] panneau « {title} » de « Vue d'ensemble (rapide) » NON ajouté : son écriture a été refusée ({e}) — retenté au prochain démarrage");
        }
    }
}

/// Seuil de lignes à partir duquel une passe d'analyse prise sur une base plus petite est à REFAIRE
/// (`P7.19-h`) : en dessous, les statistiques ne pèsent rien pour le planificateur ; au-dessus, un
/// compte pris sur une base vide — un ZÉRO écrit pour l'index partiel de la table d'événements par le
/// moteur cible — ne décrit plus la table interrogée.
pub(crate) const SEUIL_DE_LIGNES_DE_REARMEMENT_DE_L_ANALYSE: i64 = 1_000;
/// Facteur de croissance de la table qui réarme la passe : analysée à N lignes, la base l'est de
/// nouveau à 4N. Une poignée de passes sur la vie d'une base (1 k, 4 k, 16 k, … 4 M), jamais une par
/// démarrage — et sous rétention, l'identifiant continue de croître avec l'ingestion, ce qui est le
/// sens voulu : plus de lignes VUES, des statistiques à rafraîchir.
pub(crate) const FACTEUR_DE_CROISSANCE_DE_REARMEMENT_DE_L_ANALYSE: i64 = 4;

/// Le jalon `analyze_full_done` porte la version de schéma ET la taille de la table au moment de la
/// passe : `<version>@<lignes>`. Un jalon ancien (`<version>` seul) se lit comme une taille INCONNUE,
/// valant base vide : la passe se refait dès que la table dépasse le seuil, une fois.
pub(crate) fn jalon_d_analyse_complete(version: &str, lignes: i64) -> String {
    format!("{version}@{lignes}")
}

/// `P10.20-b` (tranche entretien) — LA TAILLE PORTÉE PAR UN JALON, EN TROIS ISSUES. `Mesuree(n)` : `<version>@<n>`,
/// `n` entier positif ou nul. `Absente` : un jalon ancien `<version>` seul, écrit avant que la taille n'y soit portée —
/// taille INCONNUE, tenue pour base vide à dessein (la passe se refait une fois au seuil). `Illisible` : un `@` suivi
/// d'autre chose qu'un entier positif ou nul (`@abc`, `@365.0`, `@`, `@-5`) — ce n'est PAS une base vide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TailleDuJalon {
    Mesuree(i64),
    Absente,
    Illisible,
}

/// Décompose un jalon en (version de schéma, taille analysée). Avant, `lignes.parse().unwrap_or(0)` lisait un jalon
/// `<version>@<illisible>` comme une passe prise sur ZÉRO ligne : la passe due n'était refaite qu'au seuil, sans un mot.
pub(crate) fn lire_le_jalon_d_analyse_complete(jalon: &str) -> (&str, TailleDuJalon) {
    match jalon.split_once('@') {
        Some((version, lignes)) => match lignes.parse::<i64>() {
            Ok(n) if n >= 0 => (version, TailleDuJalon::Mesuree(n)),
            _ => (version, TailleDuJalon::Illisible),
        },
        None => (jalon, TailleDuJalon::Absente),
    }
}

/// La passe est à refaire quand la version de schéma du jalon n'est plus la courante (un bump
/// d'index l'a désynchronisé, à dessein), OU quand la table a franchi le seuil ET grandi du facteur
/// depuis la passe. `None` = jamais analysée. Une base vide qui reste vide ne relance rien.
/// `P10.20-b` — une taille ILLISIBLE ne dit pas sur quelle table la passe a été prise : la passe est refaite, et le jalon
/// qu'elle réécrit (`<version>@<lignes>`, lisible) la répare — une fois, pas une boucle.
pub(crate) fn la_passe_d_analyse_complete_est_a_refaire(
    jalon: Option<&str>,
    version: &str,
    lignes_maintenant: i64,
) -> bool {
    let Some(jalon) = jalon else { return true };
    let (version_du_jalon, taille) = lire_le_jalon_d_analyse_complete(jalon);
    if version_du_jalon != version {
        return true;
    }
    let lignes_du_jalon = match taille {
        TailleDuJalon::Mesuree(n) => n,
        TailleDuJalon::Absente => 0,
        TailleDuJalon::Illisible => return true,
    };
    let plancher = SEUIL_DE_LIGNES_DE_REARMEMENT_DE_L_ANALYSE
        .max(lignes_du_jalon.saturating_mul(FACTEUR_DE_CROISSANCE_DE_REARMEMENT_DE_L_ANALYSE));
    lignes_maintenant >= plancher
}

/// Taille de la table d'événements telle que la passe la mesure : `MAX(id)` et non `COUNT(*)`, parce
/// que compter balaie — et sous SQLCipher déchiffre — la table entière à CHAQUE démarrage, quand
/// l'identifiant monotone se lit en une descente d'arbre et borne par le haut le nombre de lignes
/// jamais insérées.
///
/// `P10.20-b` (tranche entretien) — rend `Result` : `Ok(0)` est une table VIDE (fait établi), `Err` une lecture
/// ratée. Avant, `unwrap_or(0)` rendait la seconde comme la première, et la passe écrivait un jalon `<version>@0`
/// mesuré sur rien (ou sautait une passe due sans un mot).
pub(crate) fn taille_de_la_table_des_evenements(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COALESCE(MAX(id),0) FROM event", [], |r| r.get(0))
}

/// ANALYZE COMPLET (analysis_limit=0) EN TÂCHE DE FOND : déchiffre toute la table `event`
/// (coûteux : 1-2 min sur base SQLCipher volumineuse) pour des stats exactes -> le planner choisit
/// idx_event_sev_srcip. Lancé APRÈS le bind (boot non bloquant). Gardé par la meta clé 'analyze_full_done'
/// = `<version du schéma>@<lignes de event>` au moment du ANALYZE : refait à chaque bump de schéma
/// (idempotent, ré-armé si un futur changement d'index bump la version) ET quand la table a franchi le
/// seuil et grandi du facteur depuis la passe (`P7.19-h` : une passe prise sur une base VIDE à
/// l'installation ne fige plus ses zéros pour toute la vie du schéma). On prend le lock writer (ANALYZE
/// écrit sqlite_stat1), mais brièvement comparé au bind, et hors du chemin de démarrage.
///
/// `P10.20-b` (tranche entretien) — AVANT : version lue en `unwrap_or_else("0")`, jalon en `.ok()`, taille en
/// `unwrap_or(0)`, `ANALYZE` et jalon en `let _`. Une version non lue valait « 0 » (passe refaite, jalon `0@N` écrit,
/// donc refaite encore au démarrage suivant) ; un jalon non lu valait « jamais analysée » (un `ANALYZE` COMPLET, minutes
/// de verrou d'écriture, lancé sur une lecture ratée) ; une taille non lue valait une table vide (jalon `@0` écrit sur
/// rien, ou passe due sautée) ; un `ANALYZE` refusé posait quand même son jalon, et la ligne disait « terminé ».
/// DÉSORMAIS : une lecture ratée (ou une version ABSENTE) ne lance ni ne saute la passe en silence — rien n'est fait,
/// rien n'est écrit, la ligne le dit, le démarrage suivant reprend ; un `ANALYZE` refusé n'écrit pas de jalon ; un jalon
/// refusé (ou à zéro ligne) est dit, jamais suivi de « terminé ».
pub(crate) fn analyze_full_background(db: &Arc<Mutex<Connection>>) -> CompteRenduDEntretien {
    use rusqlite::OptionalExtension as _;
    let conn = db.lock();
    let mut cr = CompteRenduDEntretien::default();
    let ver: String = match conn
        .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0))
        .optional()
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            cr.dire("[analyze] ANALYZE complet NON tenté : la version de schéma est ABSENTE de meta — aucun jalon écrit, retry au prochain boot".to_string());
            return cr;
        }
        Err(e) => {
            cr.lecture_non_faite(format!("[analyze] ANALYZE complet NON tenté : la version de schéma n'a pas pu être lue ({e}) — aucun jalon écrit, retry au prochain boot"));
            return cr;
        }
    };
    let done: Option<String> = match conn
        .query_row("SELECT value FROM meta WHERE key='analyze_full_done'", [], |r| r.get(0))
        .optional()
    {
        Ok(d) => d,
        Err(e) => {
            cr.lecture_non_faite(format!("[analyze] ANALYZE complet NON tenté : le jalon analyze_full_done n'a pas pu être lu ({e}) — ni refait ni tenu pour fait, retry au prochain boot"));
            return cr;
        }
    };
    let lignes = match taille_de_la_table_des_evenements(&conn) {
        Ok(n) => n,
        Err(e) => {
            cr.lecture_non_faite(format!("[analyze] ANALYZE complet NON tenté : la taille de la table event n'a pas pu être lue ({e}) — aucun jalon écrit, retry au prochain boot"));
            return cr;
        }
    };
    if !la_passe_d_analyse_complete_est_a_refaire(done.as_deref(), &ver, lignes) {
        return cr; // déjà fait pour ce schéma, sur une table de taille comparable
    }
    // `P10.20-b` — un jalon de la version courante dont la taille est illisible est DIT avant la passe qu'il relance : ni
    // lu comme une base vide, ni refait en silence. Le jalon lui-même n'est pas recopié au journal.
    let taille_du_jalon_illisible = matches!(
        done.as_deref().map(lire_le_jalon_d_analyse_complete),
        Some((version_du_jalon, TailleDuJalon::Illisible)) if version_du_jalon == ver
    );
    if taille_du_jalon_illisible {
        cr.dire(format!(
            "[analyze] jalon analyze_full_done de la version {ver} : taille illisible (ni un entier positif ni absente) — \
             la taille de la passe précédente n'est pas établie, ANALYZE complet refait et jalon réécrit"
        ));
    }
    if let Err(e) = conn.execute_batch("PRAGMA analysis_limit=0; ANALYZE;") {
        cr.ecriture_refusee(format!("[analyze] ANALYZE complet ÉCHEC ({e}) — jalon NON écrit, la passe sera retentée au prochain boot"));
        return cr;
    }
    let jalon = jalon_d_analyse_complete(&ver, lignes);
    let ecrit = conn
        .execute("INSERT OR REPLACE INTO meta(key,value) VALUES('analyze_full_done', ?1)", params![jalon])
        .and_then(une_ligne_ecrite);
    match ecrit {
        Ok(()) => cr.dire(format!("[analyze] ANALYZE complet terminé (tâche de fond, jalon {jalon}) -> stats exactes pour les index composés")),
        Err(e) => cr.ecriture_refusee(format!("[analyze] ANALYZE complet fait, mais son jalon {jalon} n'a PAS été écrit ({e}) — la passe sera refaite au prochain boot")),
    }
    cr
}

/// PHASE 1 — BACKFILL EN FOND de `event_fields_fts` pour les 1,24M lignes existantes. Modèle
/// analyze_full_background : std::thread::spawn APRÈS le bind, sleep initial (laisse passer bind +
/// liveness). JAMAIS synchrone (anti-crashloop k8s). Actif SEULEMENT si PLUME_FTS_FIELDS=1 ET
/// PLUME_FTS_FIELDS_BACKFILL=1. IDEMPOTENT + REPRENABLE par WATERMARK décroissant (meta
/// 'fts_fields_backfill_hi' = plus petit id non encore traité) : on indexe du plus RÉCENT au plus
/// ancien -> les recherches récentes profitent du FTS en premier. Un kill k8s à mi-backfill reprend
/// au lot suivant (le watermark survit). Borné par lot sous lock writer COURT (modèle ingest batch)
/// + respiration entre lots (ne famine ni l'ingest ni les lectures). RAM bornée (INSERT...SELECT
/// streame, pas d'accumulation -> respecte <100Mo). Gardé final par meta 'fts_fields_backfill_done'.
///
/// `P10.20-b` (tranche entretien) — AVANT : présence de la vtable en `.is_ok()`, jalon et watermark en `.ok()`,
/// `MAX(id)+1` en `unwrap_or(0)`, watermark et jalon final écrits en `let _`. Une lecture ratée du jalon ou du
/// watermark relançait le backfill ENTIER sans un mot ; un `MAX(id)` non lu (ou un watermark non entier, que
/// `CAST(… AS INTEGER)` rendait 0) donnait `lo = 0` : la boucle ne tournait pas, le jalon `done` était ÉCRIT et la
/// ligne disait « TERMINÉ » — un backfill déclaré fait sans avoir rien indexé ; un watermark ou un jalon refusé était
/// suivi de « TERMINÉ ». DÉSORMAIS : chaque lecture a trois issues (absent, lu, non lu ; une valeur illisible est non
/// lue, jamais zéro) ; une lecture ratée arrête la tâche sans rien écrire et le dit ; un watermark refusé arrête la
/// tâche (reprise au dernier watermark écrit : les lots déjà indexés ne sont pas doublés, `NOT EXISTS`) ; un jalon
/// final refusé est dit, et « TERMINÉ » n'est imprimé que s'il est écrit.
pub(crate) fn fts_backfill_background(db: &Arc<Mutex<Connection>>) -> CompteRenduDEntretien {
    use rusqlite::OptionalExtension as _;
    let mut cr = CompteRenduDEntretien::default();
    let conf = load_config();
    if cfg(&conf, "PLUME_FTS_FIELDS", "0") != "1" || cfg(&conf, "PLUME_FTS_FIELDS_BACKFILL", "1") != "1" {
        return cr; // Phase 1 OFF ou backfill historique désactivé -> rien (les triggers indexent le neuf).
    }
    let batch: i64 = cfg(&conf, "PLUME_FTS_BACKFILL_BATCH", "5000").parse().unwrap_or(5000).clamp(100, 100_000);
    let sleep_ms: u64 = cfg(&conf, "PLUME_FTS_BACKFILL_SLEEP_MS", "200").parse().unwrap_or(200);
    let done_tag = "40"; // version de schéma à laquelle ce backfill correspond (comme analyze_full_done)

    // Garde idempotente : déjà terminé pour ce schéma -> no-op immédiat.
    {
        let conn = db.lock();
        // L'infra doit exister (PLUME_FTS_FIELDS=1 a créé la vtable en v40) ; sinon on s'abstient.
        match objet_present_au_catalogue(&conn, "table", "event_fields_fts") {
            Ok(true) => {}
            Ok(false) => return cr,
            Err(e) => {
                cr.lecture_non_faite(format!("[fts-backfill] backfill NON tenté : la présence de event_fields_fts n'a pas pu être lue ({e}) — retry au prochain boot"));
                return cr;
            }
        }
        let done: Option<String> = match conn
            .query_row("SELECT value FROM meta WHERE key='fts_fields_backfill_done'", [], |r| r.get(0))
            .optional()
        {
            Ok(d) => d,
            Err(e) => {
                cr.lecture_non_faite(format!("[fts-backfill] backfill NON tenté : le jalon fts_fields_backfill_done n'a pas pu être lu ({e}) — ni refait ni tenu pour fait, retry au prochain boot"));
                return cr;
            }
        };
        if done.as_deref() == Some(done_tag) {
            return cr;
        }
    }

    // lo = watermark (plus petit id NON encore traité). Init = MAX(id)+1 (tout l'historique restant).
    let mut lo: i64 = {
        let conn = db.lock();
        let wm: Option<rusqlite::types::Value> = match conn
            .query_row("SELECT value FROM meta WHERE key='fts_fields_backfill_hi'", [], |r| r.get(0))
            .optional()
        {
            Ok(v) => v,
            Err(e) => {
                cr.lecture_non_faite(format!("[fts-backfill] backfill NON tenté : le watermark fts_fields_backfill_hi n'a pas pu être lu ({e}) — retry au prochain boot"));
                return cr;
            }
        };
        match wm {
            Some(v) => match watermark_entier(&v) {
                Ok(n) => n,
                Err(genre) => {
                    cr.lecture_non_faite(format!("[fts-backfill] backfill NON tenté : le watermark fts_fields_backfill_hi est illisible ({genre}) — ni repris à zéro ni recommencé, retry au prochain boot"));
                    return cr;
                }
            },
            None => match conn.query_row("SELECT COALESCE(MAX(id),0)+1 FROM event", [], |r| r.get(0)) {
                Ok(n) => n,
                Err(e) => {
                    cr.lecture_non_faite(format!("[fts-backfill] backfill NON tenté : MAX(id) de event n'a pas pu être lu ({e}) — retry au prochain boot"));
                    return cr;
                }
            },
        }
    };

    cr.dire(format!("[fts-backfill] démarrage backfill event_fields_fts (watermark id<{lo}, lot {batch})"));
    while lo > 0 {
        let next = (lo - batch).max(0);
        {
            let conn = db.lock();
            // Transaction bornée (modèle ingest batch). INSERT...SELECT streame (RAM bornée).
            // NOT EXISTS rend chaque lot ré-insérable sans doublon (idempotent même si le watermark
            // est perdu). On indexe la tranche [next, lo).
            let r = conn.execute(
                "INSERT INTO event_fields_fts(rowid, v) \
                 SELECT e.id, (SELECT group_concat(je.value,' ') FROM json_each(e.fields) je \
                                WHERE je.value IS NOT NULL AND je.type IN ('text','integer','real')) \
                   FROM event e \
                  WHERE e.id >= ?1 AND e.id < ?2 \
                    AND e.fields IS NOT NULL AND json_valid(e.fields) \
                    AND NOT EXISTS (SELECT 1 FROM event_fields_fts WHERE rowid = e.id)",
                params![next, lo],
            );
            if let Err(e) = r {
                cr.ecriture_refusee(format!("[fts-backfill] lot [{next},{lo}) ÉCHEC ({e}) — réessai au prochain boot"));
                return cr; // watermark inchangé -> reprise au même endroit au prochain démarrage
            }
        }
        // avance + persiste le watermark APRÈS le COMMIT du lot (reprise exacte). Lock writer relâché.
        {
            let conn = db.lock();
            let ecrit = conn
                .execute(
                    "INSERT OR REPLACE INTO meta(key,value) VALUES('fts_fields_backfill_hi', ?1)",
                    params![next.to_string()],
                )
                .and_then(une_ligne_ecrite);
            if let Err(e) = ecrit {
                cr.ecriture_refusee(format!("[fts-backfill] lot [{next},{lo}) indexé, mais le watermark id<{next} n'a PAS été écrit ({e}) — backfill arrêté, reprise au dernier watermark écrit au prochain boot (sans doublon : NOT EXISTS)"));
                return cr;
            }
        }
        lo = next;
        if lo > 0 {
            std::thread::sleep(Duration::from_millis(sleep_ms)); // respiration : laisse ingest + lectures passer
        }
    }
    {
        let conn = db.lock();
        let ecrit = conn
            .execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES('fts_fields_backfill_done', ?1)",
                params![done_tag],
            )
            .and_then(une_ligne_ecrite);
        if let Err(e) = ecrit {
            cr.ecriture_refusee(format!("[fts-backfill] historique indexé, mais le jalon fts_fields_backfill_done n'a PAS été écrit ({e}) — le backfill se rejouera au prochain boot (sans doublon : NOT EXISTS)"));
            return cr;
        }
    }
    cr.dire("[fts-backfill] backfill event_fields_fts TERMINÉ (historique indexé)".to_string());
    cr
}

/// `P10.20-b` (tranche entretien) — LE WATERMARK DU BACKFILL, LU STRICTEMENT : un entier SQLite POSITIF OU NUL, ou un
/// texte qui est EXACTEMENT l'écriture décimale d'un tel entier (la forme qu'écrit `fts_backfill_background` :
/// `next.to_string()`, jamais négatif puisque `next = (lo - batch).max(0)`). « Exactement » se juge par l'ALLER-RETOUR :
/// le texte doit être égal à l'écriture de l'entier lu, ce qui refuse les espaces, le signe `+`, les zéros de tête et
/// les formes réelles (`7.0`). Tout le reste est ILLISIBLE, et l'erreur rend le GENRE de la valeur pour la ligne de
/// journal (jamais la valeur elle-même) — jamais 0, que `CAST(… AS INTEGER)` rendait et qui faisait déclarer le backfill
/// terminé.
///
/// UN WATERMARK NÉGATIF EST ILLISIBLE, ET C'EST LA MÊME FAUTE : `lo <= 0`, la boucle `while lo > 0` ne tourne pas, le
/// jalon `done` est écrit et la ligne dit « TERMINÉ » sans rien indexer. Le produit ne l'écrit jamais ; il ne peut venir
/// que d'une corruption, et une corruption ne déclare pas un travail fait.
fn watermark_entier(v: &rusqlite::types::Value) -> Result<i64, &'static str> {
    let n = match v {
        rusqlite::types::Value::Integer(n) => *n,
        rusqlite::types::Value::Text(t) => match t.parse::<i64>() {
            Ok(n) if n.to_string() == *t => n,
            _ => return Err("texte non entier"),
        },
        rusqlite::types::Value::Null => return Err("NULL"),
        rusqlite::types::Value::Real(_) => return Err("réel"),
        rusqlite::types::Value::Blob(_) => return Err("BLOB"),
    };
    if n < 0 {
        return Err("entier négatif");
    }
    Ok(n)
}

/// L'IDENTITÉ DE CET HÔTE, LUE OU AVOUÉE (`S33`) — /etc/hostname, sinon $HOSTNAME, sinon un AVEU.
/// Le seul endroit du démon qui nomme ces deux sources ; tout le reste passe par la fonction
/// paramétrée de `mesure_environnement`, donc s'exerce sans dépendre du nom de la machine de test.
pub(crate) fn identite_hote() -> crate::mesure_environnement::Mesure<String> {
    crate::mesure_environnement::identite_hote_depuis(
        std::path::Path::new("/etc/hostname"),
        std::env::var("HOSTNAME").ok().as_deref(),
    )
}

/// Nom de l'hôte courant (central), avec un repli `localhost` — RÉSERVÉ À L'ÉTIQUETAGE.
///
/// LA DISTINCTION AVEC `identite_hote` EST LE SUJET, PAS UN DÉTAIL. Ce nom sert à ÉTIQUETER
/// l'enveloppe des récepteurs poussés (`host` d'un lot HEC/OTLP/Firehose/Pub/Sub/MinIO), où il faut
/// bien écrire quelque chose et où une valeur de repli ne DÉCIDE de rien. Il ne doit PAS servir à
/// décider quelles actions s'exécutent localement : là, un nom d'hôte plausible inventé fait
/// exécuter des actions destinées à une autre machine, ou fait dormir indéfiniment celles qui
/// visaient celle-ci. Ce chemin-là passe par `identite_hote`, qui n'a pas de troisième valeur.
/// LIMITE NOMMÉE : deux hôtes dont l'identité est illisible s'étiquettent tous deux `localhost` et
/// se confondent dans le cloisonnement par hôte du dédoublonnage. C'est la part que ce repli garde,
/// et elle est écrite ici plutôt que tue.
pub(crate) fn host_self() -> String {
    match identite_hote() {
        crate::mesure_environnement::Mesure::Lue(h) => h,
        crate::mesure_environnement::Mesure::Illisible { .. } => "localhost".into(),
    }
}
