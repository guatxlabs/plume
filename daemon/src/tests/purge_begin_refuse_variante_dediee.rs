// =====================================================================================
// `P10.29-h` — LE `BEGIN` REFUSÉ DE LA PURGE CONFIRMÉE SORT SOUS SA VARIANTE PROPRE, EN 503.
//
// LE DÉFAUT (relu sur 32db17a8) : `purge_apply` ouvrait par un `BEGIN IMMEDIATE` nu ; un refus (verrou d'écriture tenu
// par une autre connexion, refus du moteur) était dit et compté au journal, puis rendu `PurgeRefusal::Db("verrou base
// indisponible")` — 500 `{ok:false, refusal:"db"}`, le même code et le même statut qu'une lecture non faite, quelle
// que soit la cause.
//
// CE QUE CES TÉMOINS JUGENT, sur la ROUTE `purge_apply_route` entière (porte de témoin ouverte sur ce fil) :
//  - verrou tenu par une seconde connexion sur la même base (`BEGIN IMMEDIATE` pendant, gestionnaire d'occupation
//    qui renonce aussitôt) -> 503, `refusal:"transaction_not_opened"`, et le refus compté sous
//    `begin refusé purge verrou` (la cause va au journal). « Aucune ligne supprimée » et « rien au registre » y sont
//    VRAIS PAR CONSTRUCTION (la seconde connexion tient l'écriture : l'écrivain ne peut rien écrire) — ce témoin ne
//    les juge PAS ;
//  - `BEGIN` refusé par un autorisateur SQLite -> même réponse, compté sous `hors_verrou`. C'est le SEUL témoin qui
//    tient « rien supprimé, rien inscrit » : rien n'y empêche l'écriture hors du `BEGIN` refusé ;
//  - le corps ne porte PAS la cause du moteur (`database is locked`, `not authorized`) ni l'ancienne phrase, et ne
//    renvoie pas au seul « journal du démon » (la CLI écrit la cause sur sa sortie d'erreur) ;
//  - contrôle positif : le même jeton, verrou levé, purge le périmètre (le refus n'a rien consommé).
// MUTATIONS (jouées sous VERIF_MUT, retirées du source) : `Z3_RETOUR_DB` (`purge_apply` rend de nouveau `Db`) et
// `Z3_STATUT_500` (la variante servie en 500) rougissent les deux témoins.
// CE QUE CES TÉMOINS NE TIENNENT PAS : la CLI (même code machine dans sa sortie `--json`, code de sortie 3 inchangé pour
// tout refus) n'est pas relancée ici ; la phrase écrite au journal (`eprintln!`) n'est pas capturée, seul son compte
// par cause l'est ; la console ne lit pas `/api/purge`.
// =====================================================================================
mod purge_begin_refuse_variante_dediee {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const PBRV_CAUSES_DU_MOTEUR: [&str; 4] = ["database is locked", "locked", "not authorized", "verrou base indisponible"];

    fn pbrv_juger_la_reponse(statut: u16, corps: &Value, quoi: &str) {
        assert_eq!(statut, 503, "{quoi} : transaction non ouverte servie en 503 : {corps}");
        assert_eq!(corps["ok"], json!(false), "{quoi} : ok:false : {corps}");
        assert_eq!(corps["refusal"], json!("transaction_not_opened"), "{quoi} : variante dédiée, pas `db` : {corps}");
        let message = corps["message"].as_str().unwrap_or_default();
        assert_eq!(message, PurgeRefusal::TransactionNotOpened.to_string(), "{quoi} : texte de la variante : {corps}");
        for cause in PBRV_CAUSES_DU_MOTEUR {
            assert!(!message.contains(cause), "{quoi} : la cause du moteur (`{cause}`) reste au journal, pas dans le corps : {corps}");
        }
        assert!(!message.contains("journal du démon"), "{quoi} : le texte vaut aussi pour la CLI (sortie d'erreur) : {corps}");
        assert!(message.contains("qui a lancé la purge"), "{quoi} : la cause est au journal de l'appelant : {corps}");
    }

    fn pbrv_jeton(st: &AppState, au: &AuthUser) -> String {
        with_write(st, au, |c| purge_plan(c, pcr_scope()).expect("fixture : plan nominal").digest().to_string())
    }

    fn pbrv_compte(st: &AppState, au: &AuthUser, cause: &str) -> u64 {
        with_write(st, au, |c| crate::comptes_de_transaction::compte_des_temoins(c, &format!("begin refusé purge {cause}")))
    }

    /// Verrou d'écriture tenu par une AUTRE connexion sur la même base : 503 dédié, cause comptée.
    #[tokio::test]
    async fn pbrv_verrou_tenu_ailleurs_sert_un_503_dedie_et_compte_la_cause() {
        let (st, p) = pcr_etat("pbrv-verrou");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        let jeton = pbrv_jeton(&st, &au);
        let avant = (pcr_events_servis(&st, &au), with_write(&st, &au, |c| pcr_registre(c)));
        assert_eq!(avant, (6, 0), "précondition : six lignes purgeables, registre vide");
        let compte_avant = pbrv_compte(&st, &au, "verrou");

        let autre = open_db(&p).unwrap();
        autre.execute_batch("BEGIN IMMEDIATE").expect("fixture : la seconde connexion prend le verrou d'écriture");
        with_write(&st, &au, |c| c.busy_handler(Some(|_| false)).expect("fixture : aucune attente du verrou"));
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        autre.execute_batch("ROLLBACK").expect("fixture : verrou levé");

        pbrv_juger_la_reponse(statut, &corps, "verrou tenu ailleurs");
        // « Rien supprimé, rien inscrit » est vrai par construction ici (verrou tenu ailleurs) : non jugé, voir l'en-tête.
        assert_eq!(pbrv_compte(&st, &au, "verrou"), compte_avant + 1, "la cause (verrou) est dite et comptée au journal");

        // Contrôle positif : verrou levé, le MÊME jeton purge le périmètre — le refus n'a rien consommé.
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        assert_eq!(statut, 200, "verrou levé, même jeton : la purge aboutit : {corps}");
        assert_eq!(pcr_events_servis(&st, &au), 0, "périmètre purgé");
        assert_eq!(with_write(&st, &au, |c| pcr_registre(c)), 1, "une inscription au registre");
    }

    /// `BEGIN` refusé par un autorisateur (refus du moteur qui n'est pas un verrou) : même réponse dédiée.
    #[tokio::test]
    async fn pbrv_begin_refuse_par_le_moteur_sert_le_meme_503_dedie() {
        let (st, _p) = pcr_etat("pbrv-autorisateur");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        let jeton = pbrv_jeton(&st, &au);
        let compte_avant = pbrv_compte(&st, &au, "hors_verrou");

        with_write(&st, &au, |c| {
            c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Transaction { operation: TransactionOperation::Begin } => Authorization::Deny,
                _ => Authorization::Allow,
            }))
        });
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        with_write(&st, &au, |c| c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None));

        pbrv_juger_la_reponse(statut, &corps, "BEGIN refusé par l'autorisateur");
        assert_eq!(pcr_events_servis(&st, &au), 6, "aucune ligne supprimée");
        assert_eq!(with_write(&st, &au, |c| pcr_registre(c)), 0, "rien inscrit au registre");
        assert_eq!(pbrv_compte(&st, &au, "hors_verrou"), compte_avant + 1, "la cause (hors verrou) est comptée au journal");
    }
}
