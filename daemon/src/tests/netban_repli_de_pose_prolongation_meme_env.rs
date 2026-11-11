// `P10.20-b` (reste : repli de la pose sous rechargement refusé, `auth::netban_upsert`).
//
// Quand le rechargement qui suit une pose écrite est refusé, la ligne écrite est fusionnée dans le cache
// avec la valeur qu'il tient déjà (`auth::netban_fusionner_echeance`). La moitié « sinon l'échéance la plus
// lointaine » de cette fusion ne s'exécute JAMAIS au chargement (l'`ORDER BY` lit d'abord l'échéance la plus
// lointaine) : seul ce repli y passe. Cas courant : un ban à échéance déjà en cache est PROLONGÉ par une
// nouvelle pose du MÊME `env_id` (l'upsert met la ligne à jour) pendant que les lectures sont refusées.
// Le témoin (1) exige que l'adresse reste bloquée après l'ancienne échéance et redevienne libre après la
// nouvelle : la prolongation est enforcée, ni ignorée ni changée en ban permanent.
//
// INVERSÉ (`P11.25-a`, décision de l'exploitant du 2026-11-10) : le témoin (2) épinglait qu'une pose du même
// `env_id` RACCOURCISSAIT la base (permanent ramené à une échéance) pendant que le cache, fusionné, tenait encore le
// permanent. Aucune pose de production ne raccourcit plus (la pose qui remplace, `netban_upsert`, est réservée aux
// témoins) : la pose courte sur un permanent est CONSERVÉE en base, et le cache comme le premier chargement réussi
// tiennent le permanent. Le témoin (2) pose par `netban_upsert_sans_raccourcir`, qui lit `net_ban.expires_ts` dans son
// `CASE` : son refus de rechargement est fabriqué par un autorisateur qui refuse les énoncés `SELECT` (le chargement
// en est un, l'upsert non), `nrp_refuser_les_select`. Pour le témoin (1), le
// refus de lecture est fabriqué par un authorizer sur `net_ban.expires_ts` (`nbr_refuser_le_rechargement`,
// déclaré dans `netban_restes_comptes_et_levee_sans_flatten.rs`), pas par une base réellement abîmée.

fn nrp_refuser_les_select(c: &Connection) {
    c.authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| match ctx.action {
        rusqlite::hooks::AuthAction::Select => rusqlite::hooks::Authorization::Deny,
        _ => rusqlite::hooks::Authorization::Allow,
    }));
}

fn nrp_echeance_en_base(c: &Connection, ip: &str) -> Option<i64> {
    c.query_row("SELECT expires_ts FROM net_ban WHERE ip = ?1", params![ip], |r| r.get(0)).unwrap()
}

/// (1) PROLONGATION DU MÊME ENV SOUS RECHARGEMENT REFUSÉ : échéance courte chargée, lectures refusées, pose du
/// même `env_id` à échéance plus lointaine rendue `Arme` -> une seule ligne en base, à la nouvelle échéance, et
/// le cache bloque après l'ancienne échéance, plus après la nouvelle.
#[test]
fn netban_repli_de_pose_prolongation_meme_env_enforcee() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    let courte = now() + 60;
    let longue = now() + 3600;
    nbr_poser(&c, "203.0.113.181", Some(courte));
    assert!(netban_reload(&c));
    assert!(net_ban_is_blocked("203.0.113.181", now()), "contrôle : l'échéance courte est chargée");
    assert!(!net_ban_is_blocked("203.0.113.181", courte + 1), "contrôle : avant la pose, libre après la courte");
    nbr_refuser_le_rechargement(&c);
    let chargement_refuse = netban_charger_cap(&c, 10).is_err();
    let p = netban_upsert(&c, "203.0.113.181", Some(longue), "t", "op", "prod");
    nbr_lever_le_refus(&c);
    assert!(chargement_refuse, "contrôle : le rechargement qui suit la pose est bien refusé");
    assert!(matches!(p, PoseDeBan::Arme), "contrôle : la prolongation est écrite");
    assert_eq!(nbr_lignes(&c), 1, "même env : l'upsert met la ligne à jour");
    assert_eq!(nrp_echeance_en_base(&c, "203.0.113.181"), Some(longue), "la base porte la prolongation");
    assert!(
        net_ban_is_blocked("203.0.113.181", courte + 1),
        "prolongation : l'adresse reste bloquée après l'ancienne échéance"
    );
    assert!(
        !net_ban_is_blocked("203.0.113.181", longue + 1),
        "prolongation : libre après la nouvelle échéance (pas changée en ban permanent)"
    );
}

/// (2) INVERSÉ — POSE COURTE SUR UN PERMANENT DU MÊME ENV, SOUS RECHARGEMENT REFUSÉ : CONSERVÉE. Permanent chargé,
/// lectures refusées, pose du même `env_id` à échéance rendue `Arme` -> la base garde le permanent, le cache bloque
/// après l'échéance, et le premier chargement réussi le tient toujours (avant `P11.25-a`, la base portait l'échéance
/// courte et ce chargement libérait l'adresse).
#[test]
fn netban_repli_de_pose_courte_sur_permanent_meme_env_conservee() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    let courte = now() + 60;
    nbr_poser(&c, "203.0.113.182", None);
    assert!(netban_reload(&c));
    nrp_refuser_les_select(&c);
    let chargement_refuse = netban_charger_cap(&c, 10).is_err();
    let p = netban_upsert_sans_raccourcir(&c, "203.0.113.182", Some(courte), "t", "op", "prod");
    nbr_lever_le_refus(&c);
    assert!(chargement_refuse, "contrôle : le rechargement qui suit la pose est bien refusé");
    assert!(matches!(p, PoseDeBan::Arme), "contrôle : la pose est une pose réussie (l'adresse reste bannie)");
    assert_eq!(nrp_echeance_en_base(&c, "203.0.113.182"), None, "la base garde le permanent : la pose courte ne raccourcit pas");
    assert!(net_ban_is_blocked("203.0.113.182", courte + 1), "le cache tient le permanent");
    assert!(netban_reload(&c), "contrôle : le chargement suivant réussit");
    assert!(net_ban_is_blocked("203.0.113.182", courte + 1), "le premier chargement réussi tient toujours le permanent");
}

/// (3) POSE AUTOMATIQUE COURTE SUR UNE ÉCHÉANCE RÉELLE, SOUS RECHARGEMENT REFUSÉ : CONSERVÉE. Une échéance réelle (dans
/// le passé comme nombre) est chargée sans fin ; lectures refusées, pose automatique courte rendue `Arme` -> la cellule
/// reste réelle et inchangée, le cache bloque loin après l'échéance demandée, et le premier chargement réussi aussi.
/// MUTATION : `AUTO_SANS_TYPEOF` (la base prend l'échéance courte).
#[test]
fn netban_repli_de_pose_courte_sur_echeance_reelle_conservee() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    let courte = now() + 60;
    nbr_poser(&c, "203.0.113.183", Some(now() - 100));
    c.execute("UPDATE net_ban SET expires_ts = expires_ts + 0.5 WHERE ip = '203.0.113.183'", []).unwrap();
    let cellule = |c: &Connection| -> (String, String) {
        c.query_row("SELECT typeof(expires_ts), CAST(expires_ts AS TEXT) FROM net_ban WHERE ip = '203.0.113.183'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
    };
    let avant = cellule(&c);
    assert_eq!(avant.0, "real", "fixture : cellule réelle");
    assert!(netban_reload(&c));
    assert!(net_ban_is_blocked("203.0.113.183", courte + 3600), "contrôle : le chargement la tient sans fin");
    nrp_refuser_les_select(&c);
    let chargement_refuse = netban_charger_cap(&c, 10).is_err();
    let p = netban_upsert_sans_raccourcir(&c, "203.0.113.183", Some(courte), "t", "op", "prod");
    nbr_lever_le_refus(&c);
    assert!(chargement_refuse, "contrôle : le rechargement qui suit la pose est bien refusé");
    assert!(matches!(p, PoseDeBan::Arme), "contrôle : la pose est une pose réussie (l'adresse reste bannie)");
    assert_eq!(cellule(&c), avant, "la cellule réelle reste entière : la pose courte ne raccourcit pas");
    assert!(net_ban_is_blocked("203.0.113.183", courte + 3600), "le cache tient le ban sans fin");
    assert!(netban_reload(&c), "contrôle : le chargement suivant réussit");
    assert!(net_ban_is_blocked("203.0.113.183", courte + 3600), "le premier chargement réussi le tient toujours");
}
