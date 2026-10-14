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
// CE QUE CES TÉMOINS NE TIENNENT PAS : le repli FUSIONNE, il ne remplace pas. Un ban RACCOURCI par une pose
// du même `env_id` (permanent ramené à une échéance) reste tenu à l'ancienne valeur, plus longue, par le
// cache tant que les chargements sont refusés, alors que la base le dit échu. Le témoin (2) ÉPINGLE ce sens
// fail-closed assumé et montre que le premier chargement réussi le corrige ; il ne le corrige pas. Le
// refus de lecture est fabriqué par un authorizer sur `net_ban.expires_ts` (`nbr_refuser_le_rechargement`,
// déclaré dans `netban_restes_comptes_et_levee_sans_flatten.rs`), pas par une base réellement abîmée.

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

/// (2) RACCOURCISSEMENT DU MÊME ENV : TENU PAR LE CACHE (fail-closed, déclaré). Permanent chargé, lectures
/// refusées, pose du même `env_id` à échéance -> la base la dit échue après l'échéance, le cache bloque encore ;
/// le premier chargement réussi remplace l'instantané et libère l'adresse.
#[test]
fn netban_repli_de_pose_raccourcissement_meme_env_tenu_jusqu_au_chargement() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    let courte = now() + 60;
    nbr_poser(&c, "203.0.113.182", None);
    assert!(netban_reload(&c));
    nbr_refuser_le_rechargement(&c);
    let chargement_refuse = netban_charger_cap(&c, 10).is_err();
    let p = netban_upsert(&c, "203.0.113.182", Some(courte), "t", "op", "prod");
    nbr_lever_le_refus(&c);
    assert!(chargement_refuse, "contrôle : le rechargement qui suit la pose est bien refusé");
    assert!(matches!(p, PoseDeBan::Arme), "contrôle : le raccourcissement est écrit");
    assert_eq!(nrp_echeance_en_base(&c, "203.0.113.182"), Some(courte), "la base porte l'échéance courte");
    assert!(
        net_ban_is_blocked("203.0.113.182", courte + 1),
        "fail-closed déclaré : le cache tient encore le ban permanent"
    );
    assert!(netban_reload(&c), "contrôle : le chargement suivant réussit");
    assert!(
        !net_ban_is_blocked("203.0.113.182", courte + 1),
        "le premier chargement réussi remplace l'instantané par la base"
    );
}
