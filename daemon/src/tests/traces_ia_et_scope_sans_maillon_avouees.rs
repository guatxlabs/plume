// =====================================================================================
// `P10.31-u` (deuxième tranche : `handlers/ai.rs`, `handlers/engagement.rs`) — LA TRACE D'UN APPEL IA ET L'ANNONCE
// D'UN REFUS DE SCOPE D'ENGAGEMENT NE SE PERDENT PLUS EN SILENCE.
//
// LE DÉFAUT, MESURÉ SUR 318bf0e AVANT LE CORRECTIF.
// (1) `ai_nl2soql` : `ledger_append(&conn, "ai.call", &detail);` — appel nu, juste avant le corps de succès. L'appel au
//     fournisseur d'IA a DÉJÀ eu lieu (une question rédigée est sortie du processus) ; si le maillon n'entrait pas, la
//     réponse servait le succès sans un mot.
// (2) `annoncer_refus_de_scope_une_fois` : le détail entrait au mémo de processus AVANT l'écriture au registre, et
//     l'issue était jetée. Un maillon refusé laissait le refus marqué « annoncé » pour toute la vie du processus : le
//     seul signal « une ligne de scope de pentest ne protège plus » était perdu jusqu'au redémarrage, sans retentative.
//     Idem pour la ligne « mémo plein » : le mémo était vidé, que la ligne entre ou non.
//
// LA PANNE ÉPROUVÉE : un déclencheur `BEFORE INSERT ON ledger` qui lève `RAISE(ABORT)` (la lecture du hachage
// précédent passe, seule l'écriture du maillon tombe), puis le même déclencheur LEVÉ pour la reprise.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le handler `ai_nl2soql` n'est pas joué jusqu'à son bras de succès — en test,
// l'égress vers un faux fournisseur sur la boucle locale est refusé par la garde SSRF (never-egress) et
// `PLUME_SSRF_ALLOW` est figée au premier usage ; c'est la fonction extraite `ai_nl2soql_reponse_de_succes`, appelée
// telle quelle par le handler, qui est éprouvée, et seulement sous `--features ai` (le module entier est exclu du
// profil par défaut). Le refus de scope non inscrit n'est avoué que par la primitive, sur la sortie d'erreur, une
// fois par tour (aucun compteur ventilé). Restent nus : les quelque cinquante-cinq autres appels de `ledger_append`
// (actions.rs dont les deux `match netban_remove`, caseops.rs, idp.rs, saved_queries.rs, incidents.rs…) ; aucune
// garde ni `#[must_use]` n'interdit un appel nu ; la console ne lit pas `registre_sans_maillon` sur la route IA.
// =====================================================================================
mod traces_ia_et_scope_sans_maillon_avouees {
    use super::*;

    /// Base complète sur fichier (schéma + chaîne de migrations), connexion ouverte.
    fn tisa_base(tag: &str) -> (Connection, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("tisa-{tag}"));
        let conn = open_db(&chemin).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture `P10.31-u` : la chaîne de migrations doit aller au bout");
        (conn, chemin)
    }

    /// LA PANNE : le maillon ne s'écrit plus, le registre se lit toujours.
    fn tisa_registre_hors_d_atteinte(conn: &Connection) {
        conn.execute_batch(
            "CREATE TRIGGER tisa_ledger_refuse BEFORE INSERT ON ledger \
             BEGIN SELECT RAISE(ABORT, 'registre hors d atteinte (temoin P10.31-u)'); END;",
        )
        .expect("fixture : le déclencheur se pose");
    }

    fn tisa_registre_rendu(conn: &Connection) {
        conn.execute_batch("DROP TRIGGER tisa_ledger_refuse;").expect("fixture : le déclencheur se lève");
    }

    fn tisa_lignes(conn: &Connection, genre: &str, motif: &str) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1 AND detail LIKE ?2", params![genre, motif], |r| r.get(0))
            .expect("fixture : le registre se lit")
    }

    // ------------------------------ (1) la trace d'un appel IA ------------------------------

    #[cfg(feature = "ai")]
    fn tisa_issue() -> guatx_core::ai::Nl2SoqlOutcome {
        guatx_core::ai::Nl2SoqlOutcome {
            soql: "source=sshd | count by src_ip".into(),
            sql: Some("SELECT 1".into()),
            valid: true,
            error: None,
            retried: false,
            prompt_tokens: 42,
            completion_tokens: 13,
        }
    }

    /// Le corps d'avant le correctif, reconstruit champ pour champ.
    #[cfg(feature = "ai")]
    fn tisa_corps_d_avant(o: &guatx_core::ai::Nl2SoqlOutcome) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "soql": o.soql,
            "sql": o.sql,
            "valid": o.valid,
            "error": o.error,
            "retried": o.retried,
            "prompt_tokens": o.prompt_tokens,
            "completion_tokens": o.completion_tokens,
        }))
        .unwrap()
    }

    #[cfg(feature = "ai")]
    async fn tisa_reponse(r: Response) -> (u16, Vec<u8>, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, octets, v)
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, le bras de succès de `/api/ai/nl2soql` rend 200 avec TOUS les champs
    /// de l'issue (l'appel a eu lieu, il n'est pas renié) et gagne `registre_sans_maillon` = `CAUSE_GESTE_SANS_TRACE`
    /// suivie de la cause du moteur, sans le détail du maillon (le hachage du prompt, le compte) ; aucune ligne
    /// `ai.call`.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : jeter le maillon (appel nu, mutant `K7_AI_NU`, joué puis retiré du source) — l'aveu disparaît.
    #[cfg(feature = "ai")]
    #[tokio::test]
    async fn tisa_appel_ia_sans_maillon_l_avoue() {
        let (conn, _tmp) = tisa_base("ia-panne");
        tisa_registre_hors_d_atteinte(&conn);
        let o = tisa_issue();
        let detail = "ai.call détail-témoin-tisa prompt_sha=deadbeef user=analyste-tisa";
        let (statut, _, v) = tisa_reponse(ai_nl2soql_reponse_de_succes(&conn, detail, &o)).await;
        assert_eq!(statut, 200, "l'appel a eu lieu : le succès est servi, pas renié : {v}");
        for (cle, attendu) in [
            ("soql", json!(o.soql)),
            ("sql", json!(o.sql)),
            ("valid", json!(true)),
            ("retried", json!(false)),
            ("prompt_tokens", json!(42)),
            ("completion_tokens", json!(13)),
        ] {
            assert_eq!(v.get(cle), Some(&attendu), "le champ `{cle}` reste servi : {v}");
        }
        let aveu = v
            .get(CLE_REGISTRE_SANS_MAILLON)
            .and_then(|x| x.as_str())
            .unwrap_or_else(|| panic!("un appel IA dont le maillon manque l'AVOUE sous `registre_sans_maillon` : {v}"));
        assert!(aveu.starts_with(CAUSE_GESTE_SANS_TRACE), "l'aveu est la phrase commune du geste sans trace : {aveu}");
        assert!(aveu.ends_with(&format!(" ({CAUSE_MAILLON_NON_ECRIT})")) && !aveu.contains("registre hors d atteinte"), "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : l'aveu porte la phrase fixe du maillon non écrit, jamais le texte du moteur : {aveu}");
        assert!(!aveu.contains("analyste-tisa") && !aveu.contains("deadbeef"), "jamais le détail du maillon : {aveu}");
        assert_eq!(tisa_lignes(&conn, "ai.call", "%"), 0, "aucune ligne `ai.call` n'est entrée");
    }

    /// CONTRÔLE NOMINAL : registre sain, le corps est OCTET POUR OCTET celui d'avant (aucune clé
    /// `registre_sans_maillon`) et la ligne `ai.call` est posée une fois, avec son détail.
    #[cfg(feature = "ai")]
    #[tokio::test]
    async fn tisa_appel_ia_nominal_octet_pour_octet() {
        let (conn, _tmp) = tisa_base("ia-nominal");
        let o = tisa_issue();
        let detail = "ai.call détail-nominal-tisa";
        let (statut, octets, v) = tisa_reponse(ai_nl2soql_reponse_de_succes(&conn, detail, &o)).await;
        assert_eq!(statut, 200);
        assert!(v.get(CLE_REGISTRE_SANS_MAILLON).is_none(), "chemin nominal : aucun aveu : {v}");
        assert_eq!(octets, tisa_corps_d_avant(&o), "chemin nominal : le corps d'avant, octet pour octet");
        assert_eq!(tisa_lignes(&conn, "ai.call", "ai.call détail-nominal-tisa"), 1, "la ligne `ai.call` est posée une fois");
    }

    // ------------------------------ (2) l'annonce d'un refus de scope ------------------------------

    /// Le mémo est un état de PROCESSUS : les témoins qui le lisent ou le vident passent un à un.
    static TISA_MEMO_SERIE: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    const TISA_ENGAGEMENT: &str = "tisa-engagement-scope-refuse";

    fn tisa_annonces_de_l_engagement() -> usize {
        let prefixe = format!("engagement {TISA_ENGAGEMENT} :");
        crate::handlers::engagement::memo_des_refus_de_scope_annonces().read().iter().filter(|d| d.starts_with(&prefixe)).count()
    }

    fn tisa_oublier_l_engagement() {
        let prefixe = format!("engagement {TISA_ENGAGEMENT} :");
        crate::handlers::engagement::memo_des_refus_de_scope_annonces().write().retain(|d| !d.starts_with(&prefixe));
    }

    /// CE QU'IL TIENT : un engagement ACTIF dont l'unique ligne de scope est refusée par l'analyseur (joker hors
    /// frontière) produit deux refus à annoncer (la ligne, puis « AUCUNE ligne exploitable »). Registre hors d'atteinte :
    /// AUCUN des deux n'est marqué annoncé au mémo. Registre rendu : le tour suivant les ÉCRIT, une fois chacun ; un
    /// troisième tour n'en écrit aucun de plus (pas de doublon sur le chemin nominal).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : garder au mémo un refus dont le maillon n'est pas entré
    /// (mutant `K7_MEMO_AVANT`, le comportement d'avant, joué puis retiré) — le mémo le dit annoncé et la reprise n'écrit rien.
    #[test]
    fn tisa_refus_de_scope_sans_maillon_reste_a_annoncer() {
        let _serie = TISA_MEMO_SERIE.lock();
        tisa_oublier_l_engagement();
        let (conn, _tmp) = tisa_base("scope-refus");
        conn.execute(
            "INSERT INTO engagement(id,name,box,scope,window_start,window_end,status,created) VALUES(?1,'n','greybox','[\"203.0.113.7*\"]',0,?2,'active',0)",
            params![TISA_ENGAGEMENT, now() + 3600],
        )
        .expect("fixture : l'engagement se pose");
        let motif = format!("engagement {TISA_ENGAGEMENT} :%");

        tisa_registre_hors_d_atteinte(&conn);
        let liste = load_active_engagements(&conn, now()).expect("la table se lit");
        assert!(liste.iter().all(|e| e.engagement_id != TISA_ENGAGEMENT), "l'engagement sans ligne exploitable sort du cache");
        assert_eq!(tisa_lignes(&conn, "engagement.scope.refus", &motif), 0, "fixture : rien n'est entré au registre");
        assert_eq!(
            tisa_annonces_de_l_engagement(),
            0,
            "un refus dont le maillon n'est pas entré N'EST PAS marqué annoncé (sinon il ne serait plus jamais retenté)"
        );

        tisa_registre_rendu(&conn);
        load_active_engagements(&conn, now()).expect("la table se lit");
        assert_eq!(tisa_lignes(&conn, "engagement.scope.refus", &motif), 2, "le tour suivant écrit les deux refus");
        assert_eq!(tisa_annonces_de_l_engagement(), 2, "inscrits, ils sont marqués annoncés");

        load_active_engagements(&conn, now()).expect("la table se lit");
        assert_eq!(tisa_lignes(&conn, "engagement.scope.refus", &motif), 2, "chemin nominal : aucun doublon");
        tisa_oublier_l_engagement();
    }

    /// CE QU'IL TIENT : la même règle pour la ligne « mémo plein ». Mémo rempli jusqu'au plafond, registre hors
    /// d'atteinte : un refus neuf n'efface PAS le mémo (une sentinelle déjà annoncée y reste) et n'y entre pas ; aucune
    /// ligne « mémo plein ». Registre rendu : le refus suivant pose la ligne « mémo plein » une fois, vide le mémo
    /// (sentinelle partie) et y garde le seul refus qui vient d'être écrit.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : vider le mémo quelle que soit l'issue de la ligne « mémo plein »
    /// (mutant `K7_PLEIN_AVANT`, le comportement d'avant, joué puis retiré) — la sentinelle disparaît sans trace.
    #[test]
    fn tisa_memo_plein_n_est_vide_que_si_sa_ligne_entre() {
        use crate::handlers::engagement::{
            annoncer_refus_de_scope_une_fois, memo_des_refus_de_scope_annonces, LIGNE_MEMO_DES_REFUS_DE_SCOPE_PLEIN,
            REFUS_DE_SCOPE_MEMO_CAP,
        };
        let _serie = TISA_MEMO_SERIE.lock();
        let (conn, _tmp) = tisa_base("scope-plein");
        let sentinelle = "tisa-sentinelle-deja-annoncee";
        let neuf = "tisa-refus-neuf-sur-memo-plein";
        {
            let mut m = memo_des_refus_de_scope_annonces().write();
            m.clear();
            m.insert(sentinelle.to_string());
            for i in 1..REFUS_DE_SCOPE_MEMO_CAP {
                m.insert(format!("tisa-remplissage-{i}"));
            }
            assert_eq!(m.len(), REFUS_DE_SCOPE_MEMO_CAP, "fixture : le mémo est au plafond");
        }

        tisa_registre_hors_d_atteinte(&conn);
        annoncer_refus_de_scope_une_fois(&conn, neuf);
        {
            let m = memo_des_refus_de_scope_annonces().read();
            assert!(m.contains(sentinelle), "la ligne « mémo plein » n'est pas entrée : le mémo N'EST PAS vidé");
            assert!(!m.contains(neuf), "le refus neuf dont le maillon manque n'est pas marqué annoncé");
        }
        assert_eq!(tisa_lignes(&conn, "engagement.scope.refus", LIGNE_MEMO_DES_REFUS_DE_SCOPE_PLEIN), 0);

        tisa_registre_rendu(&conn);
        annoncer_refus_de_scope_une_fois(&conn, neuf);
        {
            let m = memo_des_refus_de_scope_annonces().read();
            assert!(!m.contains(sentinelle), "la ligne « mémo plein » est entrée : le mémo est vidé");
            assert!(m.contains(neuf), "le refus écrit reste marqué annoncé après le vidage");
        }
        assert_eq!(tisa_lignes(&conn, "engagement.scope.refus", LIGNE_MEMO_DES_REFUS_DE_SCOPE_PLEIN), 1, "la ligne « mémo plein » une fois");
        assert_eq!(tisa_lignes(&conn, "engagement.scope.refus", neuf), 1, "le refus neuf une fois");
        memo_des_refus_de_scope_annonces().write().clear();
    }
}
