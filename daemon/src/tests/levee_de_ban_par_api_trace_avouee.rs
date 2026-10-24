// =====================================================================================
// `P10.31-u` (tranche) — LA LEVÉE `DELETE /api/netban/{ip}` CONSOMME SES TROIS MAILLONS.
//
// LE DÉFAUT, RELU SUR c78be971 AVANT LE CORRECTIF. `netban_delete` (handlers/actions.rs) jetait
// l'issue de ses trois `ledger_append` : la levée faite posait `netban.remove` puis servait
// `{"ok": true, …}` que la ligne soit entrée ou non — l'aveu ne vivait que sur la sortie d'erreur
// de la primitive (ledger.rs) ; les deux refus (saisie, puis forme canonique) jetaient le maillon de
// `netban.remove.echec` pendant que le cinq cent trois laissait croire l'échec consigné.
//
// CE QUE CES TÉMOINS JOUENT. Un trigger `BEFORE INSERT ON ledger` filtré par genre refuse le seul
// maillon visé (fabrication de `primitives_avouent_leur_ecriture.rs` et
// `levee_de_ban_issue_consommee.rs`) ; un trigger `BEFORE DELETE ON net_ban` refuse la levée ; la
// levée PARTIELLE est fabriquée par un trigger `AFTER DELETE` qui réinsère une fois la ligne retirée
// (un ban reposé entre les deux passes), puis refuse la passe sur la forme canonique. Chaque témoin
// porte son contrôle positif dans le même corps.
//
// CE QU'ILS NE TIENNENT PAS : la console ne lit pas `registre_sans_maillon` sur la réponse de cette
// levée ; les onze autres appels nus de `ledger_append` d'`actions.rs` restent (refus de pose
// `netban.plafond`/`netban.non-arme` compris).
//
// MUTATIONS JOUÉES (variable `VERIF_MUT` sous `cfg!(test)`, retirées avant le commit) :
// `r6_jete_succes` (le maillon de la levée faite rejeté de nouveau), `r6_jete_echec_saisie` et
// `r6_jete_echec_canon` (les maillons des deux refus rejetés de nouveau), `r6_cle_non_servie`
// (l'aveu servi sous une autre clé), `r6_aveu_sans_panne` (l'aveu servi sur le chemin nominal),
// `s3_ok_faux` et `s3_canon_perdu` (sur le chemin de l'aveu, `ok` faux ou `canon` retiré).
// =====================================================================================
mod levee_de_ban_par_api_trace_avouee {
    use super::*;

    const R6_MENTION: &str = " ; cet échec n'est PAS au registre non plus (";

    fn r6_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("r6-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM net_ban", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn r6_au() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn r6_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn r6_genre(st: &AppState, genre: &str) -> i64 {
        st.db
            .lock()
            .query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![genre], |r| r.get(0))
            .expect("fixture : le compte par genre se lit")
    }

    fn r6_bans(st: &AppState) -> i64 {
        st.db.lock().query_row("SELECT COUNT(*) FROM net_ban", [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn r6_ban_actif(st: &AppState, ip: &str) {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO net_ban(ip,reason,created_ts,expires_ts,created_by,env_id) VALUES(?1,'temoin',1000,NULL,'analyste','prod')",
            params![ip],
        )
        .expect("fixture : le ban s'insère");
        netban_reload(&conn);
        assert!(net_ban_is_blocked(ip, now()), "fixture : le ban est actif dans le cache");
    }

    fn r6_maillon_refuse(genre: &str) -> String {
        format!(
            "CREATE TRIGGER r6_maillon_refuse BEFORE INSERT ON ledger WHEN NEW.kind='{genre}' \
             BEGIN SELECT RAISE(ABORT, 'maillon refuse par le temoin'); END;"
        )
    }

    fn r6_phrase(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    async fn r6_lever(st: &AppState, saisie: &str) -> (u16, Value) {
        pb_json(netban_delete(State(st.clone()), Extension(r6_au()), Path(saisie.to_string())).await).await
    }

    /// CE QU'IL TIENT : la levée FAITE dont le maillon `netban.remove` n'entre pas rend 200, le ban
    /// est levé (table et cache), et le corps porte `registre_sans_maillon` = la phrase partagée
    /// suivie de la cause du registre. CONTRE-ÉPREUVE : le registre réparé, le corps est celui
    /// d'avant, clé pour clé, sans aveu.
    /// MUTATIONS : `r6_jete_succes`, `r6_cle_non_servie` (aveu absent), `r6_aveu_sans_panne` (aveu nominal),
    /// `s3_ok_faux` et `s3_canon_perdu` (corps hors aveu altéré sur le chemin de l'aveu).
    #[tokio::test]
    async fn r6_une_levee_faite_sans_maillon_l_avoue_a_cote_du_succes() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = r6_etat("faite-sans-maillon");
        let ip = "203.0.113.71";
        r6_ban_actif(&st, ip);
        r6_ecrire(&st, &r6_maillon_refuse("netban.remove"));

        let (code, corps) = r6_lever(&st, ip).await;
        assert_eq!(code, 200, "la levée a eu lieu : c'est un succès : {corps}");
        assert_eq!(corps.get("retires"), Some(&json!(1)), "{corps}");
        assert_eq!(r6_bans(&st), 0, "la ligne du ban est retirée");
        assert!(!net_ban_is_blocked(ip, now()), "et le cache ne bloque plus l'adresse");
        assert_eq!(r6_genre(&st, "netban.remove"), 0, "fixture : le maillon n'est pas entré");
        let aveu = corps.get(CLE_REGISTRE_SANS_MAILLON).and_then(|v| v.as_str()).unwrap_or("");
        assert!(aveu.starts_with(&format!("{CAUSE_GESTE_SANS_TRACE} (")), "la trace manquante est avouée dans le corps : {corps}");
        assert!(aveu.ends_with(&format!(" ({CAUSE_MAILLON_NON_ECRIT})")) && !aveu.contains("maillon refuse par le temoin"), "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : l'aveu porte la phrase fixe du maillon non écrit, jamais le texte du moteur : {corps}");
        assert!(!aveu.contains("203.0.113"), "l'aveu ne porte pas l'adresse : {corps}");
        // Le corps privé de l'aveu est le corps nominal, clé pour clé : l'aveu s'ajoute, rien ne change.
        let mut sans_aveu = corps.clone();
        sans_aveu.as_object_mut().expect("le corps est un objet").remove(CLE_REGISTRE_SANS_MAILLON);
        assert_eq!(
            sans_aveu,
            json!({ "ok": true, "ip": ip, "canon": ip, "retires": 1 }),
            "hors aveu, le corps de la levée faite est le corps nominal : {corps}"
        );

        // CONTRE-ÉPREUVE NOMINALE — le registre réparé, le corps d'avant, rien de plus.
        r6_ecrire(&st, "DROP TRIGGER r6_maillon_refuse;");
        let ip2 = "203.0.113.72";
        r6_ban_actif(&st, ip2);
        let (code, nominal) = r6_lever(&st, ip2).await;
        assert_eq!(code, 200, "{nominal}");
        assert_eq!(
            nominal,
            json!({ "ok": true, "ip": ip2, "canon": ip2, "retires": 1 }),
            "le chemin nominal sert le corps d'avant, sans aveu"
        );
        assert_eq!(r6_genre(&st, "netban.remove"), 1, "la levée nominale est attestée");
        netban_cache().write().clear();
    }

    /// CE QU'IL TIENT : la levée refusée dont le maillon `netban.remove.echec` n'entre pas non plus
    /// rend le 503 d'avant suivi d'une mention distincte, sans adresse ; le ban reste actif.
    /// CONTRÔLE POSITIF : le registre réparé, le 503 est la phrase d'avant, mot pour mot.
    /// MUTATION : `r6_jete_echec_saisie`.
    #[tokio::test]
    async fn r6_une_levee_refusee_sans_maillon_d_echec_le_dit_dans_le_503() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = r6_etat("refusee-sans-maillon");
        let ip = "203.0.113.73";
        r6_ban_actif(&st, ip);
        r6_ecrire(&st, "CREATE TRIGGER r6_levee_refusee BEFORE DELETE ON net_ban BEGIN SELECT RAISE(ABORT, 'levee refusee par le temoin'); END;");
        r6_ecrire(&st, &r6_maillon_refuse("netban.remove.echec"));
        // `P10.29-l` (vague AJ) — INVERSÉ : la phrase portait le texte du store (`: levee refusee par le temoin`) ; elle
        // ne le porte plus, le texte va au journal seul (témoin `aj3_` de
        // `texte_du_moteur_hors_couverture_ti_inventaire_elagage_et_levee_de_ban.rs`).
        let phrase_d_avant = "levée de ban IMPOSSIBLE (store indisponible) — RÉESSAYER ; le ban est TOUJOURS actif";

        let (code, corps) = r6_lever(&st, ip).await;
        assert_eq!(code, 503, "{corps}");
        let phrase = r6_phrase(&corps);
        assert!(phrase.starts_with(&format!("{phrase_d_avant}{R6_MENTION}")), "la phrase d'avant, puis la mention de la trace manquante : {corps}");
        assert!(phrase.contains(&format!("({CAUSE_MAILLON_NON_ECRIT})")) && !phrase.contains("maillon refuse par le temoin"), "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : la mention porte la phrase fixe, jamais le texte du moteur : {corps}");
        assert!(!phrase.contains("203.0.113"), "sans adresse : {corps}");
        assert_eq!(r6_genre(&st, "netban.remove.echec"), 0, "fixture : l'échec n'est pas au registre");
        assert_eq!(r6_bans(&st), 1, "la ligne du ban est intacte");
        assert!(net_ban_is_blocked(ip, now()), "le ban est TOUJOURS actif");

        // CONTRÔLE POSITIF — le registre prend l'échec : la phrase d'avant, rien de plus.
        r6_ecrire(&st, "DROP TRIGGER r6_maillon_refuse;");
        let (code, corps) = r6_lever(&st, ip).await;
        assert_eq!(code, 503, "{corps}");
        assert_eq!(r6_phrase(&corps), phrase_d_avant, "l'échec consigné sert la phrase d'avant : {corps}");
        assert_eq!(r6_genre(&st, "netban.remove.echec"), 1, "l'échec est au registre");
        netban_cache().write().clear();
    }

    /// CE QU'IL TIENT : la levée PARTIELLE (saisie retirée, forme canonique refusée) dont le maillon
    /// d'échec n'entre pas rend le 503 d'avant suivi de la mention distincte, sans adresse.
    /// CONTRÔLE POSITIF : le registre réparé, le 503 est la phrase d'avant, mot pour mot.
    /// MUTATION : `r6_jete_echec_canon`.
    #[tokio::test]
    async fn r6_une_levee_partielle_sans_maillon_d_echec_le_dit_dans_le_503() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = r6_etat("partielle-sans-maillon");
        let canon = "203.0.113.74";
        let saisie = "::ffff:203.0.113.74";
        r6_ban_actif(&st, canon);
        // Première passe : la ligne est retirée puis reposée une fois (un ban reposé entre les deux
        // passes) ; toute suppression suivante — la passe canonique — est refusée.
        r6_ecrire(
            &st,
            "CREATE TABLE r6_compteur(n INTEGER); INSERT INTO r6_compteur VALUES(0);
             CREATE TRIGGER r6_refus_canon BEFORE DELETE ON net_ban WHEN (SELECT n FROM r6_compteur) >= 1
               BEGIN SELECT RAISE(ABORT, 'levee refusee par le temoin'); END;
             CREATE TRIGGER r6_reposer AFTER DELETE ON net_ban WHEN (SELECT n FROM r6_compteur) = 0
               BEGIN UPDATE r6_compteur SET n = 1;
                 INSERT INTO net_ban(ip,reason,created_ts,expires_ts,created_by,env_id) VALUES(OLD.ip,'temoin',1000,NULL,'analyste','prod'); END;",
        );
        r6_ecrire(&st, &r6_maillon_refuse("netban.remove.echec"));
        // `P10.29-l` (vague AJ) — INVERSÉ : la phrase ne porte plus le texte du store (journal seul).
        let phrase_d_avant = "levée de ban PARTIELLE (1 retiré(s)) puis ÉCHEC sur la forme canonique — RÉESSAYER";

        let (code, corps) = r6_lever(&st, saisie).await;
        assert_eq!(code, 503, "{corps}");
        let phrase = r6_phrase(&corps);
        assert!(phrase.starts_with(&format!("{phrase_d_avant}{R6_MENTION}")), "la phrase d'avant, puis la mention : {corps}");
        assert!(phrase.contains(&format!("({CAUSE_MAILLON_NON_ECRIT})")) && !phrase.contains("maillon refuse par le temoin"), "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : {corps}");
        assert!(!phrase.contains("203.0.113"), "sans adresse : {corps}");
        assert_eq!(r6_genre(&st, "netban.remove.echec"), 0, "fixture : l'échec n'est pas au registre");
        assert_eq!(r6_bans(&st), 1, "la ligne reposée est toujours là");

        // CONTRÔLE POSITIF — même fabrication, registre réparé.
        r6_ecrire(&st, "DROP TRIGGER r6_maillon_refuse; UPDATE r6_compteur SET n = 0;");
        let (code, corps) = r6_lever(&st, saisie).await;
        assert_eq!(code, 503, "{corps}");
        assert_eq!(r6_phrase(&corps), phrase_d_avant, "l'échec consigné sert la phrase d'avant : {corps}");
        assert_eq!(r6_genre(&st, "netban.remove.echec"), 1, "l'échec est au registre");
        netban_cache().write().clear();
    }
}
