// =====================================================================================
// `P10.21-n` (tranche réclamation d'action) — LA CONDITION DE RÉCLAMATION ÉCRITE UNE FOIS, ET SA BORNE.
//
// LE RESTE MESURÉ SUR LA BASE (`handlers/actions.rs`, arbre `e66bb760`) : la clause de fenêtre
// `(claimed_ts IS NULL OR <maintenant>-claimed_ts><délai>)` existait en TROIS écritures — le littéral
// du SELECT d'`actions_pending` (avec le reste de la condition recopié mot pour mot), la constante
// `CONDITION_DE_RECLAMATION_D_AGENT` de l'UPDATE, et `ACTIONS_A_RECLAMER_ICI` du responder local —
// tenues ensemble par un test d'équivalence dont la grille ignorait `unban_ip`, la borne exacte jamais
// éprouvée. CE QUI NE TENAIT PAS DANS L'ÉNONCÉ : les trois écritures n'étaient pas trois copies de la
// même condition. Hôte et genre du responder diffèrent À DESSEIN (vocabulaire fermé entier, identité
// lue `S33`) ; seule la fenêtre est commune, et c'est elle qui devient unique. La valeur de la fenêtre
// (`RECLAMATION_PERIMEE_S`) était déjà une seule constante, et la comparaison déjà stricte partout.
//
// CE QUE CES TÉMOINS TIENNENT :
//   * la fenêtre n'a plus qu'une écriture dans le CODE d'`actions.rs` (commentaires exclus), et les trois
//     énoncés en dérivent (SELECT par `CONDITION_DE_RECLAMATION_D_AGENT`, UPDATE idem, responder par la
//     macro) ;
//   * la borne à 299, 300 et 301 s, sur la route `actions_pending`, sur `remettre_les_actions_lues` et sur
//     l'énoncé du responder : la réclamation tient encore à la borne exacte, elle est périmée au-delà ;
//   * la grille d'équivalence avec `unban_ip` (statut x genre x hôte x réclamation), TSV de la route à
//     l'octet.
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit), chacun vu ROUGE : `aw9_ge` (comparaison large sur
// le SELECT et l'UPDATE, ce que changerait la macro), `aw9_sans_unban` (genre réduit au ban). Le
// témoin de source est rouge sur l'arbre d'avant (trois écritures).
//
// CE QU'ILS NE TIENNENT PAS : une mutation de l'énoncé du responder seul (constante, `respond_run` sans
// couture de test) ne se joue pas à l'exécution — elle est tenue par le témoin de source (une seule
// écriture) et par la borne exercée sur la constante du produit ; la moitié agent de la clé (riposte
// ré-exécutée après l'abandon de son verdict) est hors de ce lot.
// =====================================================================================
mod reclamation_d_action_une_seule_ecriture {
    use super::*;
    use crate::handlers::actions::{
        reclamation_libre_ou_perimee, remettre_les_actions_lues, ACTIONS_A_RECLAMER_ICI, CONDITION_DE_RECLAMATION_D_AGENT,
        RECLAMATION_PERIMEE_S,
    };
    use std::collections::BTreeSet;

    const HOTE: &str = "hote-rue";

    fn agent() -> AuthUser {
        AuthUser {
            name: HOTE.into(),
            role: "agent".into(),
            tenant: "default".into(),
            is_superadmin: false,
            method: "token".into(),
            csrf: String::new(),
            env: None,
        }
    }

    async fn servir(st: &AppState) -> (u16, String) {
        let r = actions_pending(State(st.clone()), Extension(agent())).await;
        let statut = r.status().as_u16();
        let corps = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (statut, String::from_utf8(corps.to_vec()).unwrap())
    }

    /// Trois actions approuvées ciblées sur l'hôte, réclamées il y a 299, 300 et 301 s (ids 299, 300, 301).
    fn poser_la_borne(conn: &Connection, maintenant: i64) {
        for age in [RECLAMATION_PERIMEE_S - 1, RECLAMATION_PERIMEE_S, RECLAMATION_PERIMEE_S + 1] {
            conn.execute(
                "INSERT INTO action(id,ts,kind,target,status,dry_run,host,claimed_ts) VALUES(?1,1,'unban_ip',?2,'approved',0,?3,?4)",
                params![age, format!("198.51.100.{}", age - 290), HOTE, maintenant - age],
            )
            .unwrap();
        }
    }

    fn reclamation(conn: &Connection, id: i64) -> Option<i64> {
        conn.query_row("SELECT claimed_ts FROM action WHERE id=?1", [id], |r| r.get(0)).unwrap()
    }

    /// LA FENÊTRE N'A QU'UNE ÉCRITURE. Rouge sur l'arbre d'avant : trois `claimed_ts IS NULL` dans le code.
    #[test]
    fn p10_21n_la_fenetre_de_reclamation_n_a_qu_une_ecriture_dont_derivent_les_trois_enonces() {
        let src = std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/handlers/actions.rs")).unwrap();
        let code: String = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        assert_eq!(code.matches("claimed_ts IS NULL").count(), 1, "une seule écriture de la fenêtre dans le code d'actions.rs");
        assert_eq!(code.matches("-claimed_ts>").count() + code.matches("- claimed_ts >").count(), 1, "une seule comparaison de fenêtre");
        assert!(CONDITION_DE_RECLAMATION_D_AGENT.ends_with(reclamation_libre_ou_perimee!("?2", "?3")), "{CONDITION_DE_RECLAMATION_D_AGENT}");
        assert!(ACTIONS_A_RECLAMER_ICI.ends_with(reclamation_libre_ou_perimee!("?3", "?4")), "{ACTIONS_A_RECLAMER_ICI}");
        let debut = code.find("pub(crate) async fn actions_pending(").expect("actions_pending existe");
        let fin = debut + code[debut..].find("\n}\n").expect("fin d'actions_pending");
        let corps = &code[debut..fin];
        assert_eq!(
            corps.matches("SELECT id,kind,target,dry_run FROM action WHERE {CONDITION_DE_RECLAMATION_D_AGENT} ORDER BY id LIMIT 100").count(),
            1,
            "le SELECT d'actions_pending dérive de la condition de l'UPDATE :\n{corps}"
        );
    }

    /// LA BORNE SUR L'UPDATE (`remettre_les_actions_lues`, maintenant explicite) : 299 et 300 s, la
    /// réclamation tient — rien n'est remis ni écrit ; 301 s, périmée — remise et re-réclamée.
    #[test]
    fn p10_21n_borne_de_la_fenetre_sur_la_reclamation_299_300_301() {
        let (st, _p) = sp_state("rue-borne-update");
        let maintenant = 1_700_000_000;
        let c = st.db.lock();
        poser_la_borne(&c, maintenant);
        let lues: Vec<(i64, String, String, bool)> = [299i64, 300, 301]
            .iter()
            .map(|id| (*id, "unban_ip".to_string(), format!("198.51.100.{}", id - 290), false))
            .collect();
        let rendu = remettre_les_actions_lues(&c, &lues, HOTE, maintenant);
        assert_eq!(rendu, Ok("301\tunban_ip\t198.51.100.11\t0\n".to_string()), "seule la réclamation de PLUS de 300 s est périmée");
        assert_eq!(reclamation(&c, 299), Some(maintenant - 299), "299 s : la réclamation tient, intacte");
        assert_eq!(reclamation(&c, 300), Some(maintenant - 300), "300 s, borne exacte : la réclamation tient encore, intacte");
        assert_eq!(reclamation(&c, 301), Some(maintenant), "301 s : re-réclamée maintenant");
    }

    /// LA BORNE PAR LA ROUTE. `actions_pending` lit son horloge : la scène est rejouée tant que la
    /// seconde a changé pendant l'échange (aucune durée n'est jugée, seule l'égalité de la seconde).
    #[tokio::test]
    async fn p10_21n_borne_de_la_fenetre_par_la_route_299_300_301() {
        let mut stable = None;
        for essai in 0..20 {
            let (st, p) = sp_state(&format!("rue-borne-route-{essai}"));
            let t0 = now();
            poser_la_borne(&st.db.lock(), t0);
            let servi = servir(&st).await;
            if now() == t0 {
                stable = Some((st, p, t0, servi));
                break;
            }
        }
        let (st, _p, t0, (statut, corps)) =
            stable.expect("instrument : la seconde a changé pendant chacun des vingt échanges, la borne n'a pas pu être jugée");
        assert_eq!(statut, 200);
        assert_eq!(corps, "301\tunban_ip\t198.51.100.11\t0\n", "TSV à l'octet : seule l'action réclamée il y a plus de 300 s est remise");
        let c = st.db.lock();
        assert_eq!(reclamation(&c, 300), Some(t0 - 300), "300 s : non remise, réclamation intacte");
        assert_eq!(reclamation(&c, 299), Some(t0 - 299));
        assert_eq!(reclamation(&c, 301), Some(t0));
    }

    /// LA BORNE SUR L'ÉNONCÉ DU RESPONDER LOCAL (la constante que `respond_run` prépare).
    #[test]
    fn p10_21n_borne_de_la_fenetre_sur_le_responder_local_299_300_301() {
        let (st, _p) = sp_state("rue-borne-responder");
        let maintenant = 1_700_000_000;
        let c = st.db.lock();
        poser_la_borne(&c, maintenant);
        let mut s = c.prepare(ACTIONS_A_RECLAMER_ICI).unwrap();
        let ids: Vec<i64> = s
            .query_map(params![HOTE, 1i64, maintenant, RECLAMATION_PERIMEE_S], |r| r.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(ids, vec![301], "le responder ne reprend que la réclamation de PLUS de 300 s");
    }

    /// L'ÉQUIVALENCE, `unban_ip` compris : statut x genre (ban, levée, hors vocabulaire d'agent) x hôte x
    /// réclamation. La route sert, et la réclamation réclame, exactement la règle écrite ici en Rust ; le
    /// TSV de la route est rendu à l'octet.
    #[tokio::test]
    async fn p10_21n_equivalence_select_update_avec_la_levee() {
        let maintenant = now();
        let recente = maintenant - 1;
        let perimee = maintenant - RECLAMATION_PERIMEE_S - 100;
        let mut etats: Vec<(i64, &str, &str, Option<&str>, Option<i64>)> = Vec::new();
        let mut id = 0i64;
        for statut in ["approved", "cancelled"] {
            for genre in ["ban_ip", "unban_ip", "isolate_host"] {
                for hote in [Some(HOTE), None, Some(""), Some("autre-hote")] {
                    for reclamee in [None, Some(recente), Some(perimee)] {
                        id += 1;
                        etats.push((id, statut, genre, hote, reclamee));
                    }
                }
            }
        }
        assert!(etats.len() >= 72 && etats.len() <= 100, "plancher de la grille, sous la borne de 100 du SELECT : {}", etats.len());
        let poser = |st: &AppState| {
            let c = st.db.lock();
            for (id, statut, genre, hote, reclamee) in &etats {
                c.execute(
                    "INSERT INTO action(id,ts,kind,target,status,dry_run,host,claimed_ts) VALUES(?1,?1,?2,?3,?4,1,?5,?6)",
                    params![id, genre, format!("198.51.100.{id}"), statut, hote, reclamee],
                )
                .unwrap();
            }
        };
        let (st_servi, _p1) = sp_state("rue-equiv-servi");
        let (st_reclame, _p2) = sp_state("rue-equiv-reclame");
        poser(&st_servi);
        poser(&st_reclame);
        let attendu: Vec<(i64, &str)> = etats
            .iter()
            .filter(|(_, s, g, h, c)| {
                *s == "approved"
                    && (*g == "ban_ip" || *g == "unban_ip")
                    && matches!(h, None | Some("") | Some(HOTE))
                    && c.map_or(true, |c| c == perimee)
            })
            .map(|e| (e.0, e.2))
            .collect();
        assert_eq!(attendu.iter().filter(|(_, g)| *g == "unban_ip").count(), 6, "contrôle : six levées admises");
        assert_eq!(attendu.len(), 12, "contrôle : deux genres x trois hôtes x deux réclamations admises");
        let tsv_attendu: String = attendu.iter().map(|(id, g)| format!("{id}\t{g}\t198.51.100.{id}\t1\n")).collect();
        let (statut, servi) = servir(&st_servi).await;
        assert_eq!(statut, 200);
        assert_eq!(servi, tsv_attendu, "le SELECT d'actions_pending suit la règle écrite, TSV à l'octet");
        let toutes: Vec<(i64, String, String, bool)> = etats.iter().map(|(id, _, g, _, _)| (*id, g.to_string(), format!("198.51.100.{id}"), true)).collect();
        let tsv = remettre_les_actions_lues(&st_reclame.db.lock(), &toutes, HOTE, maintenant).expect("des réclamations écrites");
        let reclamees: BTreeSet<i64> = tsv.lines().map(|l| l.split('\t').next().unwrap().parse().unwrap()).collect();
        let attendus: BTreeSet<i64> = attendu.iter().map(|a| a.0).collect();
        assert_eq!(reclamees, attendus, "l'UPDATE de réclamation suit la MÊME règle que le SELECT");
    }
}
