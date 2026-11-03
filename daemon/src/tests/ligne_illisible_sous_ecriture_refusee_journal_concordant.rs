// =====================================================================================
// `P10.32-o` (vague BJ, correction) — LA LIGNE DE JOURNAL D'UNE LIGNE DE CACHE ILLISIBLE DIT CE QUI EST SERVI QUAND UNE
// ÉCRITURE REFUSÉE EST NOTÉE.
//
// RELEVÉ PAR LE VÉRIFICATEUR DE LA VAGUE BJ : ligne de cache ILLISIBLE, panneau qui compile, refus d'écriture noté. La
// ligne `[panel] … ILLISIBLE` était écrite à la lecture, avant le jugement du 503 : elle annonçait « servie comme une
// charge utile illisible (`paye_utile_illisible`) … rafraîchissement armé », puis `serve_swr` servait le 503 nommé de
// l'écriture refusée, souvent sans rien armer (refus récent). Le cas `bh3-classe-blob` ne jugeait que le corps.
//
// CE QUE CE TÉMOIN JUGE (en sous-processus : le journal est la sortie d'erreur de l'enfant) :
//  (A) ligne BLOB (illisible), panneau sain, refus d'écriture noté maintenant : 503 `cache_non_ecrit`, et la ligne
//      ILLISIBLE de ce panneau dit le refus nommé de l'écriture, jamais `paye_utile_illisible` ni « rafraîchissement armé » ;
//  (B) contrôle : même ligne sans refus noté : 200 `paye_utile_illisible`, et la ligne ILLISIBLE garde sa fin d'origine.
// MUTANT JOUÉ (variable `VERIF_MUT` sous `cfg!(test)`, retiré avant le commit) : `BJ1C_ILLISIBLE_TAIT_LE_REFUS` (la
// branche du refus noté neutralisée : (A) rougit).
// CE QU'IL NE TIENT PAS : le contenu de la cause (texte du moteur, rang global des lectures ratées) ; le tenant n'est que
// celui du mode mono-tenant (`"default"`), l'échappement multi-tenant est jugé par `ligne_de_cache_non_lue_jamais_servie_en_chauffe`.
// =====================================================================================
mod ligne_illisible_sous_ecriture_refusee_journal_concordant {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const BJ1C_ENFANT: &str = "BJ1C_ENFANT_LIGNE_ILLISIBLE_SOUS_ECRITURE_REFUSEE";
    const BJ1C_MARQUE: &str = "BJ1C-ETAPE:";
    /// Les deux fins de ligne, écrites ici : un témoin qui lirait le texte de production ne verrait pas qu'il change.
    const BJ1C_FIN_SOUS_REFUS: &str = " — une écriture refusée est notée pour cette ligne : le refus nommé de l'écriture est servi (503, ligne suivante), pas la charge illisible";
    const BJ1C_FIN_ORDINAIRE: &str = " — servie comme une charge utile illisible (corps synthétique `paye_utile_illisible`, sans `warming`), rafraîchissement armé si le panneau compile, qui la remplacera";

    async fn bj1c_cas(tag: &str, refus_note: bool) -> (i64, u16, Value) {
        let (st, dbp, _gxql, _panne, sain) = t3c_state(tag);
        let from = t3c_from();
        let (rk, fp, _ttl) = t3c_cle(&st, sain, from);
        st.db
            .lock()
            .execute(
                "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,X'00FF')",
                params![sain, rk, fp, now() - 5],
            )
            .expect("fixture : ligne de cache BLOB");
        if refus_note {
            st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Insert { table_name: "panel_cache" } | AuthAction::Insert { table_name: "panel_cost" } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            let r = panneau_avoue::cache_ecrire_dit(&st.db.lock(), sain, &rk, &fp, now(), "{}");
            assert!(r.is_err(), "fixture : l'écriture qui note le refus est refusée");
        }
        eprintln!("{BJ1C_MARQUE}{tag}");
        let r = panel_data(State(st.clone()), Extension(t3c_admin()), Path(sain), t3c_q(from)).await;
        let (code, v) = t3c_json(r).await;
        t3c_attendre_la_tache(&st).await;
        ff_rm(&dbp);
        (sain, code, v)
    }

    #[tokio::test]
    async fn bj1c_ligne_illisible_et_refus_d_ecriture_note_le_journal_dit_le_503() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // panel_data lit load_config()
        if std::env::var(BJ1C_ENFANT).is_ok() {
            let (id_a, code_a, v_a) = bj1c_cas("bj1c-sous-refus", true).await;
            assert_eq!(code_a, 503, "contrôle (A) : le refus nommé de l'écriture : {v_a}");
            assert_eq!(v_a["stats"]["coverage"]["reason"], json!("cache_non_ecrit"), "contrôle (A) : raison : {v_a}");
            let (id_b, code_b, v_b) = bj1c_cas("bj1c-ordinaire", false).await;
            assert_eq!(code_b, 200, "contrôle (B) : corps synthétique : {v_b}");
            assert_eq!(v_b["stats"]["coverage"]["reason"], json!("paye_utile_illisible"), "contrôle (B) : raison : {v_b}");
            eprintln!("{BJ1C_MARQUE}fin");
            println!("BJ1C-IDS:{id_a}:{id_b}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ligne_illisible_sous_ecriture_refusee_journal_concordant::bj1c_ligne_illisible_et_refus_d_ecriture_note_le_journal_dit_le_503",
            ])
            .env(BJ1C_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let ids = stdout.lines().find_map(|l| l.split_once("BJ1C-IDS:").map(|(_, r)| r.to_string())).expect("contrôle : identifiants rendus");
        let (id_a, id_b) = ids.split_once(':').expect("contrôle : deux identifiants");
        // Les lignes ILLISIBLE de chaque étape, lues entre les marques posées par l'enfant (même flux, même fil).
        let mut etape = String::new();
        let mut illisibles: Vec<(String, String)> = Vec::new();
        for l in stderr.lines() {
            if let Some((_, e)) = l.split_once(BJ1C_MARQUE) {
                etape = e.trim().to_string();
            } else if l.contains("ligne de cache ILLISIBLE") {
                illisibles.push((etape.clone(), l.to_string()));
            }
        }
        let de = |e: &str| illisibles.iter().filter(|(x, _)| x == e).map(|(_, l)| l.clone()).collect::<Vec<_>>();
        let a = de("bj1c-sous-refus");
        let b = de("bj1c-ordinaire");
        assert_eq!(a.len(), 1, "(A) une seule ligne ILLISIBLE : {a:?}\n{stderr}");
        assert_eq!(b.len(), 1, "(B) une seule ligne ILLISIBLE : {b:?}\n{stderr}");
        let tete = |id: &str| format!("[panel] WARN ligne de cache ILLISIBLE (lue, non décodable), panneau #{id}, tenant \"default\" : ");
        assert!(a[0].starts_with(&tete(id_a)), "(A) tête exacte : {}", a[0]);
        assert!(a[0].ends_with(BJ1C_FIN_SOUS_REFUS), "(A) la ligne dit le 503 de l'écriture refusée : {}", a[0]);
        assert!(!a[0].contains("paye_utile_illisible") && !a[0].contains("rafraîchissement armé"), "(A) rien d'annoncé qui ne soit servi : {}", a[0]);
        assert!(b[0].starts_with(&tete(id_b)), "(B) tête exacte : {}", b[0]);
        assert!(b[0].ends_with(BJ1C_FIN_ORDINAIRE), "(B) contrôle : la fin d'origine sans refus noté : {}", b[0]);
    }
}
