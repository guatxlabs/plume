// =====================================================================================
// `P10.29-l` (vague BG) — LE QUATRIÈME 503 D'`actions.rs` QUI SERVAIT LE TEXTE DU MOTEUR, ET LA NOTE DE CONNEXION
// ARMÉE DE L'INSTRUMENT DU CŒUR.
//
// LE DÉFAUT, LU SUR 3cddef81 (BASE DE LA VAGUE BH) AVANT LE CORRECTIF :
//  * `handlers/actions.rs`, `action_approve` (riposte `unban_ip`, miroir HTTP armé) : le bras `NonLevee` servait
//    `format!("{CAUSE_LEVEE_NON_FAITE} ({erreur}){trace}")`, `erreur` = `netban_remove(..).map_err(|e| e.to_string())`
//    (auth.rs), donc le texte rendu par SQLite (message d'un déclencheur, nom de table). Les trois autres 503 du même
//    motif passaient déjà par `laisser_la_cause_au_journal` (vagues BE, BF) ; celui-ci y passe désormais : ligne
//    `[actions] WARN levée du ban de la riposte #<id> NON faite, le ban reste actif (tenant '<t>') : "<moteur>"`, et
//    la phrase fixe `CAUSE_DU_MOTEUR_LAISSEE_AU_JOURNAL` entre parenthèses. Le registre (`netban.remove.echec`, lu par
//    l'administrateur seul) garde le texte, comme `netban.non-arme`. Le test qui exigeait le message du déclencheur dans
//    le corps (`levee_de_ban_issue_consommee.rs`) est inversé nommément.
//  * `query_exec.rs`, `read_conn_get` : chaque prise d'une connexion de lecture effaçait, sous `cfg(test)`, la note de
//    la connexion armée par `panne_de_test_au_coeur` sur ce fil. Le mutant qui retirait cet effacement restait vert
//    (aucun témoin) ; et l'effacement ouvrait le trou que la note ferme : une connexion armée ENCORE VIVANTE, rendue
//    après qu'une autre connexion a été prise sur le même fil, était remise au pool. L'effacement est retiré ; la note
//    ne s'efface plus qu'à la remise de la connexion armée.
//
// LES TÉMOINS :
// (1) `bg3_levee_refusee_texte_du_moteur_au_journal_par_tenant` — mode 1, DEUX tenants réels, en sous-processus : la
//     levée refusée (déclencheur `BEFORE DELETE ON net_ban`) rend, pour chaque tenant, un 503 dont le corps vaut
//     exactement `{error: "<phrase> (<cause au journal>)", id}`, sans le texte du moteur ; le registre du tenant garde
//     ce texte ; la sortie d'erreur porte UNE ligne `[actions] WARN` par tenant, ÉGALE à la ligne attendue (tenant de
//     l'appelant, numéro de la riposte, jamais l'adresse visée), dans l'ordre. MUTANTS : `BG3_LEVEE_TEXTE` (la cause
//     redevient le texte du moteur, aucune ligne au journal) ; `BG3_JOURNAL_TENANT` (la ligne nomme `default` au lieu
//     du tenant de l'appelant : seule la comparaison du journal rougit).
// (2) `bg3_connexion_armee_vivante_fermee_malgre_une_prise` — une connexion armée, tenue vivante pendant qu'une autre
//     est prise sur le même fil, est FERMÉE à sa remise ; la connexion saine prise entre-temps est remise au pool et
//     lit. MUTANT : `VI3_OUBLI` (l'effacement de la note remis dans `read_conn_get`). Seconde phase
//     `..._servie_par_le_pool` : la prise sort du pool au lieu d'ouvrir une connexion neuve. MUTANT :
//     `BG3_OUBLI_AU_POOL` (effacement remis seulement sur la prise servie par le pool).
//     Correction de la vague BI : la prise servie par le pool est reconnue par sa POIGNÉE (égale à celle de la
//     connexion saine laissée au repos), plus par un compte de connexions au repos, qui valait aussi 0 si l'éviction
//     LRU globale du pool (`READ_POOL_CAP`, toutes bases, tests parallèles) avait fermé la saine.
// (3) Vague BI — LA NOTE PÉRIMÉE (ancienne limite écrite au module : note restée après une connexion armée jamais
//     rendue, adresse reprise par une connexion plus tard, que `read_conn_put` fermait au lieu de la garder au pool).
//     `read_conn_get` efface la note quand la connexion qu'il rend porte la poignée notée.
//     `bi1_note_perimee_effacee_quand_l_adresse_revient_par_le_pool` : la note est posée sur la poignée d'une connexion
//     au repos (l'adresse d'une connexion fermée, simulée) ; la prise qui la rend efface la note, et la remise garde la
//     connexion au pool. Une prise d'une AUTRE poignée laisse la note. MUTANTS : `BI1_NOTE_AU_POOL` (effacement retiré
//     du chemin du pool), `BI1_EFFACE_TOUT` (effacement sans comparer la poignée, l'écriture d'avant la vague BG).
//     `bi1_note_perimee_effacee_quand_l_adresse_revient_a_l_ouverture` : une connexion ouverte puis fermée laisse son
//     adresse notée ; la connexion suivante, ouverte sur un pool vide, reprend cette adresse (l'allocateur la rend) ;
//     sa prise efface la note et sa remise la garde au pool. MUTANT : `BI1_NOTE_A_L_OUVERTURE`. Si l'allocateur ne
//     rend pas l'adresse, le témoin refuse de conclure (canal de refus), il ne passe pas en silence.
// Mutants posés sous `cfg!(test)` (variable `VERIF_MUT`), compilés une fois, retirés du source avant le commit.
// =====================================================================================
mod bg3_levee_refusee_au_journal_et_connexion_armee_vivante {
    use super::*;

    /// La phrase du 503 de la levée, recopiée mot pour mot (jamais lue dans la constante de production).
    const BG3_PHRASE_DU_503: &str = "LEVÉE IMPOSSIBLE : la ligne du blocage HTTP n'a pas pu être retirée, donc le ban est TOUJOURS actif. La levée se fait directement par DELETE /api/netban/{ip} (approuver de nouveau la riposte ne la rejoue pas une fois la riposte exécutée).";
    /// Ce que portent les parenthèses à la place du texte du moteur (littéral).
    const BG3_CAUSE_AU_JOURNAL: &str = "la cause rendue par la base est au journal du démon";
    /// Le message que le déclencheur fait rendre au moteur.
    const BG3_TEXTE_DU_MOTEUR: &str = "bg3 levee refusee par le moteur";
    const BG3_ENFANT: &str = "BG3_ENFANT_DEUX_TENANTS";
    const BG3_NETBAN_DES_RIPOSTES: &str = "PLUME_NETBAN_FROM_ACTIONS";
    const BG3_FIN: &str = "BG3-FIN:";
    const BG3_ALPHA: &str = "bg3-alpha";
    const BG3_BETA: &str = "bg3-beta";
    const BG3_RIPOSTE: i64 = 5201;
    const BG3_ADRESSE: &str = "203.0.113.91";

    async fn bg3_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&octets).unwrap_or(Value::Null))
    }

    /// La levée refusée, jouée sur le tenant `t` par son administrateur.
    async fn bg3_jouer_sur(st: &AppState, t: &str) {
        let h = st.tenants.handle_for(t).expect("contrôle : base du tenant");
        {
            let c = h.lock();
            c.execute_batch(&format!(
                "INSERT INTO net_ban(ip,reason,created_ts,expires_ts,created_by,env_id) VALUES('{BG3_ADRESSE}','bg3',1000,NULL,'adm-bg3','prod');\
                 INSERT INTO action(id,ts,kind,target,status,dry_run,host) VALUES({BG3_RIPOSTE},1000,'unban_ip','{BG3_ADRESSE}','pending',0,'');\
                 CREATE TRIGGER bg3_levee BEFORE DELETE ON net_ban BEGIN SELECT RAISE(ABORT, '{BG3_TEXTE_DU_MOTEUR}'); END;"
            ))
            .expect("fixture : ban actif, riposte de levée et déclencheur");
        }
        let admin = AuthUser {
            name: "adm-bg3".into(), role: "admin".into(), tenant: t.into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        };
        let (code, corps) = bg3_corps(action_approve(State(st.clone()), Extension(admin), Path(BG3_RIPOSTE)).await).await;
        assert_eq!(code, 503, "{t} : la levée refusée rend un 503 : {corps}");
        // Corps ENTIER : deux clés, la phrase et sa cause fixe, un identifiant de corrélation.
        let mut cles: Vec<&str> = corps.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        cles.sort_unstable();
        assert_eq!(cles, vec!["error", "id"], "{t} : ensemble exact des clés : {corps}");
        assert_eq!(corps["error"], json!(format!("{BG3_PHRASE_DU_503} ({BG3_CAUSE_AU_JOURNAL})")), "{t} : phrase fixe : {corps}");
        assert!(corps["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{t} : identifiant de corrélation : {corps}");
        assert!(!corps.to_string().contains(BG3_TEXTE_DU_MOTEUR), "{t} : aucune trace du texte du moteur : {corps}");
        // Le registre du tenant garde le texte (lu par l'administrateur seul), la riposte reste approuvée.
        let c = h.lock();
        let detail: String = c
            .query_row("SELECT detail FROM ledger WHERE kind='netban.remove.echec'", [], |r| r.get(0))
            .expect("contrôle : l'échec est au registre du tenant");
        assert_eq!(detail, format!("{BG3_ADRESSE} NON levé (auto: action unban_ip) : {BG3_TEXTE_DU_MOTEUR}"), "{t}");
        let statut: String = c.query_row("SELECT status FROM action WHERE id=?1", params![BG3_RIPOSTE], |r| r.get(0)).expect("statut lu");
        assert_eq!(statut, "approved", "{t} : la riposte reste approuvée");
    }

    #[tokio::test]
    async fn bg3_levee_refusee_texte_du_moteur_au_journal_par_tenant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(BG3_ENFANT).is_ok() {
            let (st, _dir) = mk_mode1_state();
            let mut chemins = Vec::new();
            for t in [BG3_ALPHA, BG3_BETA] {
                let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-bg3")), Json(json!({ "id": t, "name": t }))).await;
                assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
                chemins.push(st.tenants.ready_db_path(t).expect("contrôle : chemin de la base du tenant"));
            }
            assert_ne!(chemins[0], chemins[1], "contrôle : deux bases distinctes");
            let mut joues = 0usize;
            for t in [BG3_ALPHA, BG3_BETA] {
                bg3_jouer_sur(&st, t).await;
                joues += 1;
            }
            netban_cache().write().clear();
            println!("{BG3_FIN} {joues}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::bg3_levee_refusee_au_journal_et_connexion_armee_vivante::bg3_levee_refusee_texte_du_moteur_au_journal_par_tenant",
            ])
            .env(BG3_ENFANT, "1")
            .env(BG3_NETBAN_DES_RIPOSTES, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{BG3_FIN} 2")), "contrôle : un geste joué par tenant : {stdout}\n{stderr}");
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[actions] WARN ")).collect();
        let attendu: Vec<String> = [BG3_ALPHA, BG3_BETA]
            .iter()
            .map(|t| format!("[actions] WARN levée du ban de la riposte #{BG3_RIPOSTE} NON faite, le ban reste actif (tenant '{t}') : \"{BG3_TEXTE_DU_MOTEUR}\""))
            .collect();
        assert_eq!(lignes, attendu, "une ligne EXACTE par tenant, tenant de l'appelant, sans l'adresse :\n{stderr}");
    }

    #[tokio::test]
    async fn bg3_connexion_armee_vivante_fermee_malgre_une_prise() {
        use crate::query_exec::panne_de_test_au_coeur::{demander, encore_demandee, retirer, PanneAuCoeur};
        use crate::query_exec::{connexions_de_lecture_au_repos, read_conn_get, read_conn_put, run_on_conn, run_query_ex};
        let _env = VERROU_ENV_PROCESSUS.read(); // le cœur lit son plafond de lignes dans l'environnement
        let (st, _base) = router_test_state("bg3-prise");
        let chemin = st.db_path.as_ref().clone();
        let vider = |chemin: &str| {
            while connexions_de_lecture_au_repos(chemin) > 0 {
                drop(read_conn_get(chemin).expect("fixture : connexion au repos"));
            }
        };
        vider(&chemin);
        let armee = read_conn_get(&chemin).expect("fixture : connexion à armer");
        demander(&chemin, PanneAuCoeur::RefusDeLAutorisateur);
        let lue = run_on_conn(&armee, &chemin, "SELECT message FROM event", 5_000, None);
        let servie = !encore_demandee(&chemin);
        retirer(&chemin);
        assert!(servie && lue.is_err(), "contrôle : la connexion est armée : {lue:?}");
        // Une AUTRE connexion est prise sur ce fil pendant que l'armée vit encore.
        let prise = read_conn_get(&chemin).expect("fixture : connexion prise pendant que l'armée vit");
        read_conn_put(&chemin, armee);
        assert_eq!(connexions_de_lecture_au_repos(&chemin), 0, "la connexion armée est fermée à sa remise, malgré la prise intercalée (MUTANT `VI3_OUBLI`)");
        // Contrôle : la connexion saine est remise au pool, et elle lit.
        read_conn_put(&chemin, prise);
        assert_eq!(connexions_de_lecture_au_repos(&chemin), 1, "contrôle : la connexion saine est remise au pool");
        let total = run_query_ex(&chemin, "SELECT COUNT(*) AS n FROM event", 5_000, None);
        assert!(total.is_ok(), "contrôle : la connexion remise lit : {total:?}");
        vider(&chemin);
    }

    /// Même trou, l'autre chemin de `read_conn_get` : la prise intercalée est SERVIE PAR LE POOL (une connexion saine
    /// est laissée au repos avant l'armement), au lieu d'ouvrir une connexion neuve. MUTANT : `BG3_OUBLI_AU_POOL`
    /// (l'effacement de la note remis seulement quand la prise sort du pool).
    #[tokio::test]
    async fn bg3_connexion_armee_vivante_fermee_malgre_une_prise_servie_par_le_pool() {
        use crate::query_exec::panne_de_test_au_coeur::{demander, encore_demandee, poignee, retirer, PanneAuCoeur};
        use crate::query_exec::{connexions_de_lecture_au_repos, read_conn_get, read_conn_put, run_on_conn};
        let _env = VERROU_ENV_PROCESSUS.read(); // le cœur lit son plafond de lignes dans l'environnement
        let (st, _base) = router_test_state("bg3-prise-pool");
        let chemin = st.db_path.as_ref().clone();
        let vider = |chemin: &str| {
            while connexions_de_lecture_au_repos(chemin) > 0 {
                drop(read_conn_get(chemin).expect("fixture : connexion au repos"));
            }
        };
        vider(&chemin);
        let saine = read_conn_get(&chemin).expect("fixture : connexion saine");
        let poignee_saine = poignee(&saine);
        let armee = read_conn_get(&chemin).expect("fixture : connexion à armer");
        read_conn_put(&chemin, saine);
        assert_eq!(connexions_de_lecture_au_repos(&chemin), 1, "contrôle : une connexion saine au repos avant l'armement");
        demander(&chemin, PanneAuCoeur::RefusDeLAutorisateur);
        let lue = run_on_conn(&armee, &chemin, "SELECT message FROM event", 5_000, None);
        let servie = !encore_demandee(&chemin);
        retirer(&chemin);
        assert!(servie && lue.is_err(), "contrôle : la connexion est armée : {lue:?}");
        let prise = read_conn_get(&chemin).expect("fixture : connexion prise pendant que l'armée vit");
        assert_eq!(
            poignee(&prise),
            poignee_saine,
            "contrôle : la prise est la connexion saine servie par le pool (pas une connexion ouverte après une éviction)"
        );
        read_conn_put(&chemin, armee);
        assert_eq!(
            connexions_de_lecture_au_repos(&chemin),
            0,
            "la connexion armée est fermée à sa remise, malgré une prise servie par le pool (MUTANT `BG3_OUBLI_AU_POOL`)"
        );
        read_conn_put(&chemin, prise);
        assert_eq!(connexions_de_lecture_au_repos(&chemin), 1, "contrôle : la connexion saine est remise au pool");
        vider(&chemin);
    }
    /// (3) La note périmée, chemin du pool. Déterministe : la note est posée sur la poignée d'une connexion au repos,
    /// comme l'aurait laissée une connexion armée fermée sans remise dont la connexion au repos a repris l'adresse.
    #[tokio::test]
    async fn bi1_note_perimee_effacee_quand_l_adresse_revient_par_le_pool() {
        use crate::query_exec::panne_de_test_au_coeur::{note_de_ce_fil, noter_pour_un_temoin, poignee};
        use crate::query_exec::{connexions_de_lecture_au_repos, read_conn_get, read_conn_put};
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _base) = router_test_state("bi1-note-pool");
        let chemin = st.db_path.as_ref().clone();
        let vider = |chemin: &str| {
            while connexions_de_lecture_au_repos(chemin) > 0 {
                drop(read_conn_get(chemin).expect("fixture : connexion au repos"));
            }
        };
        vider(&chemin);
        noter_pour_un_temoin(0);
        let c = read_conn_get(&chemin).expect("fixture : connexion");
        let p = poignee(&c);
        read_conn_put(&chemin, c);
        assert_eq!(connexions_de_lecture_au_repos(&chemin), 1, "contrôle : la connexion est au repos");
        // Une prise d'une AUTRE poignée laisse la note (l'adresse notée n'est le début d'aucune connexion : `p + 8`
        // tombe à l'intérieur de la structure de `c`, jamais lue).
        noter_pour_un_temoin(p + 8);
        let autre = read_conn_get(&chemin).expect("fixture : prise");
        assert_eq!(poignee(&autre), p, "contrôle : la prise est la connexion au repos");
        assert_eq!(note_de_ce_fil(), p + 8, "une prise d'une autre poignée laisse la note (MUTANT `BI1_EFFACE_TOUT`)");
        noter_pour_un_temoin(0);
        read_conn_put(&chemin, autre);
        assert_eq!(connexions_de_lecture_au_repos(&chemin), 1, "contrôle : la connexion est de nouveau au repos");
        // La note désigne l'adresse de la connexion au repos : la prise qui la rend efface la note.
        noter_pour_un_temoin(p);
        let prise = read_conn_get(&chemin).expect("fixture : prise de l'adresse notée");
        assert_eq!(poignee(&prise), p, "contrôle : la prise est la connexion au repos (pas une connexion neuve)");
        assert_eq!(note_de_ce_fil(), 0, "la prise de la poignée notée efface la note (MUTANT `BI1_NOTE_AU_POOL`)");
        read_conn_put(&chemin, prise);
        assert_eq!(
            connexions_de_lecture_au_repos(&chemin),
            1,
            "la connexion qui a repris l'adresse notée est gardée au pool, pas fermée (MUTANT `BI1_NOTE_AU_POOL`)"
        );
        noter_pour_un_temoin(0);
        vider(&chemin);
    }

    /// (3) La note périmée, chemin de l'ouverture : une connexion fermée sans remise laisse son adresse notée, la
    /// connexion ouverte ensuite la reprend.
    #[tokio::test]
    async fn bi1_note_perimee_effacee_quand_l_adresse_revient_a_l_ouverture() {
        use crate::query_exec::panne_de_test_au_coeur::{note_de_ce_fil, noter_pour_un_temoin, poignee};
        use crate::query_exec::{connexions_de_lecture_au_repos, read_conn_get, read_conn_put};
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _base) = router_test_state("bi1-note-ouverture");
        let chemin = st.db_path.as_ref().clone();
        let vider = |chemin: &str| {
            while connexions_de_lecture_au_repos(chemin) > 0 {
                drop(read_conn_get(chemin).expect("fixture : connexion au repos"));
            }
        };
        let mut reprise = None;
        for _essai in 0..8 {
            vider(&chemin);
            noter_pour_un_temoin(0);
            let fermee = read_conn_get(&chemin).expect("fixture : connexion fermée sans remise");
            let p = poignee(&fermee);
            drop(fermee);
            noter_pour_un_temoin(p);
            let ouverte = read_conn_get(&chemin).expect("fixture : connexion ouverte sur un pool vide");
            if poignee(&ouverte) == p {
                reprise = Some(ouverte);
                break;
            }
            noter_pour_un_temoin(0);
            drop(ouverte);
        }
        let Some(ouverte) = reprise else {
            noter_pour_un_temoin(0);
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "bi1_note_perimee_effacee_quand_l_adresse_revient_a_l_ouverture",
                "l'allocateur n'a pas rendu l'adresse de la connexion fermée à la connexion ouverte ensuite",
            );
            return;
        };
        assert_eq!(note_de_ce_fil(), 0, "l'ouverture à l'adresse notée efface la note (MUTANT `BI1_NOTE_A_L_OUVERTURE`)");
        read_conn_put(&chemin, ouverte);
        assert_eq!(
            connexions_de_lecture_au_repos(&chemin),
            1,
            "la connexion ouverte à l'adresse notée est gardée au pool, pas fermée (MUTANT `BI1_NOTE_A_L_OUVERTURE`)"
        );
        noter_pour_un_temoin(0);
        vider(&chemin);
    }
}
