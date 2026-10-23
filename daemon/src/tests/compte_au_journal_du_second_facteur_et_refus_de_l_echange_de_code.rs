// =====================================================================================
// `P10.31-u` (reste AF : dix lignes `[mfa] WARN` de `handlers/idp.rs`, quatre de `handlers/frein_du_second_facteur.rs`,
// libellé de transaction de `mfa_disable`) et `P10.29-l` (reste AF : le 401 `échange de code refusé (HTTP n)` d'`oidc_callback`).
//
// LE DÉFAUT, MESURÉ SUR 1011ec9f AVANT LE CORRECTIF.
//   * Dix lignes `[mfa] WARN` d'`idp.rs` — enrôlement (compte non lu ; lignes écrites), activation (lignes écrites),
//     désactivation (codes de secours non lus ; suppression non écrite), connexion (époque non lue ; code de secours non
//     consommé ; codes de secours non lus ; pas TOTP non consommé), défi (époque non lue) — et les quatre du frein (essai
//     non compté, deux « non rendu », remise à zéro refusée) nommaient le compte (`'{user}'`, `au.name`). Les libellés de
//     transaction aussi : `désactivation du second facteur de '<nom>'`, et ceux du frein (réservation et retour d'un
//     essai) ; ils partent au journal quand le `BEGIN` est refusé (`dire_la_transaction_non_ouverte`).
//   * `oidc_callback` servait `échange de code refusé (HTTP n)` à un appelant NON AUTHENTIFIÉ : le statut rendu par le
//     point de jeton du fournisseur d'identité.
//
// LE CORRECTIF (décision par défaut de la vague AG). Chaque ligne et chaque libellé disent `compte #<user.id>`
// (`compte_au_journal`, lu sur la connexion que le site TIENT déjà — le verrou n'est pas réentrant —, sinon « sans ligne
// `user` » ou « identifiant non lu ») ; statuts et ordre des vérifications inchangés. Le 401 garde son statut et le préfixe
// « échange de code » avec une phrase FIXE (`PHRASE_ECHANGE_DE_CODE_REFUSE`) ; le statut de l'IdP va au journal seul, avec
// l'identifiant interne du fournisseur et l'étape, sans URL (`refus_de_l_echange_de_code` -> `servir_l_echec_de_l_etape`).
//
// LES PANNES ÉPROUVÉES : `user.hash` en BLOB ; `BEGIN` refusé par un autorisateur SQLite (tous, ou à partir du
// deuxième) ; liste de codes de secours corrompue ; déclencheurs `RAISE(ABORT)` sur `setting` (état du frein) et sur
// `user_mfa` ; époque du compte illisible dans `meta`. Lignes de journal lues sur le stderr d'un sous-processus, chacune
// ENTIÈRE, par égalité.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit), chacun vu ROUGE. Production, le nom du compte rendu au
// site (`compte_au_journal` masqué au site par une fermeture qui rend `'<nom>'`) : `AG1_M1313`, `AG1_M1579`, `AG1_M1584`,
// `AG1_M1785`, `AG1_M1843`, `AG1_M1849`, `AG1_M1877`, `AG1_M1914` (idp.rs), `AG1_L1524` (libellé de `mfa_disable`),
// `AG1_F112`, `AG1_F211`, `AG1_F214`, `AG1_F223` (lignes du frein), `AG1_F162`, `AG1_F197` (libellés du frein).
// Constructeur du 401 : `AG1_401_ANCIEN` (texte d'avant servi, sans journal), `AG1_401_SANS_JOURNAL`, `AG1_401_STATUT`
// (502), `AG1_401_DETAIL` (statut de l'IdP absent du journal). Source jugé : `AG1_S401_ANCIEN`, `AG1_S401_BRAS` (bras qui
// resservirait le statut avant l'appel), `AG1_S401_FOURNISSEUR`, `AG1_SN_ENROLEMENT_ANCIEN`, `AG1_SN_ENROLEMENT_BRAS`,
// `AG1_SN_ACTIVATION_ANCIEN`, `AG1_SN_ACTIVATION_BRAS`, `AG1_SW_NOM` (une ligne `[mfa] WARN` rendue au nom).
// CORRECTION APRÈS VÉRIFICATION, chacun vu ROUGE de même. Production : `AG1_A1402`, `AG1_A1825` (le compte passé au refus
// de réservation du frein par `mfa_verify` et `login_mfa_post`, qui n'était joué que par `mfa_disable`). Source jugé :
// `AG1_S401_BRAS_AVANT` (bras posé AVANT le bloc du 401, qui resservait le statut sous un autre libellé et passait),
// `AG1_S401_BRAS_MATCH`, `AG1_S401_APRES`, `AG1_SN_MULTILIGNE` (bras devant l'`Ok(n)` de l'enrôlement, `eprintln!` sur
// plusieurs lignes qui nomme le compte, que la lecture ligne à ligne laissait passer), `AG1_SW_DOUBLE`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les deux `Ok(n)` (enrôlement, activation) ne sont pas atteignables — `user_mfa.user`
// est unique, l'écriture rend zéro ou une ligne —, ni le 401 d'`oidc_callback` (point de jeton https joignable exigé, garde
// SSRF, levier que ce témoin n'écrit pas) : blocs comparés EN ENTIER dans le source, constructeur du 401 joué directement.
// Les issues « sans ligne `user` » et « identifiant non lu » de `compte_au_journal` sont jouées par les témoins `af1_`.
// Hors périmètre : les lignes `[session] WARN époque du compte '<nom>'` de `session.rs` nomment encore le compte.
// =====================================================================================
mod compte_au_journal_du_second_facteur_et_refus_de_l_echange_de_code {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// Le compte porteur du second facteur : un nom qu'aucune sortie du témoin ne porte.
    const AG1_PORTEUR: &str = "ag1porteur";
    const AG1_PASSE: &str = "motdepasse12345";
    const AG1_GRAINE: &[u8] = b"12345678901234567890";
    /// Un code de secours (forme `xxxx-xxxxxx`, jamais celle d'un code TOTP).
    const AG1_SECOURS: &str = "a1b2-c3d4e5";
    const AG1_LISTE_CORROMPUE: &str = "pas une liste";
    const AG1_EPOQUE_ILLISIBLE: &str = "ag1-illisible";
    const AG1_MOTEUR_FREIN: &str = "ag1 frein non oublie";
    const AG1_MOTEUR_SUPPRESSION: &str = "ag1 suppression refusee";
    const AG1_MOTEUR_CONSOMMATION: &str = "ag1 consommation refusee";
    const AG1_FOURNISSEUR: i64 = 77;
    const AG1_STATUT_IDP: u16 = 503;

    fn ag1_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : une écriture de préparation doit passer ({e})"));
    }

    async fn ag1_reponse(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    fn ag1_pair() -> std::net::SocketAddr {
        "192.0.2.11:45455".parse().expect("adresse de test")
    }

    /// L'état d'un témoin : le compte porteur (admin, mot de passe local), le frein du second facteur ARMÉ.
    fn ag1_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (mut st, p) = sp_state(&format!("ag1-{tag}"));
        st.lock_threshold = 5;
        st.db
            .lock()
            .execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,'admin')", params![AG1_PORTEUR, hash_pw(AG1_PASSE).unwrap()])
            .expect("fixture : compte posé");
        (st, p)
    }

    /// Second facteur ACTIF du porteur, aucun pas consommé, liste de secours `recovery` ; rend le code TOTP courant.
    fn ag1_mfa_active(st: &AppState, recovery: &str) -> String {
        let graine = base32_encode(AG1_GRAINE);
        let conn = st.db.lock();
        conn.execute("DELETE FROM user_mfa WHERE user=?1", params![AG1_PORTEUR]).expect("fixture : MFA retirée");
        conn.execute(
            "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES(?1,?2,1,?3,-1,0,0)",
            params![AG1_PORTEUR, graine, recovery],
        )
        .expect("fixture : MFA posée");
        hotp(&base32_decode(&graine).expect("graine base32"), (now() / 30) as u64, 6)
    }

    /// Les `BEGIN` refusés par un autorisateur sur l'écrivain partagé, à partir du `a_partir_du`-ième (1 : tous).
    fn ag1_refuser_les_begin(st: &AppState, a_partir_du: usize) {
        let mut vus = 0usize;
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Begin } => {
                vus += 1;
                if vus >= a_partir_du {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            _ => Authorization::Allow,
        }));
    }

    fn ag1_lever_l_autorisateur(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// La cause que le moteur rend à un `BEGIN` refusé par l'autorisateur, rejouée telle quelle.
    fn ag1_cause_du_begin_refuse(st: &AppState) -> String {
        ag1_refuser_les_begin(st, 1);
        let cause = st.db.lock().execute_batch("BEGIN IMMEDIATE").expect_err("fixture : BEGIN refusé").to_string();
        ag1_lever_l_autorisateur(st);
        cause
    }

    /// La ligne ENTIÈRE de `dire_la_transaction_non_ouverte` pour un `BEGIN` refusé hors verrou.
    fn ag1_begin_refuse(geste: &str, refus: &str) -> String {
        format!(
            "[mfa] ERREUR {geste} NON pris(e) : BEGIN refusé par la base, et ce n'est pas un verrou ({refus}) — rien n'est écrit ; \
             un nouvel essai sera refusé de même tant que la cause demeure (base en lecture seule, disque, E/S)"
        )
    }

    async fn ag1_ticket(st: &AppState) -> String {
        let (statut, defi) = ag1_reponse(mfa_challenge_response(st, AG1_PORTEUR, "admin")).await;
        assert_eq!(statut, 200, "fixture : ticket de défi émis");
        defi["ticket"].as_str().expect("fixture : ticket de défi").to_string()
    }

    async fn ag1_connexion(st: &AppState, ticket: &str, code: &str) -> u16 {
        ag1_reponse(login_mfa_post(State(st.clone()), ConnectInfo(ag1_pair()), Json(json!({ "ticket": ticket, "code": code }))).await).await.0
    }

    async fn ag1_desactiver(st: &AppState, code: &str) -> u16 {
        ag1_reponse(mfa_disable(State(st.clone()), ConnectInfo(ag1_pair()), Extension(sp_au(AG1_PORTEUR, "admin")), Json(json!({ "code": code }))).await)
            .await
            .0
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus, chacune ENTIÈRE : les dix sites `[mfa] WARN`
    /// atteignables, le refus de réservation du frein aux trois routes qui le servent (désactivation, activation,
    /// connexion) et les trois libellés de transaction (désactivation, réservation et retour d'un essai) disent
    /// `compte #<id>` ; statuts d'avant (contrôles) ; le nominal n'écrit rien ; le 401 de l'échange de code sert sa phrase
    /// fixe, corps ENTIER, et le statut de l'IdP va au journal seul ; le nom du compte n'apparaît NULLE PART dans la sortie.
    /// MUTATIONS : `AG1_M*`, `AG1_L1524`, `AG1_F*`, `AG1_401_*`, `AG1_A1402`, `AG1_A1825`.
    #[tokio::test]
    async fn ag1_lignes_de_journal() {
        const ENFANT: &str = "AG1_ENFANT_JOURNAL";
        const PHASE: &str = "AG1-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _tmp) = ag1_etat("journal");
            let mut sans_frein = st.clone();
            sans_frein.lock_threshold = 0;
            let portee = crate::handlers::frein_du_second_facteur::PORTEE_DU_FREIN_DU_SECOND_FACTEUR;
            let mut statuts: Vec<u16> = Vec::new();
            let mut causes: Vec<String> = vec![ag1_cause_du_begin_refuse(&st)];

            eprintln!("{PHASE}enrolement");
            ag1_sql(&st, &format!("UPDATE user SET hash=x'00' WHERE name='{AG1_PORTEUR}';"));
            let r = mfa_enroll(State(st.clone()), ConnectInfo(ag1_pair()), Extension(sp_au(AG1_PORTEUR, "admin")), Json(json!({ "password": AG1_PASSE }))).await;
            statuts.push(ag1_reponse(r).await.0);
            let cause = st.db.lock().query_row("SELECT hash FROM user WHERE name=?1", params![AG1_PORTEUR], |r| r.get::<_, String>(0));
            causes.push(cause.expect_err("fixture : hash illisible").to_string());
            st.db.lock().execute("UPDATE user SET hash=?1 WHERE name=?2", params![hash_pw(AG1_PASSE).unwrap(), AG1_PORTEUR]).expect("fixture : hash rendu");

            // Tous les `BEGIN` refusés : la réservation de l'essai n'est pas prise.
            eprintln!("{PHASE}reservation");
            let code = ag1_mfa_active(&st, "[]");
            ag1_refuser_les_begin(&st, 1);
            statuts.push(ag1_desactiver(&st, &code).await);
            ag1_lever_l_autorisateur(&st);

            // La même réservation refusée à l'ACTIVATION (enrôlement en attente) puis à la CONNEXION : le compte que chacune
            // passe au refus du frein est celui qu'elle sert au journal.
            eprintln!("{PHASE}reservation_activation");
            ag1_sql(&st, &format!("UPDATE user_mfa SET enabled=0 WHERE user='{AG1_PORTEUR}';"));
            ag1_refuser_les_begin(&st, 1);
            let r = mfa_verify(State(st.clone()), ConnectInfo(ag1_pair()), Extension(sp_au(AG1_PORTEUR, "admin")), Json(json!({ "code": code }))).await;
            statuts.push(ag1_reponse(r).await.0);
            ag1_lever_l_autorisateur(&st);

            eprintln!("{PHASE}reservation_connexion");
            let code = ag1_mfa_active(&st, "[]");
            let ticket = ag1_ticket(&st).await;
            ag1_refuser_les_begin(&st, 1);
            statuts.push(ag1_connexion(&st, &ticket, &code).await);
            ag1_lever_l_autorisateur(&st);

            // La réservation passe, les `BEGIN` suivants sont refusés : la transaction du geste, puis le retour de l'essai.
            eprintln!("{PHASE}geste");
            ag1_refuser_les_begin(&st, 2);
            statuts.push(ag1_desactiver(&st, &code).await);
            ag1_lever_l_autorisateur(&st);
            ag1_sql(&st, &format!("DELETE FROM setting WHERE scope='{portee}';"));

            // Liste de secours corrompue, et l'oubli de l'état du frein refusé : codes non lus, puis essai non rendu.
            eprintln!("{PHASE}secours");
            ag1_mfa_active(&st, AG1_LISTE_CORROMPUE);
            ag1_sql(&st, &format!("CREATE TRIGGER ag1_frein BEFORE DELETE ON setting WHEN OLD.scope='{portee}' BEGIN SELECT RAISE(ABORT,'{AG1_MOTEUR_FREIN}'); END;"));
            statuts.push(ag1_desactiver(&st, AG1_SECOURS).await);
            let illisible = serde_json::from_str::<Vec<String>>(AG1_LISTE_CORROMPUE).expect_err("fixture : liste corrompue");
            causes.push(format!("liste des codes de secours corrompue : {illisible}"));

            // Désactivation réussie, la remise à zéro du frein refusée.
            eprintln!("{PHASE}remise");
            let code = ag1_mfa_active(&st, "[]");
            statuts.push(ag1_desactiver(&st, &code).await);
            ag1_sql(&st, &format!("DROP TRIGGER ag1_frein; DELETE FROM setting WHERE scope='{portee}';"));

            // La suppression de `user_mfa` refusée (frein éteint) : désactivation non écrite.
            eprintln!("{PHASE}suppression");
            let code = ag1_mfa_active(&st, "[]");
            ag1_sql(&st, &format!("CREATE TRIGGER ag1_suppression BEFORE DELETE ON user_mfa BEGIN SELECT RAISE(ABORT,'{AG1_MOTEUR_SUPPRESSION}'); END;"));
            statuts.push(ag1_desactiver(&sans_frein, &code).await);
            ag1_sql(&st, "DROP TRIGGER ag1_suppression;");

            // L'époque du compte illisible : aucun ticket émis, puis un ticket déjà émis refusé sans examen du code.
            eprintln!("{PHASE}epoque");
            let code = ag1_mfa_active(&st, "[]");
            let ticket = ag1_ticket(&st).await;
            let cle = crate::session::cle_de_l_epoque_du_compte(AG1_PORTEUR);
            st.db.lock().execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![cle, AG1_EPOQUE_ILLISIBLE]).expect("fixture : époque illisible");
            statuts.push(ag1_reponse(mfa_challenge_response(&st, AG1_PORTEUR, "admin")).await.0);
            statuts.push(ag1_connexion(&st, &ticket, &code).await);
            causes.push(crate::session::epoque_du_compte(&st.db.lock(), AG1_PORTEUR).expect_err("fixture : époque illisible").to_string());
            st.db.lock().execute("DELETE FROM meta WHERE key=?1", params![cle]).expect("fixture : époque rendue");

            // Connexion, frein éteint : liste de secours corrompue ; puis l'écriture de `user_mfa` refusée (code de secours,
            // puis pas TOTP).
            eprintln!("{PHASE}connexion");
            ag1_mfa_active(&st, AG1_LISTE_CORROMPUE);
            let ticket = ag1_ticket(&st).await;
            statuts.push(ag1_connexion(&sans_frein, &ticket, AG1_SECOURS).await);
            let code = ag1_mfa_active(&st, &json!([sha256_hex(AG1_SECOURS.as_bytes())]).to_string());
            ag1_sql(&st, &format!("CREATE TRIGGER ag1_consommation BEFORE UPDATE ON user_mfa BEGIN SELECT RAISE(ABORT,'{AG1_MOTEUR_CONSOMMATION}'); END;"));
            let ticket = ag1_ticket(&st).await;
            statuts.push(ag1_connexion(&sans_frein, &ticket, AG1_SECOURS).await);
            let ticket = ag1_ticket(&st).await;
            statuts.push(ag1_connexion(&sans_frein, &ticket, &code).await);
            ag1_sql(&st, "DROP TRIGGER ag1_consommation;");

            // Le nominal : connexion acceptée, frein armé.
            eprintln!("{PHASE}calme");
            let code = ag1_mfa_active(&st, "[]");
            let ticket = ag1_ticket(&st).await;
            statuts.push(ag1_connexion(&st, &ticket, &code).await);

            eprintln!("{PHASE}echange");
            let (statut, corps) = ag1_reponse(refus_de_l_echange_de_code(AG1_FOURNISSEUR, AG1_STATUT_IDP)).await;
            statuts.push(statut);
            println!("AG1-CORPS-ECHANGE:{corps}");
            eprintln!("{PHASE}fin");
            println!("AG1-STATUTS:{}", statuts.iter().map(u16::to_string).collect::<Vec<_>>().join(":"));
            println!("AG1-CAUSES:{}", json!(causes));
            let compte: i64 = st.db.lock().query_row("SELECT id FROM user WHERE name=?1", params![AG1_PORTEUR], |r| r.get(0)).expect("fixture : identifiant");
            println!("AG1-COMPTE:{compte}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::compte_au_journal_du_second_facteur_et_refus_de_l_echange_de_code::ag1_lignes_de_journal",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> String {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").to_string()
        };
        let statuts: Vec<String> = marque("AG1-STATUTS:").split(':').map(str::to_string).collect();
        assert_eq!(
            statuts,
            ["503", "503", "503", "503", "503", "503", "200", "503", "503", "401", "503", "503", "503", "200", "401"],
            "contrôle : chaque site atteint, statuts d'avant, nominal accepté"
        );
        let corps: Value = serde_json::from_str(&marque("AG1-CORPS-ECHANGE:")).expect("contrôle : corps du 401");
        assert_eq!(corps, json!({ "error": PHRASE_ECHANGE_DE_CODE_REFUSE }), "le 401 de l'échange de code : la phrase fixe seule");
        let causes: Vec<String> = serde_json::from_str(&marque("AG1-CAUSES:")).expect("contrôle : causes rejouées");
        assert_eq!(causes.len(), 4, "contrôle : quatre causes rejouées : {causes:?}");
        let (begin, hash, liste, epoque) = (&causes[0], &causes[1], &causes[2], &causes[3]);
        let porteur = format!("compte #{}", marque("AG1-COMPTE:"));
        let phase = |nom: &str, motif: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.contains(motif)).map(str::to_string).collect()
        };
        let reservation_refusee = || {
            vec![
                ag1_begin_refuse(&format!("réservation d'un essai du second facteur du {porteur}"), begin),
                format!("[mfa] WARN essai du second facteur du {porteur} NON compté, code non examiné : {begin}"),
            ]
        };
        let attendues: [(&str, Vec<String>); 10] = [
            ("enrolement", vec![format!("[mfa] WARN {porteur} NON lu à l'enrôlement : {hash}")]),
            ("reservation", reservation_refusee()),
            ("reservation_activation", reservation_refusee()),
            ("reservation_connexion", reservation_refusee()),
            (
                "geste",
                vec![
                    ag1_begin_refuse(&format!("désactivation du second facteur du {porteur}"), begin),
                    ag1_begin_refuse(&format!("retour d'un essai du second facteur du {porteur}"), begin),
                    format!("[mfa] WARN essai du second facteur du {porteur} NON rendu (un échec de trop reste compté) : {begin}"),
                ],
            ),
            (
                "secours",
                vec![
                    format!("[mfa] WARN codes de secours du {porteur} NON lus : {liste}"),
                    format!("[mfa] WARN essai du second facteur du {porteur} NON rendu (un échec de trop reste compté) : {AG1_MOTEUR_FREIN}"),
                ],
            ),
            ("remise", vec![format!("[mfa] WARN frein du second facteur du {porteur} NON remis à zéro (ses échecs restent comptés) : {AG1_MOTEUR_FREIN}")]),
            ("suppression", vec![format!("[mfa] WARN désactivation du {porteur} NON écrite : {AG1_MOTEUR_SUPPRESSION}")]),
            (
                "epoque",
                vec![
                    format!("[mfa] WARN époque du {porteur} NON lue, aucun ticket émis : {epoque}"),
                    format!("[mfa] WARN époque du {porteur} NON lue, ticket refusé sans examen du code : {epoque}"),
                ],
            ),
            (
                "connexion",
                vec![
                    format!("[mfa] WARN codes de secours du {porteur} NON lus : {liste}"),
                    format!("[mfa] WARN code de secours du {porteur} NON consommé : {AG1_MOTEUR_CONSOMMATION}"),
                    format!("[mfa] WARN pas TOTP du {porteur} NON consommé : {AG1_MOTEUR_CONSOMMATION}"),
                ],
            ),
        ];
        assert!(attendues.len() >= 10, "plancher : dix phases");
        for (nom, lignes) in &attendues {
            let nom: &str = nom;
            assert_eq!(&phase(nom, "[mfa]"), lignes, "phase {nom} : chaque ligne entière, l'identifiant interne seul");
        }
        assert!(phase("calme", "WARN").is_empty() && phase("calme", "ERREUR").is_empty(), "le nominal n'écrit rien : {stderr}");
        assert_eq!(
            phase("echange", "[idp]"),
            [format!("[idp] WARN connexion OIDC (fournisseur #{AG1_FOURNISSEUR}) échouée à l'étape « échange de code » : HTTP {AG1_STATUT_IDP}")],
            "le statut de l'IdP au journal seul, avec le fournisseur et l'étape"
        );
        for (canal, texte) in [("stdout", &stdout), ("stderr", &stderr)] {
            assert!(!texte.contains(AG1_PORTEUR), "{canal} de l'enfant : le nom du compte n'est jamais écrit : {texte}");
        }
    }

    /// Le source de production d'un fichier de `handlers/` (module de témoins coupé).
    fn ag1_source_jugee(source: &str) -> String {
        let prod = source.split("#[cfg(test)]\nmod tests").next().unwrap_or(source);
        prod.to_string()
    }

    /// Le corps d'une fonction du source jugé : de son en-tête à la première accolade fermante en colonne zéro.
    fn ag1_corps_de<'a>(prod: &'a str, entete: &str) -> &'a str {
        assert_eq!(prod.matches(entete).count(), 1, "instrument : `{entete}` une fois dans le source");
        let debut = prod.find(entete).unwrap_or_else(|| panic!("instrument : `{entete}` dans le source"));
        let reste = &prod[debut..];
        &reste[..reste.find("\n}\n").unwrap_or(reste.len())]
    }

    /// Le bloc dont la première ligne porte `ancre` (une fois dans `corps`) : jusqu'à la première ligne `}` de même
    /// retrait, incluse ; espaces normalisés.
    fn ag1_bloc(corps: &str, ancre: &str) -> String {
        assert_eq!(corps.matches(ancre).count(), 1, "instrument : ancre `{ancre}` une fois dans le corps");
        let pos = corps.find(ancre).unwrap_or_else(|| panic!("instrument : ancre `{ancre}` absente"));
        let debut = corps[..pos].rfind('\n').map_or(0, |i| i + 1);
        let retrait = &corps[debut..pos];
        assert!(retrait.trim().is_empty(), "instrument : l'ancre `{ancre}` ouvre sa ligne");
        let fermeture = format!("{retrait}}}");
        let mut fin = corps.len();
        let mut curseur = debut;
        for ligne in corps[debut..].split_inclusive('\n') {
            curseur += ligne.len();
            if ligne.trim_end() == fermeture {
                fin = curseur;
                break;
            }
        }
        corps[debut..fin].split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Les sites que le témoin ne peut pas jouer : (site, fonction, bloc attendu EN ENTIER).
    const AG1_BLOCS_DU_SOURCE: [(&str, &str, &str); 3] = [
        (
            "401 de l'échange de code",
            "pub(crate) async fn oidc_callback(",
            "if !(200..300).contains(&tok_resp.status) { return refus_de_l_echange_de_code(fournisseur.id, tok_resp.status); }",
        ),
        (
            "lignes écrites à l'enrôlement",
            "pub(crate) async fn mfa_enroll(",
            "Ok(n) => { eprintln!(\"[mfa] WARN enrôlement du {} : {n} ligne(s) écrite(s) au lieu d'une\", compte_au_journal(&conn, &au.name)); \
             return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_ENROLEMENT_NON_ECRIT); }",
        ),
        (
            "lignes écrites à l'activation",
            "pub(crate) async fn mfa_verify(",
            "Ok(n) => { eprintln!(\"[mfa] WARN activation du {} : {n} ligne(s) écrite(s) au lieu d'une\", compte_au_journal(&conn, &au.name)); \
             frein::rendre_l_essai(&st, &conn, &au.name, essai); return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_MFA_NON_ACTIVEE); }",
        ),
    ];

    /// CE QU'IL TIENT (lecture du source, faute de point de jeton joignable et d'écriture à plusieurs lignes) : chacun des
    /// trois blocs est, EN ENTIER, celui attendu — aucun bras ajouté avant l'appel, aucun nom au journal — et les formes
    /// d'avant n'existent plus. Rouge sous `AG1_S401_ANCIEN`, `AG1_S401_BRAS`, `AG1_S401_FOURNISSEUR`,
    /// `AG1_SN_ENROLEMENT_ANCIEN`, `AG1_SN_ENROLEMENT_BRAS`, `AG1_SN_ACTIVATION_ANCIEN`, `AG1_SN_ACTIVATION_BRAS`.
    #[test]
    fn ag1_blocs_hors_d_atteinte_compares_en_entier() {
        let prod = ag1_source_jugee(include_str!("../handlers/idp.rs"));
        assert!(AG1_BLOCS_DU_SOURCE.len() >= 3, "plancher : trois blocs");
        for (site, fonction, attendu) in AG1_BLOCS_DU_SOURCE {
            let attendu = attendu.split_whitespace().collect::<Vec<_>>().join(" ");
            let ancre = &attendu[..attendu.find(" {").map(|i| i + 2).unwrap_or(attendu.len())];
            assert_eq!(ag1_bloc(ag1_corps_de(&prod, fonction), ancre), attendu, "site {site} : le bloc entier dans `{fonction}`");
        }
        let anciens = ["échange de code refusé (HTTP", "enrôlement de '", "activation de '"];
        assert!(anciens.len() >= 3, "plancher : trois formes d'avant");
        for ancien in anciens {
            assert!(!prod.contains(ancien), "la forme d'avant `{ancien}` a disparu");
        }
    }

    /// Tout ce qui va de l'appel au point de jeton à la lecture de sa réponse, dans `oidc_callback`, EN ENTIER.
    const AG1_ECHANGE_JUSQU_A_SA_LECTURE: &str = "let tok_resp = match tokio::task::spawn_blocking(move || { \
         ssrf_guard(&token_url)?; // le token_endpoint (config/discovery) est un égress -> garde SSRF \
         http_call(\"POST\", &token_url, &[(\"Content-Type\", \"application/x-www-form-urlencoded\"), (\"Accept\", \"application/json\")], Some(body.as_bytes())) \
         }).await { Ok(Ok(r)) => r, \
         Ok(Err(e)) => return servir_l_echec_de_l_etape(StatusCode::BAD_GATEWAY, PHRASE_ECHANGE_DE_CODE_ECHOUE, \"connexion OIDC\", fournisseur.id, \"échange de code\", &e), \
         Err(_) => return server_err(\"échec interne (token)\"), }; \
         if !(200..300).contains(&tok_resp.status) { return refus_de_l_echange_de_code(fournisseur.id, tok_resp.status); }";

    /// CE QU'IL TIENT (le 401 n'est pas jouable : point de jeton https, garde SSRF) : de `let tok_resp = match` à
    /// `let tok_json`, le source d'`oidc_callback` est EN ENTIER celui attendu — aucun bras ajouté dans le `match` de
    /// l'appel ni entre ce `match` et le 401 —, et la réponse de l'IdP n'est nommée nulle part ailleurs dans la fonction
    /// (quatre mentions : la liaison, les deux du 401, la lecture du corps) : aucun statut resservi plus loin. Rouge sous
    /// `AG1_S401_BRAS_AVANT` (bras avant le 401), `AG1_S401_BRAS_MATCH` (garde dans le `match`), `AG1_S401_APRES` (statut
    /// resservi après la lecture du corps).
    #[test]
    fn ag1_echange_de_code_jusqu_a_sa_lecture_compare_en_entier() {
        let prod = ag1_source_jugee(include_str!("../handlers/idp.rs"));
        let corps = ag1_corps_de(&prod, "pub(crate) async fn oidc_callback(");
        let (debut, fin) = ("let tok_resp = match", "let tok_json");
        assert_eq!((corps.matches(debut).count(), corps.matches(fin).count()), (1, 1), "instrument : bornes une fois chacune");
        let de = corps.find(debut).expect("instrument : borne de début");
        let a = corps.find(fin).expect("instrument : borne de fin");
        assert!(de < a, "instrument : bornes dans l'ordre");
        let segment = corps[de..a].split_whitespace().collect::<Vec<_>>().join(" ");
        let attendu = AG1_ECHANGE_JUSQU_A_SA_LECTURE.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(segment, attendu, "de l'appel au point de jeton à la lecture de sa réponse, le source entier");
        assert_eq!(corps.matches("tok_resp").count(), 4, "la réponse de l'IdP nommée quatre fois, pas une de plus : {corps}");
    }

    /// Les appels `eprintln!(…)` d'un source, arguments ENTIERS même écrits sur plusieurs lignes : parenthèses appariées hors
    /// chaînes (une parenthèse dans le texte du message ne ferme rien).
    fn ag1_appels_eprintln(source: &str) -> Vec<String> {
        let mut appels = Vec::new();
        let mut reste = source;
        while let Some(i) = reste.find("eprintln!(") {
            let apres = &reste[i + "eprintln!(".len()..];
            let (mut profondeur, mut dans_chaine, mut echappe, mut fermante) = (1usize, false, false, None);
            for (k, c) in apres.char_indices() {
                if dans_chaine {
                    if echappe {
                        echappe = false;
                    } else if c == '\\' {
                        echappe = true;
                    } else if c == '"' {
                        dans_chaine = false;
                    }
                    continue;
                }
                match c {
                    '"' => dans_chaine = true,
                    '(' => profondeur += 1,
                    ')' => {
                        profondeur -= 1;
                        if profondeur == 0 {
                            fermante = Some(k);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let fermante = fermante.unwrap_or_else(|| panic!("instrument : un `eprintln!(` jamais refermé : {apres}"));
            appels.push(apres[..fermante].to_string());
            reste = &apres[fermante..];
        }
        appels
    }

    /// Les arguments d'un appel, privés de chaque `compte_au_journal(…)` (parenthèses appariées).
    fn ag1_sans_compte_au_journal(arguments: &str) -> String {
        let mut out = String::new();
        let mut reste = arguments;
        while let Some(i) = reste.find("compte_au_journal(") {
            out.push_str(&reste[..i]);
            let apres = &reste[i + "compte_au_journal(".len()..];
            let mut profondeur = 1usize;
            let mut fin = apres.len();
            for (k, c) in apres.char_indices() {
                match c {
                    '(' => profondeur += 1,
                    ')' => {
                        profondeur -= 1;
                        if profondeur == 0 {
                            fin = k + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            reste = &apres[fin..];
        }
        out.push_str(reste);
        out
    }

    /// CE QU'IL TIENT : dans `idp.rs` et `frein_du_second_facteur.rs`, CHAQUE `eprintln!` dont le message commence par
    /// `[mfa]` — écrit sur une ligne ou sur plusieurs — passe par `compte_au_journal`, n'interpole aucun nom entre
    /// apostrophes, et ne nomme ni `name` ni `user` HORS de `compte_au_journal`, capture du message comprise (vingt-deux appels : les huit de la vague
    /// AF, les dix et les quatre de ce lot). Rouge sous `AG1_SW_NOM` (nom sur une ligne), `AG1_SN_MULTILIGNE` (bras ajouté
    /// avant l'`Ok(n)` de l'enrôlement, `eprintln!` sur plusieurs lignes qui nomme le compte), `AG1_SW_DOUBLE` (le nom
    /// passé EN PLUS de l'identifiant).
    #[test]
    fn ag1_chaque_ligne_mfa_du_source_dit_l_identifiant() {
        let sources = [ag1_source_jugee(include_str!("../handlers/idp.rs")), ag1_source_jugee(include_str!("../handlers/frein_du_second_facteur.rs"))];
        let appels: Vec<String> = sources.iter().flat_map(|s| ag1_appels_eprintln(s)).filter(|a| a.trim_start().starts_with("\"[mfa]")).collect();
        assert!(appels.len() >= 22, "plancher : vingt-deux appels `[mfa]` : {}", appels.len());
        for appel in &appels {
            assert!(appel.contains("compte_au_journal("), "appel `[mfa]` sans l'identifiant interne : {appel}");
            assert!(!appel.contains("'{"), "appel `[mfa]` qui interpole un nom : {appel}");
            // Message compris : une capture `{user}` écrite dans le texte du message est un nom passé, elle aussi.
            let hors_identifiant = ag1_sans_compte_au_journal(appel);
            let jetons: Vec<&str> = hors_identifiant.split(|c: char| !(c.is_alphanumeric() || c == '_')).collect();
            assert!(!jetons.iter().any(|j| *j == "name" || *j == "user"), "appel `[mfa]` qui passe le compte hors de l'identifiant : {appel}");
        }
    }
}
