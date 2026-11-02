// =====================================================================================
// `P10.20-b` (reste des instantanés) — UNE VENTILATION PAR MACHINE COUPÉE À SA BORNE LE DIT, ET LA TAILLE DU PARC
// SERVIE N'EST PAS LA LONGUEUR DE LA LISTE COUPÉE.
//
// LE DÉFAUT, RELU SUR LA BASE AVANT LE CORRECTIF. `dernier_instantane_par_hote` (`ingest/store.rs`) s'arrêtait à
// `max` machines et rendait la fin `Complet` sans rien d'autre ; `panel` (`handlers/overview.rs`) servait alors
// `n_hosts: hosts.len()` et `suppressions_get` (`handlers/admin_ui.rs`) `firewall_n_hosts: firewall_hosts.len()`, soit
// cinq cents pour un parc de cinq cent une machines, sans un mot : un plafond atteint se lisait comme le parc entier.
//
// LE CORRECTIF. La même requête compte les machines du genre (`COUNT(*) OVER ()` dans la sous-requête groupée par
// hôte) ; `coupee_a_la_borne` vaut vrai quand la liste rend sa borne ET que le genre compte davantage de machines ;
// `taille_du_parc` rend ce nombre quand la liste est coupée, la longueur sinon, `None` sur une fin non complète. Les
// deux routes servent cette taille (`n_hosts`, `firewall_n_hosts`) et disent la coupe par une clé neuve, absente quand
// la liste est entière : `hosts_borne` et `firewall_hosts_borne`, valeur la borne (cinq cents).
//
// PAR LA ROUTE : routeur réel (`build_router`), jeton du rôle le plus faible admis — `viewer` pour `GET /api/panel/{kind}`,
// l'administrateur pour `GET /api/suppressions` ; corps ENTIERS (le panneau à l'égalité de valeur, les suppressions par
// l'ensemble de leurs clés et la valeur de chaque clé `firewall*`). Les fixtures portent un instantané ANCIEN pour
// quelques machines : le nombre servi est celui des MACHINES, pas celui des lignes de `snapshot`.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit), chacun vu ROUGE : BF4_TOTAL_DE_LA_LISTE (store : le
// nombre de machines remplacé par celui des machines rendues), BF4_COUPEE_SANS_BORNE (la coupe sans la condition de
// borne : une lecture interrompue se dirait coupée), BF4_COUPEE_PILE (`>=` au lieu de `>` : une liste PILE à la borne
// se dirait coupée), BF4_PANEL_TAILLE_DE_LA_LISTE, BF4_PANEL_SANS_BORNE, BF4_FW_TAILLE_DE_LA_LISTE, BF4_FW_SANS_BORNE.
// Correction (liste coupée ET interrompue — une ligne illisible n'arrête pas la lecture, la borne reste atteignable — et
// doublon exact `(host, ts)` à la date max), mutants vus ROUGES : C1_TAILLE_SANS_FIN (`taille_du_parc` ignore la fin),
// C1_FW_N_SANS_FIN (`firewall_n_hosts` = `machines_du_genre`), C1_PANEL_BORNE_SI_COMPLET et C1_FW_BORNE_SI_COMPLET (la
// borne tue quand la fin n'est pas complète), C1_SQL_EXTERNE (`COUNT(*) OVER ()` dans la requête externe : les lignes à
// la date max, pas les machines).
// Reprise (vague BG) — LES BORDS, LE GENRE, LA SÉRIE SANS HÔTE, AUX DEUX ROUTES. (a) Une liste qui atteint PILE sa borne
// après une ligne illisible sautée, sans machine au-delà, se disait coupée : `coupee_a_la_borne` compte désormais les
// machines VUES (rendues plus lignes illisibles sautées) ; une liste interrompue par une erreur de `step()` après BORNE-1
// machines (crochet de test `crochet_d_interruption_des_instantanes`, `ingest/store.rs`) n'est pas coupée ; BORNE
// lisibles avec une ligne illisible derrière la borne, jamais lue, est coupée et la compte. (b) Quatre machines d'un
// autre genre ne comptent jamais. (c) La série SANS HÔTE compte pour une machine (règle : la liste la porte comme une
// entrée `host` nul, le compte aussi). (d) Les suppressions interrompues sous la borne ne portent pas
// `firewall_hosts_borne`. Limite écrite et témoignée : un double illisible exact `(host, ts)` d'une machine rendue tait
// la coupe (lecture déjà dite interrompue, dénominateur nul). Mutants vus ROUGES : BG1_COUPEE_BORNE_MOINS_UN
// (`rendues + 1 >= borne`), BG1_COUPEE_SANS_ILLISIBLES (les lignes illisibles sautées ignorées), BG1_SQL_TOUS_GENRES
// (machines de tous les genres), BG1_SQL_COUNT_HOST (`COUNT(host)` : la série sans hôte ignorée),
// BG1_FW_BORNE_SI_INTERROMPU et BG1_PANEL_BORNE_SI_INTERROMPU (la borne dite sur toute lecture interrompue),
// BG1_CROCHET_INERTE (le crochet n'interrompt rien : le cas BORNE-1 perd son interruption).
// Correction de la reprise : (e) l'armement de l'`InterruptHandle` du crochet vivait dans `ingest/store.rs` et faisait
// rougir la garde `budget_guard_is_the_only_way_to_arm_an_interrupt` ; il vit ici (`pcb_armer_l_interruption`), le
// module de `store.rs` ne fait qu'appeler la fonction enregistrée. (f) Deux lignes illisibles sautées avant la borne
// comptent pour deux machines vues. Mutants vus ROUGES : BG1C_ILLISIBLES_BOOL (`(erreurs > 0) as usize`, deux lignes
// comptées pour une), BG1C_CROCHET_NON_JOUE (la fonction enregistrée n'est pas appelée) ; et la garde rougit sur une
// ligne `get_interrupt_handle().interrupt()` posée hors de `src/tests/`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ce que la console peint de `hosts_borne` / `firewall_hosts_borne` (elle ne les
// lit pas encore ; `n_hosts` et `firewall_n_hosts` gardent leur sens et sont peints comme avant, « 1 machine sur N ») ;
// la mise en page.
// =====================================================================================
mod parc_coupe_a_sa_borne_dit_sa_taille {
    use super::*;

    const PCB_ADMIN: &str = "root:rootpw1234567";
    /// La borne attendue des deux routes, écrite ici en littéral (jamais relue de la production).
    const PCB_BORNE: usize = 500;

    fn pcb_admin() -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(PCB_ADMIN))
    }

    /// `n` machines du genre `kind` : `srv-0001` la plus fraîche (ts 100000 - i), et, pour les trois premières, un
    /// instantané ANCIEN en plus (même machine, ts 1) — des lignes de `snapshot` qui ne sont pas des machines de plus.
    fn pcb_semer(st: &AppState, kind: &str, n: usize) {
        st.db
            .lock()
            .execute_batch(&format!(
                "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i<{n}) \
                 INSERT INTO snapshot(ts,kind,hash,data,host) \
                 SELECT 100000-i,'{kind}','h-'||i,'{{}}','srv-'||printf('%04d',i) FROM s; \
                 INSERT INTO snapshot(ts,kind,hash,data,host) \
                 SELECT 1,'{kind}','vieux','{{}}',host FROM snapshot WHERE kind='{kind}' AND host IN ('srv-0001','srv-0002','srv-0003');"
            ))
            .expect("fixture : parc semé");
    }

    /// Une ligne ILLISIBLE (empreinte binaire, la cellule n'est pas une chaîne) pour la machine `srv-zzzz`, PLUS FRAÎCHE
    /// que tout le parc : elle passe la première, la lecture la compte comme erreur et CONTINUE — la liste peut alors
    /// atteindre sa borne avec une fin interrompue. Elle compte parmi les machines du genre (sa cellule n'est pas lue).
    fn pcb_semer_illisible(st: &AppState, kind: &str) {
        st.db
            .lock()
            .execute_batch(&format!("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(200000,'{kind}',X'00ff','{{}}','srv-zzzz');"))
            .expect("fixture : ligne illisible");
    }

    /// Un DOUBLON EXACT `(host, ts)` à la date la plus fraîche de `srv-0001` (même empreinte, même contenu) : deux lignes
    /// de `snapshot` à la date max pour UNE machine, que la lecture réduit au premier vu.
    fn pcb_semer_doublon_frais(st: &AppState, kind: &str) {
        st.db
            .lock()
            .execute_batch(&format!("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(99999,'{kind}','h-1','{{}}','srv-0001');"))
            .expect("fixture : doublon à la date max");
    }

    /// Ce que le panneau doit lister pour les `k` premières machines.
    fn pcb_machines_du_panneau(k: usize) -> Vec<Value> {
        (1..=k)
            .map(|i| json!({ "host": format!("srv-{i:04}"), "ts": 100_000 - i as i64, "hash": format!("h-{i}"), "data": {} }))
            .collect()
    }

    fn pcb_machines_du_pare_feu(k: usize) -> Vec<Value> {
        (1..=k).map(|i| json!({ "host": format!("srv-{i:04}"), "ts": 100_000 - i as i64, "data": {} })).collect()
    }

    /// Statut, corps servi (recollé s'il est découpé), corps lu.
    async fn pcb_appel(addr: std::net::SocketAddr, chemin: &str, qui: &str) -> (u16, String, Value) {
        let (statut, brut) = router_probe_envoi(addr, "GET", chemin, Some(qui), &[], "").await;
        let (tete, apres) = brut.split_once("\r\n\r\n").unwrap_or(("", ""));
        let c = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            let (mut out, mut reste) = (String::new(), apres);
            while let Some((taille, suite)) = reste.split_once("\r\n") {
                let n = usize::from_str_radix(taille.trim(), 16).unwrap_or(0);
                if n == 0 || suite.len() < n {
                    break;
                }
                out.push_str(&suite[..n]);
                reste = suite[n..].strip_prefix("\r\n").unwrap_or(&suite[n..]);
            }
            out
        } else {
            apres.to_string()
        };
        let v: Value = serde_json::from_str(&c).unwrap_or_else(|e| panic!("{chemin} : corps JSON entier attendu ({e}) : {}", &c[..c.len().min(300)]));
        (statut, c, v)
    }

    fn pcb_cles(v: &Value) -> std::collections::BTreeSet<String> {
        v.as_object().expect("objet").keys().cloned().collect()
    }

    /// LE PANNEAU COUPÉ : cinq cent une machines, la liste en rend cinq cents, `n_hosts` vaut 501, `hosts_borne` 500.
    #[tokio::test]
    async fn pcb_le_panneau_coupe_dit_sa_borne_et_la_taille_du_parc() {
        let (st, _p) = router_test_state("pcb-panneau-coupe");
        pcb_semer(&st, "firewall", PCB_BORNE + 1);
        let addr = router_serve(st.clone()).await;
        let (statut, brut, v) = pcb_appel(addr, "/api/panel/firewall", &viewer_authz()).await;
        assert_eq!(statut, 200, "{}", &brut[..brut.len().min(300)]);
        let attendu = json!({
            "kind": "firewall", "ts": 99_999, "hash": "h-1", "host": "srv-0001", "data": {},
            "hosts": pcb_machines_du_panneau(PCB_BORNE), "n_hosts": PCB_BORNE + 1, "hosts_borne": PCB_BORNE
        });
        assert_eq!(pcb_cles(&v), pcb_cles(&attendu), "ensemble exact des clés");
        assert_eq!(v["n_hosts"], json!(501), "la taille du parc, pas la longueur de la liste coupée");
        assert_eq!(v["hosts_borne"], json!(500), "la coupe est dite");
        assert_eq!(v, attendu, "corps entier");
    }

    /// PILE À LA BORNE : cinq cents machines, rien n'est coupé — ni `hosts_borne`, ni autre taille que la liste.
    #[tokio::test]
    async fn pcb_le_panneau_pile_a_la_borne_n_avoue_rien() {
        let (st, _p) = router_test_state("pcb-panneau-pile");
        pcb_semer(&st, "firewall", PCB_BORNE);
        let addr = router_serve(st.clone()).await;
        let (statut, brut, v) = pcb_appel(addr, "/api/panel/firewall", &viewer_authz()).await;
        assert_eq!(statut, 200, "{}", &brut[..brut.len().min(300)]);
        let attendu = json!({
            "kind": "firewall", "ts": 99_999, "hash": "h-1", "host": "srv-0001", "data": {},
            "hosts": pcb_machines_du_panneau(PCB_BORNE), "n_hosts": PCB_BORNE
        });
        assert_eq!(pcb_cles(&v), pcb_cles(&attendu), "chemin d'une liste entière : aucune clé neuve");
        assert_eq!(v, attendu, "corps entier");
    }

    /// INTERROMPU SOUS LA BORNE : une ligne illisible sur quatre machines. La lecture est partielle (`hosts_etat`,
    /// `n_hosts` nul), elle n'est pas coupée : le genre compte plus de machines que la liste n'en rend, mais la liste
    /// n'a pas atteint sa borne — `hosts_borne` reste absente.
    #[tokio::test]
    async fn pcb_le_panneau_interrompu_sous_la_borne_ne_se_dit_pas_coupe() {
        let (st, _p) = router_test_state("pcb-panneau-interrompu");
        pcb_semer(&st, "controls", 3);
        st.db
            .lock()
            .execute_batch("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(90000,'controls',X'00ff','{}','srv-zzzz');")
            .expect("fixture : ligne illisible");
        let addr = router_serve(st.clone()).await;
        let (statut, brut, v) = pcb_appel(addr, "/api/panel/controls", &viewer_authz()).await;
        assert_eq!(statut, 200, "{}", &brut[..brut.len().min(300)]);
        let attendu = json!({
            "kind": "controls", "ts": 99_999, "hash": "h-1", "host": "srv-0001", "data": {},
            "hosts": pcb_machines_du_panneau(3), "n_hosts": null, "hosts_etat": "interrompu"
        });
        assert_eq!(v, attendu, "corps entier : partiel, pas coupé");
    }

    /// COUPÉ ET INTERROMPU : la ligne illisible passe la première, puis cinq cents machines lisibles remplissent la liste.
    /// La coupe reste un fait (`hosts_borne`), la lecture reste partielle (`hosts_etat`) et le dénominateur n'est pas
    /// établi (`n_hosts` nul) — ni le nombre de machines du genre (502), ni la longueur de la liste (500).
    #[tokio::test]
    async fn pcb_le_panneau_coupe_et_interrompu_dit_les_deux() {
        let (st, _p) = router_test_state("pcb-panneau-coupe-interrompu");
        pcb_semer(&st, "firewall", PCB_BORNE + 1);
        pcb_semer_illisible(&st, "firewall");
        let addr = router_serve(st.clone()).await;
        let (statut, brut, v) = pcb_appel(addr, "/api/panel/firewall", &viewer_authz()).await;
        assert_eq!(statut, 200, "{}", &brut[..brut.len().min(300)]);
        let attendu = json!({
            "kind": "firewall", "ts": 99_999, "hash": "h-1", "host": "srv-0001", "data": {},
            "hosts": pcb_machines_du_panneau(PCB_BORNE), "n_hosts": null, "hosts_borne": PCB_BORNE,
            "hosts_etat": "interrompu"
        });
        assert_eq!(v["hosts_borne"], json!(500), "la coupe se dit aussi quand la lecture est interrompue");
        assert_eq!(v["n_hosts"], Value::Null, "lecture interrompue : dénominateur non établi");
        assert_eq!(v, attendu, "corps entier");
    }

    /// DOUBLON À LA DATE MAX : cinq cent une machines, `srv-0001` porte deux lignes à sa date la plus fraîche. Le nombre
    /// servi est celui des MACHINES (501), pas celui des lignes à la date max (502) ; le corps est celui du parc coupé.
    #[tokio::test]
    async fn pcb_le_panneau_compte_les_machines_pas_les_doublons_a_la_date_max() {
        let (st, _p) = router_test_state("pcb-panneau-doublon");
        pcb_semer(&st, "firewall", PCB_BORNE + 1);
        pcb_semer_doublon_frais(&st, "firewall");
        let addr = router_serve(st.clone()).await;
        let (statut, brut, v) = pcb_appel(addr, "/api/panel/firewall", &viewer_authz()).await;
        assert_eq!(statut, 200, "{}", &brut[..brut.len().min(300)]);
        let attendu = json!({
            "kind": "firewall", "ts": 99_999, "hash": "h-1", "host": "srv-0001", "data": {},
            "hosts": pcb_machines_du_panneau(PCB_BORNE), "n_hosts": PCB_BORNE + 1, "hosts_borne": PCB_BORNE
        });
        assert_eq!(v["n_hosts"], json!(501), "machines, pas lignes à la date max");
        assert_eq!(v, attendu, "corps entier");
    }

    /// Ce qu'on ajoute au parc semé avant d'appeler la route.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum PcbAjout {
        Rien,
        /// Une ligne illisible PLUS FRAÎCHE que le parc (`srv-zzzz`) : lue la première, sautée, la lecture continue.
        Illisible,
        /// Une ligne illisible PLUS ANCIENNE que le parc (`srv-yyyy`, ts 50) : derrière la borne, jamais lue.
        IllisibleAuDela,
        DoublonFrais,
        /// La série SANS HÔTE (`host` NULL), plus ancienne que le parc (ts 50) : une machine de plus, derrière la borne.
        SansHote,
        /// Quatre machines d'un AUTRE genre (`controls`, `aut-0001`..`aut-0004`, plus fraîches que le parc) : elles ne
        /// comptent jamais parmi les machines du pare-feu.
        AutreGenre,
    }

    /// Un cas joué par la route : `n` machines lisibles semées, un ajout, une interruption de `step()` armée après
    /// `interrompre_apres` machines rendues (crochet de test de `ingest/store.rs`), et la coupe attendue.
    #[derive(Clone, Copy, Debug)]
    struct PcbCas {
        n: usize,
        ajout: PcbAjout,
        interrompre_apres: Option<usize>,
        coupe: bool,
    }

    impl PcbCas {
        fn simple(n: usize, ajout: PcbAjout, coupe: bool) -> Self {
            PcbCas { n, ajout, interrompre_apres: None, coupe }
        }
        fn interrompu(&self) -> bool {
            self.ajout == PcbAjout::Illisible || self.interrompre_apres.is_some()
        }
        /// Les machines que la liste rend (les `srv-NNNN` les plus fraîches).
        fn rendues(&self) -> usize {
            self.interrompre_apres.unwrap_or(PCB_BORNE.min(self.n))
        }
        /// Les machines DU GENRE `firewall` dans la base.
        fn machines(&self) -> usize {
            self.n + matches!(self.ajout, PcbAjout::Illisible | PcbAjout::IllisibleAuDela | PcbAjout::SansHote) as usize
        }
        /// Le dénominateur servi : nul sur une lecture interrompue, le nombre de machines si coupée, la liste sinon.
        fn denominateur(&self) -> Value {
            if self.interrompu() {
                Value::Null
            } else if self.coupe {
                json!(self.machines())
            } else {
                json!(self.rendues())
            }
        }
    }

    /// Les interruptions armées : `(chemin de la base, machines rendues)`, chacune consommée au premier passage.
    static PCB_INTERRUPTIONS_ARMEES: std::sync::Mutex<Vec<(String, usize)>> = std::sync::Mutex::new(Vec::new());

    /// Arme une interruption de `step()` sur UNE base (son chemin) après `rendues` machines rendues, et enregistre auprès
    /// de `ingest/store.rs` la fonction qui la joue. L'armement de l'`InterruptHandle` vit ici, sous `src/tests/` : c'est
    /// la seule place que la garde `budget_guard_is_the_only_way_to_arm_an_interrupt` laisse hors des deux mécanismes.
    fn pcb_armer_l_interruption(chemin: &str, rendues: usize) {
        assert!(!chemin.is_empty(), "crochet : une base en mémoire n'a pas de chemin propre");
        crate::ingest::store::crochet_d_interruption_des_instantanes::enregistrer(pcb_jouer_l_interruption);
        PCB_INTERRUPTIONS_ARMEES.lock().unwrap_or_else(|e| e.into_inner()).push((chemin.to_string(), rendues));
    }

    fn pcb_jouer_l_interruption(conn: &rusqlite::Connection, rendues: usize) {
        let chemin = conn.path().unwrap_or_default();
        let mut armes = PCB_INTERRUPTIONS_ARMEES.lock().unwrap_or_else(|e| e.into_inner());
        let Some(i) = armes.iter().position(|(c, k)| !chemin.is_empty() && c == chemin && *k == rendues) else {
            return;
        };
        armes.remove(i);
        conn.get_interrupt_handle().interrupt();
    }

    fn pcb_preparer(st: &AppState, cas: PcbCas) {
        pcb_semer(st, "firewall", cas.n);
        match cas.ajout {
            PcbAjout::Rien => {}
            PcbAjout::Illisible => pcb_semer_illisible(st, "firewall"),
            PcbAjout::IllisibleAuDela => {
                st.db
                    .lock()
                    .execute_batch("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(50,'firewall',X'00ff','{}','srv-yyyy');")
                    .expect("fixture : ligne illisible au-delà de la borne");
            }
            PcbAjout::DoublonFrais => pcb_semer_doublon_frais(st, "firewall"),
            PcbAjout::SansHote => {
                st.db
                    .lock()
                    .execute_batch("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(50,'firewall','h-nul','{}',NULL);")
                    .expect("fixture : série sans hôte");
            }
            PcbAjout::AutreGenre => {
                st.db
                    .lock()
                    .execute_batch(
                        "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES \
                         (300001,'controls','c-1','{}','aut-0001'),(300002,'controls','c-2','{}','aut-0002'), \
                         (300003,'controls','c-3','{}','aut-0003'),(300004,'controls','c-4','{}','aut-0004');",
                    )
                    .expect("fixture : autre genre");
            }
        }
        if let Some(k) = cas.interrompre_apres {
            let chemin = st.db.lock().path().expect("base sur fichier").to_string();
            pcb_armer_l_interruption(&chemin, k);
        }
    }

    /// LE PANNEAU, corps entier à l'égalité de valeur, par la route et le jeton `viewer`.
    async fn pcb_juger_le_panneau(cas: PcbCas) {
        let (st, _p) = router_test_state(&format!("pcb-panneau-{}-{}-{}", cas.n, cas.ajout as u8, cas.interrompre_apres.unwrap_or(0)));
        pcb_preparer(&st, cas);
        let addr = router_serve(st.clone()).await;
        let (statut, brut, v) = pcb_appel(addr, "/api/panel/firewall", &viewer_authz()).await;
        assert_eq!(statut, 200, "{cas:?} : {}", &brut[..brut.len().min(300)]);
        let mut attendu = json!({
            "kind": "firewall", "ts": 99_999, "hash": "h-1", "host": "srv-0001", "data": {},
            "hosts": pcb_machines_du_panneau(cas.rendues()), "n_hosts": cas.denominateur()
        });
        if cas.coupe {
            attendu["hosts_borne"] = json!(500);
        }
        if cas.interrompu() {
            attendu["hosts_etat"] = json!("interrompu");
        }
        assert_eq!(pcb_cles(&v), pcb_cles(&attendu), "{cas:?} : ensemble exact des clés");
        assert_eq!(v["n_hosts"], cas.denominateur(), "{cas:?} : dénominateur");
        assert_eq!(v, attendu, "{cas:?} : corps entier");
    }

    /// LES SUPPRESSIONS : ensemble exact des clés, et chaque clé `firewall*` à sa valeur, par la route et l'administrateur.
    async fn pcb_juger_les_suppressions_du_cas(cas: PcbCas) {
        let (st, _p) = router_test_state(&format!("pcb-suppressions-{}-{}-{}", cas.n, cas.ajout as u8, cas.interrompre_apres.unwrap_or(0)));
        pcb_preparer(&st, cas);
        let addr = router_serve(st.clone()).await;
        let (statut, brut, v) = pcb_appel(addr, "/api/suppressions", &pcb_admin()).await;
        assert_eq!(statut, 200, "{cas:?} : {}", &brut[..brut.len().min(300)]);
        let mut attendues: std::collections::BTreeSet<String> = [
            "ok", "generated", "daemon", "collectors", "collectors_incomplets", "collectors_cause", "collectors_etat",
            "firewall", "firewall_hosts", "firewall_n_hosts", "firewall_incomplets", "firewall_etat", "legend",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        if cas.coupe {
            attendues.insert("firewall_hosts_borne".into());
        }
        assert_eq!(pcb_cles(&v), attendues, "{cas:?} : ensemble exact des clés");
        let firewall: std::collections::BTreeMap<String, Value> = v
            .as_object()
            .expect("objet")
            .iter()
            .filter(|(k, _)| k.starts_with("firewall"))
            .map(|(k, x)| (k.clone(), x.clone()))
            .collect();
        let machines = pcb_machines_du_pare_feu(cas.rendues());
        let mut attendu: std::collections::BTreeMap<String, Value> = [
            ("firewall", machines[0].clone()),
            ("firewall_hosts", Value::Array(machines)),
            ("firewall_n_hosts", cas.denominateur()),
            ("firewall_incomplets", json!(cas.interrompu())),
            ("firewall_etat", if cas.interrompu() { json!("interrompu") } else { Value::Null }),
        ]
        .into_iter()
        .map(|(k, x)| (k.to_string(), x))
        .collect();
        if cas.coupe {
            attendu.insert("firewall_hosts_borne".into(), json!(500));
        }
        assert_eq!(v["firewall_n_hosts"], cas.denominateur(), "{cas:?} : dénominateur");
        assert_eq!(firewall, attendu, "{cas:?} : chaque clé du pare-feu à sa valeur");
    }

    async fn pcb_juger_les_suppressions(n: usize, coupe: bool) {
        pcb_juger_les_suppressions_du_cas(PcbCas::simple(n, PcbAjout::Rien, coupe)).await;
    }

    async fn pcb_juger_les_suppressions_avec(n: usize, coupe: bool, ajout: PcbAjout) {
        pcb_juger_les_suppressions_du_cas(PcbCas::simple(n, ajout, coupe)).await;
    }

    #[tokio::test]
    async fn pcb_les_suppressions_coupees_disent_la_borne_et_la_taille_du_parc() {
        pcb_juger_les_suppressions(PCB_BORNE + 1, true).await;
    }

    #[tokio::test]
    async fn pcb_les_suppressions_pile_a_la_borne_n_avouent_rien() {
        pcb_juger_les_suppressions(PCB_BORNE, false).await;
    }

    #[tokio::test]
    async fn pcb_les_suppressions_coupees_et_interrompues_disent_la_borne_sans_denominateur() {
        pcb_juger_les_suppressions_avec(PCB_BORNE + 1, true, PcbAjout::Illisible).await;
    }

    #[tokio::test]
    async fn pcb_les_suppressions_comptent_les_machines_pas_les_doublons_a_la_date_max() {
        pcb_juger_les_suppressions_avec(PCB_BORNE + 1, true, PcbAjout::DoublonFrais).await;
    }

    /// INTERROMPU SOUS LA BORNE, SUPPRESSIONS : trois machines et une ligne illisible. La lecture est partielle
    /// (`firewall_etat`, `firewall_n_hosts` nul), elle n'est pas coupée : `firewall_hosts_borne` reste absente.
    #[tokio::test]
    async fn pcb_les_suppressions_interrompues_sous_la_borne_ne_se_disent_pas_coupees() {
        pcb_juger_les_suppressions_avec(3, false, PcbAjout::Illisible).await;
    }

    // ---- BORDS DE LA COUPE, aux deux routes. Une liste interrompue par une erreur de `step()` après BORNE-1 machines
    // (le genre en compte BORNE+1) n'a pas atteint sa borne : pas coupée. Une liste qui atteint PILE sa borne après une
    // ligne illisible sautée (le genre compte BORNE+1 machines, toutes vues) : pas coupée. BORNE lisibles et une ligne
    // illisible derrière la borne : coupée (la ligne n'a pas été lue). BORNE+1 lisibles et une ligne illisible lue : coupée.

    /// Le parcours interrompu par `step()` après BORNE-1 machines rendues, sur un genre de BORNE+1 machines.
    fn pcb_cas_interrompu_a_borne_moins_un() -> PcbCas {
        PcbCas { n: PCB_BORNE + 1, ajout: PcbAjout::Rien, interrompre_apres: Some(PCB_BORNE - 1), coupe: false }
    }

    #[tokio::test]
    async fn pcb_le_panneau_interrompu_a_borne_moins_un_ne_se_dit_pas_coupe() {
        pcb_juger_le_panneau(pcb_cas_interrompu_a_borne_moins_un()).await;
    }

    #[tokio::test]
    async fn pcb_les_suppressions_interrompues_a_borne_moins_un_ne_se_disent_pas_coupees() {
        pcb_juger_les_suppressions_du_cas(pcb_cas_interrompu_a_borne_moins_un()).await;
    }

    #[tokio::test]
    async fn pcb_le_panneau_pile_a_la_borne_apres_une_ligne_illisible_ne_se_dit_pas_coupe() {
        pcb_juger_le_panneau(PcbCas::simple(PCB_BORNE, PcbAjout::Illisible, false)).await;
    }

    #[tokio::test]
    async fn pcb_les_suppressions_pile_a_la_borne_apres_une_ligne_illisible_ne_se_disent_pas_coupees() {
        pcb_juger_les_suppressions_du_cas(PcbCas::simple(PCB_BORNE, PcbAjout::Illisible, false)).await;
    }

    #[tokio::test]
    async fn pcb_le_panneau_a_borne_moins_un_apres_une_ligne_illisible_ne_se_dit_pas_coupe() {
        pcb_juger_le_panneau(PcbCas::simple(PCB_BORNE - 1, PcbAjout::Illisible, false)).await;
    }

    #[tokio::test]
    async fn pcb_les_suppressions_a_borne_moins_un_apres_une_ligne_illisible_ne_se_disent_pas_coupees() {
        pcb_juger_les_suppressions_du_cas(PcbCas::simple(PCB_BORNE - 1, PcbAjout::Illisible, false)).await;
    }

    #[tokio::test]
    async fn pcb_le_panneau_coupe_avant_une_ligne_illisible_non_lue_la_compte() {
        pcb_juger_le_panneau(PcbCas::simple(PCB_BORNE, PcbAjout::IllisibleAuDela, true)).await;
    }

    #[tokio::test]
    async fn pcb_les_suppressions_coupees_avant_une_ligne_illisible_non_lue_la_comptent() {
        pcb_juger_les_suppressions_du_cas(PcbCas::simple(PCB_BORNE, PcbAjout::IllisibleAuDela, true)).await;
    }

    // ---- LE COMPTE EST CELUI DU GENRE. Quatre machines d'un autre genre semées : pile à la borne, le pare-feu n'est pas
    // coupé ; au-delà, il compte ses seules machines.

    #[tokio::test]
    async fn pcb_le_panneau_pile_a_la_borne_ne_compte_pas_un_autre_genre() {
        pcb_juger_le_panneau(PcbCas::simple(PCB_BORNE, PcbAjout::AutreGenre, false)).await;
    }

    #[tokio::test]
    async fn pcb_le_panneau_coupe_ne_compte_que_son_genre() {
        pcb_juger_le_panneau(PcbCas::simple(PCB_BORNE + 1, PcbAjout::AutreGenre, true)).await;
    }

    #[tokio::test]
    async fn pcb_les_suppressions_pile_a_la_borne_ne_comptent_pas_un_autre_genre() {
        pcb_juger_les_suppressions_du_cas(PcbCas::simple(PCB_BORNE, PcbAjout::AutreGenre, false)).await;
    }

    #[tokio::test]
    async fn pcb_les_suppressions_coupees_ne_comptent_que_leur_genre() {
        pcb_juger_les_suppressions_du_cas(PcbCas::simple(PCB_BORNE + 1, PcbAjout::AutreGenre, true)).await;
    }

    // ---- LA SÉRIE SANS HÔTE COMPTE POUR UNE MACHINE (règle tenue : la liste la porte comme une entrée, `host` nul, et
    // le compte la porte aussi). Cinq cents machines nommées plus la série sans hôte derrière la borne : coupée, 501.

    #[tokio::test]
    async fn pcb_le_panneau_compte_la_serie_sans_hote() {
        pcb_juger_le_panneau(PcbCas::simple(PCB_BORNE, PcbAjout::SansHote, true)).await;
    }

    #[tokio::test]
    async fn pcb_les_suppressions_comptent_la_serie_sans_hote() {
        pcb_juger_les_suppressions_du_cas(PcbCas::simple(PCB_BORNE, PcbAjout::SansHote, true)).await;
    }

    /// La série sans hôte DANS la liste (plus fraîche que tout) : une entrée `host` nul, comptée comme une machine.
    #[test]
    fn pcb_la_lecture_porte_la_serie_sans_hote_comme_une_machine() {
        let (st, _p) = router_test_state("pcb-lecture-sans-hote");
        let conn = st.db.lock();
        conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(2000,'fw','h-nul','{}',NULL)", []).unwrap();
        for (i, h) in ["srv-a", "srv-b"].iter().enumerate() {
            conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,'fw','h','{}',?2)", params![1000 - i as i64, h])
                .unwrap();
        }
        let l = crate::ingest::store::dernier_instantane_par_hote(&conn, "fw", 2);
        let hotes: Vec<Option<String>> = l.iter().map(|r| r.0.clone()).collect();
        assert_eq!(hotes, [None, Some("srv-a".to_string())], "la série sans hôte est une entrée de la liste");
        assert_eq!((l.machines_du_genre, l.coupee_a_la_borne(), l.taille_du_parc()), (Some(3), true, Some(3)));
    }

    /// LIMITE ÉCRITE à `coupee_a_la_borne` : une ligne illisible qui double exactement `(host, ts)` d'une machine déjà
    /// rendue compte parmi les vues sans être une machine de plus — la coupe est tue (lecture interrompue, taille non
    /// établie). Borne deux : `srv-a` lisible puis son double illisible, `srv-b`, `srv-c` derrière la borne.
    #[test]
    fn pcb_la_lecture_tait_la_coupe_sur_un_doublon_illisible() {
        let (st, _p) = router_test_state("pcb-lecture-doublon-illisible");
        let conn = st.db.lock();
        conn.execute_batch(
            "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(1000,'fw','h-a','{}','srv-a'); \
             INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(1000,'fw',X'00ff','{}','srv-a'); \
             INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(999,'fw','h-b','{}','srv-b'); \
             INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(998,'fw','h-c','{}','srv-c');",
        )
        .unwrap();
        let l = crate::ingest::store::dernier_instantane_par_hote(&conn, "fw", 2);
        assert!(matches!(l.fin, crate::query_exec::FinDeParcours::Interrompu { erreurs: 1, .. }), "le double illisible est lu");
        let hotes: Vec<Option<String>> = l.iter().map(|r| r.0.clone()).collect();
        assert_eq!(hotes, [Some("srv-a".to_string()), Some("srv-b".to_string())], "srv-c reste derrière la borne");
        assert_eq!((l.machines_du_genre, l.coupee_a_la_borne(), l.taille_du_parc()), (Some(3), false, None));
    }

    /// DEUX LIGNES ILLISIBLES SAUTÉES AVANT LA BORNE, SANS MACHINE AU-DELÀ : borne deux, deux instantanés illisibles plus
    /// frais (`srv-x`, `srv-y`) puis `srv-a` et `srv-b`. Le parcours a VU les quatre machines du genre (deux rendues, deux
    /// sautées) : la liste n'est pas coupée. Chaque erreur de fin compte pour une ligne vue — deux erreurs, deux lignes,
    /// pas « au moins une ». Puis la même base avec une machine de plus (`srv-c`, derrière la borne) : coupée.
    #[test]
    fn pcb_la_lecture_compte_chaque_ligne_illisible_sautee_avant_la_borne() {
        let conn = test_db();
        conn.execute_batch(
            "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(3000,'fw',X'00ff','{}','srv-x'); \
             INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(2999,'fw',X'00ff','{}','srv-y'); \
             INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(1000,'fw','h-a','{}','srv-a'); \
             INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(999,'fw','h-b','{}','srv-b');",
        )
        .unwrap();
        let l = crate::ingest::store::dernier_instantane_par_hote(&conn, "fw", 2);
        assert!(matches!(l.fin, crate::query_exec::FinDeParcours::Interrompu { erreurs: 2, .. }), "deux lignes illisibles lues");
        let hotes: Vec<Option<String>> = l.iter().map(|r| r.0.clone()).collect();
        assert_eq!(hotes, [Some("srv-a".to_string()), Some("srv-b".to_string())]);
        assert_eq!((l.len(), l.machines_du_genre, l.coupee_a_la_borne()), (2, Some(4), false), "toutes les machines ont été vues");

        conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(998,'fw','h-c','{}','srv-c')", []).unwrap();
        let c = crate::ingest::store::dernier_instantane_par_hote(&conn, "fw", 2);
        assert_eq!((c.len(), c.machines_du_genre, c.coupee_a_la_borne()), (2, Some(5), true), "srv-c reste hors du parcours");
    }

    /// LA FONCTION DE LECTURE, COUPÉE ET INTERROMPUE, ET UN DOUBLON À LA DATE MAX : borne deux, une ligne illisible
    /// d'abord puis trois machines — la liste est coupée (quatre machines du genre), la fin interrompue, la taille non
    /// établie ; trois machines dont une en double à sa date max — trois machines, pas quatre lignes.
    #[test]
    fn pcb_la_lecture_coupee_et_interrompue_ne_dit_pas_de_taille() {
        let conn = test_db();
        for (i, h) in ["srv-a", "srv-b", "srv-c"].iter().enumerate() {
            conn.execute(
                "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,'fw',?2,'{}',?3)",
                params![1000 - i as i64, format!("h-{h}"), h],
            )
            .unwrap();
        }
        conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(5000,'fw',X'00ff','{}','srv-z')", []).unwrap();
        let l = crate::ingest::store::dernier_instantane_par_hote(&conn, "fw", 2);
        assert!(matches!(l.fin, crate::query_exec::FinDeParcours::Interrompu { .. }), "la ligne illisible interrompt");
        assert_eq!((l.len(), l.machines_du_genre, l.coupee_a_la_borne(), l.taille_du_parc()), (2, Some(4), true, None));

        let d = test_db();
        for (i, h) in ["srv-a", "srv-b", "srv-c"].iter().enumerate() {
            d.execute(
                "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,'fw',?2,'{}',?3)",
                params![1000 - i as i64, format!("h-{h}"), h],
            )
            .unwrap();
        }
        d.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(1000,'fw','h-srv-a','{}','srv-a')", []).unwrap();
        let dd = crate::ingest::store::dernier_instantane_par_hote(&d, "fw", 2);
        assert_eq!((dd.len(), dd.machines_du_genre, dd.coupee_a_la_borne(), dd.taille_du_parc()), (2, Some(3), true, Some(3)));
    }

    /// LA FONCTION DE LECTURE, À SES BORDS : borne deux sur trois machines (coupée, trois), sur deux (entière, deux) ;
    /// les instantanés anciens ne comptent pas comme des machines.
    #[test]
    fn pcb_la_lecture_rend_le_nombre_de_machines_et_sa_coupe() {
        let conn = test_db();
        for (i, h) in ["srv-a", "srv-b", "srv-c"].iter().enumerate() {
            conn.execute(
                "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,'fw',?2,'{}',?3),(1,'fw','vieux','{}',?3)",
                params![1000 - i as i64, format!("h-{h}"), h],
            )
            .unwrap();
        }
        let coupee = crate::ingest::store::dernier_instantane_par_hote(&conn, "fw", 2);
        assert_eq!(coupee.len(), 2);
        assert!(matches!(coupee.fin, crate::query_exec::FinDeParcours::Complet), "un plafond atteint n'est pas une lecture ratée");
        assert_eq!((coupee.machines_du_genre, coupee.coupee_a_la_borne(), coupee.taille_du_parc()), (Some(3), true, Some(3)));
        let pile = crate::ingest::store::dernier_instantane_par_hote(&conn, "fw", 3);
        assert_eq!((pile.len(), pile.machines_du_genre, pile.coupee_a_la_borne(), pile.taille_du_parc()), (3, Some(3), false, Some(3)));
        let vide = crate::ingest::store::dernier_instantane_par_hote(&conn, "jamais-vu", 2);
        assert_eq!((vide.len(), vide.machines_du_genre, vide.coupee_a_la_borne(), vide.taille_du_parc()), (0, None, false, Some(0)));
    }
}
