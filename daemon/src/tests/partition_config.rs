// P8.7-a ③ — LA PARTITION DE LECTURE DE LA CONFIGURATION, FERMÉE PAR UN SCANNER
// ================================================================================================
// LE DÉFAUT, DANS SA FORME GÉNÉRALE. Plume a DEUX façons de lire un réglage `PLUME_*` :
//   - `cfg(&conf, "PLUME_X", d)` -> `env > fichier PLUME_CONFIG > défaut` (les TROIS modes de
//     déploiement obtiennent l'effet annoncé) ;
//   - `std::env::var("PLUME_X")` -> l'environnement SEUL (le fichier est invisible).
// En Docker et en k3s la distinction ne se voit pas : tout arrive par `env:` et `PLUME_CONFIG` pointe
// sur `/nonexistent`. En systemd host-natif elle décide de tout — `plume-daemon.service` ne porte
// AUCUN `EnvironmentFile`, donc une clé écrite dans `/etc/plume/soc.conf` n'atteint QUE la première
// voie. C'est ainsi qu'un destinataire d'escrow age a pu être annulé en silence (cf. `backup.rs`).
//
// CE QUE CE FICHIER GARDE, ET POURQUOI IL SCANNE AU LIEU D'ÉNUMÉRER. Corriger les sept réglages de
// sauvegarde ne ferme rien : la huitième variable ajoutée demain rouvrirait le trou exactement de la
// même façon. Le garde LIT donc les sources et DÉRIVE lui-même qui lit l'environnement — il ne tient
// aucune liste de ce qu'il doit inspecter. Il tient une seule chose : le REGISTRE DE DETTE, c'est-à-
// dire l'état MESURÉ le 2026-08-09, qui n'a le droit que de RÉTRÉCIR.
//
// LES DEUX MOITIÉS, ET POURQUOI IL EN FAUT DEUX. Un réglage peut se soustraire au fichier de deux
// manières : en appelant `env::var("PLUME_X")` directement, ou en passant par un AIGUILLEUR — une
// fonction qui reçoit le nom en paramètre et appelle `env::var(k)`. La première mesure du défaut,
// faite en cherchant `env::var("PLUME_…")`, avait manqué SIX variables pour cette raison
// (`PLUME_AI_ENABLE`, `PLUME_AI_ALLOW_CLOUD`, et les quatre paliers GFS de `backup.rs`). Le garde
// dérive donc AUSSI les aiguilleurs — depuis les sites d'appel à clé non-littérale — puis suit leurs
// arguments littéraux. Et il verrouille le nombre de ces sites : en créer un nouveau échoue, ce qui
// interdit de fabriquer un aiguilleur neuf pour contourner la première moitié.
//
// CE QU'IL NE PROUVE PAS. Qu'une variable de la dette soit UTILE dans `soc.conf` : certaines sont des
// réglages de conteneur légitimement env-only. Il prouve seulement qu'aucune NOUVELLE ne s'ajoute
// sans décision.

/// Les sites où une clé d'environnement est lue SANS être un littéral — les « aiguilleurs », plus le
/// résolveur `cfg` lui-même. MESURÉ le 2026-08-09 : 5 sites dans 4 fichiers. Le garde compare le
/// NOMBRE par fichier, pas les numéros de ligne (qui bougent à chaque édition).
///
/// UN `grep` NAÏF EN COMPTE SIX. Il ajoute `migrate.rs:5042` (`env::var(MARQUEUR)`), qui vit à
/// l'intérieur d'un `#[cfg(test)] mod` : ce n'est pas du code livré. Le scanner, lui, retire le texte
/// de test AVANT de compter — c'est la raison pour laquelle le garde est un scanner et non un `grep`.
///
/// CE QUE CHACUN EST, ET POURQUOI IL A LE DROIT D'EXISTER :
///   - `main.rs` (1) : `cfg()` — LA voie canonique elle-même (`env > conf > défaut`). Sa présence ici
///     est la définition de la cible, pas une dette.
///   - `overlays_oac.rs` (2) : résolution d'un `SecretRef` `env:NOM` / projection Vault, où le NOM est
///     fourni par l'opérateur dans un overlay. Ce n'est pas un réglage `PLUME_*`, c'est une indirection
///     de secret : la lire dans le fichier de config n'aurait aucun sens (le secret y serait EN CLAIR,
///     ce que `resolve_secret_ref` refuse explicitement).
///   - `ai/mod.rs` (1) : `env_flag` — aiguilleur, alimente 2 clés (dans la dette ci-dessous).
///   - `backup.rs` (1) : la SONDE DE PRÉSENCE de l'annonce de bascule ②
///     (`env::var_os(c).is_some()`) : elle ne résout aucune valeur, elle constate si une clé est déjà
///     portée par l'environnement pour savoir s'il faut prévenir l'opérateur.
///   - `crypto/mod.rs` (1) : la MÊME sonde de présence, pour l'annonce de bascule P8.7-b
///     (`bascule_at_rest(conf, |c| std::env::var(c).ok())`). Elle ne résout aucun réglage : elle
///     compare ce que l'environnement porte à ce que le fichier porte, pour savoir si la clé at-rest
///     change d'effet à ce démarrage. La DÉCISION, elle, est une fonction PURE testée sans env.
const SITES_LECTURE_ENV_NON_LITTERALE: &[(&str, usize)] = &[
    ("ai/mod.rs", 1),
    ("backup.rs", 1),
    ("crypto/mod.rs", 1),
    ("main.rs", 1),
    ("overlays_oac.rs", 2),
];

/// LE REGISTRE DE DETTE — les réglages `PLUME_*` qui, au 2026-08-09, se lisent dans l'environnement
/// SEUL et sont donc INVISIBLES depuis `/etc/plume/soc.conf`. MESURÉ, pas recopié : la liste a été
/// produite par ce scanner même, puis relue.
///
/// IL N'A LE DROIT QUE DE RÉTRÉCIR. Un nom qui apparaît sans être ici fait ÉCHOUER le test — c'est la
/// fermeture demandée. Un nom d'ici qui disparaît le fait échouer aussi : une dette remboursée se
/// constate, elle ne s'oublie pas.
///
/// LES SEPT DE LA SAUVEGARDE N'Y SONT PLUS (P8.7-a) : `AGE_RECIPIENT`, `REQUIRE_ASYMMETRIC`,
/// `FORCE_PLAINTEXT_EXPORT`, `SCRYPT_LOG_N`, `STAGING_DIR`, `AGE_IDENTITY`, `AGE_IDENTITY_FILE` —
/// ni les quatre paliers GFS, repliés dans le même lot.
///
/// **`PLUME_DB_KEY` ET `PLUME_DB_KEY_FILE` N'Y SONT PLUS (P8.7-b, 2026-08-09).** C'étaient les deux
/// pires : la clé était lue par les DEUX voies, qui ne s'accordaient pas. Ce que le lot précédent
/// annonçait ici (« la base devient illisible ») n'était que la MOITIÉ du défaut, et pas la pire — le
/// cas VRAIMENT coûteux a été reproduit le 2026-08-09 sur le binaire `38a23da` : base chaude **EN
/// CLAIR** (`SQLite format 3\0`, relisible par un `sqlite3` nu) pendant que le tier froid chiffrait
/// ses jours-files (`age-encryption.org/v1`) avec la clé écrite dans `soc.conf`, le tout annoncé par
/// « rétention OK ». Les deux clés passent désormais par `cfg()` (`crypto::db_key_depuis`), et le
/// tier froid n'a plus de lecture à lui : il appelle la même fonction. La prémisse qui avait fait
/// écarter le lot — « `db_key()` est appelée sans configuration en main, avant le chargement » —
/// était FAUSSE : `load_config()` est une fonction pure appelée à la demande, dès la première ligne
/// de `main()` ; il n'existe aucune phase de chargement à réordonner. Garde :
/// `tests/cle_at_rest_voie_unique.rs` (preuve sur les octets) + la moitié froide dans
/// `cold_store/tests.rs`.
///
/// Le reste attend un découpage : la famille `PLUME_CLICKHOUSE_*`/`DUCKDB` (stores optionnels), la
/// famille `PLUME_QUERY_*`/`PLUME_*_MAX` (plafonds), et le solde. Ce sont des lots séparés parce que
/// chacun a ses propres tests et ses propres documents à corriger — pas parce qu'ils sont moins vrais.
/// Le registre en compte **53** après P8.7-b (il en comptait 55 ; `PLUME_DB_KEY` et
/// `PLUME_DB_KEY_FILE` en sont sortis). « 25 sur 55 sont DOCUMENTÉES quelque part » datait du
/// 2026-08-09 AVANT ce lot et n'a PAS été re-mesuré depuis : la part documentée du solde reste donc
/// inconnue à cette date. Ce qui est sûr, c'est que ce sont les leviers qu'un opérateur d'hôte croit
/// avoir, et qui n'agissent pas.
const DETTE_LECTURE_ENV_SEULE: &[&str] = &[
    "PLUME_AI_ALLOW_CLOUD",
    "PLUME_AI_ENABLE",
    "PLUME_AI_MAX_CALLS_PER_MIN",
    "PLUME_AI_MAX_TOKENS",
    "PLUME_AUDIT_BULK_ROWS",
    "PLUME_CLICKHOUSE_CLUSTER",
    "PLUME_CLICKHOUSE_DATABASE",
    "PLUME_CLICKHOUSE_PASSWORD",
    "PLUME_CLICKHOUSE_SHARDS",
    "PLUME_CLICKHOUSE_URL",
    "PLUME_CLICKHOUSE_USER",
    "PLUME_COLD_READ_PARALLELISM",
    "PLUME_COMPLIANCE_FRAMEWORKS",
    "PLUME_CONFIG",
    "PLUME_CONTROL_KEY",
    "PLUME_DEFENDER_MAX_PAGES",
    "PLUME_DEMO",
    "PLUME_DETECT_CONCURRENCY",
    "PLUME_DUCKDB_MEMORY_LIMIT",
    "PLUME_DUCKDB_THREADS",
    "PLUME_ENDPOINT_NORMALIZE",
    "PLUME_EXPORT_MAX",
    "PLUME_FIREHOSE_MAX_DECOMPRESS",
    "PLUME_GENERIC_EXTRACT",
    "PLUME_HEC_SOURCETYPE_MAP",
    "PLUME_HTTP_PULL_MAX_PAGES",
    "PLUME_IOC_BLOOM",
    "PLUME_IOC_BLOOM_MIN",
    "PLUME_LEDGER_PUBKEY",
    "PLUME_LOKI_QUERY",
    "PLUME_MAIL_BODY_CMD",
    "PLUME_MINIO_AUDIT_BUCKETS",
    "PLUME_MINIO_AUDIT_DROP_APIS",
    "PLUME_NETBAN_DISABLE",
    "PLUME_NETBAN_FROM_ACTIONS",
    "PLUME_OTLP_MAX_DECOMPRESS",
    "PLUME_OTLP_TRACES",
    "PLUME_PROM_LOOKBACK_S",
    "PLUME_PURGE_ACTOR",
    "PLUME_QUERY_BUDGET_INTERACTIVE_MS",
    "PLUME_QUERY_BUDGET_MS",
    "PLUME_QUERY_MAX",
    // `PLUME_REFERENCE_BUILD_CHILD` (migrate.rs) N'EST PAS ICI, et c'est une mesure, pas un oubli :
    // sa clé est une CONSTANTE passée à `env::var(MARQUEUR)`, donc le scanner la classe en site NON
    // LITTÉRAL (compté dans `SITES_LECTURE_ENV_NON_LITTERALE`) et ne voit jamais son nom. Ce n'est pas
    // un réglage d'exploitation : c'est le drapeau de re-exécution du binaire de test dans un enfant.
    "PLUME_ROLLUP_MULTIDIM",
    "PLUME_SIGMA_BULK_MAX",
    "PLUME_SIGMA_BULK_MAX_BYTES",
    "PLUME_SILENCE_MAX_TTL_S",
    "PLUME_STORE_DUCKDB_EXPERIMENTAL",
    "PLUME_TAXII_MAX_PAGES",
    "PLUME_VAULT_ADDR",
    "PLUME_VAULT_CA",
    "PLUME_VAULT_TOKEN",
    "PLUME_VAULT_TOKEN_FILE",
    "PLUME_WATCH_STS",
];

/// Ce que le scanner rend pour l'arborescence : les noms `PLUME_*` lus dans l'environnement (directs
/// et via aiguilleur), les aiguilleurs dérivés, et le compte de sites non-littéraux par fichier.
struct LecturesEnv {
    noms: std::collections::BTreeSet<String>,
    aiguilleurs: std::collections::BTreeSet<String>,
    sites_non_litteraux: std::collections::BTreeMap<String, usize>,
    /// Par fichier : les noms `PLUME_*` que CE fichier lit dans l'environnement (pour le garde local).
    noms_par_fichier: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
}

/// TOUS les arguments qui suivent `ouverture` dans `l` : `Some(nom)` pour un littéral, `None` pour un
/// argument non littéral (site d'aiguilleur). On balaie la ligne ENTIÈRE — s'arrêter à la première
/// occurrence laisserait passer un second appel sur la même ligne, et un scanner qui rate en silence
/// est pire que pas de scanner.
fn arguments_apres(l: &str, ouverture: &str) -> Vec<Option<String>> {
    let mut out = Vec::new();
    let mut depuis = 0usize;
    while let Some(rel) = l[depuis..].find(ouverture) {
        let fin = depuis + rel + ouverture.len();
        let reste = l[fin..].trim_start_matches(['&', ' ']);
        match reste.strip_prefix('"') {
            Some(apres) => out.push(Some(apres.chars().take_while(|c| *c != '"').collect())),
            None => out.push(None), // argument NON littéral -> site d'aiguilleur
        }
        depuis = fin;
    }
    out
}

/// Le nom de la fonction englobante d'une ligne : la plus proche déclaration `fn NOM(` AU-DESSUS.
/// Sert à DÉRIVER les aiguilleurs — on ne les déclare pas, on les trouve.
fn fonction_englobante(lignes: &[(usize, String)], idx: usize) -> Option<String> {
    for (_, texte) in lignes[..=idx].iter().rev() {
        let Some(pos) = texte.find("fn ") else { continue };
        let apres = &texte[pos + 3..];
        let nom: String = apres.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        if !nom.is_empty() && apres[nom.len()..].starts_with('(') {
            return Some(nom);
        }
    }
    None
}

/// LE SCANNER. Deux passes : la première dérive les aiguilleurs et récolte les lectures DIRECTES ; la
/// seconde suit les arguments littéraux des aiguilleurs. `cfg` est écarté des aiguilleurs — c'est la
/// voie CIBLE, pas une fuite (et sa clé n'est pas son premier argument, donc il ne matcherait pas).
fn scanner_lectures_env() -> LecturesEnv {
    use crate::db_open::door_tests::{est_test, fichiers_de_test, rs_files, texte_de_production};
    let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut fichiers = Vec::new();
    rs_files(&racine, &mut fichiers);
    let marques = fichiers_de_test(&fichiers);
    let production: Vec<(String, Vec<(usize, String)>)> = fichiers
        .iter()
        .filter(|f| !est_test(f, &marques))
        .map(|f| {
            let src = std::fs::read_to_string(f).unwrap();
            let rel = f.strip_prefix(&racine).unwrap().to_string_lossy().into_owned();
            (rel, texte_de_production(f, &src))
        })
        .collect();

    let mut out = LecturesEnv {
        noms: Default::default(),
        aiguilleurs: Default::default(),
        sites_non_litteraux: Default::default(),
        noms_par_fichier: Default::default(),
    };

    // Passe 1 — lectures DIRECTES + dérivation des aiguilleurs.
    for (rel, lignes) in &production {
        for (i, (_, texte)) in lignes.iter().enumerate() {
            for ouverture in ["env::var(", "env::var_os("] {
                for argument in arguments_apres(texte, ouverture) {
                    match argument {
                        Some(nom) if nom.starts_with("PLUME_") => {
                            out.noms.insert(nom.clone());
                            out.noms_par_fichier.entry(rel.clone()).or_default().insert(nom);
                        }
                        Some(_) => {} // PATH, HOSTNAME… : pas un réglage plume
                        None => {
                            *out.sites_non_litteraux.entry(rel.clone()).or_insert(0) += 1;
                            if let Some(f) = fonction_englobante(lignes, i) {
                                if f != "cfg" {
                                    out.aiguilleurs.insert(f);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Passe 2 — les arguments littéraux `PLUME_*` que reçoivent les aiguilleurs dérivés.
    for (rel, lignes) in &production {
        for (_, texte) in lignes {
            for a in &out.aiguilleurs {
                if texte.contains(&format!("fn {a}(")) {
                    continue; // la DÉCLARATION de l'aiguilleur, pas un appel
                }
                for argument in arguments_apres(texte, &format!("{a}(")) {
                    if let Some(nom) = argument {
                        if nom.starts_with("PLUME_") {
                            out.noms.insert(nom.clone());
                            out.noms_par_fichier.entry(rel.clone()).or_default().insert(nom);
                        }
                    }
                }
            }
        }
    }
    out
}

/// ③ — LA FERMETURE GLOBALE. Le scanner dérive qui lit l'environnement ; le registre dit ce qui est
/// TOLÉRÉ. Toute divergence, dans un sens comme dans l'autre, échoue.
#[test]
fn p87a_partition_de_lecture_de_la_configuration_fermee() {
    let vu = scanner_lectures_env();

    // VALIDATION DE L'INSTRUMENT — un filtre qui ne rend rien se lit « je n'ai pas mesuré ».
    assert!(
        vu.noms.len() > 20,
        "l'instrument est INVALIDE : il n'a trouvé que {} lecture(s) d'environnement `PLUME_*` dans \
         toute l'arborescence de production. Le scanner ne scanne plus.",
        vu.noms.len()
    );
    assert!(
        vu.aiguilleurs.contains("env_flag"),
        "l'instrument est INVALIDE : `ai::env_flag` est un aiguilleur CONNU (il appelle `env::var(k)`) \
         et la dérivation ne l'a pas trouvé ; aiguilleurs dérivés = {:?}",
        vu.aiguilleurs
    );
    assert!(
        vu.noms.contains("PLUME_AI_ENABLE"),
        "l'instrument est INVALIDE : `PLUME_AI_ENABLE` n'est atteignable QUE par l'aiguilleur \
         `env_flag` ; ne pas le voir prouve que la passe 2 est morte"
    );

    let attendu: std::collections::BTreeSet<String> =
        DETTE_LECTURE_ENV_SEULE.iter().map(|s| s.to_string()).collect();
    let nouveaux: Vec<&String> = vu.noms.difference(&attendu).collect();
    assert!(
        nouveaux.is_empty(),
        "PARTITION ROUVERTE (P8.7-a) : {nouveaux:?} se li(sen)t dans l'environnement SEUL et \
         n'apparai(ssen)t pas dans le registre de dette. En systemd host-natif, `plume-daemon.service` \
         ne porte AUCUN `EnvironmentFile` : une clé écrite dans `/etc/plume/soc.conf` sera donc \
         IGNORÉE, en silence.\n  À faire : lire par `cfg(&conf, \"…\", défaut)` (précédence \
         `env > fichier > défaut` -> Docker et k3s inchangés, l'hôte gagne le fichier). Si le réglage \
         doit RESTER env-only, ajoutez-le au registre AVEC sa raison."
    );
    let rembourses: Vec<&String> = attendu.difference(&vu.noms).collect();
    assert!(
        rembourses.is_empty(),
        "dette REMBOURSÉE mais non consignée : {rembourses:?} ne se li(sen)t plus dans \
         l'environnement seul. Retirez-la/les de `DETTE_LECTURE_ENV_SEULE` — le registre mesure un \
         état, il ne garde pas les fantômes."
    );

    let sites_attendus: std::collections::BTreeMap<String, usize> = SITES_LECTURE_ENV_NON_LITTERALE
        .iter()
        .map(|(f, n)| (f.to_string(), *n))
        .collect();
    assert_eq!(
        vu.sites_non_litteraux, sites_attendus,
        "les sites de lecture d'environnement À CLÉ NON LITTÉRALE ont changé. Chacun est un \
         AIGUILLEUR potentiel : une fonction qui reçoit le nom en paramètre soustrait le réglage au \
         fichier de configuration SANS que le nom apparaisse jamais à côté d'`env::var`. En créer un \
         demande une justification écrite dans `SITES_LECTURE_ENV_NON_LITTERALE`."
    );
}

/// ③ (moitié locale) — LA PARTITION DE LA SAUVEGARDE EST FERMÉE, ET SANS LISTE. On n'énumère pas les
/// sept clés : on exige que `backup.rs` ne lise AUCUN réglage `PLUME_*` dans l'environnement. Une
/// huitième ajoutée demain par `env::var` échoue ici, à l'endroit exact où le mal s'est produit.
#[test]
fn p87a_backup_ne_lit_plus_aucun_reglage_dans_l_environnement() {
    let vu = scanner_lectures_env();
    let lus = vu.noms_par_fichier.get("backup.rs").cloned().unwrap_or_default();
    assert!(
        lus.is_empty(),
        "`backup.rs` lit {lus:?} dans l'environnement SEUL. Sur un hôte systemd ces clés sont \
         invisibles depuis `/etc/plume/soc.conf` (l'unité n'a pas d'`EnvironmentFile`) : c'est \
         exactement le défaut P8.7-a — un destinataire d'escrow age écrit par l'opérateur, ignoré, et \
         des archives qui repartent en chiffrement symétrique déchiffrable par le nœud. \
         Utilisez `reglage_sauvegarde(CLE_…)`."
    );
    // …et l'instrument voit bien QUELQUE CHOSE ailleurs (sinon « vide » ne veut rien dire).
    assert!(
        vu.noms_par_fichier.contains_key("ai/mod.rs"),
        "l'instrument est INVALIDE : il ne voit aucune lecture d'environnement dans `ai/mod.rs`, qui \
         en a. Un `backup.rs` vide ne prouverait alors rien."
    );
}

// ── ② LA BASCULE EST BRUYANTE ────────────────────────────────────────────────────────────────────
// Ces tests sont PURS : l'environnement du processus n'est jamais touché (il est injecté), donc ils
// sont sûrs en parallèle — la règle apprise avec `scrypt_log_n_depuis`.

fn conf_de(paires: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
    paires.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// Le cas HOST-NATIF : la clé est dans le fichier, absente de l'environnement -> elle change d'effet,
/// donc elle est ANNONCÉE, nommée, avec ce que ça change.
#[test]
fn p87a_bascule_annoncee_quand_la_cle_vient_du_fichier_seul() {
    let conf = conf_de(&[
        ("PLUME_BACKUP_AGE_RECIPIENT", "age1exemple"),
        ("PLUME_BACKUP_REQUIRE_ASYMMETRIC", "1"),
        ("PLUME_BACKUP_INTERVAL", "3600"), // déjà lue par cfg() : rien ne change pour elle
    ]);
    let cles = crate::backup::cles_sauvegarde_devenues_effectives(&conf, |_| false);
    assert_eq!(cles, vec!["PLUME_BACKUP_AGE_RECIPIENT", "PLUME_BACKUP_REQUIRE_ASYMMETRIC"]);

    let msg = crate::backup::annonce_bascule_sauvegarde(&cles).expect("une annonce est due");
    assert!(msg.contains("PLUME_BACKUP_AGE_RECIPIENT"), "l'annonce doit NOMMER la clé : {msg}");
    assert!(msg.contains("PLUME_BACKUP_REQUIRE_ASYMMETRIC"));
    assert!(
        msg.contains("REFUSÉE"),
        "l'annonce doit dire que les sauvegardes peuvent désormais être REFUSÉES — c'est le seul \
         moyen de ne pas découvrir la bascule par un échec : {msg}"
    );
    assert!(
        msg.contains("SYMÉTRIQUE") && msg.contains("ASYMÉTRIQUE"),
        "l'annonce doit dire ce qui change pour l'escrow : {msg}"
    );
    // `PLUME_BACKUP_INTERVAL` est CITÉE dans la phrase de clôture (c'est la précédence de référence)
    // mais elle ne doit pas être ÉNUMÉRÉE : elle passait déjà par `cfg()`, rien ne change pour elle.
    assert!(
        !msg.contains("  - PLUME_BACKUP_INTERVAL"),
        "une clé DÉJÀ lue par cfg() ne change pas d'effet : l'énumérer serait du bruit. {msg}"
    );
}

/// Le cas CONTENEUR (Docker/k3s) : tout arrive par l'environnement -> RIEN ne change -> SILENCE. Un
/// avertissement à chaque démarrage sur des milliers de pods serait un mensonge et un bruit.
#[test]
fn p87a_aucune_annonce_quand_la_cle_est_deja_dans_l_environnement() {
    let conf = conf_de(&[("PLUME_BACKUP_AGE_RECIPIENT", "age1exemple")]);
    let cles = crate::backup::cles_sauvegarde_devenues_effectives(&conf, |_| true);
    assert!(cles.is_empty(), "l'environnement gagne déjà : rien ne bascule");
    assert!(crate::backup::annonce_bascule_sauvegarde(&cles).is_none(), "silence attendu");

    // …et le cas VRAIMENT vide : pas de fichier du tout (PLUME_CONFIG=/nonexistent).
    let vide = conf_de(&[]);
    assert!(crate::backup::cles_sauvegarde_devenues_effectives(&vide, |_| false).is_empty());
}

/// Une clé PRÉSENTE MAIS VIDE dans le fichier ne bascule rien : `PLUME_BACKUP_AGE_RECIPIENT=` est la
/// forme que `.env.example` livre par défaut, et elle a exactement le même effet qu'avant (aucun).
#[test]
fn p87a_une_cle_vide_dans_le_fichier_ne_bascule_rien() {
    let conf = conf_de(&[("PLUME_BACKUP_AGE_RECIPIENT", ""), ("PLUME_BACKUP_STAGING_DIR", "   ")]);
    assert!(crate::backup::cles_sauvegarde_devenues_effectives(&conf, |_| false).is_empty());
}

/// La VALEUR d'une identité age privée ne doit JAMAIS apparaître dans un journal — seul son nom.
#[test]
fn p87a_l_annonce_ne_journalise_aucune_valeur() {
    const SECRET: &str = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQVALEUR";
    let conf = conf_de(&[
        ("PLUME_BACKUP_AGE_IDENTITY", SECRET),
        ("PLUME_BACKUP_AGE_RECIPIENT", "age1valeur-publique-mais-quand-meme-une-valeur"),
    ]);
    let cles = crate::backup::cles_sauvegarde_devenues_effectives(&conf, |_| false);
    let msg = crate::backup::annonce_bascule_sauvegarde(&cles).expect("une annonce est due");
    assert!(msg.contains("PLUME_BACKUP_AGE_IDENTITY"), "le NOM doit y être : {msg}");
    assert!(!msg.contains(SECRET), "la VALEUR de l'identité d'escrow a fuité dans le journal : {msg}");
    assert!(!msg.contains("age1valeur"), "aucune valeur, même publique, n'est journalisée : {msg}");
}

/// La grammaire des drapeaux est la MÊME pour les deux (elle était recopiée) — testée PUREMENT.
#[test]
fn p87a_grammaire_des_drapeaux_de_sauvegarde() {
    for vrai in ["1", "true", "yes", "on", " ON ", "True"] {
        assert!(crate::backup::drapeau_sauvegarde(vrai), "{vrai:?} doit valoir vrai");
    }
    for faux in ["", "0", "false", "no", "off", "oui", "2"] {
        assert!(!crate::backup::drapeau_sauvegarde(faux), "{faux:?} doit valoir faux");
    }
}
