// =====================================================================================
// RESTAURATION : LE CORPS D'UN DÉCLENCHEUR OU D'UNE VUE DE L'ARCHIVE EST CELUI QUE LE DÉMON A LUI-MÊME ÉCRIT
// (`backup/restauration_liste_fermee.rs` : `admettre`, `ListeFermee::preparer_une_chaine_de_l_archive`,
// `ListeFermee::juger_les_declencheurs_et_les_vues`, `juger_le_schema_du_format_ancien` ; `backup/dump_restauration.rs` :
// `restore_stream`, `restore_compressed` ; `migrate.rs` : `declencheurs_et_vues_de_reference`).
//
// LE DÉFAUT, LU SUR dcdd1454 : la liste fermée jugeait la FORME d'une instruction de l'archive (`CREATE TRIGGER`,
// `CREATE VIEW` admis sous la phase post-DDL), pas son CORPS. Un déclencheur ou une vue posés sur des objets ordinaires
// restaient dans la base publiée, et leur corps jouait ensuite sur la connexion du démon, où aucun autoriseur n'est posé.
//
// DÉSORMAIS, dans les deux formats et avant toute publication : une instruction de l'archive qui crée un déclencheur ou
// une vue n'est admise que si sa chaîne est, À L'OCTET, le texte d'un membre de l'ensemble de référence portant le nom
// que le moteur a passé à l'autoriseur. L'ensemble est relevé sur ce binaire (`db/schema.sql`, sa chaîne de migrations,
// puis les déclencheurs que l'entretien crée à l'exécution, par leurs propres textes), jamais recopié. Tout autre corps,
// tout autre nom : refus sous la cause `déclencheur ou vue autre que ceux que le démon crée`, phase post-DDL ou
// « format ancien », destination absente ou intacte à l'octet. Aucune normalisation : la chaîne entière est comparée.
//
// LES VERSIONS ANTÉRIEURES : la chaîne de ce binaire, arrêtée à CHAQUE version qu'il sait migrer, ne porte que des
// couples de l'ensemble (aucune étape ne réécrit ni ne retire un déclencheur ou une vue) ; une archive d'une base
// arrêtée avant l'étape qui pose les déclencheurs des tableaux de bord se restaure.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les LIGNES des tables (une archive porte ses données, la restauration les rend
// telles quelles) ; l'authenticité d'une archive en chiffrement asymétrique.
// =====================================================================================

mod ck2_restauration_corps_des_declencheurs_et_des_vues {
    use super::*;
    use crate::backup::SUFFIXE_RESTAURATION_EN_COURS;

    const CLE: &str = "ck2-cle-de-test-de-restauration";

    // Les phrases attendues, écrites ici en toutes lettres (jamais relues de la production).
    const ETRANGER: &str = "déclencheur ou vue autre que ceux que le démon crée";

    const TABLE: &str = "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)";

    /// Un déclencheur que le démon n'écrit pas, sur la table ordinaire `t`.
    const DECLENCHEUR_ETRANGER: &str = "CREATE TRIGGER ck2_efface AFTER INSERT ON t BEGIN DELETE FROM t; END";
    /// Un déclencheur sous le NOM d'un déclencheur de la référence (`event_ai`), au corps que le démon n'écrit pas.
    const DECLENCHEUR_AU_NOM_DE_REFERENCE: &str = "CREATE TRIGGER event_ai AFTER INSERT ON t BEGIN DELETE FROM t; END";
    /// Une vue que le démon n'écrit pas (il n'en crée aucune).
    const VUE_ETRANGERE: &str = "CREATE VIEW ck2_vue AS SELECT v FROM t";

    /// Les déclencheurs que l'entretien crée à l'exécution, hors migrations (`maintenance::reconcile_fts_fields`).
    const DE_L_ENTRETIEN: [&str; 2] = ["event_ff_ai", "event_ff_ad"];

    fn chemin(racine: &std::path::Path, nom: &str) -> String {
        racine.join(nom).to_string_lossy().into_owned()
    }

    /// age(zstd(charge)) chiffré à la passphrase `CLE` — la même enveloppe que `backup_compressed`.
    fn chiffree(charge: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let w = crate::backup::backup_encryptor(CLE, None).unwrap().wrap_output(Vec::new()).unwrap();
        let mut z = zstd::Encoder::new(w, 3).unwrap();
        z.write_all(charge).unwrap();
        z.finish().unwrap().finish().unwrap()
    }

    fn archive_de(charge: &[u8], chemin: &str) {
        std::fs::write(chemin, chiffree(charge)).unwrap();
    }

    fn contenu(racine: &std::path::Path) -> Vec<String> {
        let mut noms: Vec<String> = std::fs::read_dir(racine).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        noms.sort();
        noms
    }

    fn lignes_de(c: &rusqlite::Connection, sql: &str) -> Vec<String> {
        let mut s = c.prepare(sql).unwrap();
        let n = s.column_count();
        let mut lignes: Vec<String> = s
            .query_map([], |r| Ok((0..n).map(|i| format!("{:?}", r.get::<_, rusqlite::types::Value>(i).unwrap())).collect::<Vec<_>>().join("|")))
            .unwrap()
            .map(|l| l.unwrap())
            .collect();
        lignes.sort();
        lignes
    }

    /// Les déclencheurs et les vues d'une base : (nom, texte de `sqlite_master.sql`).
    fn declencheurs_et_vues(c: &rusqlite::Connection) -> std::collections::BTreeSet<(String, String)> {
        let mut s = c.prepare("SELECT name, sql FROM sqlite_master WHERE type IN ('trigger', 'view') AND sql IS NOT NULL").unwrap();
        s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).unwrap().map(|r| r.unwrap()).collect()
    }

    fn reference() -> std::collections::BTreeSet<(String, String)> {
        crate::migrate::declencheurs_et_vues_de_reference().expect("l'ensemble de référence se construit").clone()
    }

    fn suffixe_intacte(dest: &str) -> String {
        format!(" — la destination {dest} est INTACTE : la restauration s'écrivait dans {dest}{SUFFIXE_RESTAURATION_EN_COURS}, qui a été retiré.")
    }

    fn hors_liste(phase: &'static str, cause: &'static str) -> impl Fn(&str) -> String {
        move |dest| format!("restore : phase {phase} : instruction hors liste ({cause}){}", suffixe_intacte(dest))
    }

    /// LE TÉMOIN DE REFUS, deux fois. (1) Destination ABSENTE : la restauration échoue avec exactement `attendue(dest)`,
    /// et seul `archive.age` reste (rien de publié, ni temporaire ni clair). (2) Destination SAINE avec ses compagnons
    /// `-wal` et `-shm`, restaurée avec `--force` : même refus, base et compagnons identiques à l'octet.
    fn refusee(cas: &str, charge: &[u8], attendue: impl Fn(&str) -> String) {
        refusee_l_archive(cas, &chiffree(charge), attendue)
    }

    /// Le même témoin, sur les octets d'une archive déjà chiffrée (`archive`).
    fn refusee_l_archive(cas: &str, archive: &[u8], attendue: impl Fn(&str) -> String) {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        {
            let _tmp = crate::tmp_possede::TmpPossede::neuf(&format!("{cas}-sans-dest"));
            let racine = _tmp.racine().chemin().to_path_buf();
            std::fs::write(chemin(&racine, "archive.age"), archive).unwrap();
            let dest = chemin(&racine, "plume.db");
            let err = restore_compressed(&chemin(&racine, "archive.age"), &dest, Some(CLE), false, None)
                .expect_err(&format!("{cas} : l'archive a été restaurée et publiée"));
            assert_eq!(err, attendue(&dest), "{cas} (sans destination)");
            assert_eq!(contenu(&racine), vec!["archive.age".to_string()], "{cas} : ni destination publiée, ni temporaire, ni clair");
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf(cas);
        let racine = _tmp.racine().chemin().to_path_buf();
        std::fs::write(chemin(&racine, "archive.age"), archive).unwrap();
        let dest = chemin(&racine, "plume.db");
        {
            let c = open_db_keyed(&dest, Some(CLE)).unwrap();
            c.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('ancienne');").unwrap();
        }
        std::fs::write(format!("{dest}-wal"), b"compagnon -wal de l'ancienne base").unwrap();
        std::fs::write(format!("{dest}-shm"), b"compagnon -shm de l'ancienne base").unwrap();
        let avant: Vec<Vec<u8>> = ["", "-wal", "-shm"].iter().map(|s| std::fs::read(format!("{dest}{s}")).unwrap()).collect();
        let err = restore_compressed(&chemin(&racine, "archive.age"), &dest, Some(CLE), true, None)
            .expect_err(&format!("{cas} : l'archive a été restaurée et publiée par-dessus la destination"));
        assert_eq!(err, attendue(&dest), "{cas}");
        let apres: Vec<Vec<u8>> = ["", "-wal", "-shm"].iter().map(|s| std::fs::read(format!("{dest}{s}")).unwrap()).collect();
        assert!(apres == avant, "{cas} : la destination ou un compagnon a changé");
        assert_eq!(contenu(&racine), vec!["archive.age", "plume.db", "plume.db-shm", "plume.db-wal"], "{cas} : rien d'autre ne reste");
    }

    /// Restaure l'archive `archive` sur une destination absente ; rend la connexion à la base publiée.
    fn restauree(cas: &str, racine: &std::path::Path, archive: &str) -> rusqlite::Connection {
        let dest = chemin(racine, "plume.db");
        restore_compressed(archive, &dest, Some(CLE), false, None).unwrap_or_else(|e| panic!("{cas} : {e}"));
        open_db_keyed(&dest, Some(CLE)).unwrap()
    }

    /// Restaure `charge` sur une destination absente ; rend la connexion à la base publiée.
    fn admise(cas: &str, racine: &std::path::Path, charge: &[u8]) -> rusqlite::Connection {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        archive_de(charge, &chemin(racine, "archive.age"));
        restauree(cas, racine, &chemin(racine, "archive.age"))
    }

    // ── FORMAT COURANT : DUMPS FORGÉS ───────────────────────────────────────────────────────────────

    fn ecrire_u32(v: &mut Vec<u8>, n: u32) {
        v.extend_from_slice(&n.to_le_bytes());
    }
    fn ecrire_str(v: &mut Vec<u8>, s: &str) {
        ecrire_u32(v, s.len() as u32);
        v.extend_from_slice(s.as_bytes());
    }

    /// Un dump B1 forgé au format de `dump_stream` : la table `t` et sa ligne (1, 'restauree') au texte d'insertion de
    /// l'écrivain, aucun compteur, puis les chaînes de post-DDL `post`, puis l'octet de fin `sentinelle` (`0xFF` pour
    /// l'écrivain).
    fn dump_complet(post: &[&str], sentinelle: u8) -> Vec<u8> {
        dump_avec_tables(&[], post, sentinelle)
    }

    /// Le même dump, la section 1 portant en plus les tables `en_plus` (sans ligne), après `t`.
    fn dump_avec_tables(en_plus: &[&str], post: &[&str], sentinelle: u8) -> Vec<u8> {
        let mut v = b"PLUMEDUMP1\n".to_vec();
        ecrire_u32(&mut v, 1 + en_plus.len() as u32);
        ecrire_str(&mut v, TABLE);
        for creation in en_plus {
            ecrire_str(&mut v, creation);
        }
        ecrire_u32(&mut v, 1);
        ecrire_str(&mut v, "t");
        v.extend_from_slice(&2u16.to_le_bytes());
        ecrire_str(&mut v, "INSERT INTO \"t\" (\"id\", \"v\") VALUES (?, ?)");
        v.push(1);
        v.push(1);
        v.extend_from_slice(&1i64.to_le_bytes());
        v.push(3);
        ecrire_str(&mut v, "restauree");
        v.push(0);
        ecrire_u32(&mut v, 0);
        ecrire_u32(&mut v, post.len() as u32);
        for s in post {
            v.push(1);
            ecrire_str(&mut v, s);
        }
        v.push(sentinelle);
        v
    }

    fn dump(post: &[&str]) -> Vec<u8> {
        dump_complet(post, 0xFF)
    }

    // ── FORMAT ANCIEN ───────────────────────────────────────────────────────────────────────────────

    /// Une base SQLite EN CLAIR portant `t` et sa ligne (1, 'legacy'), puis `ddl` ; rend ses octets (la charge d'une
    /// archive au format ancien). Le fichier est retiré.
    fn clair(racine: &std::path::Path, ddl: &str) -> Vec<u8> {
        let p = chemin(racine, "clair-de-fixture.db");
        {
            let c = open_db_keyed(&p, None).unwrap();
            c.execute_batch(&format!("{TABLE}; INSERT INTO t VALUES(1, 'legacy');")).unwrap();
            c.execute_batch(ddl).unwrap();
        }
        let octets = std::fs::read(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        octets
    }

    // ── LA MESURE DU CONSTAT : UN CORPS QUE LE DÉMON N'A JAMAIS ÉCRIT ───────────────────────────────

    /// FORMAT COURANT : un déclencheur sur la table ordinaire `t` dont le corps efface `t`, sous un nom étranger puis sous
    /// le nom `event_ai` de la référence. Il était admis et la base publiée.
    #[test]
    fn courant_un_declencheur_au_corps_que_le_demon_n_ecrit_pas_est_refuse() {
        refusee("ck2-c-declencheur", &dump(&[DECLENCHEUR_ETRANGER]), hors_liste("post-DDL", ETRANGER));
        refusee("ck2-c-declencheur-nom-de-reference", &dump(&[DECLENCHEUR_AU_NOM_DE_REFERENCE]), hors_liste("post-DDL", ETRANGER));
    }

    /// FORMAT COURANT : une vue (le démon n'en crée aucune). Elle était admise et la base publiée.
    #[test]
    fn courant_une_vue_que_le_demon_n_ecrit_pas_est_refusee() {
        refusee("ck2-c-vue", &dump(&[VUE_ETRANGERE]), hors_liste("post-DDL", ETRANGER));
    }

    /// FORMAT ANCIEN : les mêmes déclencheurs, dans le fichier. Jugés sous la phase post-DDL sur le brouillon, ils étaient
    /// admis, recopiés par l'export, et la base publiée.
    #[test]
    fn ancien_un_declencheur_au_corps_que_le_demon_n_ecrit_pas_est_refuse() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ck2-a-fixtures-declencheur");
        let racine = _tmp.racine().chemin().to_path_buf();
        let ancien = hors_liste("format ancien", ETRANGER);
        refusee("ck2-a-declencheur", &clair(&racine, DECLENCHEUR_ETRANGER), &ancien);
        refusee("ck2-a-declencheur-nom-de-reference", &clair(&racine, DECLENCHEUR_AU_NOM_DE_REFERENCE), &ancien);
    }

    /// FORMAT ANCIEN : la même vue, dans le fichier.
    #[test]
    fn ancien_une_vue_que_le_demon_n_ecrit_pas_est_refusee() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ck2-a-fixtures-vue");
        let racine = _tmp.racine().chemin().to_path_buf();
        refusee("ck2-a-vue", &clair(&racine, VUE_ETRANGERE), hors_liste("format ancien", ETRANGER));
    }

    // ── L'ENSEMBLE DE RÉFÉRENCE ─────────────────────────────────────────────────────────────────────

    /// Une base de la tête (schéma de base puis toutes les migrations) ; avec `entretien`, l'entretien du démarrage
    /// (`maintenance::reconcile_index_state`, le code de production) y pose le filtre de champs plein texte et ses deux
    /// déclencheurs (`PLUME_FTS_FIELDS=1`).
    fn base_de_la_tete(c: &rusqlite::Connection, entretien: bool) {
        c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(c), "contrôle : la chaîne de migrations va au bout");
        if entretien {
            let mut conf = std::collections::HashMap::new();
            conf.insert("PLUME_FTS_FIELDS".to_string(), "1".to_string());
            let _ = crate::maintenance::reconcile_index_state(c, &conf);
        }
    }

    /// L'ENSEMBLE EST CELUI QUE CRÉE LE CODE DE PRODUCTION : sur une base de la tête où l'entretien du démarrage a posé le
    /// filtre de champs, les déclencheurs et les vues, nom ET texte, sont exactement l'ensemble de référence. Ensemble
    /// NOMMÉ : les deux déclencheurs de `db/schema.sql`, les trois de l'étape v125, les deux de l'entretien ; aucune vue.
    #[test]
    fn l_ensemble_de_reference_est_celui_que_le_code_de_production_cree() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        if std::env::var("PLUME_FTS_FIELDS").map_or(false, |v| v != "1") {
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "l_ensemble_de_reference_est_celui_que_le_code_de_production_cree",
                "PLUME_FTS_FIELDS est posé autrement qu'à 1 dans l'environnement : l'entretien ne crée pas le filtre de champs",
            );
            return;
        }
        let c = rusqlite::Connection::open_in_memory().unwrap();
        base_de_la_tete(&c, true);
        let reference = reference();
        assert_eq!(declencheurs_et_vues(&c), reference, "l'ensemble de référence est celui de la base de production");
        let noms: Vec<&str> = reference.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            noms,
            vec![
                "event_ad",
                "event_ai",
                "event_ff_ad",
                "event_ff_ai",
                "view_dashboard_suit_l_effacement",
                "view_dashboard_suit_l_insertion",
                "view_dashboard_suit_la_vue_principale",
            ],
            "les déclencheurs que le démon crée, par nom",
        );
        let vues: i64 = c.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'view'", [], |r| r.get(0)).unwrap();
        assert_eq!(vues, 0, "le démon ne crée aucune vue");
    }

    /// CONSTRUIT UNE FOIS PAR PROCESSUS : deux appels rendent le même ensemble, à la même adresse. Le coût d'une
    /// construction (base en mémoire, schéma de base, chaîne entière, entretien) est relevé ici, sur le banc, sans borne.
    #[test]
    fn l_ensemble_de_reference_est_construit_une_fois_par_processus() {
        let premier = crate::migrate::declencheurs_et_vues_de_reference().unwrap();
        let second = crate::migrate::declencheurs_et_vues_de_reference().unwrap();
        assert!(std::ptr::eq(premier, second), "le même ensemble, mémoïsé");
        let debut = std::time::Instant::now();
        let construit = crate::migrate::construire_les_declencheurs_et_vues_de_reference().unwrap();
        eprintln!("[ck2] une construction de l'ensemble de référence : {:?} (banc de test)", debut.elapsed());
        assert_eq!(&construit, premier, "la construction rend l'ensemble mémoïsé");
    }

    // ── LES VERSIONS ANTÉRIEURES ────────────────────────────────────────────────────────────────────

    /// Les étapes de la chaîne jouées hors de `migrate_step` (sans `BEGIN`) : v33, v67, v77 (`migrate_chain`).
    const ETAPES_SANS_TRANSACTION: [i64; 3] = [33, 67, 77];

    /// UNE BASE QUE CE BINAIRE MÈNE À LA VERSION `v` : `db/schema.sql`, puis SA chaîne de migrations, arrêtée après
    /// l'étape `v`. Un autoriseur compte les transactions des étapes et refuse tout à partir du `BEGIN` de l'étape `v+1`
    /// (ou, quand elle est jouée sans transaction, juste après le `COMMIT` de l'étape `v`) : l'étape suivante échoue, la
    /// chaîne s'arrête, et la version relue doit être `v` (sinon le compte est faux et le témoin le dit).
    fn base_arretee_a(v: i64) -> rusqlite::Connection {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        if v < crate::migrate::CODE_SCHEMA_MAX {
            let regulieres = (2..=v).filter(|n| !ETAPES_SANS_TRANSACTION.contains(n)).count();
            let suivante_sans_transaction = ETAPES_SANS_TRANSACTION.contains(&(v + 1));
            let compte = std::sync::Arc::new(std::sync::Mutex::new((0usize, 0usize, false)));
            let pour_l_autoriseur = compte.clone();
            c.authorizer(Some(move |ctx: AuthContext<'_>| {
                let mut e = pour_l_autoriseur.lock().unwrap();
                if e.2 {
                    return Authorization::Deny;
                }
                match ctx.action {
                    AuthAction::Transaction { operation: TransactionOperation::Begin } => {
                        e.0 += 1;
                        if !suivante_sans_transaction && e.0 == regulieres + 1 {
                            e.2 = true;
                            return Authorization::Deny;
                        }
                    }
                    AuthAction::Transaction { operation: TransactionOperation::Unknown } => {
                        e.1 += 1;
                        if suivante_sans_transaction && e.1 == regulieres {
                            e.2 = true;
                        }
                    }
                    _ => {}
                }
                Authorization::Allow
            }));
            assert!(!migrate(&c), "v{v} : la chaîne s'arrête");
            c.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        } else {
            assert!(migrate(&c), "v{v} : la chaîne va au bout");
        }
        assert_eq!(crate::migrate::read_schema_version(&c), v, "la chaîne est arrêtée à v{v}");
        c
    }

    /// À CHAQUE VERSION QUE CE BINAIRE SAIT MIGRER, sa chaîne arrêtée là ne porte que des couples (nom, texte) de
    /// l'ensemble de référence : aucun texte d'une version antérieure ne diffère de celui de la tête. Les trois
    /// déclencheurs de l'étape v125 n'y sont qu'à partir de v125, et la réunion des versions est l'ensemble privé des
    /// deux déclencheurs de l'entretien (créés hors migrations).
    #[test]
    fn a_chaque_version_la_chaine_arretee_ne_porte_que_des_couples_de_l_ensemble() {
        let reference = reference();
        let mut reunion = std::collections::BTreeSet::new();
        let max = crate::migrate::CODE_SCHEMA_MAX;
        assert!(max >= 126, "plancher : la chaîne de la base dcdd1454 va jusqu'à v126");
        for v in 1..=max {
            let couples = declencheurs_et_vues(&base_arretee_a(v));
            for couple in &couples {
                assert!(reference.contains(couple), "v{v} : {couple:?} n'est pas dans l'ensemble de référence");
            }
            let tableaux = couples.iter().filter(|(n, _)| n.starts_with("view_dashboard_suit_")).count();
            assert_eq!(tableaux, if v >= 125 { 3 } else { 0 }, "v{v} : les déclencheurs de l'étape v125");
            reunion.extend(couples);
        }
        let sans_l_entretien: std::collections::BTreeSet<(String, String)> =
            reference.into_iter().filter(|(n, _)| !DE_L_ENTRETIEN.contains(&n.as_str())).collect();
        assert_eq!(reunion, sans_l_entretien, "la réunion des versions");
    }

    /// UNE ARCHIVE D'UNE BASE ANTÉRIEURE SE RESTAURE : la chaîne arrêtée à v124 (avant les déclencheurs des tableaux de
    /// bord) et à v1 (le seul schéma de base), sauvegardées au format courant, se restaurent ; la base publiée porte les
    /// déclencheurs de sa version.
    #[test]
    fn une_archive_d_une_base_arretee_avant_la_tete_se_restaure() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        for v in [1i64, 124] {
            let _tmp = crate::tmp_possede::TmpPossede::neuf(&format!("ck2-v{v}"));
            let racine = _tmp.racine().chemin().to_path_buf();
            let src = chemin(&racine, "src.db");
            let attendus = {
                let arretee = base_arretee_a(v);
                arretee.execute_batch(&format!("ATTACH DATABASE '{src}' AS enc KEY '{CLE}'; SELECT sqlcipher_export('enc'); DETACH DATABASE enc;")).unwrap();
                declencheurs_et_vues(&arretee)
            };
            assert!(attendus.len() >= 2, "contrôle : la base v{v} porte des déclencheurs");
            let archive = chemin(&racine, "archive.age");
            backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde");
            assert!(backup_payload_head(&archive, CLE).starts_with(b"PLUMEDUMP1\n"), "v{v} : format courant");
            let dst = restauree(&format!("ck2-v{v}"), &racine, &archive);
            assert_eq!(declencheurs_et_vues(&dst), attendus, "v{v} : les déclencheurs de sa version");
        }
    }

    // ── RIEN DE CE QUE L'ÉCRIVAIN ÉMET N'EST REFUSÉ ─────────────────────────────────────────────────

    /// ALLER-RETOUR COURANT DE LA TÊTE : ses déclencheurs (ceux de `db/schema.sql` et de v125) se restaurent, nom et
    /// texte, et la base publiée porte exactement ceux de la source.
    #[test]
    fn aller_retour_courant_de_la_tete() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ck2-tete-courant");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        let attendus = {
            let c = open_db_keyed(&src, Some(CLE)).unwrap();
            base_de_la_tete(&c, false);
            declencheurs_et_vues(&c)
        };
        assert_eq!(attendus.len(), 5, "contrôle : les cinq déclencheurs de la tête");
        let archive = chemin(&racine, "archive.age");
        backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde");
        assert!(backup_payload_head(&archive, CLE).starts_with(b"PLUMEDUMP1\n"), "format courant");
        let dst = restauree("ck2-tete-courant", &racine, &archive);
        assert_eq!(declencheurs_et_vues(&dst), attendus);
    }

    /// ALLER-RETOUR ANCIEN DE LA TÊTE avec le filtre de champs (qui fait prendre le format ancien) : les sept
    /// déclencheurs se restaurent, nom et texte.
    #[test]
    fn aller_retour_ancien_de_la_tete_avec_le_filtre_de_champs() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ck2-tete-ancien");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        let attendus = {
            let c = open_db_keyed(&src, Some(CLE)).unwrap();
            base_de_la_tete(&c, true);
            declencheurs_et_vues(&c)
        };
        assert_eq!(attendus.len(), 7, "contrôle : les sept déclencheurs de la tête et de l'entretien");
        let archive = chemin(&racine, "archive.age");
        backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde");
        assert!(backup_payload_head(&archive, CLE).starts_with(b"SQLite format 3\0"), "format ancien");
        let dst = restauree("ck2-tete-ancien", &racine, &archive);
        assert_eq!(declencheurs_et_vues(&dst), attendus);
    }

    // ── LES FIXTURES QUE DES TÉMOINS ANTÉRIEURS RESTAURAIENT ────────────────────────────────────────

    /// La vue et le déclencheur `INSTEAD OF` que portaient les allers-retours de la tête de
    /// `restauration_liste_fermee_des_instructions.rs` et `restauration_format_ancien_liste_fermee.rs`.
    const VUE_DES_REFUS: &str = "CREATE VIEW vue_des_refus AS SELECT id, host, message FROM event WHERE severity >= 3;";
    const SANS_ECRITURE: &str = "CREATE TRIGGER vue_des_refus_sans_ecriture INSTEAD OF DELETE ON vue_des_refus BEGIN SELECT 1; END;";

    /// La sauvegarde réelle d'une base de la tête (avec l'entretien si `entretien`) à laquelle on ajoute `ajout`, par un
    /// écrivain qui émet tout déclencheur et toute vue (`crochet_de_l_ecrivain::tout_emettre`), comme l'écrivain d'avant
    /// la règle qu'il partage désormais avec la restauration ; rend les octets de l'archive.
    fn archive_de_la_tete_avec(cas: &str, entretien: bool, ajout: &str, tete_attendue: &[u8]) -> Vec<u8> {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _ecrivain = crate::backup::crochet_de_l_ecrivain::tout_emettre();
        let _tmp = crate::tmp_possede::TmpPossede::neuf(&format!("{cas}-source"));
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        {
            let c = open_db_keyed(&src, Some(CLE)).unwrap();
            base_de_la_tete(&c, entretien);
            c.execute_batch(ajout).unwrap();
        }
        let archive = chemin(&racine, "archive.age");
        backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde");
        assert!(backup_payload_head(&archive, CLE).starts_with(tete_attendue), "{cas} : format de l'archive");
        std::fs::read(&archive).unwrap()
    }

    /// INVERSION NOMMÉE : la vue `vue_des_refus`, que l'aller-retour courant de la tête restaurait, est refusée dans
    /// l'archive d'une base de la tête écrite par un écrivain qui émet tout ; au format ancien (filtre de champs), la même
    /// vue et son déclencheur `INSTEAD OF`, que l'aller-retour ancien restaurait. L'écrivain du démon, lui, les omet et
    /// son archive se restaure (`sauvegarde_objets_hors_reference_omis_et_dits.rs`).
    #[test]
    fn les_fixtures_des_allers_retours_anterieurs_sont_refusees() {
        let courant = archive_de_la_tete_avec("ck2-inv-courant", false, VUE_DES_REFUS, b"PLUMEDUMP1\n");
        let ancien = archive_de_la_tete_avec("ck2-inv-ancien", true, &format!("{VUE_DES_REFUS} {SANS_ECRITURE}"), b"SQLite format 3\0");
        refusee_l_archive("ck2-inv-courant", &courant, hors_liste("post-DDL", ETRANGER));
        refusee_l_archive("ck2-inv-ancien", &ancien, hors_liste("format ancien", ETRANGER));
    }

    // ── L'ORDRE : TOUTE AUTRE CAUSE GARDE SA PRIORITÉ ───────────────────────────────────────────────

    /// FORMAT COURANT : une sentinelle de fin absente l'emporte sur un déclencheur étranger (le jugement vient après elle).
    #[test]
    fn courant_une_sentinelle_absente_l_emporte_sur_le_corps() {
        refusee("ck2-c-sentinelle", &dump_complet(&[DECLENCHEUR_ETRANGER], 0x00), |dest| {
            format!("restore : sentinelle de fin absente (0x00) — dump tronqué/corrompu{}", suffixe_intacte(dest))
        });
    }

    /// FORMAT COURANT : une vue étrangère au nom d'une table fantôme, posée avant la table virtuelle, fait refuser la
    /// création de celle-ci sous la cause des noms, pas sous celle du corps.
    #[test]
    fn courant_une_vue_au_nom_d_une_table_fantome_garde_la_cause_des_noms() {
        refusee(
            "ck2-c-vue-nommee",
            &dump(&["CREATE VIEW f4_stat AS SELECT 1 AS id, x'00' AS value", "CREATE VIRTUAL TABLE f4 USING fts4(v, content='t')"]),
            hors_liste("post-DDL", "objet au nom d'une table fantôme d'une table virtuelle"),
        );
    }

    /// FORMAT ANCIEN : des tables fantômes autres que celles que le module crée l'emportent sur un déclencheur étranger
    /// (le jugement du corps vient après leur comparaison).
    #[test]
    fn ancien_des_tables_fantomes_autres_l_emportent_sur_le_corps() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ck2-a-fantome-fixture");
        let racine = _tmp.racine().chemin().to_path_buf();
        refusee(
            "ck2-a-fantome",
            &clair(&racine, &format!("CREATE VIRTUAL TABLE f USING fts5(v, content='t'); CREATE TABLE f_content(x); {DECLENCHEUR_ETRANGER};")),
            hors_liste("format ancien", "tables fantômes autres que celles que le module crée"),
        );
    }

    // ── LES CROCHETS DE TEST ET LE REPLI FERMÉ ──────────────────────────────────────────────────────

    /// `sans_jugement_des_declencheurs_et_des_vues` admet un corps étranger, et se désarme en sortie de portée : le même
    /// dump est ensuite refusé sur le même fil.
    #[test]
    fn le_crochet_qui_leve_le_jugement_du_corps_se_desarme_en_sortie_de_portee() {
        let charge = dump(&[DECLENCHEUR_ETRANGER, VUE_ETRANGERE]);
        {
            let _corps = crate::backup::crochets_de_restauration::sans_jugement_des_declencheurs_et_des_vues();
            let _tmp = crate::tmp_possede::TmpPossede::neuf("ck2-crochet-arme");
            let racine = _tmp.racine().chemin().to_path_buf();
            let c = admise("ck2-crochet-arme", &racine, &charge);
            assert_eq!(declencheurs_et_vues(&c).len(), 2, "contrôle : le crochet armé lève le jugement");
        }
        refusee("ck2-crochet-desarme", &charge, hors_liste("post-DDL", ETRANGER));
    }

    /// LE CROCHET DES GARDES PROFONDES (`sans_refus_sur_les_tables_fantomes`) LÈVE AUSSI LE JUGEMENT DU CORPS : un
    /// déclencheur étranger sur `t` se restaure sous lui (les gardes de la reconstruction et de la validation qu'il garde
    /// sont jouées après ce jugement).
    #[test]
    fn le_crochet_des_gardes_profondes_leve_aussi_le_jugement_du_corps() {
        let _arme = crate::backup::crochets_de_restauration::sans_refus_sur_les_tables_fantomes();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ck2-crochet-profond");
        let racine = _tmp.racine().chemin().to_path_buf();
        let c = admise("ck2-crochet-profond", &racine, &dump(&[DECLENCHEUR_ETRANGER]));
        assert_eq!(declencheurs_et_vues(&c).len(), 1);
    }

    /// LE REPLI FERMÉ : un ensemble de référence lu comme non construit n'a aucun membre ; la sauvegarde réelle d'une base
    /// de la tête, dont tous les déclencheurs sont ceux du démon, est alors refusée. Une archive sans déclencheur ni vue
    /// ne consulte pas l'ensemble et se restaure.
    #[test]
    fn un_ensemble_non_construit_refuse_tout_declencheur_et_n_est_pas_consulte_sans_eux() {
        let archive = archive_de_la_tete_avec("ck2-sans-ensemble", false, "", b"PLUMEDUMP1\n");
        let _sans = crate::backup::crochets_de_restauration::sans_ensemble_de_reference();
        refusee_l_archive("ck2-sans-ensemble", &archive, hors_liste("post-DDL", ETRANGER));
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ck2-sans-ensemble-ni-declencheur");
        let racine = _tmp.racine().chemin().to_path_buf();
        let c = admise("ck2-sans-ensemble-ni-declencheur", &racine, &dump(&["CREATE INDEX t_v ON t(v)"]));
        assert!(declencheurs_et_vues(&c).is_empty(), "contrôle : ni déclencheur ni vue");
    }

    // ── AUCUNE NORMALISATION ────────────────────────────────────────────────────────────────────────

    /// La table que vise `event_ai`, sans ligne : un dump forgé peut y poser le déclencheur.
    const EVENT: &str = "CREATE TABLE event(id INTEGER PRIMARY KEY, message TEXT, source TEXT, category TEXT)";

    /// LE TEXTE EXACT EST ADMIS, UNE ÉCRITURE VOISINE NE L'EST PAS : dans un dump forgé, `event_ai` au texte de la
    /// référence se restaure ; le même texte suivi d'un point-virgule, écrit en minuscules, ou nommé par sa base
    /// (`main.event_ai`, même nom pour le moteur) est refusé. Au format ancien, le moteur réécrit lui-même la tête de
    /// ce qu'il range dans `sqlite_master` : les deux premières écritures y sont posées par `writable_schema`, et refusées.
    #[test]
    fn le_texte_exact_est_admis_et_une_ecriture_voisine_est_refusee() {
        let texte = reference().into_iter().find(|(n, _)| n == "event_ai").map(|(_, t)| t).expect("event_ai est dans la référence");
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ck2-exact");
        let racine = _tmp.racine().chemin().to_path_buf();
        let c = admise("ck2-exact", &racine, &dump_avec_tables(&[EVENT], &[&texte], 0xFF));
        assert_eq!(
            lignes_de(&c, "SELECT name, sql FROM sqlite_master WHERE type = 'trigger'"),
            vec![format!("Text(\"event_ai\")|Text({texte:?})")],
            "le déclencheur au texte exact est restauré",
        );
        let voisines = [
            ("point-virgule", format!("{texte};")),
            ("minuscules", texte.replacen("CREATE TRIGGER", "create trigger", 1)),
            ("nom-qualifie", texte.replacen("CREATE TRIGGER event_ai", "CREATE TRIGGER main.event_ai", 1)),
        ];
        assert!(voisines.iter().all(|(_, v)| v != &texte), "contrôle : chaque écriture voisine diffère du texte");
        for (cas, voisine) in &voisines {
            refusee(&format!("ck2-c-voisine-{cas}"), &dump_avec_tables(&[EVENT], &[voisine], 0xFF), hors_liste("post-DDL", ETRANGER));
        }
        for (cas, voisine) in voisines.iter().take(2) {
            let fixture = crate::tmp_possede::TmpPossede::neuf(&format!("ck2-a-voisine-{cas}-fixture"));
            let ddl = format!(
                "{EVENT}; {texte}; PRAGMA writable_schema=ON; UPDATE sqlite_master SET sql = '{}' WHERE name = 'event_ai'; \
                 PRAGMA writable_schema=OFF;",
                voisine.replace('\'', "''")
            );
            refusee(&format!("ck2-a-voisine-{cas}"), &clair(fixture.racine().chemin(), &ddl), hors_liste("format ancien", ETRANGER));
        }
    }
}
