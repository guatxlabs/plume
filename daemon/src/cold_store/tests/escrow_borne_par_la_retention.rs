// `P10.34-k` — LE PLAN D'ESCROW FROID EST BORNÉ PAR LA RÉTENTION, AVOUE CE QU'IL N'A PAS LU, ET SES COPIES SONT
// DURABLES.
//
// Le défaut (VU sur 53488460) : `cold_backup_plan` (`cold_store/backup.rs`) listait tout `cold_seal` sans borne de
// rétention. L'expiration (`expire_cold_days`) garde la ligne d'un fichier qu'elle n'a pas pu retirer : ce jour expiré
// était planifié, puis copié par l'escrow local (`escrow_local.rs`) vers la destination de sauvegarde — au-delà de sa
// rétention, alors que le lecteur froid l'écarte déjà. Et une lecture ratée de l'index rendait un plan vide, c'est-à-dire
// « rien à copier », et la sous-commande `cold-escrow` sortait en 0. Enfin `copier_verbatim` publiait par `rename` un
// temporaire jamais synchronisé, sans synchroniser le répertoire : une coupure pouvait laisser un nom final au contenu
// perdu, que le relevé suivant tient pour « déjà à l'abri ».
//
// LES TÉMOINS passent par les points d'entrée (`cold_backup_plan`, `mettre_a_l_abri_les_jours_froids`, et
// `mettre_a_l_abri_avec` pour les gestes de durabilité injectés). Les phrases sont comparées à des CONSTANTES du test,
// à l'octet.
//  (1) jour expiré dont la ligne est gardée par un vrai refus d'unlink (vieillissement réel) : absent du plan et de la
//      destination, compté ; le jour dans la rétention est copié ;
//  (2) bords : dernier jour expiré écarté, lendemain planifié ;
//  (3) deux index, dont un sous une politique plus courte ; rétention froide étendue ;
//  (4) rétention illisible (« 365.0 », BLOB) : plan COMPLET et aveu ;
//  (5) index non lu (interruption du moteur) : aveu, plan vide, sortie non nulle, par l'escrow ; table absente : rien ;
//  (6) ligne d'index illisible comptée ;
//  (7) code de sortie, « quelque chose à dire », phrase entière ;
//  (8) ordre des gestes de durabilité ; (9) échec de la synchronisation du temporaire ; (10) gestes du disque ;
//  (11) câblage des appelants, lu sur le texte (`main.rs`, `server/sauvegarde_planifiee.rs`) ;
//  (12) la VALEUR de la rétention écrite en base (60 puis 10, pas le défaut de 30) borne le plan et la copie ;
//  (13) la rétention portée par la configuration (`PLUME_RETENTION_DAYS` = 10) borne le plan ;
//  (14) synchronisation du répertoire refusée APRÈS la publication : échec nommé, sortie 1, copie laissée en place
//       et rendue faite (un dépôt objet la dépose) ; (15) même chose sur le disque, répertoire `-wx` qui cache au
//       relevé la copie publiée au tour d'avant : elle n'est jamais retirée.
//
// MUTANTS JOUÉS (variable de mutation, retirés du source avant le commit), chacun vu ROUGE :
//  plan : AT2_INDEX_AVALE, AT2_ABSENTE_AVOUEE, AT2_SONDE_TOUJOURS_ABSENTE, AT2_SONDE_ERREUR_ABSENTE,
//  AT2_ILLISIBLES_TUES, AT2_RETENTION_REPLI, AT2_RETENTION_TUE, AT2_SANS_BORNE, AT2_BORD_MOINS, AT2_BORD_PLUS,
//  AT2_POLITIQUE_IGNOREE, AT2_RETENTION_BRUTE, AT2_EXPIRES_TUS, AT2_AVEU_INDEX_TU, AT2_AVEU_RETENTION_TUE,
//  AT2_AVEU_EXPIRES_TU, AT2_AVEU_ILLISIBLES_TU, AT2_PLAN_CODE_ZERO ;
//  escrow : AT2_A_DIRE_SANS_PLAN, AT2_CODE_SANS_ECHECS, AT2_CODE_SANS_INDEX, AT2_PHRASE_SANS_AVEUX,
//  AT2_ESCROW_SANS_ETAT ;
//  durabilité : AT2_ORDRE_PERMUTE (renommage avant la synchronisation du temporaire), AT2_SYNC_TEMP_OMIS,
//  AT2_SYNC_REP_OMIS, AT2_SYNC_TEMP_ECHEC_IGNORE, AT2_TEMP_GARDE, AT2_SYNC_REP_ECHEC_IGNORE,
//  AT2_DISQUE_TEMP_NOOP, AT2_DISQUE_REP_NOOP ;
//  correction : AT2C_RD_IGNOREE (rétention lue remplacée par 30), AT2C_CONF_VIDE (rétention lue sans la
//  configuration), AT2C_CIBLE_RETIREE (copie publiée supprimée sur échec de synchronisation du répertoire),
//  AT2C_REP_HORS_COPIES (copie publiée absente des copies faites), AT2C_REP_SANS_ECHEC (échec de synchronisation du
//  répertoire tu). Le mutant AT2_CIBLE_GARDEE du premier passage (copie laissée sur échec de synchronisation du
//  répertoire) est désormais le comportement voulu : la retirer détruisait une copie publiée à un tour précédent que
//  le relevé n'avait pas pu voir (15).
// Le câblage des appelants (11) est éprouvé dans le test lui-même (texte d'avant rejoué, le juge rougit).
// CE QUE CES TÉMOINS NE TIENNENT PAS : que les octets atteignent le support (une coupure seule le montre) ; que le
// point d'entrée `mettre_a_l_abri_les_jours_froids` délègue bien à `GestesDuDisque` (le lien n'est pas témoigné) ;
// (15) sous un compte privilégié, où la privation de lecture ne mord pas (alors non joué, et dit) ; la ligne
// `[backup-sched] escrow froid : …` du planificateur natif (fonction privée de `server`, format inchangé, phrase
// jugée à l'octet ici) ; les lignes `[cold-backup-plan] …` et la sortie de `main` (témoin de texte).

use super::*;
use super::super::backup::EtatDuPlan;
use super::super::escrow_local::{mettre_a_l_abri_avec, GestesDeCopie, GestesDuDisque};

const AT2_AVEU_RETENTION: &str = "réglage de rétention `retention_days` illisible : plan COMPLET, aucune borne fabriquée — des jours au-delà de la rétention peuvent y figurer";
const AT2_AVEU_INDEX_INTERROMPU: &str = "index cold_seal NON LU (code SQLite 9 (OperationInterrupted)) : aucun jour froid planifié — ce n'est pas « rien à copier », retenté au cycle suivant";
const AT2_AVEU_UN_EXPIRE: &str = "1 fichier(s) froid(s) au-delà de la rétention écarté(s) du plan (ligne cold_seal gardée, fichier non retiré)";
const AT2_AVEU_DEUX_EXPIRES: &str = "2 fichier(s) froid(s) au-delà de la rétention écarté(s) du plan (ligne cold_seal gardée, fichier non retiré)";
const AT2_AVEU_UNE_ILLISIBLE: &str = "1 ligne(s) cold_seal illisible(s) : leur(s) fichier(s) non planifié(s)";

fn at2_seal(db: &Arc<Mutex<Connection>>, env: &str, day: i64) {
    let ts = day * SECS_PER_DAY;
    seal_row(db, env, day, 0, 1, 1, 1, ts, ts, i64::MIN, i64::MIN, 1, 1);
}

fn at2_fichier(cold: &Path, env: &str, day: i64, contenu: &[u8]) {
    let p = file_path(cold, env, day, 0);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, contenu).unwrap();
}

fn at2_cle(env: &str, day: i64) -> String {
    format!("cold/default/{env}/{}-0000.parquet", ymd_from_day(day))
}

fn at2_plan(db: &Arc<Mutex<Connection>>, conf: &HashMap<String, String>, cold: &Path) -> (Vec<String>, EtatDuPlan) {
    let plan = cold_backup_plan(&db.lock(), conf, n_now(), cold, "default", &HashSet::new());
    (plan.items.iter().map(|i| i.key.clone()).collect(), plan.etat)
}

/// (1) UN JOUR EXPIRÉ DONT LA LIGNE EST GARDÉE N'EST NI PLANIFIÉ NI COPIÉ, ET IL EST COMPTÉ. L'état est celui que
/// laisse le VIEILLISSEMENT RÉEL : l'entrée du fichier scellé est un répertoire, `unlink` est refusé, la ligne
/// `cold_seal` reste ; le répertoire redevient ensuite un fichier lisible (ligne gardée ET fichier présent). Le jour
/// dans la rétention est copié. Rétention 30 j, instant `M`.
#[test]
fn at2_jour_expire_garde_par_le_vieillissement_n_est_pas_copie() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let root = tmp_root("at2-garde");
    let cold = root.join("cold");
    let destination = root.join("backups");
    let db = mkdb(&root);
    let expire = M - 40;
    let servi = M - 20;
    let entree = file_path(&cold, "prod", expire, 0);
    std::fs::create_dir_all(&entree).unwrap(); // unlink -> EISDIR, même en root
    at2_seal(&db, "prod", expire);
    let conf = conf_on(&cold, HOT_WIN);
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
    let gardees: i64 = db.lock().query_row("SELECT count(*) FROM cold_seal WHERE day=?1", params![expire], |r| r.get(0)).unwrap();
    assert_eq!(gardees, 1, "contrôle : le vieillissement a gardé la ligne du fichier non retiré");
    std::fs::remove_dir(&entree).unwrap();
    std::fs::write(&entree, b"jour expire, ligne gardee").unwrap();
    at2_seal(&db, "prod", servi);
    at2_fichier(&cold, "prod", servi, b"jour servi");
    let r = { let c = db.lock(); escrow_local::mettre_a_l_abri_les_jours_froids(&c, &conf, n_now(), &cold, "default", &destination) };
    assert_eq!(r.copies_faites, vec![(at2_cle("prod", servi), destination.join(at2_cle("prod", servi)))], "{}", r.phrase());
    assert!(!destination.join(at2_cle("prod", expire)).exists(), "le jour expiré n'est pas copié : {}", r.phrase());
    assert_eq!(r.plan, EtatDuPlan { expires_ecartes: 1, ..Default::default() }, "{}", r.phrase());
    assert_eq!(r.phrase(), format!("0 jour(s) froid(s) déjà à l'abri, 1 à copier, 1 copié(s) (10 octets), {AT2_AVEU_UN_EXPIRE}"));
    assert!(r.a_quelque_chose_a_dire());
    assert_eq!(r.code_de_sortie(), 0, "un jour écarté n'est pas un échec");
    // Le tour suivant : le jour servi est à l'abri, l'expiré reste écarté et compté, rien n'est copié.
    let r2 = { let c = db.lock(); escrow_local::mettre_a_l_abri_les_jours_froids(&c, &conf, n_now(), &cold, "default", &destination) };
    assert_eq!(r2.phrase(), format!("1 jour(s) froid(s) déjà à l'abri, 0 à copier, 0 copié(s) (0 octets), {AT2_AVEU_UN_EXPIRE}"));
}

/// (2) LES BORDS : dernier jour expiré (`M-31` à rétention 30) écarté, son lendemain (`M-30`) planifié ; un jour plus
/// ancien écarté, un plus récent planifié. Le compte est celui des fichiers écartés.
#[test]
fn at2_bords_du_dernier_jour_expire() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let root = tmp_root("at2-bords");
    let cold = root.join("cold");
    let db = mkdb(&root);
    for d in [M - 40, M - 31, M - 30, M - 23] {
        at2_seal(&db, "prod", d);
        at2_fichier(&cold, "prod", d, b"x");
    }
    let (cles, etat) = at2_plan(&db, &HashMap::new(), &cold);
    assert_eq!(cles, vec![at2_cle("prod", M - 30), at2_cle("prod", M - 23)]);
    assert_eq!(etat, EtatDuPlan { expires_ecartes: 2, ..Default::default() });
    assert_eq!(etat.aveux(), vec![AT2_AVEU_DEUX_EXPIRES.to_string()]);
}

/// (3) DEUX INDEX, UNE POLITIQUE PLUS COURTE : `stage` sous 10 j (dernier jour expiré `M-11`), `prod` sous la globale
/// (30 j). Puis la rétention froide ÉTENDUE (`PLUME_COLD_RETENTION_DAYS` = 60) garde `prod` à `M-40` : la borne est
/// celle de `Bande`, pas la rétention brute.
#[test]
fn at2_deux_index_dont_un_sous_politique_plus_courte() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let root = tmp_root("at2-politique");
    let cold = root.join("cold");
    let db = mkdb(&root);
    mk_index_policy(&db, "stage", 10);
    for (env, d) in [("prod", M - 40), ("prod", M - 20), ("stage", M - 20), ("stage", M - 11), ("stage", M - 10)] {
        at2_seal(&db, env, d);
        at2_fichier(&cold, env, d, b"x");
    }
    let (cles, etat) = at2_plan(&db, &HashMap::new(), &cold);
    assert_eq!(cles, vec![at2_cle("prod", M - 20), at2_cle("stage", M - 10)]);
    assert_eq!(etat, EtatDuPlan { expires_ecartes: 3, ..Default::default() });
    let mut etendue = HashMap::new();
    etendue.insert("PLUME_COLD_RETENTION_DAYS".to_string(), "60".to_string());
    let (cles, etat) = at2_plan(&db, &etendue, &cold);
    assert_eq!(cles, vec![at2_cle("prod", M - 40), at2_cle("prod", M - 20), at2_cle("stage", M - 10)]);
    assert_eq!(etat, EtatDuPlan { expires_ecartes: 2, ..Default::default() });
}

/// (4) RÉTENTION ILLISIBLE (« 365.0 », puis BLOB) : le plan est COMPLET — le jour qu'une borne de repli (30 j)
/// écarterait y figure — et c'est dit ; aucun jour n'est compté écarté. Sortie 0 : le plan est entier.
#[test]
fn at2_retention_illisible_plan_complet_et_aveu() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    for valeur in ["'365.0'", "X'00'"] {
        let root = tmp_root("at2-retention");
        let cold = root.join("cold");
        let db = mkdb(&root);
        db.lock()
            .execute_batch(&format!("INSERT INTO setting(scope,key,value) VALUES('global','retention_days',{valeur})"))
            .unwrap();
        for d in [M - 40, M - 20] {
            at2_seal(&db, "prod", d);
            at2_fichier(&cold, "prod", d, b"x");
        }
        let plan = cold_backup_plan(&db.lock(), &HashMap::new(), n_now(), &cold, "default", &HashSet::new());
        assert_eq!(plan.items.iter().map(|i| i.key.clone()).collect::<Vec<_>>(), vec![at2_cle("prod", M - 40), at2_cle("prod", M - 20)], "{valeur}");
        assert_eq!(plan.etat, EtatDuPlan { retention_non_lue: true, ..Default::default() }, "{valeur}");
        assert_eq!(plan.etat.aveux(), vec![AT2_AVEU_RETENTION.to_string()], "{valeur}");
        assert_eq!(plan.code_de_sortie(), 0, "{valeur}");
    }
}

/// (5) INDEX NON LU (le moteur interrompt la lecture au premier pas), PAR L'ESCROW : aucun jour copié, l'aveu nomme
/// le code, le rendu a quelque chose à dire et la sous-commande sortirait en 1. Le plan seul dit la même chose. La
/// sonde de schéma est interrompue elle aussi : une table dont on ne sait pas si elle existe n'est pas « absente ».
#[test]
fn at2_index_non_lu_avoue_et_sortie_non_nulle() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let root = tmp_root("at2-index");
    let cold = root.join("cold");
    let destination = root.join("backups");
    let db = mkdb(&root);
    at2_seal(&db, "prod", M - 20);
    at2_fichier(&cold, "prod", M - 20, b"x");
    let c = db.lock();
    c.progress_handler(1, Some(|| true));
    let r = escrow_local::mettre_a_l_abri_les_jours_froids(&c, &HashMap::new(), n_now(), &cold, "default", &destination);
    let plan = cold_backup_plan(&c, &HashMap::new(), n_now(), &cold, "default", &HashSet::new());
    c.progress_handler(1, None::<fn() -> bool>);
    assert_eq!(r.plan, EtatDuPlan { index_non_lu: Some("code SQLite 9 (OperationInterrupted)".to_string()), ..Default::default() });
    assert_eq!(r.phrase(), format!("0 jour(s) froid(s) déjà à l'abri, 0 à copier, 0 copié(s) (0 octets), {AT2_AVEU_INDEX_INTERROMPU}"));
    assert!(r.a_quelque_chose_a_dire());
    assert_eq!(r.code_de_sortie(), 1);
    assert!(!destination.join(at2_cle("prod", M - 20)).exists());
    assert!(plan.items.is_empty());
    assert_eq!(plan.etat.aveux(), vec![AT2_AVEU_INDEX_INTERROMPU.to_string()]);
    assert_eq!(plan.code_de_sortie(), 1);
    // Contrôle : sans interruption, le même jour est planifié.
    let lu = cold_backup_plan(&c, &HashMap::new(), n_now(), &cold, "default", &HashSet::new());
    assert_eq!(lu.items.len(), 1);
    assert_eq!(lu.code_de_sortie(), 0);
}

/// (6) UNE LIGNE D'INDEX ILLISIBLE (`env_id` en BLOB) est comptée et dite ; la voisine lisible est planifiée.
#[test]
fn at2_ligne_d_index_illisible_comptee() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let root = tmp_root("at2-illisible");
    let cold = root.join("cold");
    let db = mkdb(&root);
    at2_seal(&db, "prod", M - 20);
    at2_fichier(&cold, "prod", M - 20, b"x");
    db.lock()
        .execute(
            "INSERT INTO cold_seal(env_id,day,seq,expected_rows,sealed_ts,purged,max_id,ts_min,ts_max,lo_ts,lo_id,hi_id,last_file) \
             VALUES(X'00',?1,1,1,0,1,1,0,0,0,0,1,1)",
            params![M - 20],
        )
        .unwrap();
    let (cles, etat) = at2_plan(&db, &HashMap::new(), &cold);
    assert_eq!(cles, vec![at2_cle("prod", M - 20)]);
    assert_eq!(etat, EtatDuPlan { lignes_illisibles: 1, ..Default::default() });
    assert_eq!(etat.aveux(), vec![AT2_AVEU_UNE_ILLISIBLE.to_string()]);
}

/// (7) CODE DE SORTIE, « QUELQUE CHOSE À DIRE », PHRASE : chaque fait du plan, seul, fait parler le journal ; seuls
/// l'index non lu et l'échec de copie font sortir en 1 ; la phrase entière porte chaque aveu dans l'ordre fixe.
#[test]
fn at2_rendu_code_de_sortie_et_phrase_entiere() {
    let faits = [
        EtatDuPlan { index_non_lu: Some("code SQLite 9 (OperationInterrupted)".to_string()), ..Default::default() },
        EtatDuPlan { retention_non_lue: true, ..Default::default() },
        EtatDuPlan { expires_ecartes: 1, ..Default::default() },
        EtatDuPlan { lignes_illisibles: 1, ..Default::default() },
    ];
    assert!(faits.iter().filter(|f| **f != EtatDuPlan::default()).count() >= 4, "plancher : quatre faits distincts");
    for (i, f) in faits.iter().enumerate() {
        let r = escrow_local::EscrowFroidRendu { plan: f.clone(), ..Default::default() };
        assert!(r.a_quelque_chose_a_dire(), "fait {i}");
        assert_eq!(r.code_de_sortie(), if i == 0 { 1 } else { 0 }, "fait {i}");
    }
    assert!(!escrow_local::EscrowFroidRendu::default().a_quelque_chose_a_dire());
    assert_eq!(escrow_local::EscrowFroidRendu::default().code_de_sortie(), 0);
    let echec = escrow_local::EscrowFroidRendu { echecs: vec!["k : cause".to_string()], ..Default::default() };
    assert_eq!(echec.code_de_sortie(), 1);
    let tout = escrow_local::EscrowFroidRendu {
        deja_a_l_abri: 3,
        a_copier: 1,
        entrees_illisibles: 1,
        plan: EtatDuPlan {
            index_non_lu: Some("code SQLite 9 (OperationInterrupted)".to_string()),
            retention_non_lue: true,
            expires_ecartes: 2,
            lignes_illisibles: 1,
        },
        echecs: vec!["k : cause".to_string()],
        ..Default::default()
    };
    assert_eq!(
        tout.phrase(),
        format!(
            "3 jour(s) froid(s) déjà à l'abri, 1 à copier, 0 copié(s) (0 octets), 1 entrée(s) de la destination illisible(s) — ignorée(s), et dite(s), \
             {AT2_AVEU_INDEX_INTERROMPU}, {AT2_AVEU_RETENTION}, {AT2_AVEU_DEUX_EXPIRES}, {AT2_AVEU_UNE_ILLISIBLE}, 1 ÉCHEC(S) : k : cause"
        )
    );
}

/// Les gestes de durabilité, relevés : chacun dit ce qu'il voit au moment où il est joué, puis délègue au disque ou
/// échoue sur demande.
struct At2Releve {
    cible: PathBuf,
    evenements: Vec<String>,
    echec_temporaire: bool,
    echec_repertoire: bool,
}

impl GestesDeCopie for At2Releve {
    fn synchroniser_le_temporaire(&mut self, tmp: &Path) -> std::io::Result<()> {
        let cache = tmp.file_name().unwrap().to_string_lossy().starts_with('.');
        let octets = std::fs::metadata(tmp).map(|m| m.len() as i64).unwrap_or(-1);
        self.evenements.push(format!(
            "sync-temporaire cache={cache} meme-repertoire={} octets={octets} cible-presente={}",
            tmp.parent() == self.cible.parent(),
            self.cible.exists()
        ));
        if self.echec_temporaire {
            return Err(std::io::Error::other("disque refuse"));
        }
        GestesDuDisque.synchroniser_le_temporaire(tmp)
    }
    fn renommer(&mut self, de: &Path, vers: &Path) -> std::io::Result<()> {
        self.evenements.push(format!("renommer vers-cible={}", vers == self.cible));
        GestesDuDisque.renommer(de, vers)
    }
    fn synchroniser_le_repertoire(&mut self, dir: &Path) -> std::io::Result<()> {
        self.evenements.push(format!("sync-repertoire parent={} cible-presente={}", Some(dir) == self.cible.parent(), self.cible.exists()));
        if self.echec_repertoire {
            return Err(std::io::Error::other("disque refuse"));
        }
        GestesDuDisque.synchroniser_le_repertoire(dir)
    }
}

fn at2_base_un_jour(tag: &str) -> (crate::tmp_possede::TmpPossede, PathBuf, PathBuf, Arc<Mutex<Connection>>) {
    let root = tmp_root(tag);
    let cold = root.join("cold");
    let destination = root.join("backups");
    let db = mkdb(&root);
    at2_seal(&db, "prod", M - 20);
    at2_fichier(&cold, "prod", M - 20, b"contenu verbatim");
    (root, cold, destination, db)
}

fn at2_caches(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|it| it.map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).filter(|n| n.starts_with('.')).collect())
        .unwrap_or_default()
}

/// (8) L'ORDRE DES GESTES : temporaire caché, complet, synchronisé AVANT le renommage (la cible n'existe pas encore),
/// puis renommage vers la cible, puis synchronisation du répertoire de la cible (qui existe alors).
#[test]
fn at2_ordre_synchronisation_puis_renommage_puis_repertoire() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, cold, destination, db) = at2_base_un_jour("at2-ordre");
    let cible = destination.join(at2_cle("prod", M - 20));
    let mut releve = At2Releve { cible: cible.clone(), evenements: Vec::new(), echec_temporaire: false, echec_repertoire: false };
    let r = { let c = db.lock(); mettre_a_l_abri_avec(&c, &HashMap::new(), n_now(), &cold, "default", &destination, &mut releve) };
    assert_eq!(
        releve.evenements,
        vec![
            "sync-temporaire cache=true meme-repertoire=true octets=16 cible-presente=false".to_string(),
            "renommer vers-cible=true".to_string(),
            "sync-repertoire parent=true cible-presente=true".to_string(),
        ]
    );
    assert_eq!((r.copies, r.echecs.len()), (1, 0), "{}", r.phrase());
    assert_eq!(std::fs::read(&cible).unwrap(), b"contenu verbatim");
}

/// (9) LA SYNCHRONISATION DU TEMPORAIRE REFUSÉE EST UN ÉCHEC DE COPIE NOMMÉ : rien n'est publié (la cible n'existe
/// pas), le temporaire est retiré, le cycle suivant rejoue la copie. Le refus APRÈS la publication est (14) et (15).
#[test]
fn at2_synchronisation_refusee_echec_nomme_et_copie_rejouee() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let cause = "synchronisation du temporaire : disque refuse — temporaire retiré, copie rejouée au cycle suivant";
    let (_root, cold, destination, db) = at2_base_un_jour("at2-sync-refusee");
    let cle = at2_cle("prod", M - 20);
    let cible = destination.join(&cle);
    let mut releve = At2Releve { cible: cible.clone(), evenements: Vec::new(), echec_temporaire: true, echec_repertoire: false };
    let r = { let c = db.lock(); mettre_a_l_abri_avec(&c, &HashMap::new(), n_now(), &cold, "default", &destination, &mut releve) };
    assert_eq!(r.echecs, vec![format!("{cle} : {cause}")], "{}", r.phrase());
    assert_eq!((r.copies, r.octets_copies, r.copies_faites.len()), (0, 0, 0), "{}", r.phrase());
    assert_eq!(r.code_de_sortie(), 1);
    assert!(!cible.exists(), "aucune copie laissée sous son nom final : {cause}");
    assert!(at2_caches(cible.parent().unwrap()).is_empty(), "aucun temporaire laissé : {cause}");
    let r2 = { let c = db.lock(); escrow_local::mettre_a_l_abri_les_jours_froids(&c, &HashMap::new(), n_now(), &cold, "default", &destination) };
    assert_eq!((r2.deja_a_l_abri, r2.copies), (0, 1), "le cycle suivant rejoue la copie : {}", r2.phrase());
}

/// La cause d'un refus de synchronisation du répertoire, après sa nature d'E/S.
const AT2_SUITE_SYNC_REP: &str =
    " — copie publiée laissée en place (jamais retirée), sa durabilité n'est pas établie ; le cycle suivant la tiendra pour à l'abri";

/// Une destination à une seule ligne de rétention écrite, cinq jours scellés et présents.
fn at2_base_cinq_jours(tag: &str) -> (crate::tmp_possede::TmpPossede, PathBuf, PathBuf, Arc<Mutex<Connection>>) {
    let root = tmp_root(tag);
    let cold = root.join("cold");
    let destination = root.join("backups");
    let db = mkdb(&root);
    for d in [M - 70, M - 40, M - 20, M - 11, M - 5] {
        at2_seal(&db, "prod", d);
        at2_fichier(&cold, "prod", d, b"x");
    }
    (root, cold, destination, db)
}

/// (12) LA VALEUR DE LA RÉTENTION ÉCRITE BORNE LE PLAN, PAS LE DÉFAUT. Rétention écrite 60 : seul `M-70` est au-delà
/// (dernier jour expiré `M-61`) ; `M-40`, qu'une borne de 30 j écarterait, est planifié ET copié par l'escrow. Puis
/// rétention écrite 10 : tout jusqu'à `M-11` est écarté, seul `M-5` reste — `M-20` et `M-11`, qu'une borne de 30 j
/// garderait, n'y sont pas.
#[test]
fn at2_retention_ecrite_borne_le_plan_a_sa_valeur() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, cold, destination, db) = at2_base_cinq_jours("at2-retention-ecrite");
    db.lock().execute_batch("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','60')").unwrap();
    let (cles, etat) = at2_plan(&db, &HashMap::new(), &cold);
    assert_eq!(cles, vec![at2_cle("prod", M - 40), at2_cle("prod", M - 20), at2_cle("prod", M - 11), at2_cle("prod", M - 5)], "rétention écrite 60");
    assert_eq!(etat, EtatDuPlan { expires_ecartes: 1, ..Default::default() }, "rétention écrite 60");
    let r = { let c = db.lock(); escrow_local::mettre_a_l_abri_les_jours_froids(&c, &HashMap::new(), n_now(), &cold, "default", &destination) };
    assert_eq!((r.copies, r.echecs.len()), (4, 0), "{}", r.phrase());
    assert!(destination.join(at2_cle("prod", M - 40)).exists(), "jour 40 sous une rétention de 60 : copié — {}", r.phrase());
    assert!(!destination.join(at2_cle("prod", M - 70)).exists(), "jour 70 sous une rétention de 60 : écarté — {}", r.phrase());
    db.lock().execute_batch("UPDATE setting SET value='10' WHERE scope='global' AND key='retention_days'").unwrap();
    let (cles, etat) = at2_plan(&db, &HashMap::new(), &cold);
    assert_eq!(cles, vec![at2_cle("prod", M - 5)], "rétention écrite 10");
    assert_eq!(etat, EtatDuPlan { expires_ecartes: 4, ..Default::default() }, "rétention écrite 10");
}

/// (13) LA RÉTENTION PORTÉE PAR LA CONFIGURATION BORNE LE PLAN : aucune ligne écrite, `PLUME_RETENTION_DAYS` = 10 dans la
/// configuration passée au plan ; seul `M-5` reste, les quatre autres sont écartés. Une lecture sans la configuration
/// rendrait le défaut de 30 j et planifierait `M-20` et `M-11`.
#[test]
fn at2_retention_de_la_configuration_borne_le_plan() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, cold, _destination, db) = at2_base_cinq_jours("at2-retention-conf");
    let mut conf = HashMap::new();
    conf.insert("PLUME_RETENTION_DAYS".to_string(), "10".to_string());
    let (cles, etat) = at2_plan(&db, &conf, &cold);
    assert_eq!(cles, vec![at2_cle("prod", M - 5)]);
    assert_eq!(etat, EtatDuPlan { expires_ecartes: 4, ..Default::default() });
    // Contrôle : sans la configuration, le défaut de 30 j.
    let (cles, _) = at2_plan(&db, &HashMap::new(), &cold);
    assert_eq!(cles, vec![at2_cle("prod", M - 20), at2_cle("prod", M - 11), at2_cle("prod", M - 5)]);
}

/// (14) LA SYNCHRONISATION DU RÉPERTOIRE REFUSÉE, APRÈS LA PUBLICATION : l'échec est nommé et la sortie vaut 1, mais
/// la copie reste sous son nom final, entière, et elle est rendue FAITE (un dépôt objet la dépose). Le cycle suivant
/// la voit et la tient pour à l'abri — c'est dit dans la cause.
#[test]
fn at2_synchronisation_du_repertoire_refusee_copie_laissee_et_dite() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, cold, destination, db) = at2_base_un_jour("at2-sync-rep");
    let cle = at2_cle("prod", M - 20);
    let cible = destination.join(&cle);
    let mut releve = At2Releve { cible: cible.clone(), evenements: Vec::new(), echec_temporaire: false, echec_repertoire: true };
    let r = { let c = db.lock(); mettre_a_l_abri_avec(&c, &HashMap::new(), n_now(), &cold, "default", &destination, &mut releve) };
    assert_eq!(r.echecs, vec![format!("{cle} : synchronisation du répertoire : disque refuse{AT2_SUITE_SYNC_REP}")], "{}", r.phrase());
    assert_eq!((r.copies, r.octets_copies), (1, 16), "{}", r.phrase());
    assert_eq!(r.copies_faites, vec![(cle.clone(), cible.clone())], "la copie publiée est à déposer : {}", r.phrase());
    assert_eq!(r.code_de_sortie(), 1);
    assert_eq!(std::fs::read(&cible).unwrap(), b"contenu verbatim", "la copie publiée n'est jamais retirée");
    assert!(at2_caches(cible.parent().unwrap()).is_empty(), "aucun temporaire laissé");
    let r2 = { let c = db.lock(); escrow_local::mettre_a_l_abri_les_jours_froids(&c, &HashMap::new(), n_now(), &cold, "default", &destination) };
    assert_eq!((r2.deja_a_l_abri, r2.copies, r2.echecs.len()), (1, 0, 0), "{}", r2.phrase());
}

/// (15) SUR LE DISQUE : le répertoire de l'index passe en `-wx` (0300) après un premier tour qui y a publié la copie.
/// Le relevé ne peut pas le lire (entrée illisible, dite) et replanifie le jour ; la copie, le renommage passent ;
/// la synchronisation du répertoire (qui l'ouvre en lecture) est refusée. La copie publiée au tour d'avant — remplacée
/// par le renommage — est TOUJOURS là. Sous un compte privilégié la privation ne mord pas : le scénario n'est pas
/// joué, et c'est dit ((14) tient la règle par les gestes injectés).
#[cfg(unix)]
#[test]
fn at2_repertoire_illisible_la_copie_publiee_avant_n_est_jamais_retiree() {
    use std::os::unix::fs::PermissionsExt;
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, cold, destination, db) = at2_base_un_jour("at2-rep-wx");
    let cle = at2_cle("prod", M - 20);
    let cible = destination.join(&cle);
    let r1 = { let c = db.lock(); escrow_local::mettre_a_l_abri_les_jours_froids(&c, &HashMap::new(), n_now(), &cold, "default", &destination) };
    assert_eq!((r1.copies, r1.echecs.len()), (1, 0), "contrôle : premier tour publié — {}", r1.phrase());
    let rep = cible.parent().unwrap().to_path_buf();
    std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o300)).unwrap();
    if std::fs::read_dir(&rep).is_ok() {
        std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o755)).unwrap();
        crate::tests::canal_de_refus::refuser_de_conclure(module_path!(), "at2_repertoire_illisible_la_copie_publiee_avant_n_est_jamais_retiree", "compte privilégié : la privation de lecture ne mord pas, scénario NON joué ((14) tient la règle)");
        return;
    }
    let r2 = { let c = db.lock(); escrow_local::mettre_a_l_abri_les_jours_froids(&c, &HashMap::new(), n_now(), &cold, "default", &destination) };
    std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!((r2.entrees_illisibles, r2.a_copier), (1, 1), "contrôle : le relevé n'a pas vu la copie — {}", r2.phrase());
    assert_eq!(r2.echecs.len(), 1, "{}", r2.phrase());
    let prefixe = format!("{cle} : synchronisation du répertoire : ");
    assert!(r2.echecs[0].starts_with(&prefixe) && r2.echecs[0].ends_with(AT2_SUITE_SYNC_REP), "{}", r2.phrase());
    assert_eq!(r2.code_de_sortie(), 1);
    assert_eq!(std::fs::read(&cible).unwrap(), b"contenu verbatim", "la copie publiée au tour d'avant est toujours là : {}", r2.phrase());
    assert!(at2_caches(&rep).is_empty(), "aucun temporaire laissé");
}

/// (10) LES GESTES DU DISQUE TOUCHENT LE CHEMIN QU'ON LEUR DONNE : un temporaire ou un répertoire absent rend une
/// erreur (un geste réduit à « rien » rendrait Ok). Contrôle : présents, ils réussissent. Ce témoin ne prouve pas que
/// les octets atteignent le support : cela ne se voit qu'après une coupure.
#[test]
fn at2_gestes_du_disque_ouvrent_ce_qu_ils_synchronisent() {
    let root = tmp_root("at2-disque");
    let absent = root.join("absent");
    assert!(GestesDuDisque.synchroniser_le_temporaire(&absent).is_err());
    assert!(GestesDuDisque.synchroniser_le_repertoire(&absent).is_err());
    let f = root.join("present");
    std::fs::write(&f, b"x").unwrap();
    assert!(GestesDuDisque.synchroniser_le_temporaire(&f).is_ok());
    assert!(GestesDuDisque.synchroniser_le_repertoire(&root).is_ok());
}

/// Le câblage, jugé sur le texte : chaque fragment attendu présent, chaque fragment retiré absent. Rend les écarts.
fn at2_juger_le_cablage(main: &str, planificateur: &str) -> Vec<String> {
    let attendus_main = [
        "let plan = cold_store::cold_backup_plan(&conn, &conf, now(), &cold_dir, tenant_prefix, &remote_keys);",
        "        for aveu in plan.etat.aveux() {\n            eprintln!(\"[cold-backup-plan] {aveu}\");\n        }",
        "        print!(\"{out}\");\n        let code = plan.code_de_sortie();\n        if code != 0 {\n            std::process::exit(code);\n        }\n        return;",
        "let rendu = cold_store::mettre_a_l_abri_les_jours_froids(&conn, &conf, now(), &cold_dir, \"default\", std::path::Path::new(&destination));",
        "        let code = rendu.code_de_sortie();\n        if code != 0 {\n            std::process::exit(code);\n        }\n        return;",
    ];
    let retires_main = ["if !rendu.echecs.is_empty() {\n            std::process::exit(1);", "for item in &plan {"];
    let attendu_planificateur = "                let conf = crate::load_config();\n                let rendu = crate::cold_store::mettre_a_l_abri_les_jours_froids(&conn, &conf, now(), cold_dir, \"default\", std::path::Path::new(dest_dir));\n                if rendu.a_quelque_chose_a_dire() {";
    let mut ecarts = Vec::new();
    for a in attendus_main {
        if main.matches(a).count() != 1 {
            ecarts.push(format!("main.rs : {} occurrence(s) de {a:?}", main.matches(a).count()));
        }
    }
    for r in retires_main {
        if main.contains(r) {
            ecarts.push(format!("main.rs porte encore {r:?}"));
        }
    }
    if planificateur.matches(attendu_planificateur).count() != 1 {
        ecarts.push("sauvegarde_planifiee.rs : appel de l'escrow sans configuration ni instant".to_string());
    }
    // La `conf` passée est celle de `load_config()` : entre l'entrée de la sous-commande et l'appel, UNE seule liaison
    // de `conf`, et c'est celle-là (une `let conf = HashMap::new();` insérée avant l'appel le laisserait intact).
    for (entree, appel) in [
        ("Some(\"cold-backup-plan\")", "cold_store::cold_backup_plan(&conn, &conf,"),
        ("Some(\"cold-escrow\")", "cold_store::mettre_a_l_abri_les_jours_froids(&conn, &conf,"),
    ] {
        let tronc = main.find(entree).and_then(|i| main[i..].find(appel).map(|j| &main[i..i + j]));
        let Some(tronc) = tronc else {
            ecarts.push(format!("main.rs : sous-commande {entree} sans son appel {appel:?}"));
            continue;
        };
        let liaisons = tronc.matches("let conf").count() + tronc.matches("let mut conf").count() + tronc.matches("conf =").count();
        if tronc.matches("let conf = load_config();").count() != 1 || liaisons != 2 {
            ecarts.push(format!("main.rs : sous-commande {entree} : la configuration passée n'est pas la seule `let conf = load_config();`"));
        }
    }
    ecarts
}

/// (11) LES APPELANTS PASSENT LA CONFIGURATION ET L'HEURE COURANTE, DISENT LES AVEUX, ET SORTENT SELON LE RENDU.
/// Témoin de TEXTE : il ne joue pas le binaire (un test d'intégration sur `CARGO_BIN_EXE_plume-daemon` changerait les
/// comptes de la CI). Épreuves : l'ancien texte (sortie sur les seuls échecs, plan sans borne) rougit le juge, et une
/// configuration vide liée avant l'appel, dans `cold-escrow` comme dans `cold-backup-plan`, aussi.
#[test]
fn at2_cablage_des_appelants() {
    let main = include_str!("../../main.rs");
    let planificateur = include_str!("../../server/sauvegarde_planifiee.rs");
    assert_eq!(at2_juger_le_cablage(main, planificateur), Vec::<String>::new());
    let epreuves_main = [
        (
            "let code = rendu.code_de_sortie();\n        if code != 0 {\n            std::process::exit(code);\n        }",
            "if !rendu.echecs.is_empty() {\n            std::process::exit(1);\n        }",
        ),
        ("cold_backup_plan(&conn, &conf, now(), &cold_dir,", "cold_backup_plan(&conn, &cold_dir,"),
        ("        for aveu in plan.etat.aveux() {", "        for aveu in Vec::<String>::new() {"),
        ("        let code = plan.code_de_sortie();\n", "        let code = 0;\n"),
        (
            "        let rendu = cold_store::mettre_a_l_abri_les_jours_froids(",
            "        let conf = HashMap::new();\n        let rendu = cold_store::mettre_a_l_abri_les_jours_froids(",
        ),
        (
            "        let plan = cold_store::cold_backup_plan(",
            "        let conf: HashMap<String, String> = HashMap::new();\n        let plan = cold_store::cold_backup_plan(",
        ),
    ];
    assert!(epreuves_main.len() >= 6, "plancher des épreuves");
    for (de, vers) in epreuves_main {
        assert!(main.contains(de), "contrôle : le fragment éprouvé existe : {de:?}");
        assert!(!at2_juger_le_cablage(&main.replacen(de, vers, 1), planificateur).is_empty(), "épreuve non vue : {vers:?}");
    }
    let sans_conf = planificateur.replacen("                let conf = crate::load_config();\n", "", 1);
    assert!(!at2_juger_le_cablage(main, &sans_conf).is_empty(), "épreuve non vue : planificateur sans configuration");
}
