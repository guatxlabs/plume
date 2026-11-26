// =====================================================================================
// `P10.32-o` (vague CJ, correction) — LA CLASSE D'UNE CAUSE DU MOTEUR EST SON CODE ÉTENDU, ET LA DÉCISION LIT LA CAUSE QUE
// SA PROPRE INTERROGATION A VUE.
//
// LES DÉFAUTS (6afc3868, relevés par un vérificateur indépendant) :
//  * la classe d'un refus du moteur est dite « code étendu », mais aucun témoin ne le tenait : les témoins n'opposaient
//    que des codes déjà différents au niveau primaire (SQLITE_AUTH contre SQLITE_FULL, SQLITE_AUTH contre
//    SQLITE_CONSTRAINT_TRIGGER), et une régression vers le code primaire (`extended_code & 0xff`) restait verte ; elle
//    tairait CHECK -> TRIGGER, IOERR_WRITE -> IOERR_FSYNC, READONLY -> READONLY_DBMOVED ;
//  * le bras « conversion impossible » n'avait aucun témoin de son rang ni de son type lu ;
//  * la classe observée vivait dans un registre de PROCESSUS partagé, relu par la décision après le relâchement de son
//    verrou : A voit X, B voit Y, A décide sous Y et imprime X, B décide sous Y et se tait ; la ligne qui cite Y ne
//    sortait pas pendant une durée du cache, le défaut même que la vague corrige.
//
// LE CORRECTIF : la dernière cause observée est tenue PAR FIL (`CAUSES_OBSERVEES_PAR_CE_FIL`, une entrée par famille),
// les sites de journal décidant sur le fil de leur observation sans point d'attente entre les deux. Le registre de
// processus, sa borne et son oubli à la destruction d'un tenant disparaissent avec lui (rien à oublier : une décision suit
// toujours sa propre observation).
//
// CE QUE CES TÉMOINS JUGENT :
//  (E) sur une base réelle, deux refus RÉELS d'écrire le cache de même code primaire (SQLITE_CONSTRAINT) : contrainte
//      CHECK (code étendu 275) puis déclencheur RAISE (1811), codes lus du moteur en contrôle : chacun sort sa ligne
//      `ResultatDirectNonEcrit` une fois, revu il se tait ;
//  (F) appel direct : `classe_de_la_cause` sépare trois paires de codes étendus de même code primaire, et la conversion
//      impossible par rang et par type lu, sans le texte de l'erreur de conversion ;
//  (G) deux FILS, deux connexions sur la même base, même panneau : A observe X (autorisateur), B observe Y
//      (déclencheur), A décide, puis B décide : chacun décide sous la classe de SA cause, la ligne de B sort, et X revu
//      ensuite se tait (A l'a dite) ;
//  (H) sur un même fil, une lecture illisible du panneau notée d'abord, puis deux refus d'écriture de classes
//      différentes sur ce panneau : la seconde classe du refus d'écriture est dite (la recherche de la classe observée
//      filtre sur la famille ; sans ce filtre, la décision lisait la classe de la lecture illisible et se taisait) ;
//  (I) à la destruction d'un tenant, les lignes dites QUI PORTENT UNE CLASSE sont oubliées : refus X dit, X revu tu,
//      base oubliée (`oublier_les_registres_d_une_base_detruite`), X revu dit de nouveau.
// MUTANTS JOUÉS (VERIF_MUT sous `cfg!(test)` dans `handlers/panneau_avoue.rs`, retirés avant le commit), chacun vu ROUGE :
//  CJ3_CLASSE_CODE_PRIMAIRE (E, F) ; CJ3_FSC_SANS_RANG_TYPE (F) ; CJ3_CAUSE_PARTAGEE_ENTRE_FILS (la cause observée
//  revient dans un état de processus partagé : G) ; M_FIND_SANS_FAMILLE (la recherche sans le test de famille : H) ;
//  M_OUBLI_GARDE_CLASSES (l'oubli garde les entrées à classe : I) ; CJ3_SANS_OBS_ECRITURE (E, G, H, I) ;
//  CJ3_SANS_OBS_ILLISIBLE (H).
// CE QU'ILS NE TIENNENT PAS : deux causes de même classe et de textes différents (deux messages `RAISE`) restent une seule
// classe, la seconde tue jusqu'à la durée du cache ; un futur site qui placerait un point d'attente entre l'observation
// et la décision lirait la cause d'une autre interrogation du même fil (aucun site actuel ne le fait) ; la conversion
// impossible n'est atteignable qu'en (rang 0, texte) avec la lecture actuelle, ses autres formes sont jugées par appel
// direct seulement.
// =====================================================================================
mod cause_du_moteur_code_etendu_et_observee_par_ce_fil {
    use super::*;
    use crate::handlers::panneau_avoue::{classe_de_la_cause, FamilleDeCause, NatureDeLigneDite};
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const CJ3C_TTL: i64 = 3600;
    const CJ3C_DECLENCHEUR: &str =
        "CREATE TEMP TRIGGER cj3c_refus BEFORE INSERT ON panel_cache BEGIN SELECT RAISE(ABORT, 'cj3c refus du declencheur'); END";
    const CJ3C_FP_REFUSE: &str = "cj3c-refuse";

    fn cj3c_base(nom: &str, contrainte: &str) -> (crate::tmp_possede::TmpPossede, String) {
        let dir = crate::tmp_possede::TmpPossede::neuf(nom);
        let racine = std::fs::canonicalize(dir.racine().chemin()).expect("fixture : répertoire résolu");
        let chemin = racine.join("cj3c.db").to_string_lossy().into_owned();
        let conn = Connection::open(&chemin).expect("fixture : base");
        conn.execute_batch(&format!(
            "CREATE TABLE panel_cache(panel_id INTEGER, range_key TEXT, query_fp TEXT, computed_at INTEGER, payload TEXT, \
             PRIMARY KEY(panel_id, range_key, query_fp){contrainte})"
        ))
        .expect("fixture : table du cache");
        (dir, chemin)
    }

    fn cj3c_ouvrir(chemin: &str) -> Connection {
        let conn = Connection::open(chemin).expect("fixture : connexion");
        assert_eq!(conn.path().unwrap_or(""), chemin, "contrôle : SQLite nomme la base par ce chemin");
        conn
    }

    /// Le code étendu du refus que le moteur rend pour l'écriture du cache, lu en contrôle (hors du coffre).
    fn cj3c_code_etendu_du_refus(conn: &Connection) -> (rusqlite::ErrorCode, i32) {
        let e = conn
            .execute(
                "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(-1,'rk',?1,1,'{}')",
                params![CJ3C_FP_REFUSE],
            )
            .expect_err("contrôle : l'écriture est refusée");
        match e {
            rusqlite::Error::SqliteFailure(f, _) => (f.code, f.extended_code),
            autre => panic!("contrôle : refus du moteur attendu : {autre:?}"),
        }
    }

    #[test]
    fn cj3c_deux_refus_reels_de_meme_code_primaire_chacun_dit_une_fois() {
        let (_dir, chemin) = cj3c_base("cj3c-primaire", &format!(", CHECK(query_fp <> '{CJ3C_FP_REFUSE}')"));
        let conn = cj3c_ouvrir(&chemin);
        let t = now();
        let ecrire = || panneau_avoue::cache_ecrire_dit(&conn, 1, "rk", CJ3C_FP_REFUSE, t, "{}");
        let dire = |a: i64| panneau_avoue::dire_une_ligne_de_panneau(&conn, 1, NatureDeLigneDite::ResultatDirectNonEcrit, a, CJ3C_TTL);

        let (primaire_x, etendu_x) = cj3c_code_etendu_du_refus(&conn);
        assert_eq!((primaire_x, etendu_x), (rusqlite::ErrorCode::ConstraintViolation, rusqlite::ffi::SQLITE_CONSTRAINT_CHECK), "contrôle : X = CHECK");
        let x = ecrire().expect_err("contrôle : X refusée");
        assert!(x.contains("CHECK"), "contrôle : X vient de la contrainte : {x}");
        assert!(dire(t), "X : première ligne dite");
        let _ = ecrire();
        assert!(!dire(t + 1), "X revue : tue");

        conn.execute_batch(CJ3C_DECLENCHEUR).expect("fixture : déclencheur");
        let (primaire_y, etendu_y) = cj3c_code_etendu_du_refus(&conn);
        assert_eq!((primaire_y, etendu_y), (rusqlite::ErrorCode::ConstraintViolation, rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER), "contrôle : Y = TRIGGER");
        assert_eq!(etendu_x & 0xff, etendu_y & 0xff, "contrôle : même code primaire");
        let y = ecrire().expect_err("contrôle : Y refusée");
        assert!(y.contains("cj3c refus du declencheur"), "contrôle : Y vient du déclencheur : {y}");
        assert!(dire(t + 2), "Y, même code primaire que X, autre code étendu : la cause neuve est dite");
        let _ = ecrire();
        assert!(!dire(t + 3), "Y revue : tue");
    }

    #[test]
    fn cj3c_classe_par_code_etendu_et_conversion_par_rang_et_type() {
        use rusqlite::ffi;
        let echec = |code: i32| classe_de_la_cause(&rusqlite::Error::SqliteFailure(ffi::Error::new(code), Some("même texte".into())));
        for (a, b) in [
            (ffi::SQLITE_CONSTRAINT_TRIGGER, ffi::SQLITE_CONSTRAINT_UNIQUE),
            (ffi::SQLITE_IOERR_WRITE, ffi::SQLITE_IOERR_FSYNC),
            (ffi::SQLITE_READONLY, ffi::SQLITE_READONLY_DBMOVED),
        ] {
            assert_eq!(a & 0xff, b & 0xff, "contrôle : {a} et {b} ont le même code primaire");
            assert_ne!(echec(a), echec(b), "{a} et {b} : même code primaire, deux codes étendus, deux classes");
        }
        let conv = |rang: usize, lu: rusqlite::types::Type, texte: &str| {
            classe_de_la_cause(&rusqlite::Error::FromSqlConversionFailure(rang, lu, texte.into()))
        };
        use rusqlite::types::Type::{Blob, Text};
        assert_eq!(conv(0, Text, "invalid utf-8 a"), conv(0, Text, "invalid utf-8 b"), "le texte de la conversion n'est pas dans la classe");
        assert!(!conv(0, Text, "invalid utf-8 a").contains("invalid utf-8"), "la classe ne recopie pas le texte");
        assert_ne!(conv(0, Text, "m"), conv(1, Text, "m"), "deux rangs : deux classes");
        assert_ne!(conv(0, Text, "m"), conv(0, Blob, "m"), "deux types lus : deux classes");
    }

    #[test]
    fn cj3c_chaque_fil_decide_sous_la_cause_qu_il_a_vue() {
        let (_dir, chemin) = cj3c_base("cj3c-fils", "");
        let conn_a = cj3c_ouvrir(&chemin);
        let conn_b = cj3c_ouvrir(&chemin);
        conn_a.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name: "panel_cache" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        conn_b.execute_batch(CJ3C_DECLENCHEUR).expect("fixture : déclencheur sur la connexion de B");
        let t = now();
        let dire = |conn: &Connection, a: i64| panneau_avoue::dire_une_ligne_de_panneau(conn, 1, NatureDeLigneDite::ResultatDirectNonEcrit, a, CJ3C_TTL);
        let barriere = std::sync::Barrier::new(2);
        // Aucune assertion dans les fils : un fil qui paniquerait laisserait l'autre bloqué sur la barrière.
        let (barriere, dire) = (&barriere, &dire);
        let ((x, dite_a, classe_a, conn_a), (y, dite_b, classe_b)) = std::thread::scope(|s| {
            let fil_a = s.spawn(move || {
                let x = panneau_avoue::cache_ecrire_dit(&conn_a, 1, "rk", "fp", t, "{}").err();
                barriere.wait(); // 1 : A a observé X
                barriere.wait(); // 2 : B a observé Y
                let dite = dire(&conn_a, t + 1);
                let classe = panneau_avoue::cause_observee(&conn_a, 1, FamilleDeCause::EcritureDuCache);
                barriere.wait(); // 3 : A a décidé
                (x, dite, classe, conn_a)
            });
            let fil_b = s.spawn(move || {
                barriere.wait(); // 1
                let y = panneau_avoue::cache_ecrire_dit(&conn_b, 1, "rk", "fp", t, "{}").err();
                barriere.wait(); // 2
                barriere.wait(); // 3
                let dite = dire(&conn_b, t + 2);
                let classe = panneau_avoue::cause_observee(&conn_b, 1, FamilleDeCause::EcritureDuCache);
                (y, dite, classe)
            });
            (fil_a.join().expect("fil A"), fil_b.join().expect("fil B"))
        });
        let x = x.expect("contrôle : A refusée");
        let y = y.expect("contrôle : B refusée");
        assert!(x.contains("not authorized"), "contrôle : X vient de l'autorisateur : {x}");
        assert!(y.contains("cj3c refus du declencheur"), "contrôle : Y vient du déclencheur : {y}");
        assert!(classe_a.is_some() && classe_b.is_some(), "contrôle : chaque fil a observé sa cause");
        assert_ne!(classe_a, classe_b, "chaque fil lit la classe de SA cause, pas celle de l'autre");
        assert!(dite_a, "A : X jamais dite pour ce panneau, sa ligne sort");
        assert!(dite_b, "B : Y jamais dite pour ce panneau, sa ligne sort (avant : A avait pris la clé de Y, B se taisait)");
        // X revue, sur ce fil : A l'a dite sous sa propre clé, elle se tait.
        let x2 = panneau_avoue::cache_ecrire_dit(&conn_a, 1, "rk", "fp", t, "{}");
        assert!(x2.is_err(), "contrôle : X revue");
        assert!(!dire(&conn_a, t + 3), "X revue : A l'a dite sous la clé de X, tue");
    }

    /// Refuse l'écriture du cache par l'autorisateur (X) ou par un déclencheur (Y), l'autre refus retiré.
    fn cj3c_refuser(conn: &Connection, y: bool) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        let _ = conn.execute_batch("DROP TRIGGER IF EXISTS cj3c_refus");
        if y {
            conn.execute_batch(CJ3C_DECLENCHEUR).expect("fixture : déclencheur");
        } else {
            conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Insert { table_name: "panel_cache" } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
        }
    }

    #[test]
    fn cj3c_lecture_illisible_du_meme_panneau_ne_masque_pas_la_classe_neuve_du_refus_d_ecriture() {
        let (_dir, chemin) = cj3c_base("cj3c-famille", "");
        let conn = cj3c_ouvrir(&chemin);
        let t = now();
        let dire = |a: i64| panneau_avoue::dire_une_ligne_de_panneau(&conn, 7, NatureDeLigneDite::ResultatDirectNonEcrit, a, CJ3C_TTL);
        // Sur ce fil, la famille « lecture illisible » est notée la PREMIÈRE pour le panneau #7.
        conn.execute("INSERT INTO panel_cache VALUES(7,'rk','fp',1,X'00FF')", []).expect("fixture : charge BLOB");
        let lue = panneau_avoue::cache_lire_dit(&conn, 7, "rk", "fp");
        assert!(matches!(lue, panneau_avoue::LectureDeCache::Illisible(_)), "contrôle : ligne illisible : {lue:?}");
        let illisible = panneau_avoue::cause_observee(&conn, 7, FamilleDeCause::LectureIllisible);
        assert!(illisible.is_some(), "contrôle : la cause illisible est observée");

        cj3c_refuser(&conn, false);
        let x = panneau_avoue::cache_ecrire_dit(&conn, 7, "rk-e", "fp-e", t, "{}").expect_err("contrôle : X refusée");
        assert!(x.contains("not authorized"), "contrôle : X vient de l'autorisateur : {x}");
        assert!(dire(t), "X : première ligne dite");

        cj3c_refuser(&conn, true);
        let y = panneau_avoue::cache_ecrire_dit(&conn, 7, "rk-e", "fp-e", t, "{}").expect_err("contrôle : Y refusée");
        assert!(y.contains("cj3c refus du declencheur"), "contrôle : Y vient du déclencheur : {y}");
        // Les classes se lisent après la décision : la lecture passe par la recherche que le témoin juge.
        assert!(dire(t + 1), "Y, classe neuve du refus d'écriture : dite, même avec une lecture illisible du panneau notée avant");
        assert!(!dire(t + 2), "Y revue : tue");
        let classe_y = panneau_avoue::cause_observee(&conn, 7, FamilleDeCause::EcritureDuCache);
        assert!(classe_y.is_some() && classe_y != illisible, "la famille « écriture » lit sa propre classe, pas celle de la lecture illisible");
    }

    #[test]
    fn cj3c_base_detruite_oublie_les_lignes_dites_qui_portent_une_classe() {
        let (_dir, chemin) = cj3c_base("cj3c-oubli", "");
        let conn = cj3c_ouvrir(&chemin);
        let t = now();
        let dire = |a: i64| panneau_avoue::dire_une_ligne_de_panneau(&conn, 1, NatureDeLigneDite::ResultatDirectNonEcrit, a, CJ3C_TTL);
        let refus_x = || panneau_avoue::cache_ecrire_dit(&conn, 1, "rk", "fp", t, "{}").expect_err("contrôle : X refusée");
        cj3c_refuser(&conn, false);
        refus_x();
        assert!(panneau_avoue::cause_observee(&conn, 1, FamilleDeCause::EcritureDuCache).is_some(), "contrôle : la ligne porte une classe");
        assert!(dire(t), "X : première ligne dite");
        refus_x();
        assert!(!dire(t + 1), "contrôle : X revue avant l'oubli, tue (l'entrée à classe existe)");
        panneau_avoue::oublier_les_registres_d_une_base_detruite(&chemin);
        refus_x();
        assert!(dire(t + 2), "base oubliée : la ligne de classe X n'est plus connue, X revue est dite de nouveau");
    }
}
