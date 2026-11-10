// =====================================================================================
// LE MOTEUR LIÉ, RELU AVEC L'AVIS QU'IL FAIT IGNORER, ET LES COMPAGNONS D'UN FICHIER EN CLAIR VENU D'UNE ARCHIVE.
//
// LE MOTEUR. `daemon/.cargo/audit.toml` ignore un avis du moteur SQLite embarqué tant qu'aucune version publiée de la
// bibliothèque de liaison n'embarque, pour sa variante SQLCipher, un moteur corrigé. Cet ignore ne vaut que pour le
// moteur RÉELLEMENT lié : la version de SQLite et celle du codec SQLCipher sont lues par une connexion ouverte comme le
// démon ouvre une base chiffrée, et comparées à des constantes écrites à la main. Le jour où le moteur change, le témoin
// rougit et oblige à relire l'ignore ; l'ignore est présent si et seulement si le moteur lié précède la version
// corrigée (lu dans le fichier même, hors commentaires). `version_du_moteur_epinglee.rs` épingle déjà la version de
// SQLite sur une connexion en mémoire ; il ne dit rien du codec ni de l'avis.
//
// LES COMPAGNONS. La restauration d'une archive au format ancien écrit le fichier SQLite en clair qu'elle porte, puis
// l'ouvre pour le re-chiffrer. Ce fichier n'a aucune clé pour authentifier ses pages ; il est ouvert sans ses
// compagnons (`open_plain_db_ignoring_companions_without_schema_contract`, URI `immutable=1`). Témoins, par le point
// d'entrée `restore_compressed` : un `-wal` VALIDE posé à côté du clair juste avant son ouverture (crochet
// `crochet_du_clair_de_restauration`), qui ajouterait une ligne s'il était rejoué, n'apparaît pas dans la base
// restaurée ; une restauration légitime rend exactement les lignes de la source, sous un nom qui porte `%`, `?` et `#`
// (l'URI les échappe) ; et l'ouverture, même posée sur une base dont le WAL porte des écritures validées, ne lit, ne
// modifie ni ne retire ce WAL, et ces écritures restent lisibles par leur connexion.
//
// MUTANTS ÉPROUVÉS ROUGES : le clair ouvert comme avant, ou l'URI sans `immutable=1`, rougissent le voisin rejoué et la
// base vivante ; les compagnons retirés avant l'ouverture rougissent la base vivante ; chacun des trois échappements
// (`%`, `?`, `#`) retiré rougit la restauration légitime ; une version lue corrigée, une autre version touchée ou un
// autre codec rougissent l'épingle ; l'entrée retirée de `audit.toml` rougit `cargo audit --deny warnings`.
//
// NE TIENT PAS : la variante SQLCipher n'a pas de version corrigée publiée, donc le moteur lié reste celui que l'avis
// décrit ; seul le clair d'une archive au format ancien est ouvert sans ses compagnons.
// =====================================================================================

mod moteur_lie_et_compagnons_d_un_clair_d_archive {
    use super::*;

    const CLE: &str = "cc4-cle-de-test-de-restauration";
    /// Relevée sur le moteur lié (`SELECT sqlite_version()`), écrite à la main.
    const SQLITE_EPINGLE: &str = "3.39.4";
    /// Relevée sur le moteur lié (`PRAGMA cipher_version`), écrite à la main.
    const SQLCIPHER_EPINGLE: &str = "4.5.3 community";
    /// La première version du moteur que l'avis dit corrigée.
    const SQLITE_CORRIGE: (u32, u32, u32) = (3, 54, 0);
    const AVIS: &str = "RUSTSEC-2026-0459";
    const AUDIT_TOML: &str = include_str!("../../.cargo/audit.toml");

    fn chemin(racine: &std::path::Path, nom: &str) -> String {
        racine.join(nom).to_string_lossy().into_owned()
    }

    /// Vrai si `id` figure comme ENTRÉE de la liste `ignore` (une ligne `"id",` hors commentaire).
    fn avis_ignore(toml: &str, id: &str) -> bool {
        let entree = format!("\"{id}\"");
        toml.lines().any(|l| {
            let sans_commentaire = l.split('#').next().unwrap_or("").trim();
            sans_commentaire.trim_end_matches(',').trim() == entree
        })
    }

    fn version(v: &str) -> (u32, u32, u32) {
        let mut parts = v.split('.').map(|p| p.parse::<u32>().expect("version numérique"));
        (parts.next().unwrap_or(0), parts.next().unwrap_or(0), parts.next().unwrap_or(0))
    }

    #[test]
    fn la_lecture_de_l_ignore_ne_voit_que_les_entrees() {
        assert!(avis_ignore("ignore = [\n  \"RUSTSEC-2000-0001\",\n]", "RUSTSEC-2000-0001"));
        assert!(avis_ignore("ignore = [\n  \"RUSTSEC-2000-0001\"\n]", "RUSTSEC-2000-0001"));
        assert!(!avis_ignore("ignore = [\n  # \"RUSTSEC-2000-0001\",\n]", "RUSTSEC-2000-0001"));
        assert!(!avis_ignore("ignore = [\n  \"RUSTSEC-2000-0002\", # RUSTSEC-2000-0001\n]", "RUSTSEC-2000-0001"));
        assert!(version("3.39.4") < SQLITE_CORRIGE && version("3.54.0") >= SQLITE_CORRIGE);
    }

    #[test]
    fn le_moteur_lie_est_celui_que_decrit_l_avis_ignore() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cc4-moteur");
        let base = chemin(_tmp.racine().chemin(), "moteur.db");
        let conn = crate::db_open::open_db_keyed_without_schema_contract(&base, Some(CLE)).expect("base chiffrée ouverte");
        let sqlite: String = conn.query_row("SELECT sqlite_version()", [], |r| r.get(0)).expect("version du moteur");
        let codec: String = conn.query_row("PRAGMA cipher_version", [], |r| r.get(0)).expect("version du codec");
        let touche = version(&sqlite) < SQLITE_CORRIGE;
        assert_eq!(
            avis_ignore(AUDIT_TOML, AVIS),
            touche,
            "daemon/.cargo/audit.toml et le moteur lié ne se décrivent plus : moteur {sqlite} (corrigé à partir de \
             {}.{}.{}), {AVIS} {} dans la liste `ignore`. Un moteur corrigé lève l'ignore ; un moteur touché sans \
             ignore rougit `cargo audit --deny warnings`.",
            SQLITE_CORRIGE.0, SQLITE_CORRIGE.1, SQLITE_CORRIGE.2,
            if avis_ignore(AUDIT_TOML, AVIS) { "présent" } else { "absent" }
        );
        assert_eq!(
            sqlite, SQLITE_EPINGLE,
            "LE MOTEUR LIÉ A CHANGÉ : relire l'ignore de {AVIS} dans daemon/.cargo/audit.toml (le moteur embarqué par la \
             variante SQLCipher est-il corrigé ?) avant de suivre cette constante"
        );
        assert_eq!(
            codec, SQLCIPHER_EPINGLE,
            "LE CODEC SQLCIPHER LIÉ A CHANGÉ : relire l'ignore de {AVIS} dans daemon/.cargo/audit.toml avant de suivre \
             cette constante"
        );
    }

    /// Fichier SQLite EN CLAIR, en mode WAL, portant `valeurs` dans `t(v)`, entièrement replié dans le fichier
    /// principal et fermé : ses octets sont ceux qu'une archive au format ancien emporte.
    fn clair_replie(chemin: &str, valeurs: &[&str]) -> Vec<u8> {
        {
            let c = open_db_keyed(chemin, None).unwrap();
            c.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE t(v TEXT);").unwrap();
            for v in valeurs {
                c.execute("INSERT INTO t VALUES(?1)", [v]).unwrap();
            }
            c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        }
        assert!(!std::path::Path::new(&format!("{chemin}-wal")).exists(), "fixture : le WAL est replié et retiré");
        let octets = std::fs::read(chemin).unwrap();
        assert_eq!(&octets[18..20], &[2u8, 2], "fixture : l'en-tête déclare le mode WAL");
        octets
    }

    /// age(zstd(charge)) chiffré à la passphrase `CLE` — l'enveloppe de `backup_compressed`.
    fn archive_de(charge: &[u8], chemin: &str) {
        use std::io::Write;
        let out = std::fs::File::create(chemin).unwrap();
        let w = crate::backup::backup_encryptor(CLE, None).unwrap().wrap_output(out).unwrap();
        let mut z = zstd::Encoder::new(w, 3).unwrap();
        z.write_all(charge).unwrap();
        z.finish().unwrap().finish().unwrap();
    }

    fn lignes(c: &rusqlite::Connection) -> Vec<String> {
        let mut s = c.prepare("SELECT v FROM t ORDER BY v").unwrap();
        let v = s.query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        v
    }

    fn lignes_restaurees(dest: &str) -> Vec<String> {
        lignes(&open_db_keyed(dest, Some(CLE)).expect("base restaurée lisible avec la clé"))
    }

    #[test]
    fn un_wal_pose_a_cote_du_clair_n_est_pas_rejoue_dans_la_base_restauree() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cc4-voisin");
        let racine = _tmp.racine().chemin().to_path_buf();
        let source = clair_replie(&chemin(&racine, "clair.db"), &["legacy-1", "legacy-2"]);

        // Le voisin : le WAL valide d'une copie des MÊMES octets, qui porte une ligne de plus. Rejoué sur le clair,
        // il l'ajouterait à la base restaurée.
        let voisin = chemin(&racine, "voisin.db");
        std::fs::write(&voisin, &source).unwrap();
        let wal_du_voisin = {
            let c = open_db_keyed(&voisin, None).unwrap();
            c.execute_batch("PRAGMA wal_autocheckpoint=0; INSERT INTO t VALUES('du-voisin');").unwrap();
            let w = std::fs::read(format!("{voisin}-wal")).expect("fixture : le voisin a son WAL");
            let mut s = c.prepare("SELECT count(*) FROM t").unwrap();
            assert_eq!(s.query_row([], |r| r.get::<_, i64>(0)).unwrap(), 3, "fixture : le WAL porte la ligne de plus");
            w
        };

        let archive = chemin(&racine, "legacy.age");
        archive_de(&source, &archive);
        let dest = chemin(&racine, "plume.db");
        crate::backup::crochet_du_clair_de_restauration::armer(
            &dest,
            Box::new(move |clair: &str| std::fs::write(format!("{clair}-wal"), &wal_du_voisin).unwrap()),
        );
        let r = restore_compressed(&archive, &dest, Some(CLE), false, None);
        let non_passe = crate::backup::crochet_du_clair_de_restauration::desarmer(&dest);
        r.expect("restauration legacy");
        assert!(!non_passe, "le crochet doit avoir été passé : le voisin a été posé à côté du clair avant son ouverture");
        assert_eq!(lignes_restaurees(&dest), vec!["legacy-1".to_string(), "legacy-2".to_string()],
            "la base restaurée porte exactement les lignes de l'archive : le WAL posé à côté du clair n'a pas été rejoué");
    }

    #[test]
    fn une_restauration_legitime_rend_les_lignes_de_la_source_sous_un_nom_a_echapper() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cc4-legitime");
        let racine = _tmp.racine().chemin().to_path_buf();
        let valeurs = ["alpha", "beta", "gamma"];
        let source = clair_replie(&chemin(&racine, "clair.db"), &valeurs);
        let archive = chemin(&racine, "legacy.age");
        archive_de(&source, &archive);
        // Le clair temporaire prend le nom de la destination : `%41` se lirait `A`, `?` ouvrirait une requête et
        // `#` un fragment si l'URI ne les échappait pas.
        let dest = chemin(&racine, "plume%41?x#y.db");
        restore_compressed(&archive, &dest, Some(CLE), false, None).expect("restauration legacy sous un nom à échapper");
        assert_eq!(lignes_restaurees(&dest), valeurs.iter().map(|v| v.to_string()).collect::<Vec<_>>());
    }

    #[test]
    fn l_ouverture_sans_compagnons_ne_lit_ni_ne_touche_le_wal_d_une_base_vivante() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("cc4-vivante");
        let base = chemin(_tmp.racine().chemin(), "vivante.db");
        clair_replie(&base, &["dans-le-fichier"]);
        let vivante = open_db_keyed(&base, None).unwrap();
        vivante.execute_batch("PRAGMA wal_autocheckpoint=0; INSERT INTO t VALUES('valide-dans-le-wal');").unwrap();
        let principal = std::fs::read(&base).unwrap();
        let wal = std::fs::read(format!("{base}-wal")).expect("fixture : la base vivante a son WAL");

        {
            let c = crate::db_open::open_plain_db_ignoring_companions_without_schema_contract(&base).expect("ouverture");
            assert_eq!(lignes(&c), vec!["dans-le-fichier".to_string()],
                "seules les pages du fichier sont lues : la ligne validée dans le WAL n'est pas vue");
        }
        assert!(std::fs::read(&base).unwrap() == principal, "le fichier principal n'a pas changé");
        assert!(std::fs::read(format!("{base}-wal")).ok().as_deref() == Some(&wal[..]),
            "le WAL de la base vivante est intact, octet pour octet");
        assert_eq!(lignes(&vivante), vec!["dans-le-fichier".to_string(), "valide-dans-le-wal".to_string()],
            "les écritures validées dans le WAL restent lisibles par leur connexion");
    }
}
