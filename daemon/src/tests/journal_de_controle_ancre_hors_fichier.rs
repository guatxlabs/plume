// =====================================================================================
// `P10.7-r` — LE JOURNAL DES ACCÈS SUPERADMIN EST ANCRÉ HORS DE LUI-MÊME : SUPPRIMER DES MAILLONS PUIS
// RE-CHAÎNER EST ROUGE, À LA BASE COMME SUR UNE COPIE EXPORTÉE.
//
// L'ÉNONCÉ, RE-MESURÉ (premier témoin) : quatre maillons écrits par le chemin de production, le deuxième
// supprimé, les suivants re-chaînés — `control_ledger_verify_conn`, le cœur de chaîne, rend « trois maillons
// intègres, aucune rupture ». C'est vrai, et ce cœur garde ce contrat : c'est l'ANCRE qui manquait.
//
// LE CORRECTIF RÉUTILISE LE MÉCANISME DU REGISTRE VOISIN, SANS LEVIER NEUF : chaque maillon inscrit reçoit un point
// de contrôle signé par la clé du registre (`control_checkpoint`, migration à sens unique du plan de contrôle) ; la
// vérification juge chaque point contre la clé publique ÉPINGLÉE hors bande (`PLUME_LEDGER_PUBKEY`) ; l'export porte
// les points de contrôle de sa tranche et se vérifie hors ligne. UN POINT PAR MAILLON : un maillon n'est jamais
// « couvert » par un point plus récent — cette règle-là laissait blanchir une réécriture par l'écriture légitime
// suivante, que le démon signait sur la tête réécrite.
//
// CE QUE CES TÉMOINS TIENNENT :
//  (1) la base : suppression + re-chaînage, empreinte réécrite + re-chaînage, points retirés (tout ou partie), points
//      re-signés d'une clé étrangère, réécriture blanchie par une écriture légitime (points de la queue, ou tous,
//      retirés avant elle) — chacun son code et sa phrase entière ; la rupture et la lecture impossible de la chaîne
//      gardent leurs phrases d'avant ;
//  (2) sans clé épinglée, le verdict le DIT (code 2), jamais un vert muet ; journal vierge : rien à ancrer ;
//  (3) la signature posée à l'append, au point d'entrée des accès superadmin (`emit_operator_access`) : le message
//      signé, comparé à un littéral du témoin, et la clé publique ;
//  (4) la ligne de journal de l'append qui n'ancre pas (clé absente, aucune ligne prise, écriture refusée), lue
//      ENTIÈRE sur le stderr d'un sous-processus ; chemin nominal muet ;
//  (5) l'export par la route : les lignes des points de contrôle, la copie vérifiée hors ligne (0/1/2), les bornes de
//      la tranche une par une, le point illisible servi en 500 nommé, la réécriture blanchie vue sur la copie entière
//      comme sur une tranche, les rangs d'origine dans une copie mise bout à bout ;
//  (6) la sous-commande `verify-control` (`commande_verify_control`) : base, copie, `--prev`, lignes vides, fichier
//      illisible, plan de contrôle qui ne s'ouvre pas ; et le bras de `main`, lu en ENTIER sur le texte ;
//  (7) `init_control_plane` arme la clé du registre, et la désarmer la retire ; mode 0 : contrôle de non-régression
//      seulement (les deux chemins sortent AVANT le code de `P10.7-r`, ce témoin ne peut pas rougir par lui).
//
// CE QU'ILS NE TIENNENT PAS : l'ordre des deux lectures de l'ancre (points puis maillons, ce qui exclut une fausse
// accusation sous écriture concurrente) n'a pas de témoin déterministe — il faudrait intercaler une écriture entre
// deux lectures d'une même fonction ; la troncature de QUEUE accompagnée du retrait des points qui la couvrent reste
// invisible à la base (chaque maillon restant garde son point) et ne se voit que contre une copie extérieure ; le
// binaire n'est pas lancé (la fonction qu'il appelle l'est, et son bras est lu en entier).
// =====================================================================================
mod journal_de_controle_ancre_hors_fichier {
    use super::*;

    const JCAH_CLE: [u8; 32] = [21u8; 32];
    const JCAH_CLE_ETRANGERE: [u8; 32] = [99u8; 32];

    fn jcah_cle() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&JCAH_CLE)
    }

    fn jcah_epinglee() -> [u8; 32] {
        jcah_cle().verifying_key().to_bytes()
    }

    /// Un plan de contrôle en mode 1 au journal VIERGE (maillons et points retirés), sa clé de signature armée ou non.
    fn jcah_etat(signe: bool) -> (AppState, crate::tmp_possede::TmpDb) {
        let (cp, tmp) = mk_test_control();
        cp.conn
            .lock()
            .execute_batch("DELETE FROM control_ledger; DELETE FROM control_checkpoint;")
            .expect("fixture : journal vierge");
        crate::rbac::armer_la_signature_du_journal_de_controle(cp.db_path.as_str(), if signe { Some(jcah_cle()) } else { None });
        (tenant_test_state("jcah-adm", "jcah-edi", "jcah-sa", Some(cp)), tmp)
    }

    fn jcah_sql(st: &AppState, sql: &str) {
        st.tenants.control.as_ref().expect("mode 1").conn.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture `{sql}` : {e}"));
    }

    fn jcah_compte(st: &AppState, sql: &str) -> i64 {
        st.tenants.control.as_ref().expect("mode 1").conn.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : compte")
    }

    fn jcah_ecrire(st: &AppState, n: usize) {
        for i in 1..=n {
            let issue = control_ledger_append(st, "superadmin.read", "sa-jcah", "tenant-jcah", &format!("accès d'urgence {i}"));
            assert!(issue.cause_de_non_inscription().is_none(), "fixture : maillon {i} inscrit");
        }
    }

    fn jcah_verdict(st: &AppState, epinglee: Option<&[u8; 32]>) -> (i32, String) {
        crate::rbac::verdict_de_verify_control(&st.tenants.control.as_ref().expect("mode 1").conn.lock(), epinglee)
    }

    /// L'ATTAQUE : chaque maillon restant recalculé sur le précédent, dans l'ordre — la chaîne redevient cohérente.
    fn jcah_rechainer(st: &AppState) {
        let c = st.tenants.control.as_ref().expect("mode 1").conn.lock();
        let mut s = c.prepare("SELECT id,ts,kind,actor,tenant,detail FROM control_ledger ORDER BY id").expect("fixture : lecture");
        let lignes: Vec<(i64, i64, String, String, String, String)> = s
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .expect("fixture : lecture")
            .collect::<rusqlite::Result<_>>()
            .expect("fixture : lecture");
        drop(s);
        let mut prev = String::new();
        for (id, ts, kind, actor, tenant, detail) in lignes {
            let hash = sha256_hex(format!("{prev}|{ts}|{kind}|{actor}|{tenant}|{detail}").as_bytes());
            c.execute("UPDATE control_ledger SET prev_hash=?1, hash=?2 WHERE id=?3", params![prev, hash, id]).expect("fixture : re-chaînage");
            prev = hash;
        }
    }

    /// Re-signe chaque maillon d'une clé ÉTRANGÈRE, sa clé publique écrite à côté — ce que ferait qui réécrit la base.
    fn jcah_resigner(st: &AppState, cle: &[u8; 32]) {
        use ed25519_dalek::Signer;
        let k = ed25519_dalek::SigningKey::from_bytes(cle);
        let c = st.tenants.control.as_ref().expect("mode 1").conn.lock();
        c.execute("DELETE FROM control_checkpoint", []).expect("fixture");
        let mut s = c.prepare("SELECT id,hash FROM control_ledger ORDER BY id").expect("fixture : lecture");
        let lignes: Vec<(i64, String)> =
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).expect("fixture : lecture").collect::<rusqlite::Result<_>>().expect("fixture : lecture");
        drop(s);
        for (id, hash) in lignes {
            let sig = k.sign(format!("plume-control-ledger-checkpoint-v1|{id}|{hash}").as_bytes());
            c.execute(
                "INSERT INTO control_checkpoint(ts,ledger_id,ledger_hash,sig,pubkey) VALUES(1,?1,?2,?3,?4)",
                params![id, hash, hex_encode(&sig.to_bytes()), hex_encode(k.verifying_key().as_bytes())],
            )
            .expect("fixture : point re-signé");
        }
    }

    const JCAH_OK_4: &str = "control_ledger OK : 4 entrée(s) chaînées intègres, chaîne lue entièrement ; tête ancrée, 4 point(s) de contrôle signés par la clé épinglée";
    const JCAH_SUPPRIME: &str = "INTÉGRITÉ COMPROMISE : le point de contrôle signé #2 atteste le maillon #2, que la chaîne vérifiée ne porte pas — la chaîne a été réécrite après sa signature";
    const JCAH_EMPREINTE: &str = "INTÉGRITÉ COMPROMISE : le point de contrôle signé #3 atteste pour le maillon #3 une empreinte que la chaîne vérifiée ne porte plus — la chaîne a été réécrite après sa signature";
    const JCAH_TETE_ORIGINE_3: &str = "TÊTE NON ANCRÉE : 3 entrée(s) chaînées intègres, mais 3 maillon(s) depuis l'origine ne sont couverts par aucun point de contrôle signé — une suppression suivie d'un re-chaînage n'y serait pas vue : aucun verdict d'ancrage n'est rendu";
    const JCAH_TETE_APRES_1: &str = "TÊTE NON ANCRÉE : 3 entrée(s) chaînées intègres, mais 2 maillon(s) après le maillon #1 ne sont couverts par aucun point de contrôle signé — une suppression suivie d'un re-chaînage n'y serait pas vue : aucun verdict d'ancrage n'est rendu";
    const JCAH_ETRANGERE: &str = "INTÉGRITÉ COMPROMISE : le point de contrôle #1 n'est pas signé par la clé épinglée — la chaîne a été réécrite après sa signature";
    const JCAH_OK_3_RESIGNE: &str = "control_ledger OK : 3 entrée(s) chaînées intègres, chaîne lue entièrement ; tête ancrée, 3 point(s) de contrôle signés par la clé épinglée";
    const JCAH_SANS_EPINGLE_4: &str = "ANCRE NON VÉRIFIÉE : 4 entrée(s) chaînées intègres, mais aucune clé publique n'est épinglée (PLUME_LEDGER_PUBKEY) — sans elle, une chaîne réécrite puis re-signée se lirait intègre : aucun verdict d'ancrage n'est rendu";
    const JCAH_SANS_EPINGLE_3: &str = "ANCRE NON VÉRIFIÉE : 3 entrée(s) chaînées intègres, mais aucune clé publique n'est épinglée (PLUME_LEDGER_PUBKEY) — sans elle, une chaîne réécrite puis re-signée se lirait intègre : aucun verdict d'ancrage n'est rendu";
    const JCAH_VIERGE: &str = "control_ledger OK : 0 entrée(s) chaînées intègres, chaîne lue entièrement ; journal vierge, rien à ancrer";
    const JCAH_VIDE_MAIS_POINT: &str = "INTÉGRITÉ COMPROMISE : le point de contrôle signé #1 atteste le maillon #1, que la chaîne vérifiée ne porte pas — la chaîne a été réécrite après sa signature";

    // -------------------------------------------------------------------------------------
    // (1) LA BASE
    // -------------------------------------------------------------------------------------

    /// L'énoncé re-mesuré, puis corrigé : suppression du deuxième maillon et re-chaînage. Le cœur de chaîne est VERT
    /// (il le reste : son contrat est la cohérence interne) ; le verdict de `verify-control` est ROUGE, code 1, contre le
    /// point de contrôle signé du maillon supprimé.
    #[test]
    fn jcah_supprimer_puis_rechainer_est_rouge_a_la_base() {
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 4);
        let pin = jcah_epinglee();
        assert_eq!(jcah_verdict(&st, Some(&pin)), (0, JCAH_OK_4.to_string()), "contrôle positif : quatre maillons ancrés");
        jcah_sql(&st, "DELETE FROM control_ledger WHERE id=2;");
        jcah_rechainer(&st);
        assert_eq!(
            control_ledger_verify_conn(&st.tenants.control.as_ref().expect("mode 1").conn.lock()),
            Ok((3, None)),
            "L'ÉNONCÉ : le chaînage seul rend la chaîne réécrite INTÈGRE"
        );
        assert_eq!(jcah_verdict(&st, Some(&pin)), (1, JCAH_SUPPRIME.to_string()), "l'ancre l'accuse");
    }

    /// Une empreinte réécrite EN PLACE (détail d'un accès d'urgence), le reste re-chaîné : le point signé du maillon
    /// réécrit ne concorde plus.
    #[test]
    fn jcah_empreinte_reecrite_puis_rechainee_est_rouge() {
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 4);
        jcah_sql(&st, "UPDATE control_ledger SET detail='motif réécrit' WHERE id=3;");
        jcah_rechainer(&st);
        assert_eq!(jcah_verdict(&st, Some(&jcah_epinglee())), (1, JCAH_EMPREINTE.to_string()));
    }

    /// Qui réécrit retire aussi les points de contrôle : tous (tête non ancrée depuis l'origine), ou ceux de la queue
    /// (non ancrée après le dernier point restant). Jamais « intègre » : code 2, phrase entière.
    #[test]
    fn jcah_points_retires_tete_non_ancree() {
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 4);
        jcah_sql(&st, "DELETE FROM control_ledger WHERE id=2;");
        jcah_rechainer(&st);
        jcah_sql(&st, "DELETE FROM control_checkpoint WHERE ledger_id>=2;");
        assert_eq!(jcah_verdict(&st, Some(&jcah_epinglee())), (2, JCAH_TETE_APRES_1.to_string()), "le premier point concorde encore, la queue n'est pas couverte");
        jcah_sql(&st, "DELETE FROM control_checkpoint;");
        assert_eq!(jcah_verdict(&st, Some(&jcah_epinglee())), (2, JCAH_TETE_ORIGINE_3.to_string()));
    }

    /// Qui réécrit re-signe de SA clé, sa clé publique écrite à côté : refusé contre la clé épinglée (code 1). Contrôle
    /// positif : les mêmes points passent si l'on épingle la clé étrangère — c'est l'épingle qui décide, jamais la clé
    /// publique écrite en base. Sans épingle : le verdict le dit (code 2).
    #[test]
    fn jcah_points_resignes_d_une_cle_etrangere() {
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 4);
        jcah_sql(&st, "DELETE FROM control_ledger WHERE id=2;");
        jcah_rechainer(&st);
        jcah_resigner(&st, &JCAH_CLE_ETRANGERE);
        assert_eq!(jcah_verdict(&st, Some(&jcah_epinglee())), (1, JCAH_ETRANGERE.to_string()));
        let etrangere = ed25519_dalek::SigningKey::from_bytes(&JCAH_CLE_ETRANGERE).verifying_key().to_bytes();
        assert_eq!(jcah_verdict(&st, Some(&etrangere)), (0, JCAH_OK_3_RESIGNE.to_string()), "contrôle positif de l'instrument");
        assert_eq!(jcah_verdict(&st, None), (2, JCAH_SANS_EPINGLE_3.to_string()));
    }

    /// La rupture et la lecture impossible de la chaîne passent AVANT l'ancre, phrases d'avant à l'octet.
    #[test]
    fn jcah_rupture_et_chaine_illisible_gardent_leurs_phrases() {
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 3);
        jcah_sql(&st, "UPDATE control_ledger SET detail='altéré sans re-chaînage' WHERE id=2;");
        assert_eq!(
            jcah_verdict(&st, Some(&jcah_epinglee())),
            (1, "INTÉGRITÉ COMPROMISE : rupture de chaîne du plan de contrôle à l'entrée #2 (1 entrée(s) intègres avant elle)".to_string())
        );
        jcah_sql(&st, "UPDATE control_ledger SET hash=X'FF' WHERE id=2;");
        let cause = control_ledger_verify_conn(&st.tenants.control.as_ref().expect("mode 1").conn.lock()).expect_err("fixture : chaîne illisible");
        assert_eq!(
            jcah_verdict(&st, Some(&jcah_epinglee())),
            (2, format!("VERDICT IMPOSSIBLE : la chaîne du plan de contrôle n'a pas pu être lue ENTIÈREMENT ({cause}) — aucun verdict n'est rendu sur une chaîne partiellement lue"))
        );
    }

    /// L'ancre qu'on ne sait pas lire : point illisible, table des points absente. Code 2, la cause nommée.
    #[test]
    fn jcah_ancre_illisible_aucun_verdict() {
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 4);
        jcah_sql(&st, "UPDATE control_checkpoint SET sig=X'FF' WHERE id=2;");
        assert_eq!(
            jcah_verdict(&st, Some(&jcah_epinglee())),
            (2, "VERDICT IMPOSSIBLE : 4 entrée(s) chaînées intègres, mais l'ancre n'a pas pu être lue (point de contrôle ILLISIBLE (Invalid column type Blob at index: 3, name: sig) — les points de contrôle n'ont pas pu être lus entièrement) — aucun verdict d'ancrage n'est rendu".to_string())
        );
        jcah_sql(&st, "DROP TABLE control_checkpoint;");
        assert_eq!(
            jcah_verdict(&st, Some(&jcah_epinglee())),
            (2, "VERDICT IMPOSSIBLE : 4 entrée(s) chaînées intègres, mais l'ancre n'a pas pu être lue (lecture des points de contrôle du journal de contrôle : no such table: control_checkpoint) — aucun verdict d'ancrage n'est rendu".to_string())
        );
    }

    /// La relecture des maillons par l'ancre, jouée directement (le verdict la précède d'une lecture de chaîne qui
    /// échouerait d'abord) : maillon illisible, table absente.
    #[test]
    fn jcah_relecture_des_maillons_par_l_ancre() {
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 2);
        jcah_sql(&st, "UPDATE control_ledger SET hash=X'FF' WHERE id=2;");
        let pin = jcah_epinglee();
        assert_eq!(
            crate::rbac::verifier_l_ancrage_du_journal_de_controle(&st.tenants.control.as_ref().expect("mode 1").conn.lock(), Some(&pin)),
            Err("maillon ILLISIBLE (Invalid column type Blob at index: 1, name: hash) — la chaîne n'a pas pu être relue entièrement".to_string())
        );
        jcah_sql(&st, "DROP TABLE control_ledger;");
        assert_eq!(
            crate::rbac::verifier_l_ancrage_du_journal_de_controle(&st.tenants.control.as_ref().expect("mode 1").conn.lock(), Some(&pin)),
            Err("lecture du journal de contrôle : no such table: control_ledger".to_string())
        );
    }

    // -------------------------------------------------------------------------------------
    // (2) SANS CLÉ ÉPINGLÉE, ET LE JOURNAL VIERGE
    // -------------------------------------------------------------------------------------

    #[test]
    fn jcah_sans_cle_epinglee_le_verdict_le_dit() {
        let (st, _t) = jcah_etat(true);
        assert_eq!(jcah_verdict(&st, None), (0, JCAH_VIERGE.to_string()), "journal vierge, sans épingle : rien à ancrer");
        assert_eq!(jcah_verdict(&st, Some(&jcah_epinglee())), (0, JCAH_VIERGE.to_string()), "journal vierge, épingle posée");
        jcah_ecrire(&st, 4);
        assert_eq!(jcah_verdict(&st, None), (2, JCAH_SANS_EPINGLE_4.to_string()), "chaîne ancrée, mais aucune épingle : jamais un vert muet");
    }

    /// Toute la chaîne retirée, un point de contrôle resté : ce n'est pas « rien à ancrer ».
    #[test]
    fn jcah_chaine_videe_point_reste() {
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 1);
        jcah_sql(&st, "DELETE FROM control_ledger;");
        assert_eq!(jcah_verdict(&st, Some(&jcah_epinglee())), (1, JCAH_VIDE_MAIS_POINT.to_string()));
    }

    // -------------------------------------------------------------------------------------
    // (3) LA SIGNATURE POSÉE À L'APPEND, PAR LE POINT D'ENTRÉE DES ACCÈS SUPERADMIN
    // -------------------------------------------------------------------------------------

    #[test]
    fn jcah_l_acces_superadmin_est_signe_a_l_append() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let (st, _t) = jcah_etat(true);
        let _trace = emit_operator_access(&st, "sa-jcah", "default", true, Some("ouverture d'urgence jcah"));
        let (id, hash): (i64, String) =
            st.tenants.control.as_ref().expect("mode 1").conn.lock().query_row("SELECT id,hash FROM control_ledger", [], |r| Ok((r.get(0)?, r.get(1)?))).expect("un maillon");
        let (ledger_id, ledger_hash, sig, pubkey): (i64, String, String, String) = st
            .tenants
            .control
            .as_ref()
            .expect("mode 1")
            .conn
            .lock()
            .query_row("SELECT ledger_id,ledger_hash,sig,pubkey FROM control_checkpoint", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .expect("UN point de contrôle, posé par l'append");
        assert_eq!((ledger_id, ledger_hash.as_str()), (id, hash.as_str()), "le point désigne le maillon inscrit");
        assert_eq!(pubkey, hex_encode(&jcah_epinglee()), "la clé publique du registre");
        let sig: [u8; 64] = hex_decode(&sig).expect("hex").try_into().expect("64 octets");
        let message = format!("plume-control-ledger-checkpoint-v1|{id}|{hash}");
        assert!(
            VerifyingKey::from_bytes(&jcah_epinglee()).expect("clé").verify(message.as_bytes(), &Signature::from_bytes(&sig)).is_ok(),
            "la signature porte le domaine, l'identifiant et le hachage"
        );
        assert_eq!(jcah_verdict(&st, Some(&jcah_epinglee())).0, 0);
    }

    // -------------------------------------------------------------------------------------
    // (4) LA LIGNE DE JOURNAL DE L'APPEND QUI N'ANCRE PAS, LUE SUR LE STDERR D'UN SOUS-PROCESSUS
    // -------------------------------------------------------------------------------------

    #[test]
    fn jcah_l_append_qui_n_ancre_pas_le_dit() {
        let _env = VERROU_ENV_PROCESSUS.read();
        const ENFANT: &str = "JCAH_ENFANT_JOURNAL";
        if std::env::var(ENFANT).is_ok() {
            let issue = |st: &AppState, kind: &str| {
                let i = control_ledger_append(st, kind, "sa-jcah-acteur", "tenant-jcah-cible", "raison-jcah-detail");
                println!("JCAH-ISSUE-{kind}:{}", i.cause_de_non_inscription().is_none());
                println!("JCAH-POINTS-{kind}:{}", jcah_compte(st, "SELECT COUNT(*) FROM control_checkpoint"));
            };
            let (st, _t) = jcah_etat(false);
            issue(&st, "jcah.sans_cle");
            println!("JCAH-VERDICT-SANS-CLE:{}", jcah_verdict(&st, Some(&jcah_epinglee())).0);
            let (st, _t) = jcah_etat(true);
            jcah_sql(&st, "CREATE TRIGGER jcah_ignore BEFORE INSERT ON control_checkpoint BEGIN SELECT RAISE(IGNORE); END;");
            issue(&st, "jcah.ignore");
            jcah_sql(&st, "DROP TRIGGER jcah_ignore; CREATE TRIGGER jcah_refus BEFORE INSERT ON control_checkpoint BEGIN SELECT RAISE(ABORT, 'jcah refus du point'); END;");
            issue(&st, "jcah.refus");
            jcah_sql(&st, "DROP TRIGGER jcah_refus;");
            issue(&st, "jcah.nominal");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::journal_de_controle_ancre_hors_fichier::jcah_l_append_qui_n_ancre_pas_le_dit"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        for attendu in [
            "JCAH-ISSUE-jcah.sans_cle:true",
            "JCAH-POINTS-jcah.sans_cle:0",
            "JCAH-VERDICT-SANS-CLE:2",
            "JCAH-ISSUE-jcah.ignore:true",
            "JCAH-POINTS-jcah.ignore:0",
            "JCAH-ISSUE-jcah.refus:true",
            "JCAH-POINTS-jcah.refus:0",
            "JCAH-ISSUE-jcah.nominal:true",
            "JCAH-POINTS-jcah.nominal:1",
        ] {
            // Un jeton par marque : la première partage sa ligne avec l'en-tête du harnais de test.
            assert!(stdout.split(['\n', ' ']).any(|t| t == attendu), "le maillon reste inscrit, l'ancre suit : {attendu} : {stdout}");
        }
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[control_ledger] WARN point de contrôle")).collect();
        assert_eq!(
            lignes,
            vec![
                "[control_ledger] WARN point de contrôle NON posé après le maillon 'jcah.sans_cle' : aucune clé de signature du registre — la vérification dira la tête de chaîne NON ANCRÉE",
                "[control_ledger] WARN point de contrôle NON posé après le maillon 'jcah.ignore' : 0 ligne(s) écrite(s) au lieu d'une — la vérification dira la tête de chaîne NON ANCRÉE",
                "[control_ledger] WARN point de contrôle NON posé après le maillon 'jcah.refus' : l'écriture n'a pas eu lieu (jcah refus du point) — la vérification dira la tête de chaîne NON ANCRÉE",
            ],
            "trois lignes entières, aucune pour le chemin nominal, ni acteur, ni cible, ni détail : {stderr}"
        );
    }

    // -------------------------------------------------------------------------------------
    // (5) L'EXPORT PAR LA ROUTE, VÉRIFIÉ HORS LIGNE
    // -------------------------------------------------------------------------------------

    fn jcah_adm() -> AuthUser {
        sp_au("jcah-adm", "admin")
    }

    async fn jcah_telecharger(st: &AppState, parametres: &[(&str, &str)]) -> (u16, String) {
        let q: HashMap<String, String> = parametres.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let r = control_ledger_export_get(State(st.clone()), Extension(jcah_adm()), Query(q)).await;
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, String::from_utf8_lossy(&b).into_owned())
    }

    fn jcah_lignes(corps: &str) -> Vec<String> {
        corps.lines().filter(|l| !l.trim().is_empty()).map(String::from).collect()
    }

    fn jcah_hash(st: &AppState, id: i64) -> String {
        st.tenants.control.as_ref().expect("mode 1").conn.lock().query_row("SELECT hash FROM control_ledger WHERE id=?1", params![id], |r| r.get(0)).expect("fixture : hachage")
    }

    fn jcah_point_attendu(st: &AppState, ledger_id: i64) -> Value {
        st.tenants
            .control
            .as_ref()
            .expect("mode 1")
            .conn
            .lock()
            .query_row("SELECT ledger_hash,sig,pubkey,ts FROM control_checkpoint WHERE ledger_id=?1", params![ledger_id], |r| {
                Ok(json!({ "point_de_controle": { "ledger_id": ledger_id, "ledger_hash": r.get::<_, String>(0)?, "sig": r.get::<_, String>(1)?, "pubkey": r.get::<_, String>(2)?, "ts": r.get::<_, i64>(3)? } }))
            })
            .expect("fixture : point")
    }

    /// Cinq maillons ancrés : la copie porte cinq lignes de maillon puis une ligne par point de contrôle, dans l'ordre ;
    /// elle se vérifie hors ligne (0), sans épingle elle le dit (2). La base réécrite (suppression + re-chaînage) : la
    /// copie suivante est COMPROMISE (1), par le point du maillon supprimé ; les points retirés aussi : non ancrée (2).
    #[tokio::test]
    async fn jcah_l_export_porte_son_point_et_se_verifie_hors_ligne() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 5);
        let pin = jcah_epinglee();
        let (statut, corps) = jcah_telecharger(&st, &[]).await;
        let lignes = jcah_lignes(&corps);
        assert_eq!((statut, lignes.len()), (200, 10), "cinq maillons et cinq points : {corps}");
        for (rang, id) in (5..10).zip(1..=5) {
            assert_eq!(serde_json::from_str::<Value>(&lignes[rang]).expect("JSON"), jcah_point_attendu(&st, id), "la ligne du point {id}, entière");
        }
        assert_eq!(crate::governance::control_ledger_verify_export(&lignes[..5], ""), Ok(5), "les maillons, contrat d'avant");
        assert_eq!(
            crate::governance::verdict_hors_ligne_de_la_copie_du_journal_de_controle(&lignes, "", Some(&pin)),
            (0, "export OK : 5 entrée(s) chaînées intègres, chaîne lue entièrement ; tête ancrée, 5 point(s) de contrôle signés par la clé épinglée".to_string())
        );
        assert_eq!(
            crate::governance::verdict_hors_ligne_de_la_copie_du_journal_de_controle(&lignes, "", None),
            (2, "ANCRE NON VÉRIFIÉE : 5 entrée(s) chaînées intègres, mais aucune clé publique n'est épinglée (PLUME_LEDGER_PUBKEY) — sans elle, une chaîne réécrite puis re-signée se lirait intègre : aucun verdict d'ancrage n'est rendu".to_string())
        );

        jcah_sql(&st, "DELETE FROM control_ledger WHERE id=2;");
        jcah_rechainer(&st);
        let lignes = jcah_lignes(&jcah_telecharger(&st, &[]).await.1);
        assert_eq!(lignes.len(), 9, "quatre maillons et cinq points, celui du maillon supprimé compris");
        assert_eq!(
            crate::governance::verdict_hors_ligne_de_la_copie_du_journal_de_controle(&lignes, "", Some(&pin)),
            (1, "EXPORT COMPROMIS : le point de contrôle signé de la ligne 5 atteste le maillon #2, que la chaîne vérifiée ne porte pas — la chaîne a été réécrite après sa signature".to_string())
        );
        jcah_sql(&st, "DELETE FROM control_checkpoint;");
        let lignes = jcah_lignes(&jcah_telecharger(&st, &[]).await.1);
        assert_eq!(lignes.len(), 4, "aucun point à porter");
        assert_eq!(
            crate::governance::verdict_hors_ligne_de_la_copie_du_journal_de_controle(&lignes, "", Some(&pin)),
            (2, "TÊTE NON ANCRÉE : 4 entrée(s) chaînées intègres, mais 4 maillon(s) depuis l'origine ne sont couverts par aucun point de contrôle signé — une suppression suivie d'un re-chaînage n'y serait pas vue : aucun verdict d'ancrage n'est rendu".to_string())
        );
    }

    /// LES BORNES DE LA TRANCHE, une par une. `from_id=2&limit=2` : maillons 3 et 4, et les points du 3 et du 4 — pas
    /// celui du 5 (hors tranche, borne haute), et le bord `ledger_id == last_id` inclus. Les points 3 et 4 retirés :
    /// AUCUN point, même si celui du 2 existe (borne basse stricte). Tranche vide : corps vide.
    #[tokio::test]
    async fn jcah_les_bornes_de_la_tranche() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 5);
        let pin = jcah_epinglee();
        let h2 = jcah_hash(&st, 2);
        let lignes = jcah_lignes(&jcah_telecharger(&st, &[("from_id", "2"), ("limit", "2")]).await.1);
        assert_eq!(lignes.len(), 4, "deux maillons et deux points : {lignes:?}");
        assert_eq!(serde_json::from_str::<Value>(&lignes[2]).expect("JSON"), jcah_point_attendu(&st, 3), "le point du maillon 3");
        assert_eq!(serde_json::from_str::<Value>(&lignes[3]).expect("JSON"), jcah_point_attendu(&st, 4), "le point du maillon 4");
        assert_eq!(
            crate::governance::verdict_hors_ligne_de_la_copie_du_journal_de_controle(&lignes, &h2, Some(&pin)),
            (0, "export OK : 2 entrée(s) chaînées intègres, chaîne lue entièrement ; tête ancrée, 2 point(s) de contrôle signés par la clé épinglée".to_string())
        );
        jcah_sql(&st, "DELETE FROM control_checkpoint WHERE ledger_id IN (3,4);");
        let lignes = jcah_lignes(&jcah_telecharger(&st, &[("from_id", "2"), ("limit", "2")]).await.1);
        assert_eq!(lignes.len(), 2, "aucun point dans la tranche, et pas celui du maillon 2 : {lignes:?}");
        assert_eq!(
            crate::governance::verdict_hors_ligne_de_la_copie_du_journal_de_controle(&lignes, &h2, Some(&pin)),
            (2, "TÊTE NON ANCRÉE : 2 entrée(s) chaînées intègres, mais 2 maillon(s) depuis l'origine ne sont couverts par aucun point de contrôle signé — une suppression suivie d'un re-chaînage n'y serait pas vue : aucun verdict d'ancrage n'est rendu".to_string())
        );
        assert_eq!(jcah_telecharger(&st, &[("from_id", "5")]).await, (200, String::new()), "tranche vide : corps vide, aucun point");
    }

    /// Un point de contrôle de la tranche illisible : 500 nommé, exactement `error` et `id`, la phrase d'avant ; la
    /// fonction rend la cause. Contrôle positif : le point remis, 200.
    #[tokio::test]
    async fn jcah_point_illisible_aucun_export() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 3);
        let sig: String = st.tenants.control.as_ref().expect("mode 1").conn.lock().query_row("SELECT sig FROM control_checkpoint WHERE ledger_id=3", [], |r| r.get(0)).expect("fixture");
        jcah_sql(&st, "UPDATE control_checkpoint SET sig=X'FF' WHERE ledger_id=3;");
        let (statut, corps) = jcah_telecharger(&st, &[]).await;
        let v: Value = serde_json::from_str(&corps).expect("corps JSON");
        let cles: Vec<&String> = v.as_object().expect("objet").keys().collect();
        assert_eq!((statut, cles), (500, vec![&"error".to_string(), &"id".to_string()]), "{corps}");
        assert_eq!(
            v["error"],
            json!("export du journal de contrôle impossible : le plan de contrôle n'a pas pu être ouvert ni lu — rien n'est exporté ; le journal du démon nomme la cause sous l'identifiant de cette réponse.")
        );
        assert_eq!(
            crate::governance::control_ledger_export_lines_ancree(&st.tenants.control.as_ref().expect("mode 1").conn.lock(), 0, 10),
            Err("point de contrôle de la tranche ILLISIBLE (Invalid column type Blob at index: 2, name: sig) — AUCUN export, et le curseur NE bouge PAS".to_string())
        );
        st.tenants.control.as_ref().expect("mode 1").conn.lock().execute("UPDATE control_checkpoint SET sig=?1 WHERE ledger_id=3", params![sig]).expect("fixture");
        assert_eq!(jcah_telecharger(&st, &[]).await.0, 200, "contrôle positif");
    }

    /// Les refus de la copie : ligne non JSON, maillon altéré, point incomplet (chacun de ses trois champs).
    #[tokio::test]
    async fn jcah_copie_malformee_compromise() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 3);
        let pin = jcah_epinglee();
        let lignes = jcah_lignes(&jcah_telecharger(&st, &[]).await.1);
        assert_eq!(lignes.len(), 6, "fixture : trois maillons et trois points");
        let verdict = |l: &[String]| crate::governance::verdict_hors_ligne_de_la_copie_du_journal_de_controle(l, "", Some(&pin));
        assert_eq!(verdict(&lignes).0, 0, "contrôle positif");

        let mut non_json = lignes.clone();
        non_json[1] = "{pas du json".to_string();
        let cause = serde_json::from_str::<Value>("{pas du json").expect_err("fixture").to_string();
        assert_eq!(verdict(&non_json), (1, format!("EXPORT COMPROMIS : ligne 1: JSON invalide: {cause}")));

        let mut altere = lignes.clone();
        let mut v: Value = serde_json::from_str(&altere[1]).expect("JSON");
        v["detail"] = json!("détail réécrit dans la copie");
        altere[1] = v.to_string();
        assert_eq!(verdict(&altere), (1, "EXPORT COMPROMIS : ligne 1 (entrée #2): hachage recalculé différent — maillon altéré".to_string()));

        let point: Value = serde_json::from_str(&lignes[3]).expect("JSON");
        let sans = |champ: &str| {
            let mut p = point.clone();
            p["point_de_controle"].as_object_mut().expect("objet").remove(champ);
            let mut l = lignes.clone();
            l[3] = p.to_string();
            l
        };
        let incomplet = (1, "EXPORT COMPROMIS : ligne 3: point de contrôle incomplet (ledger_id, ledger_hash et sig requis)".to_string());
        assert_eq!(verdict(&sans("ledger_id")), incomplet, "sans ledger_id");
        assert_eq!(verdict(&sans("ledger_hash")), incomplet, "sans ledger_hash");
        assert_eq!(verdict(&sans("sig")), incomplet, "sans sig");
    }

    // -------------------------------------------------------------------------------------
    // (6) LA SOUS-COMMANDE `verify-control`
    // -------------------------------------------------------------------------------------

    fn jcah_args(reste: &[&str]) -> Vec<String> {
        ["plume-daemon", "verify-control"].iter().chain(reste.iter()).map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn jcah_commande_verify_control_base_et_copie() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, base) = jcah_etat(true);
        jcah_ecrire(&st, 4);
        let pin = jcah_epinglee();
        assert_eq!(crate::rbac::commande_verify_control(&jcah_args(&[]), base.as_str(), None, Some(&pin)), (0, JCAH_OK_4.to_string()), "la base");
        assert_eq!(crate::rbac::commande_verify_control(&jcah_args(&[]), base.as_str(), None, None), (2, JCAH_SANS_EPINGLE_4.to_string()), "la base, sans épingle");

        let dossier = crate::tmp_possede::TmpPossede::neuf("jcah-copie");
        let copie = dossier.sous("copie.jsonl").as_str().to_owned();
        let tranche = jcah_lignes(&jcah_telecharger(&st, &[("from_id", "2")]).await.1);
        std::fs::write(&copie, format!("{}\n\n{}\n", tranche[0], tranche[1..].join("\n"))).expect("fixture : copie avec une ligne vide");
        let h2 = jcah_hash(&st, 2);
        assert_eq!(
            crate::rbac::commande_verify_control(&jcah_args(&["--export", copie.as_str(), "--prev", h2.as_str()]), "/chemin/jamais/ouvert", None, Some(&pin)),
            (0, "export OK : 2 entrée(s) chaînées intègres, chaîne lue entièrement ; tête ancrée, 2 point(s) de contrôle signés par la clé épinglée".to_string()),
            "la copie, sans ouvrir la base, ligne vide écartée, `--prev` lu"
        );
        assert_eq!(
            crate::rbac::commande_verify_control(&jcah_args(&["--export", copie.as_str()]), "/chemin/jamais/ouvert", None, Some(&pin)),
            (1, "EXPORT COMPROMIS : ligne 0 (entrée #3): rupture de chaîne (prev_hash != hash précédent)".to_string()),
            "sans `--prev`, la tranche ne s'accroche pas à l'origine"
        );
        let absente = dossier.sous("absente.jsonl").as_str().to_owned();
        let cause = std::fs::read_to_string(&absente).expect_err("fixture").to_string();
        assert_eq!(
            crate::rbac::commande_verify_control(&jcah_args(&["--export", absente.as_str()]), base.as_str(), None, Some(&pin)),
            (2, format!("VERDICT IMPOSSIBLE : la copie ne se lit pas ({absente}) : {cause}"))
        );
        let introuvable = dossier.sous("absent/plume-control.db").as_str().to_owned();
        let cause = crate::db_open::open_db_keyed_without_schema_contract(&introuvable, None).err().expect("fixture : ouverture impossible").to_string();
        assert_eq!(
            crate::rbac::commande_verify_control(&jcah_args(&[]), &introuvable, None, Some(&pin)),
            (2, format!("VERDICT IMPOSSIBLE : le plan de contrôle ne s'ouvre pas ({introuvable}) : {cause}"))
        );
    }

    /// Le bras de `main`, lu EN ENTIER : il délègue à `commande_verify_control` avec le chemin, la clé du plan de
    /// contrôle et l'épingle, imprime la phrase et sort sur le code. Témoin de TEXTE : il ne lance pas le binaire.
    #[test]
    fn jcah_le_bras_de_main_delegue() {
        let src = include_str!("../main.rs");
        let debut = "    if args.get(1).map(String::as_str) == Some(\"verify-control\") {\n";
        assert_eq!(src.matches(debut).count(), 1, "un seul bras verify-control");
        let bras = &src[src.find(debut).expect("bras")..];
        let bras = &bras[..bras.find("\n    }\n").expect("fin du bras") + "\n    }\n".len()];
        assert_eq!(
            bras,
            "    if args.get(1).map(String::as_str) == Some(\"verify-control\") {\n\
             \x20       let conf = load_config();\n\
             \x20       let db_path = cfg(&conf, \"PLUME_DB\", \"/var/lib/plume/db/plume.db\");\n\
             \x20       let chemin = crate::state::control_db_path(&conf, &db_path);\n\
             \x20       let (code, phrase) = crate::rbac::commande_verify_control(&args, &chemin, crate::state::control_key().as_deref(), crate::ledger::ledger_pinned_pubkey().as_ref());\n\
             \x20       println!(\"{phrase}\");\n\
             \x20       if code != 0 {\n\
             \x20           std::process::exit(code);\n\
             \x20       }\n\
             \x20       return;\n\
             \x20   }\n"
        );
    }

    // -------------------------------------------------------------------------------------
    // (7) L'ARMEMENT PAR `init_control_plane`, ET LE MODE 0
    // -------------------------------------------------------------------------------------

    #[test]
    fn jcah_init_control_plane_arme_la_cle_du_registre() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let dossier = crate::tmp_possede::TmpPossede::neuf("jcah-init");
        let fichier_de_cle = dossier.sous("signature.key").as_str().to_owned();
        std::fs::write(&fichier_de_cle, hex_encode(&JCAH_CLE)).expect("fixture : clé du registre");
        let base = dossier.sous("plume.db").as_str().to_owned();
        let conf: HashMap<String, String> = [("PLUME_LEDGER_KEY_PATH".to_string(), fichier_de_cle.clone())].into_iter().collect();
        let cp = init_control_plane(&conf, &base).expect("plan de contrôle");
        let st = tenant_test_state("jcah-adm", "jcah-edi", "jcah-sa", Some(cp));
        jcah_ecrire(&st, 1);
        let pubkey: String = st.tenants.control.as_ref().expect("mode 1").conn.lock().query_row("SELECT pubkey FROM control_checkpoint", [], |r| r.get(0)).expect("un point signé");
        assert_eq!(pubkey, hex_encode(&jcah_epinglee()), "signé par la clé lue au chemin du registre");
        assert_eq!(jcah_verdict(&st, Some(&jcah_epinglee())).0, 0);
    }

    /// CONTRÔLE DE NON-RÉGRESSION, PAS UN TÉMOIN DU CORRECTIF : en mode 0, `control_ledger_append` rend `NonInscrit`
    /// avant toute écriture et la route rend 404 avant de lire une tranche — les deux sortent AVANT le code de
    /// `P10.7-r`, que ce test ne peut donc pas faire rougir.
    #[tokio::test]
    async fn jcah_mode_0_inchange() {
        let st = tenant_test_state("jcah-adm", "jcah-edi", "jcah-sa", None);
        let issue = control_ledger_append(&st, "superadmin.read", "sa-jcah", "default", "raison");
        assert_eq!(issue.cause_de_non_inscription(), Some("aucun plan de contrôle : mode mono-tenant, le journal de contrôle n'existe pas"));
        let r = control_ledger_export_get(State(st.clone()), Extension(jcah_adm()), Query(HashMap::new())).await;
        let statut = r.status().as_u16();
        let v: Value = serde_json::from_slice(&axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps")).expect("JSON");
        assert_eq!(statut, 404);
        assert_eq!(v["error"], json!("aucun plan de contrôle : le journal de contrôle n'existe qu'en mode multi-tenant (PLUME_MULTI_TENANT)"));
    }


    // -------------------------------------------------------------------------------------
    // (8) UN POINT PAR MAILLON : LA RÉÉCRITURE BLANCHIE PAR UNE ÉCRITURE LÉGITIME, LE DÉSARMEMENT, LES RANGS D'ORIGINE
    // -------------------------------------------------------------------------------------

    fn jcah_non_ancres(n: usize, non_couverts: usize, premier: i64, dernier: i64) -> String {
        format!(
            "MAILLONS NON ANCRÉS : {n} entrée(s) chaînées intègres, mais {non_couverts} maillon(s), dès le maillon #{premier}, n'ont pas \
             leur propre point de contrôle signé alors que le maillon #{dernier} en a un — une suppression suivie d'un re-chaînage \
             puis d'une écriture légitime y serait blanchie : aucun verdict d'ancrage n'est rendu"
        )
    }

    /// Le deuxième maillon supprimé, la suite re-chaînée, les points de la queue retirés : tête non ancrée (2). Puis
    /// l'écriture LÉGITIME suivante, que le démon signe sur la tête réécrite : le dernier point concorde, mais les
    /// maillons re-chaînés n'ont pas de point propre — toujours 2, jamais 0.
    #[test]
    fn jcah_reecriture_blanchie_par_une_ecriture_legitime() {
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 4);
        let pin = jcah_epinglee();
        jcah_sql(&st, "DELETE FROM control_ledger WHERE id=2;");
        jcah_rechainer(&st);
        jcah_sql(&st, "DELETE FROM control_checkpoint WHERE ledger_id>=2;");
        assert_eq!(jcah_verdict(&st, Some(&pin)), (2, JCAH_TETE_APRES_1.to_string()), "avant l'écriture légitime");
        jcah_ecrire(&st, 1);
        assert_eq!(jcah_compte(&st, "SELECT COUNT(*) FROM control_checkpoint WHERE ledger_id=5"), 1, "fixture : l'écriture légitime a posé le point du maillon 5");
        assert_eq!(jcah_verdict(&st, Some(&pin)), (2, jcah_non_ancres(4, 2, 3, 5)));
    }

    /// La même réécriture, TOUS les points retirés avant l'écriture légitime : les maillons d'avant n'ont plus de point,
    /// et le seul qui reste est celui de la tête — 2.
    #[test]
    fn jcah_reecriture_blanchie_apres_retrait_de_tous_les_points() {
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 4);
        jcah_sql(&st, "DELETE FROM control_ledger WHERE id=2;");
        jcah_rechainer(&st);
        jcah_sql(&st, "DELETE FROM control_checkpoint;");
        jcah_ecrire(&st, 1);
        assert_eq!(jcah_verdict(&st, Some(&jcah_epinglee())), (2, jcah_non_ancres(4, 3, 1, 5)));
    }

    /// La copie de la base blanchie, entière puis en tranche accrochée au maillon 1 : l'export porte les points des
    /// maillons 1 et 5 (resp. 5 seul), et la copie le dit, 2.
    #[tokio::test]
    async fn jcah_reecriture_blanchie_vue_sur_la_copie() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 4);
        let pin = jcah_epinglee();
        let h1 = jcah_hash(&st, 1);
        jcah_sql(&st, "DELETE FROM control_ledger WHERE id=2;");
        jcah_rechainer(&st);
        jcah_sql(&st, "DELETE FROM control_checkpoint WHERE ledger_id>=2;");
        jcah_ecrire(&st, 1);
        let entiere = jcah_lignes(&jcah_telecharger(&st, &[]).await.1);
        assert_eq!(entiere.len(), 6, "quatre maillons, les points des maillons 1 et 5 : {entiere:?}");
        assert_eq!(crate::governance::verdict_hors_ligne_de_la_copie_du_journal_de_controle(&entiere, "", Some(&pin)), (2, jcah_non_ancres(4, 2, 3, 5)));
        let tranche = jcah_lignes(&jcah_telecharger(&st, &[("from_id", "1")]).await.1);
        assert_eq!(tranche.len(), 4, "maillons 3, 4 et 5, le point du 5 : {tranche:?}");
        assert_eq!(crate::governance::verdict_hors_ligne_de_la_copie_du_journal_de_controle(&tranche, &h1, Some(&pin)), (2, jcah_non_ancres(3, 2, 3, 5)));
    }

    /// `armer_la_signature_du_journal_de_controle(chemin, None)` RETIRE la clé armée sur ce chemin : le maillon suivant
    /// n'a pas de point. Réarmée, le maillon d'après en a un ; celui écrit sans clé n'en aura jamais — 2.
    #[test]
    fn jcah_desarmer_retire_la_cle() {
        let (st, _t) = jcah_etat(true);
        let chemin = st.tenants.control.as_ref().expect("mode 1").db_path.clone();
        crate::rbac::armer_la_signature_du_journal_de_controle(chemin.as_str(), None);
        jcah_ecrire(&st, 1);
        assert_eq!(jcah_compte(&st, "SELECT COUNT(*) FROM control_checkpoint"), 0, "désarmée : aucun point");
        assert_eq!(
            jcah_verdict(&st, Some(&jcah_epinglee())),
            (2, "TÊTE NON ANCRÉE : 1 entrée(s) chaînées intègres, mais 1 maillon(s) depuis l'origine ne sont couverts par aucun point de contrôle signé — une suppression suivie d'un re-chaînage n'y serait pas vue : aucun verdict d'ancrage n'est rendu".to_string())
        );
        crate::rbac::armer_la_signature_du_journal_de_controle(chemin.as_str(), Some(jcah_cle()));
        jcah_ecrire(&st, 1);
        assert_eq!(jcah_compte(&st, "SELECT COUNT(*) FROM control_checkpoint"), 1, "contrôle positif : réarmée, le maillon suivant a son point");
        assert_eq!(jcah_verdict(&st, Some(&jcah_epinglee())), (2, jcah_non_ancres(2, 1, 1, 2)));
    }

    /// Deux téléchargements mis bout à bout (`limit=2`, puis `from_id=2`) : chacun porte ses points, intercalés. Le
    /// maillon 4, altéré, est nommé par son rang dans la COPIE (5), pas dans la liste des maillons (3).
    #[tokio::test]
    async fn jcah_rangs_d_origine_dans_une_copie_mise_bout_a_bout() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _t) = jcah_etat(true);
        jcah_ecrire(&st, 4);
        let pin = jcah_epinglee();
        let mut copie = jcah_lignes(&jcah_telecharger(&st, &[("limit", "2")]).await.1);
        assert_eq!(copie.len(), 4, "maillons 1 et 2, leurs deux points : {copie:?}");
        copie.extend(jcah_lignes(&jcah_telecharger(&st, &[("from_id", "2")]).await.1));
        assert_eq!(copie.len(), 8, "puis maillons 3 et 4, leurs deux points");
        assert_eq!(
            crate::governance::verdict_hors_ligne_de_la_copie_du_journal_de_controle(&copie, "", Some(&pin)),
            (0, "export OK : 4 entrée(s) chaînées intègres, chaîne lue entièrement ; tête ancrée, 4 point(s) de contrôle signés par la clé épinglée".to_string()),
            "contrôle positif"
        );
        let mut v: Value = serde_json::from_str(&copie[5]).expect("JSON");
        assert_eq!(v["id"], json!(4), "fixture : la ligne 5 de la copie est le maillon 4");
        v["detail"] = json!("détail réécrit dans la copie");
        copie[5] = v.to_string();
        assert_eq!(
            crate::governance::verdict_hors_ligne_de_la_copie_du_journal_de_controle(&copie, "", Some(&pin)),
            (1, "EXPORT COMPROMIS : ligne 5 (entrée #4): hachage recalculé différent — maillon altéré".to_string())
        );
    }
}
