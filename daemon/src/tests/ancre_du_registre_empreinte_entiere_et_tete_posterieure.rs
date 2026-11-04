// =====================================================================================
// `P10.7-r` (suite) — L'EMPREINTE D'UNE CLÉ ANTÉRIEURE SE COMPARE SUR SES 32 OCTETS, ET AUCUN CHECKPOINT
// D'UNE CLÉ ANTÉRIEURE NE PEUT ATTESTER UNE TÊTE AUTRE QUE CELLE QUE L'EMPREINTE A FIXÉE.
//
// (1) COMPARAISON ENTIÈRE. Toutes les fixtures discordantes d'`ancre_du_registre_cles_anterieures_par_empreinte`
// diffèrent dès le premier octet : une comparaison réduite à un préfixe y restait verte. Qui écrit la base
// pourrait alors renuméroter ou retirer des checkpoints anciens jusqu'à retrouver ce préfixe (environ 2^32
// essais hors ligne pour les huit caractères hex affichés) et ses checkpoints passeraient en sortie 0. Ici,
// l'empreinte VRAIE relevée par la requête de l'exploitant, avec SEUL son dernier caractère changé, puis SEUL
// un caractère du milieu : clé DISCORDANTE, ses checkpoints refusés et nommés par leur `id`, sortie 1, et les
// deux empreintes écrites EN ENTIER (huit caractères seraient identiques des deux côtés).
//
// (2) TÊTE POSTÉRIEURE. L'invariant demandé à la lettre — « aucun checkpoint d'une clé antérieure n'atteste
// une tête POSTÉRIEURE au premier checkpoint de la clé épinglée » — est FAUX en production : le constat du
// 2026-11-03 range deux clés isolées APRÈS le premier checkpoint de la clé actuelle (la décision de
// l'exploitant les admet), et la fixture de rotation le reproduit (#11 sous une clé antérieure, après le #10
// épinglé) ; un contrôle qui les refuserait accuserait la production. La loi « les positions attestées
// croissent avec l'`id` » a été écrite puis RETIRÉE par mesure (`attestation_discordante`, ledger.rs : deux
// signataires de production se chevauchent). Ce que l'empreinte impose, et que ces témoins jouent : chaque
// checkpoint d'une clé antérieure atteste EXACTEMENT la tête fixée au relevé — rejoué tel quel à un `id`
// postérieur (avec le présent rejoué aussi), re-signé par la vieille clé volée sur une tête plus récente au
// même `id`, ajouté sur une tête plus récente, ou échangé d'`id` avec le dernier checkpoint épinglé :
// chaque fois l'empreinte relue change, la clé est DISCORDANTE et le checkpoint nommé, sortie 1. Une
// empreinte concordante sur une suite falsifiée demanderait une seconde préimage SHA-256 — d'où (1).
//
// MUTANTS (VERIF_MUT sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : `BO1_Q4` (premier octet
// seul comparé), `BO1_Q5` (31 premiers octets), `BO1_Q6` (huit premiers caractères hex), `BO1_R_DEDUP` (un
// checkpoint rejoué à l'identique compté une fois dans l'empreinte), `BO1_R_CONC` (empreinte discordante
// ignorée à l'admission), `BO1_R_AVANT_PREMIER` (contrôle suggéré : clé antérieure refusée après le premier
// checkpoint épinglé — rougit le témoin de la rotation réelle, il n'est donc PAS posé).
// =====================================================================================

mod ancre_du_registre_empreinte_entiere_et_tete_posterieure {
    use super::*;
    use sha2::{Digest, Sha256};

    const EE_PIN: u8 = 61;
    const EE_OLD: u8 = 62;
    const EE_ISO: u8 = 63;
    const EE_D: &str = "empreinte de la clé antérieure discordante";

    fn ee_cle(graine: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[graine; 32])
    }
    fn ee_pub(graine: u8) -> [u8; 32] {
        ee_cle(graine).verifying_key().to_bytes()
    }
    fn ee_hex(graine: u8) -> String {
        hex_encode(&ee_pub(graine))
    }
    /// La forme tronquée d'une clé, recalculée ICI (huit caractères hex puis « … »).
    fn ee_court(graine: u8) -> String {
        format!("{}…", &ee_hex(graine)[..8])
    }

    /// Un checkpoint d'`id` choisi, signé par `graine`, attestant la tête RÉELLE.
    fn ee_signer(conn: &Connection, graine: u8, id: i64) {
        use ed25519_dalek::Signer;
        let k = ee_cle(graine);
        let tete = ledger_prev_hash(conn).expect("tête lisible");
        let sig = k.sign(tete.as_bytes());
        conn.execute(
            "INSERT INTO checkpoint(id,ts,ledger_hash,sig,pubkey) VALUES(?1,?2,?3,?4,?5)",
            params![id, now(), tete, hex_encode(&sig.to_bytes()), hex_encode(k.verifying_key().as_bytes())],
        )
        .expect("checkpoint écrit");
    }

    /// LA ROTATION RÉELLE en miniature, `id` non contigus : trois checkpoints de la clé antérieure, le premier
    /// de la clé épinglée (#10), une clé isolée APRÈS lui (#11, comme les deux isolées de production), puis
    /// l'épinglée (#12). Un maillon avant chaque checkpoint : chaque attestation est une tête distincte.
    const EE_ROTATION: &[(i64, u8)] = &[(1, EE_OLD), (2, EE_OLD), (3, EE_OLD), (10, EE_PIN), (11, EE_ISO), (12, EE_PIN)];

    fn ee_base(etiquette: &str) -> crate::tmp_possede::TmpDb {
        let coffre = crate::tmp_possede::TmpDb::neuf(etiquette);
        let conn = Connection::open(coffre.as_str()).expect("base fichier ouverte");
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        conn.execute("DELETE FROM ledger", []).expect("journal vidé");
        conn.execute("DELETE FROM checkpoint", []).expect("checkpoints vidés");
        for (id, graine) in EE_ROTATION {
            ledger_append(&conn, "config.mode", &format!("maillon avant le checkpoint {id}"));
            ee_signer(&conn, *graine, *id);
        }
        coffre
    }

    fn ee_ecrire(coffre: &crate::tmp_possede::TmpDb, sql: &str) {
        Connection::open(coffre.as_str()).expect("base fichier ouverte").execute_batch(sql).expect("falsification écrite");
    }

    /// L'EMPREINTE par la REQUÊTE DONNÉE À L'EXPLOITANT (une ligne par checkpoint, saut de ligne, SHA-256),
    /// jamais par la fonction du produit.
    fn ee_empreinte(coffre: &crate::tmp_possede::TmpDb, graine: u8) -> String {
        let conn = Connection::open(coffre.as_str()).expect("base fichier ouverte");
        let mut st = conn
            .prepare(
                "SELECT id || ':' || ifnull(ledger_hash, '') || ':' || ifnull(sig, '') FROM checkpoint \
                 WHERE lower(pubkey) = ?1 ORDER BY id",
            )
            .unwrap();
        let lignes: Vec<String> =
            st.query_map(params![ee_hex(graine)], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
        let mut h = Sha256::new();
        for l in &lignes {
            h.update(l.as_bytes());
            h.update(b"\n");
        }
        hex_encode(&h.finalize())
    }

    fn ee_ancre(old: &str, iso: &str) -> AncreEpinglee {
        AncreEpinglee {
            cle: ee_pub(EE_PIN),
            anterieures: analyser_les_cles_anterieures(&format!("{}:{old} {}:{iso}", ee_hex(EE_OLD), ee_hex(EE_ISO)), &ee_pub(EE_PIN))
                .expect("fixture : ancre valide"),
        }
    }

    fn ee_juger(coffre: &crate::tmp_possede::TmpDb, old: &str, iso: &str) -> (i32, String) {
        let v = verify_ledger_selon(coffre.as_str(), Ok(Some(ee_ancre(old, iso)))).expect("un verdict est rendu");
        rendre_le_verdict_du_registre(&v)
    }

    fn ee_concordante(graine: u8, admis: i64, relus: i64, ids: &str) -> String {
        format!("{} : {admis} admis sur {relus} relu(s) ({ids}), empreinte concordante", ee_court(graine))
    }
    fn ee_discordante(graine: u8, relus: i64, ids: &str, attendue: &str, relue: &str) -> String {
        format!(
            "{} : 0 admis sur {relus} relu(s) ({ids}), empreinte DISCORDANTE (attendue {attendue}, relue {relue})",
            ee_court(graine)
        )
    }

    /// L'empreinte `e` avec SEUL son caractère de rang `rang` changé (un autre chiffre hex).
    fn ee_un_caractere_change(e: &str, rang: usize) -> String {
        let mut c: Vec<char> = e.chars().collect();
        c[rang] = if c[rang] == '0' { '1' } else { '0' };
        let change: String = c.into_iter().collect();
        assert_eq!(change.len(), 64, "fixture : empreinte de 64 caractères");
        assert_eq!(
            change.chars().zip(e.chars()).filter(|(a, b)| a != b).count(),
            1,
            "fixture : un seul caractère diffère"
        );
        change
    }

    /// La phrase attendue quand l'empreinte de la clé antérieure `EE_OLD` est discordante sur une suite intacte.
    fn ee_vieille_cle_discordante(attendue: &str, relue: &str) -> (i32, String) {
        let o = ee_court(EE_OLD);
        (
            1,
            format!(
                "INTÉGRITÉ COMPROMISE (PIN) : 3 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=3, 6 entrées) \
                 — re-signature possible : #1 ({o}, {EE_D}), #2 ({o}, {EE_D}), #3 ({o}, {EE_D}) ; clés antérieures : {}, {}",
                ee_discordante(EE_OLD, 3, "du #1 au #3", attendue, relue),
                ee_concordante(EE_ISO, 1, 1, "#11")
            ),
        )
    }

    /// (1) LE DERNIER CARACTÈRE SEUL CHANGÉ (dernier octet) : discordante, les trois checkpoints nommés, 1.
    #[test]
    fn ee_empreinte_au_dernier_caractere_change_est_discordante() {
        let _env = VERROU_ENV_PROCESSUS.read(); // `verify_ledger_selon` lit PLUME_DB_KEY
        let coffre = ee_base("ee-dernier");
        let (old, iso) = (ee_empreinte(&coffre, EE_OLD), ee_empreinte(&coffre, EE_ISO));
        let posee = ee_un_caractere_change(&old, 63);
        assert_eq!(ee_juger(&coffre, &posee, &iso), ee_vieille_cle_discordante(&posee, &old));
    }

    /// (1) UN CARACTÈRE DU MILIEU SEUL CHANGÉ (rang 32, dix-septième octet) : discordante, nommée, 1.
    #[test]
    fn ee_empreinte_a_un_caractere_du_milieu_change_est_discordante() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ee_base("ee-milieu");
        let (old, iso) = (ee_empreinte(&coffre, EE_OLD), ee_empreinte(&coffre, EE_ISO));
        let posee = ee_un_caractere_change(&old, 32);
        assert_eq!(ee_juger(&coffre, &posee, &iso), ee_vieille_cle_discordante(&posee, &old));
    }

    /// (1) CONTRÔLE POSITIF : l'empreinte vraie, non changée, concorde (sinon « tout refuser » resterait vert).
    #[test]
    fn ee_empreinte_vraie_concorde() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ee_base("ee-vraie");
        let (old, iso) = (ee_empreinte(&coffre, EE_OLD), ee_empreinte(&coffre, EE_ISO));
        assert_eq!(
            ee_juger(&coffre, &old, &iso),
            (
                0,
                format!(
                    "ledger OK : 6 entrées chaînées intègres ; checkpoints signés OK=6 KO=0 ; clés antérieures : {}, {}",
                    ee_concordante(EE_OLD, 3, 3, "du #1 au #3"),
                    ee_concordante(EE_ISO, 1, 1, "#11")
                )
            )
        );
    }

    /// (1) PAR LE POINT D'ENTRÉE : `verify`, l'empreinte posée dans l'environnement avec SEUL son dernier
    /// caractère changé, sort en 1 et écrit la ligne entière.
    #[test]
    fn ee_verify_sur_un_dernier_caractere_change_sort_en_1() {
        const ENFANT: &str = "EE_ENFANT_VERIFY_DERNIER";
        if std::env::var(ENFANT).is_ok() {
            println!(); // la ligne de `verify` commence une ligne (libtest écrit « test … » sans saut sous un seul fil)
            verify_run();
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ee_base("ee-s-dernier");
        let (old, iso) = (ee_empreinte(&coffre, EE_OLD), ee_empreinte(&coffre, EE_ISO));
        let posee = ee_un_caractere_change(&old, 63);
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ancre_du_registre_empreinte_entiere_et_tete_posterieure::ee_verify_sur_un_dernier_caractere_change_sort_en_1",
            ])
            .env(ENFANT, "1")
            .env("PLUME_CONFIG", "/nonexistent")
            .env("PLUME_DB", coffre.as_str())
            .env("PLUME_LEDGER_PUBKEY", ee_hex(EE_PIN))
            .env("PLUME_LEDGER_PUBKEYS_ANTERIEURES", format!("{}:{posee};{}:{iso}", ee_hex(EE_OLD), ee_hex(EE_ISO)))
            .env_remove("PLUME_DB_KEY")
            .env_remove("PLUME_DB_KEY_FILE")
            .env_remove("PLUME_DB_KEY_REF")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let (code, attendu) = ee_vieille_cle_discordante(&posee, &old);
        assert_eq!(sortie.status.code(), Some(code), "verify sort en 1 : {stdout}");
        assert_eq!(stdout.lines().filter(|l| *l == attendu).count(), 1, "la ligne entière : {stdout}");
    }

    /// (2) REJEU À L'IDENTIQUE APRÈS LE PRÉSENT : le checkpoint de la clé isolée (#11) recopié tel quel en #20,
    /// puis le dernier checkpoint épinglé (#12) recopié en #21 (le présent tient donc encore). Chaque signature
    /// est valide, chaque attestation se rattache ; l'empreinte de la clé isolée porte une ligne de plus : elle
    /// est DISCORDANTE et ses deux checkpoints sont nommés, sortie 1.
    #[test]
    fn ee_un_rejeu_a_l_identique_apres_le_present_est_nomme() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ee_base("ee-rejeu");
        let (old, iso) = (ee_empreinte(&coffre, EE_OLD), ee_empreinte(&coffre, EE_ISO));
        ee_ecrire(
            &coffre,
            "INSERT INTO checkpoint(id,ts,ledger_hash,sig,pubkey) SELECT 20,ts,ledger_hash,sig,pubkey FROM checkpoint WHERE id=11;
             INSERT INTO checkpoint(id,ts,ledger_hash,sig,pubkey) SELECT 21,ts,ledger_hash,sig,pubkey FROM checkpoint WHERE id=12;",
        );
        let relue = ee_empreinte(&coffre, EE_ISO);
        let i = ee_court(EE_ISO);
        assert_eq!(
            ee_juger(&coffre, &old, &iso),
            (
                1,
                format!(
                    "INTÉGRITÉ COMPROMISE (PIN) : 2 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=6, 6 entrées) \
                     — re-signature possible : #11 ({i}, {EE_D}), #20 ({i}, {EE_D}) ; clés antérieures : {}, {}",
                    ee_concordante(EE_OLD, 3, 3, "du #1 au #3"),
                    ee_discordante(EE_ISO, 2, "du #11 au #20", &iso, &relue)
                )
            )
        );
    }

    /// (2) LA VIEILLE CLÉ VOLÉE RE-SIGNE, AU MÊME `id`, UNE TÊTE PLUS RÉCENTE que tous les checkpoints épinglés :
    /// un maillon est ajouté après le #12, puis le #11 de la clé isolée atteste ce maillon, signature valide.
    /// L'attestation se rattache à la chaîne ; l'empreinte, non : discordante, #11 nommé, sortie 1.
    #[test]
    fn ee_une_tete_plus_recente_re_signee_au_meme_id_est_nommee() {
        use ed25519_dalek::Signer;
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ee_base("ee-tete");
        let (old, iso) = (ee_empreinte(&coffre, EE_OLD), ee_empreinte(&coffre, EE_ISO));
        let tete = {
            let conn = Connection::open(coffre.as_str()).unwrap();
            ledger_append(&conn, "config.mode", "maillon après le présent");
            ledger_prev_hash(&conn).expect("tête lisible")
        };
        let sig = hex_encode(&ee_cle(EE_ISO).sign(tete.as_bytes()).to_bytes());
        ee_ecrire(&coffre, &format!("UPDATE checkpoint SET ledger_hash='{tete}', sig='{sig}' WHERE id=11"));
        let relue = ee_empreinte(&coffre, EE_ISO);
        assert_ne!(relue, iso, "fixture : la suite de la clé isolée a changé");
        assert_eq!(
            ee_juger(&coffre, &old, &iso),
            (
                1,
                format!(
                    "INTÉGRITÉ COMPROMISE (PIN) : 1 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=5, 7 entrées) \
                     — re-signature possible : #11 ({}, {EE_D}) ; clés antérieures : {}, {}",
                    ee_court(EE_ISO),
                    ee_concordante(EE_OLD, 3, 3, "du #1 au #3"),
                    ee_discordante(EE_ISO, 1, "#11", &iso, &relue)
                )
            )
        );
    }

    /// (2) LA VIEILLE CLÉ VOLÉE AJOUTE UN CHECKPOINT (#13) SUR UNE TÊTE PLUS RÉCENTE, devenu le dernier : la
    /// discordance est une accusation (1), elle passe avant le contrôle du présent (qui rendrait 2).
    #[test]
    fn ee_un_checkpoint_ajoute_sur_une_tete_plus_recente_est_nomme() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ee_base("ee-ajout");
        let (old, iso) = (ee_empreinte(&coffre, EE_OLD), ee_empreinte(&coffre, EE_ISO));
        {
            let conn = Connection::open(coffre.as_str()).unwrap();
            ledger_append(&conn, "config.mode", "maillon après le présent");
            ee_signer(&conn, EE_ISO, 13);
        }
        let relue = ee_empreinte(&coffre, EE_ISO);
        let i = ee_court(EE_ISO);
        assert_eq!(
            ee_juger(&coffre, &old, &iso),
            (
                1,
                format!(
                    "INTÉGRITÉ COMPROMISE (PIN) : 2 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=5, 7 entrées) \
                     — re-signature possible : #11 ({i}, {EE_D}), #13 ({i}, {EE_D}) ; clés antérieures : {}, {}",
                    ee_concordante(EE_OLD, 3, 3, "du #1 au #3"),
                    ee_discordante(EE_ISO, 2, "du #11 au #13", &iso, &relue)
                )
            )
        );
    }

    /// (2) RÉORDONNANCEMENT À TRAVERS LES CLÉS : le #11 de la clé isolée et le #12 épinglé échangent leur `id`,
    /// la clé isolée devient la plus récente. L'`id` est dans la ligne : discordante, #12 nommé, sortie 1.
    #[test]
    fn ee_un_echange_d_id_avec_le_dernier_checkpoint_epingle_est_nomme() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ee_base("ee-echange");
        let (old, iso) = (ee_empreinte(&coffre, EE_OLD), ee_empreinte(&coffre, EE_ISO));
        ee_ecrire(
            &coffre,
            "UPDATE checkpoint SET id=100 WHERE id=11; UPDATE checkpoint SET id=11 WHERE id=12; UPDATE checkpoint SET id=12 WHERE id=100;",
        );
        let relue = ee_empreinte(&coffre, EE_ISO);
        assert_ne!(relue, iso, "fixture : la suite de la clé isolée a changé");
        assert_eq!(
            ee_juger(&coffre, &old, &iso),
            (
                1,
                format!(
                    "INTÉGRITÉ COMPROMISE (PIN) : 1 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=5, 6 entrées) \
                     — re-signature possible : #12 ({}, {EE_D}) ; clés antérieures : {}, {}",
                    ee_court(EE_ISO),
                    ee_concordante(EE_OLD, 3, 3, "du #1 au #3"),
                    ee_discordante(EE_ISO, 1, "#12", &iso, &relue)
                )
            )
        );
    }
}
