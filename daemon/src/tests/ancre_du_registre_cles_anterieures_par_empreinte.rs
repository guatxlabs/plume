// =====================================================================================
// `P10.7-r` (suite) — L'ANCRE DU REGISTRE NOMME SES CLÉS ANTÉRIEURES, CHACUNE LIÉE À L'EMPREINTE DE CE
// QU'ELLE A SIGNÉ.
//
// DÉCISION DE L'EXPLOITANT (2026-11-03) : épingler la clé publique du registre (`PLUME_LEDGER_PUBKEY`) en
// NOMMANT les clés antérieures (`PLUME_LEDGER_PUBKEYS_ANTERIEURES`) ; la clé épinglée vaut pour tout le
// reste ; toute autre signature, passée ou future, est refusée. La première conception bornait chaque clé
// antérieure à une plage d'`id` de checkpoint : refusée, car l'`id` est attribué par la base et réécrit par
// qui écrit la base. Chaque clé antérieure est donc liée à une valeur HORS BASE : l'empreinte SHA-256 de la
// suite exacte `id:ledger_hash:sig` (une ligne par checkpoint, dans l'ordre des `id`) qu'elle a signée.
//
// CE QUE CES TÉMOINS JOUENT, sur des bases FICHIER au schéma réel, journal vidé puis UN maillon avant chaque
// checkpoint (attestations toutes distinctes), checkpoints signés par quatre clés Ed25519 de test (épinglée,
// antérieure, isolée, étrangère) à des `id` NON CONTIGUS (1, 2, 3, 10, 11, 12) : empreintes concordantes ;
// sans clé antérieure ; checkpoint retiré, ajouté, re-signé, réordonné, renuméroté, attestation seule ou
// signature seule changée ; ancres courantes retirées ; clé antérieure entièrement retirée ; chaque forme
// malformée ; sans épingle. L'empreinte attendue est recalculée ICI par la requête SQL donnée à l'exploitant
// (`ae_empreinte`), jamais par la fonction du produit. Plus : `verify` par sous-processus (point d'entrée),
// les deux gardes relues dans `main` (démarrage, `verify-control`) et la vérification Ed25519 unique du cœur.
//
// MUTANTS DE LA CORRECTION (VERIF_MUT sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE :
// `BN1C_W05` (empreinte de 33 octets tronquée), `BN1C_W07` (doublon cherché par le texte écrit),
// `BN1C_W11` (sans épingle, KO accusé), `BN1C_B5`/`BN1C_B6` (bord des refus nommés), `BN1C_W14` (ancre
// ambiguë rendue avant la rupture), `BN1C_W23` (contrôle du présent avant la rupture), `BN1C_W32` (bras de
// `verify-control` placé avant le bloc de l'ancre, dans le texte lu par l'instrument).
// =====================================================================================

/// AIDE DES TÉMOINS — `verify_ledger` n'a plus d'appelant de production (`verify_run` passe par
/// `verify_ledger_selon`) : elle ne vit plus dans `ledger.rs`. Elle rend le contrat historique
/// `(entrées, sig_ok, sig_ko, rupture)` du MÊME chemin que `verify_run` — ancre lue sur `load_config()`,
/// puis `verify_ledger_selon` — pour ses appelants de `sec.rs`, `une_chaine_sans_ancre.rs` et
/// `primitives_avouent_leur_ecriture.rs`. Elle LIT l'environnement : l'appelant prend le verrou en lecture.
fn verify_ledger(db_path: &str) -> Result<(usize, i64, i64, Option<i64>), String> {
    let v = verify_ledger_selon(db_path, ancre_epinglee(&load_config()))?;
    Ok((v.entrees, v.sig_ok, v.sig_ko, v.rupture))
}

mod ancre_du_registre_cles_anterieures_par_empreinte {
    use super::*;
    use sha2::{Digest, Sha256};

    const AE_PIN: u8 = 51;
    const AE_OLD: u8 = 52;
    const AE_ISO: u8 = 53;
    const AE_ETR: u8 = 54;

    /// L'empreinte de la suite VIDE (SHA-256 de zéro octet), écrite en littéral.
    const AE_EMPREINTE_VIDE: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn ae_cle(graine: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[graine; 32])
    }
    fn ae_pub(graine: u8) -> [u8; 32] {
        ae_cle(graine).verifying_key().to_bytes()
    }
    fn ae_hex(graine: u8) -> String {
        hex_encode(&ae_pub(graine))
    }
    fn ae_b64(graine: u8) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(ae_pub(graine))
    }
    /// La forme tronquée attendue, recalculée ICI (huit caractères hex puis « … »), jamais par la fonction du produit.
    fn ae_court_hex(hex: &str) -> String {
        format!("{}…", &hex[..8])
    }
    fn ae_court(graine: u8) -> String {
        ae_court_hex(&ae_hex(graine))
    }

    /// Un checkpoint d'`id` choisi, attestant la tête RÉELLE (concordant), signé par `graine` ; `valide = false`
    /// signe AUTRE CHOSE que la tête (signature invalide, attestation concordante).
    fn ae_signer(conn: &Connection, graine: u8, id: i64, valide: bool) {
        use ed25519_dalek::Signer;
        let k = ae_cle(graine);
        let tete = ledger_prev_hash(conn).expect("tête lisible");
        let signe = if valide { tete.clone() } else { format!("{tete}-falsifie") };
        let sig = k.sign(signe.as_bytes());
        conn.execute(
            "INSERT INTO checkpoint(id,ts,ledger_hash,sig,pubkey) VALUES(?1,?2,?3,?4,?5)",
            params![id, now(), tete, hex_encode(&sig.to_bytes()), hex_encode(k.verifying_key().as_bytes())],
        )
        .expect("checkpoint écrit");
    }

    /// Base FICHIER : schéma réel, journal et checkpoints vidés, puis pour chaque `(id, signataire, valide)` un
    /// maillon et un checkpoint de cet `id` sur la tête — chaque attestation est donc distincte.
    fn ae_base(etiquette: &str, points: &[(i64, u8, bool)]) -> crate::tmp_possede::TmpDb {
        let coffre = crate::tmp_possede::TmpDb::neuf(etiquette);
        let conn = Connection::open(coffre.as_str()).expect("base fichier ouverte");
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        conn.execute("DELETE FROM ledger", []).expect("journal vidé");
        conn.execute("DELETE FROM checkpoint", []).expect("checkpoints vidés");
        for (id, graine, valide) in points {
            ledger_append(&conn, "config.mode", &format!("maillon avant le checkpoint {id}"));
            ae_signer(&conn, *graine, *id, *valide);
        }
        coffre
    }

    /// Exécute des énoncés SQL de falsification sur la base (ce que ferait qui écrit dans la base).
    fn ae_ecrire(coffre: &crate::tmp_possede::TmpDb, sql: &str) {
        let conn = Connection::open(coffre.as_str()).expect("base fichier ouverte");
        conn.execute_batch(sql).expect("falsification écrite");
    }

    /// L'EMPREINTE d'une clé, recalculée par la REQUÊTE DONNÉE À L'EXPLOITANT (une ligne par checkpoint, puis
    /// le saut de ligne qu'imprime `sqlite3`, le tout passé à SHA-256) — jamais par la fonction du produit.
    fn ae_empreinte(coffre: &crate::tmp_possede::TmpDb, graine: u8) -> String {
        let conn = Connection::open(coffre.as_str()).expect("base fichier ouverte");
        let mut st = conn
            .prepare(
                "SELECT id || ':' || ifnull(ledger_hash, '') || ':' || ifnull(sig, '') FROM checkpoint \
                 WHERE lower(pubkey) = ?1 ORDER BY id",
            )
            .unwrap();
        let lignes: Vec<String> =
            st.query_map(params![ae_hex(graine)], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
        let mut h = Sha256::new();
        for l in &lignes {
            h.update(l.as_bytes());
            h.update(b"\n");
        }
        hex_encode(&h.finalize())
    }

    fn ae_ancre(anterieures: &[(u8, &str)]) -> AncreEpinglee {
        let ecrit: Vec<String> = anterieures.iter().map(|(g, e)| format!("{}:{e}", ae_hex(*g))).collect();
        AncreEpinglee {
            cle: ae_pub(AE_PIN),
            anterieures: analyser_les_cles_anterieures(&ecrit.join(" "), &ae_pub(AE_PIN)).expect("fixture : ancre valide"),
        }
    }

    /// Le juge de `verify`, l'ancre passée (le point d'entrée `verify_run` est joué par sous-processus plus bas).
    fn ae_juger(coffre: &crate::tmp_possede::TmpDb, ancre: Option<AncreEpinglee>) -> (i32, String) {
        let v = verify_ledger_selon(coffre.as_str(), Ok(ancre)).expect("un verdict est rendu");
        rendre_le_verdict_du_registre(&v)
    }

    /// Les `id` réels ne sont PAS les rangs : 1, 2, 3, 10, 11, 12 (rangs 1 à 6).
    const AE_ROTATION: &[(i64, u8, bool)] =
        &[(1, AE_OLD, true), (2, AE_OLD, true), (3, AE_OLD, true), (10, AE_PIN, true), (11, AE_ISO, true), (12, AE_PIN, true)];

    /// La clause d'une clé antérieure concordante, écrite ICI.
    fn ae_concordante(graine: u8, admis: i64, relus: i64, ids: &str) -> String {
        format!("{} : {admis} admis sur {relus} relu(s) ({ids}), empreinte concordante", ae_court(graine))
    }
    /// Discordantes, les deux empreintes sont écrites EN ENTIER (minuscules, comme la requête les rend).
    fn ae_discordante(graine: u8, relus: i64, ids: &str, attendue: &str, relue: &str) -> String {
        format!(
            "{} : 0 admis sur {relus} relu(s) ({ids}), empreinte DISCORDANTE (attendue {attendue}, relue {relue})",
            ae_court(graine)
        )
    }

    /// Les empreintes de la rotation, relevées sur la base INTACTE (ce que l'exploitant pose).
    fn ae_rotation(etiquette: &str) -> (crate::tmp_possede::TmpDb, String, String) {
        let coffre = ae_base(etiquette, AE_ROTATION);
        let (old, iso) = (ae_empreinte(&coffre, AE_OLD), ae_empreinte(&coffre, AE_ISO));
        (coffre, old, iso)
    }

    /// LA FORME DOCUMENTÉE, en littéral : la ligne d'un checkpoint, et l'empreinte de deux lignes dont une à
    /// signature vide (une colonne NULL est lue vide), calculée hors du produit.
    #[test]
    fn ae_la_ligne_et_l_empreinte_ont_la_forme_documentee() {
        assert_eq!(ligne_d_empreinte(7, "aa", "bb"), "7:aa:bb\n");
        let mut h = Sha256::new();
        h.update(ligne_d_empreinte(1, "x", "y").as_bytes());
        h.update(ligne_d_empreinte(2, "z", "").as_bytes());
        assert_eq!(hex_encode(&h.finalize()), "7727da50339b0491ecfbed396f9a95324492a70910ea645757be840b1d1b6428");
    }

    /// (a) ÉPINGLE SEULE, CHAÎNE MONO-CLÉ À `id` NON CONTIGUS : OK, phrase à l'octet de l'historique.
    #[test]
    fn ae_a_epingle_seule_sur_une_chaine_mono_cle() {
        let _env = VERROU_ENV_PROCESSUS.read(); // `verify_ledger_selon` lit PLUME_DB_KEY
        let coffre = ae_base("ae-a", &[(1, AE_PIN, true), (2, AE_PIN, true), (5, AE_PIN, true)]);
        assert_eq!(
            ae_juger(&coffre, Some(ae_ancre(&[]))),
            (0, "ledger OK : 3 entrées chaînées intègres ; checkpoints signés OK=3 KO=0".to_string())
        );
    }

    /// (b) ROTATION, EMPREINTES CONCORDANTES : OK, et pour chaque clé ce qu'elle a couvert, `id` RÉELS dits.
    #[test]
    fn ae_b_rotation_aux_empreintes_concordantes() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (coffre, old, iso) = ae_rotation("ae-b");
        assert_eq!(
            ae_juger(&coffre, Some(ae_ancre(&[(AE_OLD, old.as_str()), (AE_ISO, iso.as_str())]))),
            (
                0,
                format!(
                    "ledger OK : 6 entrées chaînées intègres ; checkpoints signés OK=6 KO=0 ; clés antérieures : {}, {}",
                    ae_concordante(AE_OLD, 3, 3, "du #1 au #3"),
                    ae_concordante(AE_ISO, 1, 1, "#11")
                )
            )
        );
    }

    /// (b') UNE SIGNATURE FAUSSE DANS LA SUITE RELEVÉE : l'empreinte concorde (elle a été relevée avec), la
    /// signature reste refusée et nommée, et la clé n'a admis que deux checkpoints sur trois.
    #[test]
    fn ae_b_signature_fausse_dans_la_suite_relevee() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ae_base("ae-b2", &[(1, AE_OLD, true), (2, AE_OLD, false), (3, AE_OLD, true), (10, AE_PIN, true)]);
        let old = ae_empreinte(&coffre, AE_OLD);
        assert_eq!(
            ae_juger(&coffre, Some(ae_ancre(&[(AE_OLD, old.as_str())]))),
            (
                1,
                format!(
                    "INTÉGRITÉ COMPROMISE (PIN) : 1 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=3, 4 entrées) \
                     — re-signature possible : #2 ({}, signature invalide) ; clés antérieures : {}",
                    ae_court(AE_OLD),
                    ae_concordante(AE_OLD, 2, 3, "du #1 au #3")
                )
            )
        );
    }

    /// (b'') UNE COLONNE NULL se lit vide dans le produit COMME dans la requête donnée à l'exploitant
    /// (`ifnull`) : l'empreinte relevée par la requête concorde avec celle du produit.
    #[test]
    fn ae_b_une_signature_nulle_se_lit_comme_la_requete_documentee() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ae_base("ae-b3", &[(1, AE_OLD, true), (2, AE_OLD, true), (3, AE_OLD, true), (10, AE_PIN, true)]);
        ae_ecrire(&coffre, "UPDATE checkpoint SET sig=NULL WHERE id=2");
        let old = ae_empreinte(&coffre, AE_OLD);
        assert_eq!(
            ae_juger(&coffre, Some(ae_ancre(&[(AE_OLD, old.as_str())]))),
            (
                1,
                format!(
                    "INTÉGRITÉ COMPROMISE (PIN) : 1 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=3, 4 entrées) \
                     — re-signature possible : #2 ({}, signature invalide) ; clés antérieures : {}",
                    ae_court(AE_OLD),
                    ae_concordante(AE_OLD, 2, 3, "du #1 au #3")
                )
            )
        );
    }

    /// (c) LA MÊME CHAÎNE SANS CLÉ ANTÉRIEURE : chaque checkpoint étranger est nommé par son `id` RÉEL (#11,
    /// rang 5).
    #[test]
    fn ae_c_sans_cle_anterieure_les_refus_portent_l_id_reel() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ae_base("ae-c", AE_ROTATION);
        let (o, i) = (ae_court(AE_OLD), ae_court(AE_ISO));
        assert_eq!(
            ae_juger(&coffre, Some(ae_ancre(&[]))),
            (
                1,
                format!(
                    "INTÉGRITÉ COMPROMISE (PIN) : 4 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=2, 6 entrées) \
                     — re-signature possible : #1 ({o}, clé étrangère), #2 ({o}, clé étrangère), #3 ({o}, clé étrangère), \
                     #11 ({i}, clé étrangère)"
                )
            )
        );
    }

    /// (C) UNE LIGNE ANCIENNE RETIRÉE (`DELETE` de l'id 2) : l'empreinte relue n'est plus l'attendue, la clé
    /// est nommée DISCORDANTE et ses checkpoints restants sont refusés, nommés par leur `id` RÉEL (#3, rang 2).
    #[test]
    fn ae_une_ligne_ancienne_retiree_rend_l_empreinte_discordante() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (coffre, old, iso) = ae_rotation("ae-del");
        ae_ecrire(&coffre, "DELETE FROM checkpoint WHERE id=2");
        let relue = ae_empreinte(&coffre, AE_OLD);
        let o = ae_court(AE_OLD);
        assert_eq!(
            ae_juger(&coffre, Some(ae_ancre(&[(AE_OLD, old.as_str()), (AE_ISO, iso.as_str())]))),
            (
                1,
                format!(
                    "INTÉGRITÉ COMPROMISE (PIN) : 2 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=3, 6 entrées) \
                     — re-signature possible : #1 ({o}, empreinte de la clé antérieure discordante), #3 ({o}, empreinte de \
                     la clé antérieure discordante) ; clés antérieures : {}, {}",
                    ae_discordante(AE_OLD, 2, "du #1 au #3", &old, &relue),
                    ae_concordante(AE_ISO, 1, 1, "#11")
                )
            )
        );
    }

    /// UN CHECKPOINT AJOUTÉ PAR LA VIEILLE CLÉ (volée), après le présent : signature valide, attestation
    /// concordante — l'empreinte, elle, ne concorde plus.
    #[test]
    fn ae_un_checkpoint_ajoute_par_la_vieille_cle_est_nomme() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (coffre, old, iso) = ae_rotation("ae-ajout");
        {
            let conn = Connection::open(coffre.as_str()).unwrap();
            ledger_append(&conn, "config.mode", "maillon avant le rejeu");
            ae_signer(&conn, AE_OLD, 13, true);
        }
        let relue = ae_empreinte(&coffre, AE_OLD);
        let o = ae_court(AE_OLD);
        let d = "empreinte de la clé antérieure discordante";
        assert_eq!(
            ae_juger(&coffre, Some(ae_ancre(&[(AE_OLD, old.as_str()), (AE_ISO, iso.as_str())]))),
            (
                1,
                format!(
                    "INTÉGRITÉ COMPROMISE (PIN) : 4 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=3, 7 entrées) \
                     — re-signature possible : #1 ({o}, {d}), #2 ({o}, {d}), #3 ({o}, {d}), #13 ({o}, {d}) ; clés \
                     antérieures : {}, {}",
                    ae_discordante(AE_OLD, 4, "du #1 au #13", &old, &relue),
                    ae_concordante(AE_ISO, 1, 1, "#11")
                )
            )
        );
    }

    /// LES CINQ FALSIFICATIONS D'UNE SUITE ANCIENNE qui laissent chaque signature VALIDE ou la changent seule —
    /// re-signée par la vieille clé sur une autre tête, réordonnée, renumérotée, attestation seule changée,
    /// signature seule changée : chaque fois la clé est DISCORDANTE et ses trois checkpoints nommés.
    #[test]
    fn ae_une_suite_ancienne_re_signee_reordonnee_ou_renumerotee_est_nommee() {
        use ed25519_dalek::Signer;
        let _env = VERROU_ENV_PROCESSUS.read();
        let o = ae_court(AE_OLD);
        let d = "empreinte de la clé antérieure discordante";
        let premiere_tete = |coffre: &crate::tmp_possede::TmpDb| -> String {
            Connection::open(coffre.as_str())
                .unwrap()
                .query_row("SELECT hash FROM ledger ORDER BY id LIMIT 1", [], |r| r.get(0))
                .unwrap()
        };
        let re_signer = |coffre: &crate::tmp_possede::TmpDb| {
            let tete = premiere_tete(coffre);
            let sig = hex_encode(&ae_cle(AE_OLD).sign(tete.as_bytes()).to_bytes());
            ae_ecrire(coffre, &format!("UPDATE checkpoint SET ledger_hash='{tete}', sig='{sig}' WHERE id=2"));
        };
        let attestation_seule = |coffre: &crate::tmp_possede::TmpDb| {
            let tete = premiere_tete(coffre);
            ae_ecrire(coffre, &format!("UPDATE checkpoint SET ledger_hash='{tete}' WHERE id=2"));
        };
        type Falsification<'a> = (&'a str, &'a str, Box<dyn Fn(&crate::tmp_possede::TmpDb) + 'a>);
        let cas: Vec<Falsification> = vec![
            ("ae-resigne", "du #1 au #3", Box::new(re_signer)),
            (
                "ae-reordonne",
                "du #1 au #3",
                Box::new(|c: &crate::tmp_possede::TmpDb| ae_ecrire(c, "UPDATE checkpoint SET id=100 WHERE id=1; UPDATE checkpoint SET id=1 WHERE id=2; UPDATE checkpoint SET id=2 WHERE id=100;")),
            ),
            ("ae-renumerote", "du #1 au #7", Box::new(|c: &crate::tmp_possede::TmpDb| ae_ecrire(c, "UPDATE checkpoint SET id=7 WHERE id=3"))),
            ("ae-attestation", "du #1 au #3", Box::new(attestation_seule)),
            (
                "ae-signature",
                "du #1 au #3",
                Box::new(|c: &crate::tmp_possede::TmpDb| ae_ecrire(c, "UPDATE checkpoint SET sig=(SELECT sig FROM checkpoint WHERE id=1) WHERE id=2")),
            ),
        ];
        for (etiquette, ids, falsifier) in &cas {
            let (coffre, old, iso) = ae_rotation(etiquette);
            falsifier(&coffre);
            let relue = ae_empreinte(&coffre, AE_OLD);
            assert_ne!(relue, old, "{etiquette} : la fixture change bien la suite");
            let dernier = if *ids == "du #1 au #7" { 7 } else { 3 };
            assert_eq!(
                ae_juger(&coffre, Some(ae_ancre(&[(AE_OLD, old.as_str()), (AE_ISO, iso.as_str())]))),
                (
                    1,
                    format!(
                        "INTÉGRITÉ COMPROMISE (PIN) : 3 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=3, 6 \
                         entrées) — re-signature possible : #1 ({o}, {d}), #2 ({o}, {d}), #{dernier} ({o}, {d}) ; clés \
                         antérieures : {}, {}",
                        ae_discordante(AE_OLD, 3, ids, &old, &relue),
                        ae_concordante(AE_ISO, 1, 1, "#11")
                    )
                ),
                "{etiquette}"
            );
        }
    }

    /// UNE CLÉ ÉTRANGÈRE AU MILIEU DE LA ROTATION (#10, rang 4) : nommée par son `id` réel ; les clés
    /// antérieures concordent.
    #[test]
    fn ae_une_cle_etrangere_est_nommee_par_son_id() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ae_base(
            "ae-etr",
            &[(1, AE_OLD, true), (2, AE_OLD, true), (3, AE_OLD, true), (10, AE_ETR, true), (11, AE_ISO, true), (12, AE_PIN, true)],
        );
        let (old, iso) = (ae_empreinte(&coffre, AE_OLD), ae_empreinte(&coffre, AE_ISO));
        assert_eq!(
            ae_juger(&coffre, Some(ae_ancre(&[(AE_OLD, old.as_str()), (AE_ISO, iso.as_str())]))),
            (
                1,
                format!(
                    "INTÉGRITÉ COMPROMISE (PIN) : 1 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=5, 6 entrées) \
                     — re-signature possible : #10 ({}, clé étrangère) ; clés antérieures : {}, {}",
                    ae_court(AE_ETR),
                    ae_concordante(AE_OLD, 3, 3, "du #1 au #3"),
                    ae_concordante(AE_ISO, 1, 1, "#11")
                )
            )
        );
    }

    /// (B) LES ANCRES COURANTES RETIRÉES (`DELETE` des checkpoints 10 et 12 de la clé épinglée) : les empreintes
    /// concordent toujours, le dernier checkpoint (#11) est d'une clé antérieure — aucun verdict.
    #[test]
    fn ae_les_ancres_courantes_retirees_ne_rendent_aucun_verdict() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (coffre, old, iso) = ae_rotation("ae-present");
        ae_ecrire(&coffre, "DELETE FROM checkpoint WHERE id IN (10, 12)");
        assert_eq!(
            verify_ledger_selon(coffre.as_str(), Ok(Some(ae_ancre(&[(AE_OLD, old.as_str()), (AE_ISO, iso.as_str())])))),
            Err(format!(
                "ANCRE SANS PRÉSENT (PLUME_LEDGER_PUBKEYS_ANTERIEURES) : le dernier checkpoint (#11) est signé par la clé \
                 antérieure {} — aucun checkpoint de la clé épinglée ne vient après ceux des clés antérieures (ancres \
                 courantes retirées, ou clé épinglée qui n'a encore rien signé)",
                ae_court(AE_ISO)
            ))
        );
    }

    /// (B) UN REGISTRE SANS AUCUN CHECKPOINT, une clé antérieure posée avec l'empreinte de la suite vide :
    /// aucun verdict, la cause dite.
    #[test]
    fn ae_un_registre_sans_checkpoint_sous_cle_anterieure_ne_rend_aucun_verdict() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ae_base("ae-vide", &[(1, AE_PIN, true)]);
        ae_ecrire(&coffre, "DELETE FROM checkpoint");
        assert_eq!(
            verify_ledger_selon(coffre.as_str(), Ok(Some(ae_ancre(&[(AE_OLD, AE_EMPREINTE_VIDE)])))),
            Err("ANCRE SANS PRÉSENT (PLUME_LEDGER_PUBKEYS_ANTERIEURES) : le registre ne porte aucun checkpoint — aucun \
                 checkpoint de la clé épinglée ne vient après ceux des clés antérieures (ancres courantes retirées, ou \
                 clé épinglée qui n'a encore rien signé)"
                .to_string())
        );
    }

    /// LE MÊME REGISTRE SANS CHECKPOINT SOUS L'ÉPINGLE SEULE : inchangé (le contrôle du présent ne vaut que si
    /// des clés antérieures sont nommées).
    #[test]
    fn ae_l_epingle_seule_sur_un_registre_sans_checkpoint_est_inchangee() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ae_base("ae-vide-pin", &[(1, AE_PIN, true)]);
        ae_ecrire(&coffre, "DELETE FROM checkpoint");
        assert_eq!(
            ae_juger(&coffre, Some(ae_ancre(&[]))),
            (0, "ledger OK : 1 entrées chaînées intègres ; checkpoints signés OK=0 KO=0".to_string())
        );
    }

    /// UN DERNIER CHECKPOINT DE LA CLÉ ÉPINGLÉE À SIGNATURE FAUSSE est ACCUSÉ (1, nommé), pas rendu en « aucun
    /// verdict » : l'accusation passe avant le contrôle du présent.
    #[test]
    fn ae_un_present_falsifie_est_accuse_avant_le_controle_du_present() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ae_base(
            "ae-present-faux",
            &[(1, AE_OLD, true), (2, AE_OLD, true), (3, AE_OLD, true), (10, AE_PIN, true), (11, AE_ISO, true), (12, AE_PIN, false)],
        );
        let (old, iso) = (ae_empreinte(&coffre, AE_OLD), ae_empreinte(&coffre, AE_ISO));
        assert_eq!(
            ae_juger(&coffre, Some(ae_ancre(&[(AE_OLD, old.as_str()), (AE_ISO, iso.as_str())]))),
            (
                1,
                format!(
                    "INTÉGRITÉ COMPROMISE (PIN) : 1 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=5, 6 entrées) \
                     — re-signature possible : #12 ({}, signature invalide) ; clés antérieures : {}, {}",
                    ae_court(AE_PIN),
                    ae_concordante(AE_OLD, 3, 3, "du #1 au #3"),
                    ae_concordante(AE_ISO, 1, 1, "#11")
                )
            )
        );
    }

    /// UNE CLÉ ANTÉRIEURE ENTIÈREMENT RETIRÉE (`DELETE` de 1, 2 et 3) : aucun checkpoint à nommer par `id`, la
    /// clé l'est — sortie 1, sans la clause des refus nommés (il n'y en a pas).
    #[test]
    fn ae_une_cle_anterieure_entierement_retiree_est_nommee() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (coffre, old, iso) = ae_rotation("ae-tout");
        ae_ecrire(&coffre, "DELETE FROM checkpoint WHERE id IN (1, 2, 3)");
        assert_eq!(
            ae_juger(&coffre, Some(ae_ancre(&[(AE_OLD, old.as_str()), (AE_ISO, iso.as_str())]))),
            (
                1,
                format!(
                    "INTÉGRITÉ COMPROMISE (PIN) : 0 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=3, 6 entrées) \
                     ; clés antérieures : {}, {}",
                    ae_discordante(AE_OLD, 0, "aucun checkpoint", &old, AE_EMPREINTE_VIDE),
                    ae_concordante(AE_ISO, 1, 1, "#11")
                )
            )
        );
    }

    /// LA CLÉ ANTÉRIEURE ET LE PRÉSENT RETIRÉS ENSEMBLE (`DELETE` de 1, 2, 3, 10 et 12) : la discordance est une
    /// ACCUSATION (1), elle passe avant le contrôle du présent (qui rendrait 2).
    #[test]
    fn ae_une_discordance_passe_avant_le_controle_du_present() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (coffre, old, iso) = ae_rotation("ae-tout-present");
        ae_ecrire(&coffre, "DELETE FROM checkpoint WHERE id IN (1, 2, 3, 10, 12)");
        assert_eq!(
            ae_juger(&coffre, Some(ae_ancre(&[(AE_OLD, old.as_str()), (AE_ISO, iso.as_str())]))),
            (
                1,
                format!(
                    "INTÉGRITÉ COMPROMISE (PIN) : 0 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=1, 6 entrées) \
                     ; clés antérieures : {}, {}",
                    ae_discordante(AE_OLD, 0, "aucun checkpoint", &old, AE_EMPREINTE_VIDE),
                    ae_concordante(AE_ISO, 1, 1, "#11")
                )
            )
        );
    }

    /// (f) CHAQUE FORME MALFORMÉE EST REFUSÉE ET NOMMÉE (cœur pur, sans environnement), et les formes admises
    /// (base64, empreinte en majuscules, séparateurs `;`, blancs et tabulations) rendent l'ancre attendue.
    #[test]
    fn ae_f_chaque_forme_malformee_est_refusee_et_nommee() {
        let pin = ae_pub(AE_PIN);
        let (o, i) = (ae_hex(AE_OLD), ae_hex(AE_ISO));
        let e = "ab".repeat(32);
        let refus: Vec<(String, String)> = vec![
            (
                "abc".to_string(),
                "entrée n°1 sans « : » (forme attendue : <clé publique>:<empreinte SHA-256 en hex>)".to_string(),
            ),
            (
                format!("{o}:{e} zz:{e}"),
                "entrée n°2 : clé publique illisible (ni hex de 64 caractères ni base64 de 32 octets)".to_string(),
            ),
            (
                format!("{}:{e}", ae_hex(AE_PIN)),
                format!("entrée n°1 : la clé antérieure {} EST la clé épinglée — elle vaut déjà pour tout le registre", ae_court(AE_PIN)),
            ),
            (format!("{o}:1-273"), format!("entrée n°1 ({}) : empreinte illisible (SHA-256 en hex de 64 caractères attendue)", ae_court(AE_OLD))),
            (format!("{o}:{}", &e[..63]), format!("entrée n°1 ({}) : empreinte illisible (SHA-256 en hex de 64 caractères attendue)", ae_court(AE_OLD))),
            (format!("{o}:{e}a"), format!("entrée n°1 ({}) : empreinte illisible (SHA-256 en hex de 64 caractères attendue)", ae_court(AE_OLD))),
            // LE BORD DE LONGUEUR, en hex PAIR (la parité n'y est pour rien) : 31 et 33 octets sont refusés, jamais tronqués ni complétés.
            (format!("{o}:{}", "ab".repeat(31)), format!("entrée n°1 ({}) : empreinte illisible (SHA-256 en hex de 64 caractères attendue)", ae_court(AE_OLD))),
            (format!("{o}:{}", "ab".repeat(33)), format!("entrée n°1 ({}) : empreinte illisible (SHA-256 en hex de 64 caractères attendue)", ae_court(AE_OLD))),
            (format!("{o}:{}", "+0".repeat(32)), format!("entrée n°1 ({}) : empreinte illisible (SHA-256 en hex de 64 caractères attendue)", ae_court(AE_OLD))),
            (format!("{o}:"), format!("entrée n°1 ({}) : empreinte illisible (SHA-256 en hex de 64 caractères attendue)", ae_court(AE_OLD))),
            (format!("{o}:{e}:1-273"), format!("entrée n°1 ({}) : empreinte illisible (SHA-256 en hex de 64 caractères attendue)", ae_court(AE_OLD))),
            (
                format!("{o}:{e};{i}:{e};{o}:{}", "cd".repeat(32)),
                format!("entrée n°3 : la clé antérieure {} est déjà nommée à l'entrée n°1 — une clé n'a qu'une empreinte", ae_court(AE_OLD)),
            ),
            // LA MÊME CLÉ SOUS DEUX ÉCRITURES (hex puis base64, minuscules puis majuscules) : le doublon se juge
            // sur les OCTETS de la clé, jamais sur le texte écrit.
            (
                format!("{o}:{e} {}:{}", ae_b64(AE_OLD), "cd".repeat(32)),
                format!("entrée n°2 : la clé antérieure {} est déjà nommée à l'entrée n°1 — une clé n'a qu'une empreinte", ae_court(AE_OLD)),
            ),
            (
                format!("{o}:{e} {}:{}", o.to_uppercase(), "cd".repeat(32)),
                format!("entrée n°2 : la clé antérieure {} est déjà nommée à l'entrée n°1 — une clé n'a qu'une empreinte", ae_court(AE_OLD)),
            ),
        ];
        for (ecrit, attendu) in &refus {
            assert_eq!(analyser_les_cles_anterieures(ecrit, &pin), Err(attendu.clone()), "« {ecrit} »");
        }
        let b64 = ae_b64(AE_OLD);
        let admis = analyser_les_cles_anterieures(&format!(" {b64}:{} ;\t{i}:{}  ", e.to_uppercase(), "cd".repeat(32)), &pin);
        assert_eq!(
            admis,
            Ok(vec![
                CleAnterieure { cle: ae_pub(AE_OLD), empreinte: [0xab; 32] },
                CleAnterieure { cle: ae_pub(AE_ISO), empreinte: [0xcd; 32] },
            ])
        );
        assert_eq!(analyser_les_cles_anterieures(" ; \t ", &pin), Ok(Vec::new()), "rien que des séparateurs : aucune clé");
    }

    /// (f') LA LECTURE DE L'ANCRE (`ancre_epinglee`, appelée par `verify`, `verify-control` et au démarrage)
    /// sur une CONFIGURATION, l'environnement du processus jamais touché : rien, clés antérieures sans
    /// épingle, épingle illisible, épingle seule, épingle vide ou de blancs, entrée refusée (préfixe du levier).
    #[test]
    fn ae_f_la_lecture_de_l_ancre_refuse_et_nomme() {
        let _env = VERROU_ENV_PROCESSUS.read(); // `cfg` lit l'environnement AVANT la configuration
        for levier in ["PLUME_LEDGER_PUBKEY", "PLUME_LEDGER_PUBKEYS_ANTERIEURES"] {
            if std::env::var_os(levier).is_some() {
                crate::tests::canal_de_refus::refuser_de_conclure(
                    module_path!(),
                    "ae_f_la_lecture_de_l_ancre_refuse_et_nomme",
                    "un levier de l'ancre est posé dans l'environnement du processus : il masquerait la configuration jouée",
                );
                return;
            }
        }
        let conf = |paires: &[(&str, String)]| -> HashMap<String, String> {
            paires.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
        };
        let e = "ab".repeat(32);
        let ant = format!("{}:{e}", ae_hex(AE_OLD));
        assert_eq!(ancre_epinglee(&HashMap::new()), Ok(None), "ni épingle ni clé antérieure : comportement historique");
        assert_eq!(
            ancre_epinglee(&conf(&[("PLUME_LEDGER_PUBKEYS_ANTERIEURES", ant.clone())])),
            Err("ANCRE AMBIGUË : PLUME_LEDGER_PUBKEYS_ANTERIEURES est posé sans clé épinglée (PLUME_LEDGER_PUBKEY) — \
                 des clés antérieures ne nomment rien sans la clé qui vaut pour le reste"
                .to_string())
        );
        assert_eq!(
            ancre_epinglee(&conf(&[("PLUME_LEDGER_PUBKEY", "zz".to_string())])),
            Err("ANCRE AMBIGUË : PLUME_LEDGER_PUBKEY est posée mais illisible (ni hex de 64 caractères ni base64 \
                 de 32 octets) — elle ne vaut pas « aucune épingle »"
                .to_string())
        );
        assert_eq!(
            ancre_epinglee(&conf(&[("PLUME_LEDGER_PUBKEY", ae_hex(AE_PIN))])),
            Ok(Some(AncreEpinglee { cle: ae_pub(AE_PIN), anterieures: Vec::new() }))
        );
        assert_eq!(ancre_epinglee(&conf(&[("PLUME_LEDGER_PUBKEY", " \t ".to_string())])), Ok(None), "épingle de blancs : aucune ancre");
        assert_eq!(
            ancre_epinglee(&conf(&[("PLUME_LEDGER_PUBKEYS_ANTERIEURES", "  \t  ".to_string())])),
            Ok(None),
            "clés antérieures de blancs seuls, sans épingle : aucune ancre"
        );
        assert_eq!(
            ancre_epinglee(&conf(&[("PLUME_LEDGER_PUBKEY", ae_hex(AE_PIN)), ("PLUME_LEDGER_PUBKEYS_ANTERIEURES", "abc".to_string())])),
            Err("ANCRE AMBIGUË (PLUME_LEDGER_PUBKEYS_ANTERIEURES) : entrée n°1 sans « : » (forme attendue : <clé \
                 publique>:<empreinte SHA-256 en hex>)"
                .to_string())
        );
        assert_eq!(
            ancre_epinglee(&conf(&[("PLUME_LEDGER_PUBKEY", ae_hex(AE_PIN)), ("PLUME_LEDGER_PUBKEYS_ANTERIEURES", ant)])),
            Ok(Some(AncreEpinglee {
                cle: ae_pub(AE_PIN),
                anterieures: vec![CleAnterieure { cle: ae_pub(AE_OLD), empreinte: [0xab; 32] }],
            }))
        );
    }

    /// (g) SANS ÉPINGLE : comportement historique, aucune clause, aucun refus nommé.
    #[test]
    fn ae_g_sans_epingle_le_verdict_est_inchange() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ae_base("ae-g", AE_ROTATION);
        let v = verify_ledger_selon(coffre.as_str(), Ok(None)).expect("un verdict est rendu");
        assert_eq!((v.anterieures_relues.clone(), v.refuses.clone()), (None, Vec::new()));
        assert_eq!(
            rendre_le_verdict_du_registre(&v),
            (0, "ledger OK : 6 entrées chaînées intègres ; checkpoints signés OK=6 KO=0".to_string())
        );
        // UNE SIGNATURE FAUSSE SANS ÉPINGLE reste un SIGNALEMENT (sortie 0, KO compté), jamais une accusation :
        // c'est le bras que l'épingle seule fait passer en 1.
        let coffre = ae_base("ae-g-ko", &[(1, AE_PIN, true), (2, AE_PIN, false)]);
        let v = verify_ledger_selon(coffre.as_str(), Ok(None)).expect("un verdict est rendu");
        assert_eq!((v.sig_ko, v.anterieures_relues.clone(), v.refuses.clone()), (1, None, Vec::new()));
        assert_eq!(
            rendre_le_verdict_du_registre(&v),
            (0, "ledger OK : 2 entrées chaînées intègres ; checkpoints signés OK=1 KO=1".to_string())
        );
    }

    /// LA RUPTURE NOMMÉE PASSE D'ABORD, même avec une clé étrangère refusée sous épingle.
    #[test]
    fn ae_la_rupture_passe_avant_le_refus_sous_epingle() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ae_base("ae-rup", &[(1, AE_OLD, true), (2, AE_PIN, true), (3, AE_ETR, true)]);
        let old = ae_empreinte(&coffre, AE_OLD);
        let conn = Connection::open(coffre.as_str()).unwrap();
        let deuxieme: i64 = conn.query_row("SELECT id FROM ledger ORDER BY id LIMIT 1 OFFSET 1", [], |r| r.get(0)).unwrap();
        conn.execute("UPDATE ledger SET detail='falsifie' WHERE id=?1", params![deuxieme]).unwrap();
        drop(conn);
        let v = verify_ledger_selon(coffre.as_str(), Ok(Some(ae_ancre(&[(AE_OLD, old.as_str())])))).expect("la rupture est un verdict");
        assert_eq!((v.rupture, v.sig_ko), (Some(deuxieme), 1), "les deux surviennent ensemble");
        assert_eq!(
            rendre_le_verdict_du_registre(&v),
            (1, format!("INTÉGRITÉ COMPROMISE : rupture de chaîne à l'entrée #{deuxieme} (3 entrées)"))
        );
    }

    /// Falsifie le DEUXIÈME maillon du journal (ce que ferait qui écrit dans la base) et rend son `id`.
    fn ae_falsifier_le_deuxieme_maillon(coffre: &crate::tmp_possede::TmpDb) -> i64 {
        let conn = Connection::open(coffre.as_str()).expect("base fichier ouverte");
        let deuxieme: i64 = conn.query_row("SELECT id FROM ledger ORDER BY id LIMIT 1 OFFSET 1", [], |r| r.get(0)).unwrap();
        conn.execute("UPDATE ledger SET detail='falsifie' WHERE id=?1", params![deuxieme]).unwrap();
        deuxieme
    }

    /// LA RUPTURE NOMMÉE PASSE AVANT UNE ANCRE AMBIGUË (`Err` de la lecture de l'ancre) : la chaîne rompue est
    /// un verdict (1, l'entrée nommée) ; la même ancre ambiguë sur la chaîne INTACTE n'en rend aucun (son refus).
    #[test]
    fn ae_la_rupture_nommee_passe_avant_l_ancre_ambigue() {
        let _env = VERROU_ENV_PROCESSUS.read();
        const REFUS: &str = "ANCRE AMBIGUË : témoin de la rupture";
        let intacte = ae_base("ae-rup-ambigue-intacte", AE_ROTATION);
        assert_eq!(verify_ledger_selon(intacte.as_str(), Err(REFUS.to_string())), Err(REFUS.to_string()));
        let coffre = ae_base("ae-rup-ambigue", AE_ROTATION);
        let deuxieme = ae_falsifier_le_deuxieme_maillon(&coffre);
        let v = verify_ledger_selon(coffre.as_str(), Err(REFUS.to_string())).expect("la rupture est un verdict, malgré l'ancre ambiguë");
        assert_eq!(v.rupture, Some(deuxieme));
        assert_eq!(
            rendre_le_verdict_du_registre(&v),
            (1, format!("INTÉGRITÉ COMPROMISE : rupture de chaîne à l'entrée #{deuxieme} (6 entrées)"))
        );
    }

    /// LA RUPTURE NOMMÉE PASSE AVANT « ANCRE SANS PRÉSENT » : ancres courantes retirées (`DELETE` de 10 et 12),
    /// empreintes concordantes, AUCUNE clé étrangère (rien n'est accusé : le contrôle du présent compterait),
    /// puis un maillon falsifié — la rupture est nommée (1), pas rendue en « aucun verdict ».
    #[test]
    fn ae_la_rupture_passe_avant_le_controle_du_present() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (coffre, old, iso) = ae_rotation("ae-rup-present");
        ae_ecrire(&coffre, "DELETE FROM checkpoint WHERE id IN (10, 12)");
        let deuxieme = ae_falsifier_le_deuxieme_maillon(&coffre);
        let v = verify_ledger_selon(coffre.as_str(), Ok(Some(ae_ancre(&[(AE_OLD, old.as_str()), (AE_ISO, iso.as_str())]))))
            .expect("la rupture est un verdict");
        assert_eq!((v.rupture, v.sig_ko), (Some(deuxieme), 0), "rien d'accusé hors la rupture");
        assert_eq!(
            rendre_le_verdict_du_registre(&v),
            (1, format!("INTÉGRITÉ COMPROMISE : rupture de chaîne à l'entrée #{deuxieme} (6 entrées)"))
        );
    }

    /// LES REFUS NOMMÉS SONT BORNÉS, LE RESTE COMPTÉ, aux deux côtés du bord : cinq étrangers, cinq nommés et
    /// aucune suite ; six, « et 1 autre(s) » ; sept, « et 2 autre(s) ».
    #[test]
    fn ae_les_refus_nommes_sont_bornes_et_le_reste_compte() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let x = ae_court(AE_ETR);
        for (etrangers, suite) in [(5_i64, ""), (6, " et 1 autre(s)"), (7, " et 2 autre(s)")] {
            let mut points: Vec<(i64, u8, bool)> = (1..=etrangers).map(|i| (i * 2, AE_ETR, true)).collect();
            points.push((20, AE_PIN, true));
            let coffre = ae_base(&format!("ae-borne-{etrangers}"), &points);
            assert_eq!(
                ae_juger(&coffre, Some(ae_ancre(&[]))),
                (
                    1,
                    format!(
                        "INTÉGRITÉ COMPROMISE (PIN) : {etrangers} checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=1, \
                         {} entrées) — re-signature possible : #2 ({x}, clé étrangère), #4 ({x}, clé étrangère), #6 ({x}, \
                         clé étrangère), #8 ({x}, clé étrangère), #10 ({x}, clé étrangère){suite}",
                        etrangers + 1
                    )
                ),
                "{etrangers} étrangers"
            );
        }
    }

    /// UNE CLÉ IN-BAND ILLISIBLE est nommée comme telle, par son `id`.
    #[test]
    fn ae_une_cle_in_band_illisible_est_nommee_comme_telle() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ae_base("ae-illisible", &[(1, AE_PIN, true), (4, AE_PIN, true)]);
        ae_ecrire(&coffre, "UPDATE checkpoint SET pubkey='zz' WHERE id=4");
        assert_eq!(
            ae_juger(&coffre, Some(ae_ancre(&[]))),
            (
                1,
                "INTÉGRITÉ COMPROMISE (PIN) : 1 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=1, 2 entrées) \
                 — re-signature possible : #4 (clé illisible, clé in-band illisible)"
                    .to_string()
            )
        );
    }

    // ---- LE POINT D'ENTRÉE `verify_run`, par sous-processus (l'environnement du processus de test n'est jamais touché). ----

    /// `verify` lit l'épingle et les clés antérieures dans l'ENVIRONNEMENT, dit ce que chaque clé a couvert, sort en 0.
    #[test]
    fn ae_verify_dit_chaque_cle_anterieure_et_sort_en_0() {
        const ENFANT: &str = "AE_ENFANT_VERIFY_OK";
        if std::env::var(ENFANT).is_ok() {
            println!(); // la ligne de `verify` commence une ligne (libtest écrit « test … » sans saut sous un seul fil)
            verify_run();
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        let (coffre, old, iso) = ae_rotation("ae-s-ok");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ancre_du_registre_cles_anterieures_par_empreinte::ae_verify_dit_chaque_cle_anterieure_et_sort_en_0",
            ])
            .env(ENFANT, "1")
            .env("PLUME_CONFIG", "/nonexistent")
            .env("PLUME_DB", coffre.as_str())
            .env("PLUME_LEDGER_PUBKEY", ae_hex(AE_PIN))
            .env("PLUME_LEDGER_PUBKEYS_ANTERIEURES", format!("{}:{old};{}:{iso}", ae_hex(AE_OLD), ae_hex(AE_ISO)))
            .env_remove("PLUME_DB_KEY")
            .env_remove("PLUME_DB_KEY_FILE")
            .env_remove("PLUME_DB_KEY_REF")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let attendu = format!(
            "ledger OK : 6 entrées chaînées intègres ; checkpoints signés OK=6 KO=0 ; clés antérieures : {}, {}",
            ae_concordante(AE_OLD, 3, 3, "du #1 au #3"),
            ae_concordante(AE_ISO, 1, 1, "#11")
        );
        assert_eq!(sortie.status.code(), Some(0), "verify sort en 0 : {stdout}");
        assert_eq!(stdout.lines().filter(|l| *l == attendu).count(), 1, "la ligne entière : {stdout}");
    }

    /// `verify` sur une suite ancienne dont une ligne a été retirée : 1, la clé et les `id` réels nommés.
    #[test]
    fn ae_verify_sur_une_empreinte_discordante_sort_en_1() {
        const ENFANT: &str = "AE_ENFANT_VERIFY_KO";
        if std::env::var(ENFANT).is_ok() {
            println!(); // la ligne de `verify` commence une ligne (libtest écrit « test … » sans saut sous un seul fil)
            verify_run();
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        let (coffre, old, iso) = ae_rotation("ae-s-ko");
        ae_ecrire(&coffre, "DELETE FROM checkpoint WHERE id=2");
        let relue = ae_empreinte(&coffre, AE_OLD);
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ancre_du_registre_cles_anterieures_par_empreinte::ae_verify_sur_une_empreinte_discordante_sort_en_1",
            ])
            .env(ENFANT, "1")
            .env("PLUME_CONFIG", "/nonexistent")
            .env("PLUME_DB", coffre.as_str())
            .env("PLUME_LEDGER_PUBKEY", ae_hex(AE_PIN))
            .env("PLUME_LEDGER_PUBKEYS_ANTERIEURES", format!("{}:{old} {}:{iso}", ae_hex(AE_OLD), ae_hex(AE_ISO)))
            .env_remove("PLUME_DB_KEY")
            .env_remove("PLUME_DB_KEY_FILE")
            .env_remove("PLUME_DB_KEY_REF")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let o = ae_court(AE_OLD);
        let attendu = format!(
            "INTÉGRITÉ COMPROMISE (PIN) : 2 checkpoint(s) NON signé(s) par la clé escrow épinglée (OK=3, 6 entrées) \
             — re-signature possible : #1 ({o}, empreinte de la clé antérieure discordante), #3 ({o}, empreinte de \
             la clé antérieure discordante) ; clés antérieures : {}, {}",
            ae_discordante(AE_OLD, 2, "du #1 au #3", &old, &relue),
            ae_concordante(AE_ISO, 1, 1, "#11")
        );
        assert_eq!(sortie.status.code(), Some(1), "verify sort en 1 : {stdout}");
        assert_eq!(stdout.lines().filter(|l| *l == attendu).count(), 1, "la ligne entière : {stdout}");
    }

    /// `verify` sur une ancre malformée (ancienne forme à plages) : 2, aucun verdict, l'entrée nommée.
    #[test]
    fn ae_verify_ancre_malformee_sort_en_2() {
        const ENFANT: &str = "AE_ENFANT_VERIFY_AMBIGUE";
        if std::env::var(ENFANT).is_ok() {
            println!(); // la ligne de `verify` commence une ligne (libtest écrit « test … » sans saut sous un seul fil)
            verify_run();
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        let coffre = ae_base("ae-s-amb", AE_ROTATION);
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ancre_du_registre_cles_anterieures_par_empreinte::ae_verify_ancre_malformee_sort_en_2",
            ])
            .env(ENFANT, "1")
            .env("PLUME_CONFIG", "/nonexistent")
            .env("PLUME_DB", coffre.as_str())
            .env("PLUME_LEDGER_PUBKEY", ae_hex(AE_PIN))
            .env("PLUME_LEDGER_PUBKEYS_ANTERIEURES", format!("{}:1-3", ae_hex(AE_OLD)))
            .env_remove("PLUME_DB_KEY")
            .env_remove("PLUME_DB_KEY_FILE")
            .env_remove("PLUME_DB_KEY_REF")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let attendu = format!(
            "VERDICT IMPOSSIBLE : ANCRE AMBIGUË (PLUME_LEDGER_PUBKEYS_ANTERIEURES) : entrée n°1 ({}) : empreinte \
             illisible (SHA-256 en hex de 64 caractères attendue) — aucun verdict n'est rendu sur ce que la vérification \
             n'a pas pu établir",
            ae_court(AE_OLD)
        );
        assert_eq!(sortie.status.code(), Some(2), "verify sort en 2 : {stdout}");
        assert_eq!(stdout.lines().filter(|l| *l == attendu).count(), 1, "la ligne entière : {stdout}");
    }

    /// `verify` quand les ancres courantes ont été retirées : 2, aucun verdict, la cause dite.
    #[test]
    fn ae_verify_sans_present_sort_en_2() {
        const ENFANT: &str = "AE_ENFANT_VERIFY_PRESENT";
        if std::env::var(ENFANT).is_ok() {
            println!(); // la ligne de `verify` commence une ligne (libtest écrit « test … » sans saut sous un seul fil)
            verify_run();
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        let (coffre, old, iso) = ae_rotation("ae-s-present");
        ae_ecrire(&coffre, "DELETE FROM checkpoint WHERE id IN (10, 12)");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ancre_du_registre_cles_anterieures_par_empreinte::ae_verify_sans_present_sort_en_2",
            ])
            .env(ENFANT, "1")
            .env("PLUME_CONFIG", "/nonexistent")
            .env("PLUME_DB", coffre.as_str())
            .env("PLUME_LEDGER_PUBKEY", ae_hex(AE_PIN))
            .env("PLUME_LEDGER_PUBKEYS_ANTERIEURES", format!("{}:{old};{}:{iso}", ae_hex(AE_OLD), ae_hex(AE_ISO)))
            .env_remove("PLUME_DB_KEY")
            .env_remove("PLUME_DB_KEY_FILE")
            .env_remove("PLUME_DB_KEY_REF")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let attendu = format!(
            "VERDICT IMPOSSIBLE : ANCRE SANS PRÉSENT (PLUME_LEDGER_PUBKEYS_ANTERIEURES) : le dernier checkpoint (#11) est \
             signé par la clé antérieure {} — aucun checkpoint de la clé épinglée ne vient après ceux des clés antérieures \
             (ancres courantes retirées, ou clé épinglée qui n'a encore rien signé) — aucun verdict n'est rendu sur ce \
             que la vérification n'a pas pu établir",
            ae_court(AE_ISO)
        );
        assert_eq!(sortie.status.code(), Some(2), "verify sort en 2 : {stdout}");
        assert_eq!(stdout.lines().filter(|l| *l == attendu).count(), 1, "la ligne entière : {stdout}");
    }

    /// `verify` lit les clés antérieures dans le FICHIER DE CONFIGURATION (hôte natif, `soc.conf`) : 0.
    #[test]
    fn ae_verify_lit_les_cles_anterieures_dans_la_configuration() {
        const ENFANT: &str = "AE_ENFANT_VERIFY_CONF";
        if std::env::var(ENFANT).is_ok() {
            println!(); // la ligne de `verify` commence une ligne (libtest écrit « test … » sans saut sous un seul fil)
            verify_run();
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        let (coffre, old, iso) = ae_rotation("ae-s-conf");
        let dossier = crate::tmp_possede::TmpPossede::neuf("ae-s-conf-fichier");
        let conf = dossier.sous("soc.conf");
        std::fs::write(
            conf.as_str(),
            format!(
                "PLUME_LEDGER_PUBKEY={}\nPLUME_LEDGER_PUBKEYS_ANTERIEURES={}:{old};{}:{iso}\n",
                ae_hex(AE_PIN),
                ae_hex(AE_OLD),
                ae_hex(AE_ISO)
            ),
        )
        .expect("configuration écrite");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ancre_du_registre_cles_anterieures_par_empreinte::ae_verify_lit_les_cles_anterieures_dans_la_configuration",
            ])
            .env(ENFANT, "1")
            .env("PLUME_CONFIG", conf.as_str())
            .env("PLUME_DB", coffre.as_str())
            .env_remove("PLUME_LEDGER_PUBKEY")
            .env_remove("PLUME_LEDGER_PUBKEYS_ANTERIEURES")
            .env_remove("PLUME_DB_KEY")
            .env_remove("PLUME_DB_KEY_FILE")
            .env_remove("PLUME_DB_KEY_REF")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let attendu = format!(
            "ledger OK : 6 entrées chaînées intègres ; checkpoints signés OK=6 KO=0 ; clés antérieures : {}, {}",
            ae_concordante(AE_OLD, 3, 3, "du #1 au #3"),
            ae_concordante(AE_ISO, 1, 1, "#11")
        );
        assert_eq!(sortie.status.code(), Some(0), "verify sort en 0 : {stdout}");
        assert_eq!(stdout.lines().filter(|l| *l == attendu).count(), 1, "la ligne entière : {stdout}");
    }

    /// L'ÉPINGLE SE LIT À LA MÊME SOURCE PAR TOUS SES LECTEURS, sous-processus seulement : posée dans le
    /// fichier de configuration, `ledger_pinned_pubkey` (conversion au repos, `verify-control`) et
    /// `ancre_epinglee` la voient ; vide dans l'environnement, ni l'un ni l'autre ne pose d'ancre ; illisible
    /// dans le fichier, `ledger_pinned_pubkey` rend `None` et `ancre_epinglee` la refuse.
    #[test]
    fn ae_l_epingle_se_lit_a_une_seule_source() {
        const ENFANT: &str = "AE_ENFANT_SOURCE";
        if std::env::var(ENFANT).is_ok() {
            println!();
            println!("{:?}", (ledger_pinned_pubkey(), ancre_epinglee(&load_config())));
            return;
        }
        let _env = VERROU_ENV_PROCESSUS.read();
        let dossier = crate::tmp_possede::TmpPossede::neuf("ae-source-unique");
        let lisible = dossier.sous("lisible.conf");
        std::fs::write(lisible.as_str(), format!("PLUME_LEDGER_PUBKEY={}\n", ae_hex(AE_PIN))).expect("configuration écrite");
        let illisible = dossier.sous("illisible.conf");
        std::fs::write(illisible.as_str(), "PLUME_LEDGER_PUBKEY=zz\n").expect("configuration écrite");
        const NOM: &str = "tests::ancre_du_registre_cles_anterieures_par_empreinte::ae_l_epingle_se_lit_a_une_seule_source";
        let du_fichier = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", NOM])
            .env(ENFANT, "1")
            .env("PLUME_CONFIG", lisible.as_str())
            .env_remove("PLUME_LEDGER_PUBKEY")
            .env_remove("PLUME_LEDGER_PUBKEYS_ANTERIEURES")
            .output()
            .expect("ré-exécution du binaire de test");
        let vide = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", NOM])
            .env(ENFANT, "1")
            .env("PLUME_CONFIG", lisible.as_str())
            .env("PLUME_LEDGER_PUBKEY", "")
            .env_remove("PLUME_LEDGER_PUBKEYS_ANTERIEURES")
            .output()
            .expect("ré-exécution du binaire de test");
        let mauvaise = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", NOM])
            .env(ENFANT, "1")
            .env("PLUME_CONFIG", illisible.as_str())
            .env_remove("PLUME_LEDGER_PUBKEY")
            .env_remove("PLUME_LEDGER_PUBKEYS_ANTERIEURES")
            .output()
            .expect("ré-exécution du binaire de test");
        let ligne = |attendu: String, sortie: &std::process::Output| {
            let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
            assert_eq!(stdout.lines().filter(|l| *l == attendu).count(), 1, "{attendu} dans : {stdout}");
        };
        let rien: (Option<[u8; 32]>, Result<Option<AncreEpinglee>, String>) = (None, Ok(None));
        ligne(
            format!("{:?}", (Some(ae_pub(AE_PIN)), Ok::<_, String>(Some(AncreEpinglee { cle: ae_pub(AE_PIN), anterieures: Vec::new() })))),
            &du_fichier,
        );
        // Vide dans l'environnement : `cfg` prend la valeur de l'environnement (vide), pas celle du fichier.
        ligne(format!("{rien:?}"), &vide);
        ligne(
            format!(
                "{:?}",
                (
                    None::<[u8; 32]>,
                    Err::<Option<AncreEpinglee>, String>(
                        "ANCRE AMBIGUË : PLUME_LEDGER_PUBKEY est posée mais illisible (ni hex de 64 caractères ni base64 \
                         de 32 octets) — elle ne vaut pas « aucune épingle »"
                            .to_string()
                    )
                )
            ),
            &mauvaise,
        );
    }

    // ---- LES DEUX GARDES RELUES DANS `main`, et la vérification unique du cœur. ----

    /// Le bloc EXACT que `main` doit porter avant `tokio::runtime::Builder::new_multi_thread()`.
    const AE_BLOC_DU_DEMARRAGE: &str = "    if let Err(refus) = ledger::ancre_epinglee(&load_config()) {
        eprintln!(\"[FATAL] {refus} — refus de démarrer (fail-closed)\");
        std::process::exit(78);
    }
    tokio::runtime::Builder::new_multi_thread()";

    /// L'ouverture du dispatch des sous-commandes dans `main` ; sa fin est le premier `}` en retrait de quatre qui suit.
    const AE_DEBUT_DU_DISPATCH: &str = "\n    if premier_argument != ARGUMENT_ABSENT_LE_SERVEUR {\n";

    /// L'instrument : dans le corps de `fn main()` (jusqu'à la fin du fichier ou au `fn` suivant en colonne 0),
    /// le bloc exact apparaît UNE fois, après la dernière sortie des sous-commandes inconnues ; entre la fin du
    /// dispatch et la garde il n'y a que des commentaires ou des lignes vides ; et le runtime n'est lancé
    /// (`block_on(`) qu'UNE fois, après la garde.
    fn ae_la_garde_du_demarrage(src: &str) -> Result<(), String> {
        let debut = src.find("\nfn main() {").ok_or("fn main() introuvable")?;
        let corps = &src[debut + 1..];
        let fin = corps[1..].find("\nfn ").map(|i| i + 1).unwrap_or(corps.len());
        let corps = &corps[..fin];
        let occurrences: Vec<usize> = corps.match_indices(AE_BLOC_DU_DEMARRAGE).map(|(i, _)| i).collect();
        if occurrences.len() != 1 {
            return Err(format!("bloc de garde trouvé {} fois dans main", occurrences.len()));
        }
        let inconnu = corps.rfind("AUCUN serveur n'a été lancé").ok_or("sortie des arguments inconnus introuvable")?;
        if occurrences[0] < inconnu {
            return Err("bloc de garde placé avant la fin du dispatch des sous-commandes".into());
        }
        let dispatch = corps.find(AE_DEBUT_DU_DISPATCH).ok_or("dispatch des sous-commandes introuvable")?;
        let apres = dispatch + AE_DEBUT_DU_DISPATCH.len();
        let fin_du_dispatch = corps[apres..]
            .find("\n    }\n")
            .map(|i| apres + i + "\n    }\n".len())
            .ok_or("fin du dispatch des sous-commandes introuvable")?;
        if fin_du_dispatch > occurrences[0] {
            return Err("bloc de garde placé avant la fin du dispatch des sous-commandes".into());
        }
        if let Some(ligne) = corps[fin_du_dispatch..occurrences[0]]
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("//"))
        {
            return Err(format!("code entre la fin du dispatch et la garde : « {ligne} »"));
        }
        let lancements: Vec<usize> = corps.match_indices("block_on(").map(|(i, _)| i).collect();
        if lancements.len() != 1 || lancements[0] < occurrences[0] {
            return Err(format!("le runtime est lancé {} fois dans main, dont avant la garde", lancements.len()));
        }
        Ok(())
    }

    #[test]
    fn ae_le_serveur_ne_demarre_pas_sur_une_ancre_ambigue() {
        let src = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
            .expect("main.rs lisible");
        assert_eq!(ae_la_garde_du_demarrage(&src), Ok(()), "main porte la garde avant le lancement du serveur");
        // L'INSTRUMENT ÉPROUVÉ SUR DES CORPUS FABRIQUÉS : garde retirée, code de sortie changé, garde placée
        // avant le dispatch, garde doublée -> refusé.
        let sans = src.replacen(AE_BLOC_DU_DEMARRAGE, "    tokio::runtime::Builder::new_multi_thread()", 1);
        assert_eq!(ae_la_garde_du_demarrage(&sans), Err("bloc de garde trouvé 0 fois dans main".to_string()));
        let autre_code = src.replacen("std::process::exit(78);\n    }\n    tokio::", "std::process::exit(1);\n    }\n    tokio::", 1);
        assert_eq!(ae_la_garde_du_demarrage(&autre_code), Err("bloc de garde trouvé 0 fois dans main".to_string()));
        let fabrique = format!(
            "\nfn main() {{\n{AE_BLOC_DU_DEMARRAGE}\n        .block_on(run());{AE_DEBUT_DU_DISPATCH}        eprintln!(\"AUCUN serveur n'a été lancé\");\n    }}\n}}\nfn suite() {{}}\n"
        );
        assert_eq!(
            ae_la_garde_du_demarrage(&fabrique),
            Err("bloc de garde placé avant la fin du dispatch des sous-commandes".to_string())
        );
        let double = format!(
            "\nfn main() {{{AE_DEBUT_DU_DISPATCH}        eprintln!(\"AUCUN serveur n'a été lancé\");\n    }}\n{AE_BLOC_DU_DEMARRAGE}\n{AE_BLOC_DU_DEMARRAGE}\n        .block_on(run());\n}}\n"
        );
        assert_eq!(ae_la_garde_du_demarrage(&double), Err("bloc de garde trouvé 2 fois dans main".to_string()));
        let nominal = format!(
            "\nfn main() {{{AE_DEBUT_DU_DISPATCH}        eprintln!(\"AUCUN serveur n'a été lancé\");\n        std::process::exit(2);\n    }}\n    // une note\n\n{AE_BLOC_DU_DEMARRAGE}\n        .block_on(run());\n}}\n"
        );
        assert_eq!(ae_la_garde_du_demarrage(&nominal), Ok(()));
        const LANCEMENT: &str = "tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(run());";
        let insere = src.replacen(AE_BLOC_DU_DEMARRAGE, &format!("    {LANCEMENT}\n    return;\n{AE_BLOC_DU_DEMARRAGE}"), 1);
        assert_eq!(ae_la_garde_du_demarrage(&insere), Err(format!("code entre la fin du dispatch et la garde : « {LANCEMENT} »")));
        let retour = src.replacen(AE_BLOC_DU_DEMARRAGE, &format!("    return;\n{AE_BLOC_DU_DEMARRAGE}"), 1);
        assert_eq!(ae_la_garde_du_demarrage(&retour), Err("code entre la fin du dispatch et la garde : « return; »".to_string()));
        let avant = src.replacen("\nfn main() {\n", &format!("\nfn main() {{\n    {LANCEMENT}\n"), 1);
        assert_eq!(
            ae_la_garde_du_demarrage(&avant),
            Err("le runtime est lancé 2 fois dans main, dont avant la garde".to_string())
        );
    }

    /// Le bloc EXACT que `main` porte avant le bras de `verify-control` (le bras lui-même est épinglé à l'octet
    /// par `jcah_le_bras_de_main_delegue`).
    const AE_BLOC_DE_VERIFY_CONTROL: &str = "    if args.get(1).is_some_and(|a| a == \"verify-control\") {
        if let Err(refus) = crate::ledger::ancre_epinglee(&load_config()) {
            println!(\"VERDICT IMPOSSIBLE : {refus} — aucun verdict d'ancrage n'est rendu\");
            std::process::exit(2);
        }
    }
";
    const AE_BRAS_DE_VERIFY_CONTROL: &str = "    if args.get(1).map(String::as_str) == Some(\"verify-control\") {\n";

    /// Le bras de `verify`, que le bloc suit immédiatement.
    const AE_BRAS_DE_VERIFY: &str =
        "    if args.get(1).map(String::as_str) == Some(\"verify\") {\n        verify_run();\n        return;\n    }\n";

    /// L'instrument : le bloc apparaît UNE fois dans `main.rs`, AVANT le bras de `verify-control`, et entre les
    /// deux il n'y a que des commentaires ou des lignes vides (un `return`, un autre bras ou la fin de `main`
    /// y feraient sauter le refus). TOUTE LA ZONE QUI LE PRÉCÈDE est jugée aussi : depuis l'ouverture de
    /// `fn main()`, aucune mention de `"verify-control"` (un bras placé avant le bloc le contournerait), et le
    /// bloc suit le bras de `verify` sans autre code que des commentaires ou des lignes vides.
    fn ae_verify_control_juge_l_ancre(src: &str) -> Result<(), String> {
        let occurrences: Vec<usize> = src.match_indices(AE_BLOC_DE_VERIFY_CONTROL).map(|(i, _)| i).collect();
        if occurrences.len() != 1 {
            return Err(format!("bloc de l'ancre de verify-control trouvé {} fois", occurrences.len()));
        }
        let fin = occurrences[0] + AE_BLOC_DE_VERIFY_CONTROL.len();
        let bras = src.find(AE_BRAS_DE_VERIFY_CONTROL).ok_or("bras de verify-control introuvable")?;
        if bras < fin {
            return Err("bloc de l'ancre placé après le bras de verify-control".into());
        }
        let main = src.find("\nfn main() {").ok_or("fn main() introuvable")?;
        if main > occurrences[0] {
            return Err("bloc de l'ancre placé hors de fn main()".into());
        }
        if src[main..occurrences[0]].contains("\"verify-control\"") {
            return Err("verify-control est traité dans main avant le bloc de l'ancre".into());
        }
        let verify = src[main..occurrences[0]]
            .rfind(AE_BRAS_DE_VERIFY)
            .map(|i| main + i + AE_BRAS_DE_VERIFY.len())
            .ok_or("bras de verify introuvable avant le bloc de l'ancre")?;
        if let Some(ligne) = src[verify..occurrences[0]].lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with("//")) {
            return Err(format!("code entre le bras de verify et le bloc de l'ancre : « {ligne} »"));
        }
        if let Some(ligne) = src[fin..bras].lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with("//")) {
            return Err(format!("code entre le bloc de l'ancre et le bras de verify-control : « {ligne} »"));
        }
        Ok(())
    }

    #[test]
    fn ae_verify_control_refuse_de_conclure_sur_une_ancre_ambigue() {
        let src = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
            .expect("main.rs lisible");
        assert_eq!(ae_verify_control_juge_l_ancre(&src), Ok(()), "main juge l'ancre avant le bras de verify-control");
        let sans = src.replacen(AE_BLOC_DE_VERIFY_CONTROL, "", 1);
        assert_eq!(ae_verify_control_juge_l_ancre(&sans), Err("bloc de l'ancre de verify-control trouvé 0 fois".to_string()));
        let autre_code = src.replacen(
            "aucun verdict d'ancrage n'est rendu\");\n            std::process::exit(2);",
            "aucun verdict d'ancrage n'est rendu\");\n            std::process::exit(0);",
            1,
        );
        assert_eq!(ae_verify_control_juge_l_ancre(&autre_code), Err("bloc de l'ancre de verify-control trouvé 0 fois".to_string()));
        let double = src.replacen(AE_BLOC_DE_VERIFY_CONTROL, &format!("{AE_BLOC_DE_VERIFY_CONTROL}{AE_BLOC_DE_VERIFY_CONTROL}"), 1);
        assert_eq!(ae_verify_control_juge_l_ancre(&double), Err("bloc de l'ancre de verify-control trouvé 2 fois".to_string()));
        let apres = src
            .replacen(AE_BLOC_DE_VERIFY_CONTROL, "", 1)
            .replacen(AE_BRAS_DE_VERIFY_CONTROL, &format!("{AE_BRAS_DE_VERIFY_CONTROL}{AE_BLOC_DE_VERIFY_CONTROL}"), 1);
        assert_eq!(ae_verify_control_juge_l_ancre(&apres), Err("bloc de l'ancre placé après le bras de verify-control".to_string()));
        let entre = src.replacen(AE_BRAS_DE_VERIFY_CONTROL, &format!("    return;\n{AE_BRAS_DE_VERIFY_CONTROL}"), 1);
        assert_eq!(
            ae_verify_control_juge_l_ancre(&entre),
            Err("code entre le bloc de l'ancre et le bras de verify-control : « return; »".to_string())
        );
        // UN BRAS DE `verify-control` PLACÉ AVANT LE BLOC (juste après le bras de `verify`, ou plus haut dans
        // `main`) le contourne : refusé, quelle que soit sa place.
        const CONTOURNEMENT: &str = "    if args.get(1).is_some_and(|a| a == \"verify-control\") { std::process::exit(0); }\n";
        let juste_avant = src.replacen(AE_BRAS_DE_VERIFY, &format!("{AE_BRAS_DE_VERIFY}{CONTOURNEMENT}"), 1);
        assert_eq!(
            ae_verify_control_juge_l_ancre(&juste_avant),
            Err("verify-control est traité dans main avant le bloc de l'ancre".to_string())
        );
        let plus_haut = src.replacen(AE_BRAS_DE_VERIFY, &format!("{CONTOURNEMENT}{AE_BRAS_DE_VERIFY}"), 1);
        assert_eq!(
            ae_verify_control_juge_l_ancre(&plus_haut),
            Err("verify-control est traité dans main avant le bloc de l'ancre".to_string())
        );
        let sortie = src.replacen(AE_BRAS_DE_VERIFY, &format!("{AE_BRAS_DE_VERIFY}    std::process::exit(0);\n"), 1);
        assert_eq!(
            ae_verify_control_juge_l_ancre(&sortie),
            Err("code entre le bras de verify et le bloc de l'ancre : « std::process::exit(0); »".to_string())
        );
    }

    /// La ligne qui porte l'UNIQUE vérification Ed25519 du cœur : `Option::filter` ne l'évalue que si les tests
    /// bon marché (le `match` qui la précède) ont retenu une clé.
    const AE_VERIFICATION_UNIQUE: &str = "let admise_sous = sous.filter(|k| signature_valide_sous(k, lh, sig));";

    /// L'instrument : dans le corps de `verify_ledger_conn_ancre`, une seule vérification de signature écrite
    /// (`signature_valide_sous(` une fois, aucun `.verify(`), sur la ligne `AE_VERIFICATION_UNIQUE`, après le tri.
    fn ae_une_seule_verification_par_checkpoint(src: &str) -> Result<(), String> {
        let debut = src.find("pub(crate) fn verify_ledger_conn_ancre(").ok_or("cœur introuvable")?;
        let corps = &src[debut..];
        let corps = &corps[..corps.find("\n}\n").ok_or("fin du cœur introuvable")?];
        let n = corps.matches("signature_valide_sous(").count() + corps.matches(".verify(").count();
        if n != 1 {
            return Err(format!("{n} vérification(s) de signature écrites dans le cœur"));
        }
        let ligne = corps.find(AE_VERIFICATION_UNIQUE).ok_or("la vérification n'est pas gardée par le tri bon marché")?;
        let tri = corps.find("let (sous, cause, anterieure)").ok_or("tri bon marché introuvable")?;
        if tri > ligne {
            return Err("vérification placée avant le tri bon marché".into());
        }
        Ok(())
    }

    #[test]
    fn ae_une_seule_verification_ed25519_par_checkpoint_apres_le_tri() {
        let src = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ledger.rs"))
            .expect("ledger.rs lisible");
        assert_eq!(ae_une_seule_verification_par_checkpoint(&src), Ok(()));
        let double = src.replacen(
            AE_VERIFICATION_UNIQUE,
            &format!("let _ = signature_valide_sous(&a_cle, lh, sig);\n        {AE_VERIFICATION_UNIQUE}"),
            1,
        );
        assert_eq!(ae_une_seule_verification_par_checkpoint(&double), Err("2 vérification(s) de signature écrites dans le cœur".to_string()));
        let directe = src.replacen(AE_VERIFICATION_UNIQUE, "let admise_sous = Some(k).filter(|_| vk.verify(m, s).is_ok());", 1);
        assert_eq!(ae_une_seule_verification_par_checkpoint(&directe), Err("la vérification n'est pas gardée par le tri bon marché".to_string()));
        let sans_filtre = src.replacen(AE_VERIFICATION_UNIQUE, "let admise_sous = signature_valide_sous(&k, lh, sig).then_some(k);", 1);
        assert_eq!(ae_une_seule_verification_par_checkpoint(&sans_filtre), Err("la vérification n'est pas gardée par le tri bon marché".to_string()));
        let avant = src
            .replacen(AE_VERIFICATION_UNIQUE, "", 1)
            .replacen("let (sous, cause, anterieure)", &format!("{AE_VERIFICATION_UNIQUE}\n        let (sous, cause, anterieure)"), 1);
        assert_eq!(ae_une_seule_verification_par_checkpoint(&avant), Err("vérification placée avant le tri bon marché".to_string()));
    }
}
