// P8.7-b — LA CLÉ SQLCIPHER SE LIT PAR UNE SEULE VOIE, ET ON LE PROUVE SUR LES OCTETS
// ================================================================================================
// LE DÉFAUT, DANS SA FORME LA PLUS COÛTEUSE. `PLUME_DB_KEY` était la SEULE clé lue par les DEUX voies
// de configuration, et elles ne s'accordaient pas : `crypto::db_key()` — celle qui OUVRE la base
// chaude — la lisait dans l'environnement SEUL, `cold_store::crypto` la lisait par `cfg()`, donc
// AUSSI dans `/etc/plume/soc.conf`. Sur un hôte systemd (`PLUME_CONFIG=/etc/plume/soc.conf`, AUCUN
// `EnvironmentFile` — délibérément, pour ne pas exporter la clé dans `/proc/<pid>/environ`), une clé
// écrite dans le fichier chiffrait donc le tier FROID et laissait la base CHAUDE en clair.
//
// REPRODUIT PAR EXÉCUTION LE 2026-08-09, hors-processus, binaire `38a23da --features cold_tier`,
// environnement VIDE hormis `PLUME_CONFIG` : `cold/prod/2026-07-30-0000.parquet` commence par
// `age-encryption.org/v1` (chiffré — déchiffré hors-processus avec HKDF(clé de `soc.conf`) -> `PAR1`)
// pendant que `db/plume.db` commence par `53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00`
// (`SQLite format 3\0`, EN CLAIR : `sqlite3` nu y relit les messages d'événement). Sortie du
// processus : « rétention OK ». Rien d'autre.
//
// CE QUE CES TESTS GARDENT. Le premier est le seul qui compte vraiment : il rejoue le cas sur une
// VRAIE base, à travers la VRAIE fonction de démarrage, et regarde les OCTETS — avec son témoin
// négatif (la même base, la même fonction, la clé RETIRÉE du fichier -> l'en-tête SQLite reste). Les
// suivants verrouillent la précédence (l'environnement gagne toujours -> Docker/k3s inchangés) et
// l'annonce (une bascule ne se découvre pas par un échec).

// AUCUN VERROU D'ENVIRONNEMENT ICI, ET C'EST UNE CORRECTION PAYÉE PAR UNE MESURE. La première version
// de ce fichier posait `PLUME_CONFIG` sur un `soc.conf` de test, sous un verrou local. La suite
// COMPLÈTE (`cargo test --offline --locked`, 180 s) a rendu ROUGE deux tests d'incidents sans rapport
// — `p3a_advanced_rule_captures_src_ip_and_wizard_prefills_ban_ip` et
// `p3a_ambiguous_groupby_leaves_structured_null` — sur `file is not a database` : un `PRAGMA key`
// appliqué à LEUR base en clair, parce que `db_key()` lit la configuration AMBIANTE et voyait celle du
// test voisin. Un verrou local ne pouvait pas fermer ça : le partage n'est pas entre les tests qui
// mutent, il est entre CELUI qui mute et TOUS ceux qui ouvrent une base. La réponse n'est donc pas un
// verrou plus large, c'est de retirer la lecture ambiante du chemin mesuré : `ensure_encrypted` prend
// désormais la `conf` que son appelant tient déjà. Ces tests n'écrivent plus AUCUN état de processus.

/// L'en-tête d'un fichier SQLite NON chiffré. SQLCipher chiffre la page 1 en entier, en-tête compris :
/// sa présence est donc la preuve DIRECTE, sur le disque, que la base est en clair.
const ENTETE_SQLITE_EN_CLAIR: &[u8; 16] = b"SQLite format 3\0";

/// Les 16 premiers octets du fichier — LA valeur dont ces tests mesurent le changement.
fn tete(chemin: &std::path::Path) -> Vec<u8> {
    let mut f = std::fs::File::open(chemin).expect("ouverture du fichier de base");
    let mut buf = [0u8; 16];
    std::io::Read::read_exact(&mut f, &mut buf).expect("lecture des 16 premiers octets");
    buf.to_vec()
}

/// Fabrique une base SQLite EN CLAIR non triviale (une table, une ligne) à `chemin`.
fn base_en_clair(chemin: &std::path::Path) {
    let c = Connection::open(chemin).expect("création de la base en clair");
    c.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES('valeur-en-clair-p87b');")
        .expect("écriture dans la base en clair");
}

/// ① LE CAS DANGEREUX, SUR LES OCTETS, AVEC SON TÉMOIN. Une clé présente dans le fichier de
/// configuration SEUL doit désormais chiffrer la base chaude ; la MÊME base, la MÊME fonction, sans
/// cette ligne dans le fichier, doit rester EN CLAIR. Deux verdicts opposés produits par UNE SEULE
/// mutation (la ligne `PLUME_DB_KEY` de la carte de configuration) : c'est ce qui distingue une mesure
/// d'une croyance. La carte est INJECTÉE — aucun état de processus n'est touché.
#[test]
fn p87b_une_cle_du_fichier_seul_chiffre_desormais_la_base_chaude() {
    assert!(
        std::env::var("PLUME_DB_KEY").map(|v| v.is_empty()).unwrap_or(true)
            && std::env::var("PLUME_DB_KEY_FILE").map(|v| v.is_empty()).unwrap_or(true),
        "ce test EXIGE un environnement muet sur la clé : il mesure ce que le FICHIER apporte, et \
         l'environnement gagne sur le fichier (c'est précisément l'invariant Docker/k3s)"
    );
    let _tmpg = crate::tmp_possede::TmpPossede::neuf("p87b-at-rest");
    let dir = _tmpg.racine().chemin().to_path_buf();
    let dir = dir.as_path();

    // (a) TÉMOIN NÉGATIF — configuration SANS clé : la base reste en clair.
    let temoin = dir.join("temoin.db");
    base_en_clair(&temoin);
    ensure_encrypted(&conf_at_rest(&[]), &temoin.to_string_lossy());
    assert_eq!(
        tete(&temoin),
        ENTETE_SQLITE_EN_CLAIR.to_vec(),
        "sans clé nulle part, la base DOIT rester en clair (rétrocompat : c'est le défaut annoncé)"
    );

    // (b) LE CAS MESURÉ — la MÊME clé, portée par la configuration de FICHIER SEULE.
    let base = dir.join("chaude.db");
    base_en_clair(&base);
    assert_eq!(tete(&base), ENTETE_SQLITE_EN_CLAIR.to_vec(), "état de départ : en clair");
    ensure_encrypted(
        &conf_at_rest(&[("PLUME_DB_KEY", "cle-ecrite-dans-soc-conf-p87b")]),
        &base.to_string_lossy(),
    );

    let apres = tete(&base);
    assert_ne!(
        apres,
        ENTETE_SQLITE_EN_CLAIR.to_vec(),
        "RÉGRESSION P8.7-b : la base chaude porte encore `SQLite format 3\\0` alors qu'une clé est \
         écrite dans le fichier de configuration. C'est l'état MESURÉ le 2026-08-09 : le tier froid \
         chiffrait ses jours-files avec cette clé pendant que les 7 derniers jours — les incidents \
         récents — restaient lisibles par un `sqlite3` nu."
    );
    // …et ce n'est pas « illisible », c'est CHIFFRÉ AVEC CETTE CLÉ : la sonde non destructive le dit.
    assert_eq!(
        probe_db(&base.to_string_lossy(), "cle-ecrite-dans-soc-conf-p87b"),
        DbProbe::OpensWithKey,
        "la base doit s'OUVRIR avec la clé du fichier — sinon on aurait échangé une base en clair \
         contre une base perdue"
    );
    // …et la copie en clair ne traîne pas à côté.
    assert!(
        !dir.join("chaude.db.plaintext.bak").exists(),
        "la copie EN CLAIR de la migration doit être effacée, sinon le chiffrement at-rest est \
         cosmétique"
    );
}

// ① bis — LA MÊME LECTURE POUR LES DEUX MOITIÉS : le test vit dans `cold_store/tests.rs`, le seul
// endroit d'où `cold_base_secret` est visible (`pub(super)`). Ouvrir une porte `pub(crate)` juste
// pour l'observer d'ici affaiblirait la frontière du module pour rien.

// ── ② LA PRÉCÉDENCE, ET DONC LA NON-RÉGRESSION DES CONTENEURS ────────────────────────────────────
// Ces tests sont PURS : l'environnement est INJECTÉ, jamais muté -> sûrs en parallèle.

fn conf_at_rest(paires: &[(&str, &str)]) -> HashMap<String, String> {
    paires.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// Le cas HOST-NATIF : la clé n'est que dans le fichier -> elle change d'effet -> elle est ANNONCÉE.
#[test]
fn p87b_bascule_annoncee_quand_la_cle_vient_du_fichier_seul() {
    let conf = conf_at_rest(&[("PLUME_DB_KEY", "peu-importe-la-valeur")]);
    assert_eq!(bascule_at_rest(&conf, |_| None), Some("PLUME_DB_KEY"));

    let msg = annonce_bascule_at_rest(Some("PLUME_DB_KEY"), DbProbe::Plaintext).expect("annonce due");
    assert!(msg.contains("PLUME_DB_KEY"), "l'annonce doit NOMMER la clé : {msg}");
    assert!(
        msg.contains("RÉÉCRITE"),
        "sur une base EN CLAIR, l'annonce doit dire que le fichier va être réécrit — c'est le seul \
         moyen de ne pas découvrir une réécriture complète par sa durée : {msg}"
    );
    assert!(
        !msg.contains("peu-importe-la-valeur"),
        "la VALEUR de la clé SQLCipher n'a rien à faire dans un journal : {msg}"
    );
}

/// Le cas CONTENEUR (Docker/k3s) : la clé arrive par l'environnement -> RIEN ne change -> SILENCE. Un
/// avertissement à chaque démarrage sur des milliers de pods serait un mensonge et un bruit.
#[test]
fn p87b_aucune_annonce_quand_la_cle_est_deja_dans_l_environnement() {
    let dans_env = |c: &str| (c == "PLUME_DB_KEY").then(|| "cle-du-pod".to_string());
    // Fichier muet (PLUME_CONFIG=/nonexistent) comme en k3s…
    assert_eq!(bascule_at_rest(&conf_at_rest(&[]), dans_env), None);
    // …et fichier qui dit AUTRE CHOSE : l'environnement gagne, donc rien ne change, donc silence.
    assert_eq!(bascule_at_rest(&conf_at_rest(&[("PLUME_DB_KEY", "cle-du-fichier")]), dans_env), None);
    assert_eq!(annonce_bascule_at_rest(None, DbProbe::Plaintext), None, "silence attendu");
}

/// `deploy/k3s.yaml` livre `PLUME_DB_KEY: ""` dans son ConfigMap : une variable PRÉSENTE et VIDE. Elle
/// doit continuer de valoir « aucune clé » — et NEUTRALISER une valeur du fichier, exactement comme
/// `cfg()` le fait pour tous les autres réglages. Sinon une installation k3s par défaut se mettrait à
/// chiffrer (ou pas) selon ce qui traîne dans un `soc.conf`.
#[test]
fn p87b_une_variable_presente_mais_vide_vaut_aucune_cle() {
    let env_vide = |c: &str| (c == "PLUME_DB_KEY").then(String::new);
    assert_eq!(bascule_at_rest(&conf_at_rest(&[]), env_vide), None);
    assert_eq!(bascule_at_rest(&conf_at_rest(&[("PLUME_DB_KEY", "cle-du-fichier")]), env_vide), None);
    assert_eq!(
        db_key_depuis(&conf_at_rest(&[("PLUME_DB_KEY", "")])),
        None,
        "une clé vide dans le fichier ne doit pas produire une base « chiffrée » avec la chaîne vide"
    );
}

/// LA PRÉCÉDENCE ENTRE LES DEUX CLÉS, ET POURQUOI SON BASCULEMENT DOIT ÊTRE DIT. Un
/// `PLUME_DB_KEY_FILE` écrit dans le fichier prend le pas sur un `PLUME_DB_KEY` posé dans
/// l'environnement : ce n'est pas un changement de PROVENANCE, c'est un changement de CLÉ — donc,
/// potentiellement, une base qui ne s'ouvre plus. Il est annoncé, et c'est le fichier de clé qui est
/// nommé.
#[test]
fn p87b_le_fichier_de_cle_prend_le_pas_et_la_bascule_est_dite() {
    let dans_env = |c: &str| (c == "PLUME_DB_KEY").then(|| "cle-du-pod".to_string());
    let conf = conf_at_rest(&[("PLUME_DB_KEY_FILE", "/etc/plume/db.key")]);
    assert_eq!(bascule_at_rest(&conf, dans_env), Some("PLUME_DB_KEY_FILE"));

    let msg = annonce_bascule_at_rest(Some("PLUME_DB_KEY_FILE"), DbProbe::WrongKeyOrCorrupt)
        .expect("annonce due");
    assert!(msg.contains("PLUME_DB_KEY_FILE"));
    assert!(
        msg.contains("REFUSÉ"),
        "quand la base existante ne s'ouvre pas avec la clé qui devient effective, l'annonce doit \
         dire que le démarrage va être refusé : {msg}"
    );
}

/// Le FAIL-CLOSED n'a pas bougé de place : il reste sur la PREMIÈRE branche. On ne peut pas
/// l'exercer ici sans tuer le processus (`exit(78)`) — on verrouille donc ce qu'on peut sans le
/// déclencher : un `PLUME_DB_KEY_FILE` VIDE (ou absent) ne l'arme pas et laisse la passphrase jouer.
#[test]
fn p87b_un_fichier_de_cle_vide_n_arme_pas_le_fail_closed() {
    assert!(
        std::env::var("PLUME_DB_KEY").map(|v| v.is_empty()).unwrap_or(true)
            && std::env::var("PLUME_DB_KEY_FILE").map(|v| v.is_empty()).unwrap_or(true),
        "environnement muet exigé"
    );
    let conf = conf_at_rest(&[("PLUME_DB_KEY_FILE", ""), ("PLUME_DB_KEY", "la-passphrase")]);
    assert_eq!(db_key_depuis(&conf), Some("la-passphrase".to_string()));
}

/// L'ANNONCE PARLE POUR CHAQUE VERDICT DE BASE, sans exception : un `match` incomplet rendrait un
/// message vide sur le cas qu'on n'a pas prévu — c'est-à-dire le silence qu'on vient de fermer.
#[test]
fn p87b_l_annonce_a_quelque_chose_a_dire_de_chaque_etat_de_base() {
    for v in [
        DbProbe::Fresh,
        DbProbe::OpensWithKey,
        DbProbe::Plaintext,
        DbProbe::WrongKeyOrCorrupt,
        DbProbe::Unopenable,
        DbProbe::Locked,
    ] {
        let msg = annonce_bascule_at_rest(Some("PLUME_DB_KEY"), v).expect("annonce due");
        assert!(msg.contains("PLUME_DB_KEY"), "{v:?} : la clé doit être nommée");
        assert!(
            msg.contains("\n  - ") && msg.split("\n  - ").nth(1).is_some_and(|l| l.len() > 40),
            "{v:?} : l'annonce doit dire ce qui arrive à la base EXISTANTE, pas seulement que la clé \
             change d'effet : {msg}"
        );
    }
}
