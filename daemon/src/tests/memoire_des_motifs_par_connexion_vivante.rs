// =====================================================================================
// `P10.32-q` — LA FORMULE DE MÉMOIRE DES MOTIFS MULTIPLIE PAR LES CONNEXIONS DE LECTURE VIVANTES.
//
// LE TEXTE FAUX, LU SUR 50aab3e6 : l'en-tête de `regex_de_requete.rs` donnait la mémoire au pire cas « par connexion de
// lecture » (`2 × MOTIFS_EN_CACHE` motifs) sans la multiplier par le nombre de connexions vivantes, alors que les deux
// caches de motifs sont posés sur la CONNEXION par `install_query_udfs` et la suivent au pool. Le nombre de connexions
// vivantes n'est pas `READ_POOL_CAP` : ce plafond ne borne que les connexions AU REPOS, une prise sur pool vide ouvre.
//
// CE QU'IL TIENT, sur une base à lui, dans un SOUS-PROCESSUS (le pool est global au processus et son éviction LRU est
// inter-bases : sous `cargo test`, les autres tests du même processus fermeraient nos connexions au repos) :
//   (1) `READ_POOL_CAP + 1` connexions prises À LA FOIS sur la même base sont toutes servies (le pool ne borne pas les
//       connexions en cours) ;
//   (2) le même motif posé sur chacune compile UNE fois PAR CONNEXION ET PAR UDF (`READ_POOL_CAP + 1` compilations
//       par `regexp`, autant par `re_cap`, comptées à part) : les DEUX caches sont par connexion, pas par processus ni
//       par fil, et distincts l'un de l'autre (le même texte de motif compile une fois dans chacun) ;
//   (3) reposé sur chacune, il ne recompile pas (0 et 0) ;
//   (4) rendues au pool, `READ_POOL_CAP` restent au repos (une fermée) ;
//   (5) reprises, elles servent le motif SANS recompiler (0 et 0) : les caches sont gardés d'une requête à l'autre ;
//   (6) une connexion de plus, ouverte sur pool vide, compile (1 et 1).
// MUTANTS (variable de mutation, posés sous `cfg!(test)` puis retirés avant le commit) : `BB5_CACHE_DU_FIL` (un cache par fil,
// partagé par toutes les connexions, pour `regexp` : (2) vaut 1 pour lui), `BC5_CACHE_RE_CAP_DU_FIL` (le même partage pour
// `re_cap` seul, closure `re_cap` de `query_exec.rs` : (2) vaut 1 pour lui), `BB5_POOL_SANS_REPOS` (`read_conn_put` ferme au lieu de garder :
// (4) vaut 0 et (5) recompile), `BB5_POOL_BORNE_EN_COURS` (la prise refuse d'ouvrir au-delà de `READ_POOL_CAP`
// connexions en cours : (1) échoue).
// CE QU'IL NE TIENT PAS : la taille en octets de chaque part (lue dans la source de la bibliothèque, non mesurée, sauf
// le cache du DFA paresseux, voir `regex_de_requete_bornee.rs`) ; le nombre de lectures en vol en production, que rien
// ne borne dans le pool.
// =====================================================================================
mod memoire_des_motifs_par_connexion_vivante {
    use super::*;

    const BB5_ENFANT: &str = "BB5_ENFANT_MOTIFS_PAR_CONNEXION";
    const BB5_RENDU: &str = "BB5_RENDU ";
    const BB5_MOTIF: &str = "bb5-(?P<n>[0-9]+)-motif";

    /// Pose le motif sur chaque connexion, d'abord par `regexp`, puis par `re_cap` : `[compilations regexp,
    /// compilations re_cap]`, comptées séparément (le compteur du fil voit les deux caches).
    fn bb5_poser_le_motif(conns: &[rusqlite::Connection]) -> [u64; 2] {
        let avant = crate::regex_de_requete::compilations_du_fil();
        for c in conns {
            let correspond: bool = c
                .query_row("SELECT regexp(?1, 'valeur bb5-42-motif')", [BB5_MOTIF], |r| r.get(0))
                .expect("fixture : regexp sur une connexion de lecture");
            assert!(correspond, "fixture : le motif mord");
        }
        let milieu = crate::regex_de_requete::compilations_du_fil();
        for c in conns {
            let capture: Option<String> = c
                .query_row("SELECT re_cap('valeur bb5-42-motif', ?1, 'n')", [BB5_MOTIF], |r| r.get(0))
                .expect("fixture : re_cap sur une connexion de lecture");
            assert_eq!(capture.as_deref(), Some("42"), "fixture : le groupe nommé est capturé");
        }
        [milieu - avant, crate::regex_de_requete::compilations_du_fil() - milieu]
    }

    fn bb5_prendre(chemin: &str, n: usize) -> Vec<rusqlite::Connection> {
        (0..n)
            .map(|i| crate::query_exec::read_conn_get(chemin).unwrap_or_else(|e| panic!("connexion en cours n° {i} refusée : {e}")))
            .collect()
    }

    #[test]
    fn les_motifs_sont_gardes_par_connexion_vivante_au_dela_du_plafond_du_pool() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let cap = crate::query_exec::READ_POOL_CAP;
        if std::env::var(BB5_ENFANT).is_ok() {
            let chemin = crate::tmp_possede::TmpDb::neuf("bb5-motifs");
            {
                let conn = open_db(&chemin).unwrap();
                conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
                assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            }
            let chemin = chemin.as_str().to_string();
            assert_eq!(crate::query_exec::connexions_de_lecture_au_repos(&chemin), 0, "fixture : pool vide pour cette base");
            let vivantes = bb5_prendre(&chemin, cap + 1);
            let premiere = bb5_poser_le_motif(&vivantes);
            let deuxieme = bb5_poser_le_motif(&vivantes);
            for c in vivantes {
                crate::query_exec::read_conn_put(&chemin, c);
            }
            let au_repos = crate::query_exec::connexions_de_lecture_au_repos(&chemin);
            let reprises = bb5_prendre(&chemin, cap);
            let troisieme = bb5_poser_le_motif(&reprises);
            let de_plus = bb5_prendre(&chemin, 1);
            let quatrieme = bb5_poser_le_motif(&de_plus);
            println!("{BB5_RENDU}{}", json!([premiere, deuxieme, au_repos, troisieme, quatrieme]));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::memoire_des_motifs_par_connexion_vivante::les_motifs_sont_gardes_par_connexion_vivante_au_dela_du_plafond_du_pool",
            ])
            .env(BB5_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 : {stdout}\n{stderr}");
        let rendus: Vec<serde_json::Value> = stdout
            .lines()
            .filter_map(|l| l.split_once(BB5_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("ligne de rendu lisible ({e}) : {v}")))
            .collect();
        let cap = cap as u64;
        assert_eq!(
            rendus,
            vec![json!([[cap + 1, cap + 1], [0, 0], cap, [0, 0], [1, 1]])],
            "[[regexp, re_cap] sur CAP+1 vivantes, re-posé, au repos après rendu, reprises, une de plus] : {stdout}\n{stderr}"
        );
    }
}
