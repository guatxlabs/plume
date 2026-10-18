// =====================================================================================
// `P10.32-q` — LE MOTIF REGEX D'UNE REQUÊTE A UN COÛT BORNÉ (chemin chaud : UDF `regexp` et `re_cap`).
//
// LE DÉFAUT, LU SUR ccfa0875 AVANT LE CORRECTIF. `install_query_udfs` (`query_exec.rs`) compilait par
// `regex::Regex::new` (limites par défaut de la bibliothèque, dix fois celles de `parsers.rs`), gardait UN seul
// motif par UDF (deux expressions alternées recompilaient à chaque ligne) et servait `r.clone()` à chaque
// ligne — clone qui ne recompile pas mais repart d'un `Pool` neuf, donc d'un cache de DFA paresseux vide.
// Le plafond de 512 octets existait déjà au chaud (la cellule disait « aucune limite de taille » : faux pour
// la longueur, vrai pour le programme).
//
// LE CORRECTIF. `crate::regex_de_requete` : `compiler_motif` (plafond de longueur + `RegexBuilder` à
// `size_limit`/`dfa_size_limit` explicites), `CacheDeMotifs` à `MOTIFS_EN_CACHE` motifs qui PRÊTE un
// `MotifCompile` sans `Clone`. Les deux UDF passent par lui ; messages d'erreur inchangés. Le tier froid
// (`cold_store/planner.rs`) passe par le même constructeur : témoins dans `cold_store/planner/regex_du_froid_bornee.rs`.
//
// MUTANTS (variable de mutation, retirés avant le commit) : `S4_CACHE_UN` (cache ramené à un motif),
// `S4_SANS_SIZE_LIMIT` (taille du programme laissée au défaut de la bibliothèque), `S4_FROID_SANS_PLAFOND`
// (le froid recompile par `Regex::new`, sans plafond). Seconde passe, sur les défauts d'un vérificateur :
// `M_FIFO` (le motif re-servi n'est pas remis en fin : éviction du plus ANCIEN POSÉ), `M_SANS_DFA`
// (`dfa_size_limit` retiré), `M_LONG_CHARS` (longueur comptée en caractères), `M_SIGMA_DEFAUT` (l'import
// Sigma `|re` revalide par `Regex::new`), `M_SIGMA_CHARS` (`sigma_regex_token` compte en caractères).
//
// L'IMPORT SIGMA. `sigma.rs` validait un `|re` par `regex::Regex::new`, aux limites de la bibliothèque : un
// motif court au programme trop gros (`\w{100}`) passait l'import puis échouait à CHAQUE évaluation de l'UDF
// — la règle muette que cette validation existe pour empêcher. Il passe désormais par `compiler_motif`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la part de la formule de mémoire de `regex_de_requete.rs` qui n'est
// pas le cache du DFA paresseux (automates, onepass, caches par fil du `Pool`) — lue dans la source, non
// mesurée ; (les tokens Sigma NON `|re` passent désormais aussi par `compiler_motif` : témoins dans
// `sigma_jetons_hors_re_compiles_comme_l_udf.rs`) ; le clone par ligne n'est pas observable à l'exécution (il ne recompile
// pas) — il est rendu impossible par le type (`MotifCompile` sans `Clone`, champ privé), pas témoigné ; la
// famine du sémaphore interactif (`acquire_query_permit`, politique de file non écrite) ; le coût de
// recherche d'un motif admis à la limite ; la valeur recopiée en `String` à chaque ligne ; les compilations de
// motifs de `handlers/detection.rs` et `processors.rs`.
// =====================================================================================
mod regex_de_requete_bornee {
    use super::*;
    use crate::regex_de_requete::{
        compilations_du_fil, compiler_motif, CacheDeMotifs, MotifRefuse, LONGUEUR_MAX_DU_MOTIF, MESSAGE_MOTIF_TROP_LONG,
        MOTIFS_EN_CACHE, PLAFOND_DU_DFA_PARESSEUX, PLAFOND_DU_PROGRAMME,
    };

    /// Mille lignes de texte, numérotées, un tiers porteuses d'un `code=5..`.
    fn rdr_connexion() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        install_query_udfs(&conn);
        conn.execute_batch(
            "CREATE TABLE t(i INTEGER, v TEXT);
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 1000)
             INSERT INTO t SELECT i, 'ligne-' || i || CASE WHEN i % 3 = 0 THEN ' code=5' || (i % 100) ELSE '' END FROM n;",
        )
        .unwrap();
        conn
    }

    fn rdr_valeurs(conn: &rusqlite::Connection) -> Vec<String> {
        let mut st = conn.prepare("SELECT v FROM t ORDER BY i").unwrap();
        let v: Result<Vec<String>, _> = st.query_map([], |r| r.get(0)).unwrap().collect();
        v.unwrap()
    }

    #[test]
    fn regexp_deux_motifs_alternes_sur_mille_lignes_compilent_deux_fois() {
        let conn = rdr_connexion();
        let valeurs = rdr_valeurs(&conn);
        assert_eq!(valeurs.len(), 1000);
        let (p1, p2) = ("code=5[0-9]{1,2}$", "-[0-9]*7( |$)");
        let avant = compilations_du_fil();
        let (n1, n2): (i64, i64) = conn
            .query_row("SELECT sum(regexp(?1, v)), sum(regexp(?2, v)) FROM t", [p1, p2], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        let compilations = compilations_du_fil() - avant;
        assert_eq!(compilations, 2, "deux motifs alternés sur mille lignes : deux compilations, pas une par ligne");
        let (r1, r2) = (regex::Regex::new(p1).unwrap(), regex::Regex::new(p2).unwrap());
        assert_eq!(n1, valeurs.iter().filter(|v| r1.is_match(v)).count() as i64);
        assert_eq!(n2, valeurs.iter().filter(|v| r2.is_match(v)).count() as i64);
        assert!(n1 > 0 && n2 > 0, "fixture : les deux motifs doivent mordre");
    }

    #[test]
    fn re_cap_deux_motifs_alternes_sur_mille_lignes_compilent_deux_fois() {
        let conn = rdr_connexion();
        let valeurs = rdr_valeurs(&conn);
        let (p1, p2) = ("code=(?P<c>5[0-9]*)", "ligne-(?P<n>[0-9]*)");
        let avant = compilations_du_fil();
        let mut st = conn.prepare("SELECT re_cap(v, ?1, 'c'), re_cap(v, ?2, 'n') FROM t ORDER BY i").unwrap();
        let rendu: Result<Vec<(Option<String>, Option<String>)>, _> =
            st.query_map([p1, p2], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect();
        let rendu = rendu.unwrap();
        assert_eq!(compilations_du_fil() - avant, 2, "re_cap : deux compilations pour deux motifs alternés");
        let (r1, r2) = (regex::Regex::new(p1).unwrap(), regex::Regex::new(p2).unwrap());
        let attendu: Vec<(Option<String>, Option<String>)> = valeurs
            .iter()
            .map(|v| {
                (
                    r1.captures(v).and_then(|c| c.name("c").map(|m| m.as_str().to_string())),
                    r2.captures(v).and_then(|c| c.name("n").map(|m| m.as_str().to_string())),
                )
            })
            .collect();
        assert_eq!(rendu, attendu);
    }

    #[test]
    fn cache_de_motifs_evince_le_moins_recent_au_motif_de_trop() {
        let motifs: Vec<String> = (0..=MOTIFS_EN_CACHE).map(|k| format!("^ligne-{k}")).collect();
        let valeurs = ["ligne-0", "ligne-1x", "ligne-3", "autre", "ligne-4"];
        let reference = |p: &str, v: &str| regex::Regex::new(p).unwrap().is_match(v);
        let mut cache = CacheDeMotifs::new();
        let verifier = |cache: &mut CacheDeMotifs, p: &str| {
            let m = cache.motif(p).unwrap();
            for v in valeurs {
                assert_eq!(m.correspond(v), reference(p, v), "motif {p} sur {v}");
            }
        };
        let c0 = compilations_du_fil();
        for p in &motifs[..MOTIFS_EN_CACHE] {
            verifier(&mut cache, p);
        }
        assert_eq!(compilations_du_fil() - c0, MOTIFS_EN_CACHE as u64, "remplissage : une compilation par motif");
        for p in &motifs[..MOTIFS_EN_CACHE] {
            verifier(&mut cache, p);
        }
        assert_eq!(compilations_du_fil() - c0, MOTIFS_EN_CACHE as u64, "les N motifs restent compilés");
        // Le motif de trop évince le moins récemment servi : `motifs[0]`.
        verifier(&mut cache, &motifs[MOTIFS_EN_CACHE]);
        assert_eq!(compilations_du_fil() - c0, MOTIFS_EN_CACHE as u64 + 1);
        for p in &motifs[1..=MOTIFS_EN_CACHE] {
            verifier(&mut cache, p);
        }
        assert_eq!(compilations_du_fil() - c0, MOTIFS_EN_CACHE as u64 + 1, "les N plus récents restent compilés");
        verifier(&mut cache, &motifs[0]);
        assert_eq!(compilations_du_fil() - c0, MOTIFS_EN_CACHE as u64 + 2, "le motif évincé se recompile");
    }

    #[test]
    fn regexp_au_dela_du_cache_rend_les_memes_valeurs() {
        let conn = rdr_connexion();
        let valeurs = rdr_valeurs(&conn);
        let motifs: Vec<String> = (0..=MOTIFS_EN_CACHE).map(|k| format!("-[0-9]*{k}( |$)")).collect();
        let colonnes: Vec<String> = (1..=motifs.len()).map(|k| format!("regexp(?{k}, v)")).collect();
        let sql = format!("SELECT {} FROM t ORDER BY i", colonnes.join(", "));
        let mut st = conn.prepare(&sql).unwrap();
        let rendu: Result<Vec<Vec<bool>>, _> = st
            .query_map(rusqlite::params_from_iter(motifs.iter()), |r| (0..motifs.len()).map(|k| r.get::<_, bool>(k)).collect())
            .unwrap()
            .collect();
        let refs: Vec<regex::Regex> = motifs.iter().map(|p| regex::Regex::new(p).unwrap()).collect();
        let attendu: Vec<Vec<bool>> = valeurs.iter().map(|v| refs.iter().map(|r| r.is_match(v)).collect()).collect();
        assert_eq!(rendu.unwrap(), attendu, "N+1 motifs : éviction à chaque ligne, valeurs identiques");
    }

    #[test]
    fn motif_de_513_octets_refuse_au_chaud_512_admis() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        install_query_udfs(&conn);
        let trop_long = "a".repeat(LONGUEUR_MAX_DU_MOTIF + 1);
        let a_la_limite = "a".repeat(LONGUEUR_MAX_DU_MOTIF);
        assert_eq!(LONGUEUR_MAX_DU_MOTIF, 512);
        assert!(matches!(compiler_motif(&trop_long), Err(MotifRefuse::TropLong)));
        assert!(compiler_motif(&a_la_limite).is_ok());
        for sql in ["SELECT regexp(?1, 'x')", "SELECT regexp(?1, NULL)", "SELECT re_cap('x', ?1, 'g')"] {
            let e = conn.query_row(sql, [&trop_long], |r| r.get::<_, Option<i64>>(0).map(|_| ())).unwrap_err();
            assert!(e.to_string().contains(MESSAGE_MOTIF_TROP_LONG), "{sql} : {e}");
            assert!(conn.query_row(sql, [&a_la_limite], |r| r.get::<_, rusqlite::types::Value>(0)).is_ok(), "{sql} à 512");
        }
    }

    #[test]
    fn motif_court_au_programme_trop_gros_refuse() {
        // `\w` est Unicode : cent répétitions dépassent le plafond du programme, pas le défaut de la bibliothèque.
        let motif = r"\w{100}";
        assert!(motif.len() <= LONGUEUR_MAX_DU_MOTIF);
        assert!(regex::Regex::new(motif).is_ok(), "contre-épreuve : le défaut de la bibliothèque l'admettrait");
        match compiler_motif(motif) {
            Err(MotifRefuse::Invalide(regex::Error::CompiledTooBig(limite))) => assert_eq!(limite, PLAFOND_DU_PROGRAMME),
            Err(e) => panic!("refus inattendu : {e:?}"),
            Ok(_) => panic!("{motif} doit dépasser le plafond du programme"),
        }
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        install_query_udfs(&conn);
        for sql in ["SELECT regexp(?1, 'x')", "SELECT re_cap('x', ?1, 'g')"] {
            let e = conn.query_row(sql, [motif], |r| r.get::<_, rusqlite::types::Value>(0)).unwrap_err();
            assert!(e.to_string().contains("exceeds size limit"), "{sql} : {e}");
        }
    }

    #[test]
    fn regexp_et_re_cap_rendent_sur_un_corpus_fixe_les_valeurs_d_avant() {
        // L'avant : `regex::Regex::new(p).is_match(texte)`, `false` sur NULL / non-texte ; `re_cap` -> groupe ou NULL.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        install_query_udfs(&conn);
        conn.execute_batch(
            "CREATE TABLE c(i INTEGER, v);
             INSERT INTO c VALUES (1, 'GET /admin 200'), (2, 'été chaud'), (3, NULL), (4, 42), (5, x'00ff'),
                                  (6, ''), (7, 'src=192.0.2.7 dst=10.0.0.9'), (8, 'ÉTÉ');",
        )
        .unwrap();
        let textes: Vec<(i64, Option<String>)> = {
            let mut st = conn.prepare("SELECT i, CASE WHEN typeof(v) = 'text' THEN v END FROM c ORDER BY i").unwrap();
            let r: Result<Vec<_>, _> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect();
            r.unwrap()
        };
        for p in ["^GET", "(?i)été", r"src=(?P<g>[0-9.]+)", "^$", "x?"] {
            let re = regex::Regex::new(p).unwrap();
            let mut st = conn.prepare("SELECT regexp(?1, v), re_cap(v, ?1, 'g') FROM c ORDER BY i").unwrap();
            let rendu: Result<Vec<(bool, Option<String>)>, _> = st.query_map([p], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect();
            let attendu: Vec<(bool, Option<String>)> = textes
                .iter()
                .map(|(_, t)| match t {
                    Some(t) => (re.is_match(t), re.captures(t).and_then(|c| c.name("g").map(|m| m.as_str().to_string()))),
                    None => (false, None),
                })
                .collect();
            assert_eq!(rendu.unwrap(), attendu, "motif {p}");
        }
    }

    #[test]
    fn cache_de_motifs_re_servir_le_plus_ancien_l_epargne_au_motif_de_trop() {
        // L'ordre de service diffère de l'ordre de pose : seule une éviction du moins récemment SERVI garde
        // `motifs[0]` (une file FIFO l'évincerait, lui, le plus ancien posé).
        let motifs: Vec<String> = (0..=MOTIFS_EN_CACHE).map(|k| format!("^lru-{k}$")).collect();
        let mut cache = CacheDeMotifs::new();
        let servir = |cache: &mut CacheDeMotifs, p: &str| {
            let m = cache.motif(p).unwrap();
            assert!(m.correspond(&p[1..p.len() - 1]), "motif {p}");
            assert!(!m.correspond("autre"), "motif {p}");
        };
        let c0 = compilations_du_fil();
        for p in &motifs[..MOTIFS_EN_CACHE] {
            servir(&mut cache, p);
        }
        servir(&mut cache, &motifs[0]);
        assert_eq!(compilations_du_fil() - c0, MOTIFS_EN_CACHE as u64, "re-servir motifs[0] ne recompile pas");
        servir(&mut cache, &motifs[MOTIFS_EN_CACHE]);
        assert_eq!(compilations_du_fil() - c0, MOTIFS_EN_CACHE as u64 + 1, "le motif de trop se compile");
        servir(&mut cache, &motifs[0]);
        assert_eq!(
            compilations_du_fil() - c0,
            MOTIFS_EN_CACHE as u64 + 1,
            "motifs[0], re-servi avant le motif de trop, reste compilé"
        );
        servir(&mut cache, &motifs[1]);
        assert_eq!(compilations_du_fil() - c0, MOTIFS_EN_CACHE as u64 + 2, "motifs[1], le moins récemment servi, a été évincé");
    }

    #[test]
    fn motif_multioctet_de_514_octets_refuse_au_chaud_512_octets_admis() {
        // La limite est en OCTETS : 257 « é » font 514 octets, sous la limite si l'on comptait les caractères.
        let trop_long = "é".repeat(LONGUEUR_MAX_DU_MOTIF / 2 + 1);
        let a_la_limite = "é".repeat(LONGUEUR_MAX_DU_MOTIF / 2);
        assert_eq!((trop_long.len(), trop_long.chars().count()), (LONGUEUR_MAX_DU_MOTIF + 2, LONGUEUR_MAX_DU_MOTIF / 2 + 1));
        assert_eq!(a_la_limite.len(), LONGUEUR_MAX_DU_MOTIF);
        assert!(matches!(compiler_motif(&trop_long), Err(MotifRefuse::TropLong)));
        assert!(compiler_motif(&a_la_limite).is_ok());
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        install_query_udfs(&conn);
        for sql in ["SELECT regexp(?1, 'x')", "SELECT regexp(?1, NULL)", "SELECT re_cap('x', ?1, 'g')"] {
            let e = conn.query_row(sql, [&trop_long], |r| r.get::<_, Option<i64>>(0).map(|_| ())).unwrap_err();
            assert!(e.to_string().contains(MESSAGE_MOTIF_TROP_LONG), "{sql} : {e}");
            assert!(conn.query_row(sql, [&a_la_limite], |r| r.get::<_, rusqlite::types::Value>(0)).is_ok(), "{sql} à 512 octets");
        }
    }

    #[test]
    fn cache_du_dfa_paresseux_plafonne_le_pic_de_tas_sous_le_defaut_de_la_bibliotheque() {
        // Le défaut que `dfa_size_limit` remplace : `regex` 1.12, `builders.rs`, `hybrid_cache_capacity(2 * (1 << 20))`.
        const CACHE_DU_DFA_PAR_DEFAUT: usize = 2 * (1 << 20);
        assert!(PLAFOND_DU_DFA_PARESSEUX < CACHE_DU_DFA_PAR_DEFAUT);
        // Un motif dont le DFA a 2^16 états (les seize derniers chiffres lus) : le cache se remplit et se vide
        // jusqu'à sa capacité. Texte de 0/1 pseudo-aléatoires (graine fixe), sans [2-9] : parcouru en entier.
        let motif = "(?-u)1[01]{15}[2-9]";
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let texte: String = (0..400_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                if x & 1 == 0 { '0' } else { '1' }
            })
            .collect();
        let borne = compiler_motif(motif).unwrap();
        let au_defaut = regex::RegexBuilder::new(motif).size_limit(PLAFOND_DU_PROGRAMME).build().unwrap();
        // Les deux expressions sont compilées AVANT la mesure ; le cache se crée au premier appel, sur ce fil.
        let (trouve_borne, pic_borne) = crate::tas_du_fil::pic_vivant_pendant(|| borne.is_match(&texte));
        let (trouve_au_defaut, pic_au_defaut) = crate::tas_du_fil::pic_vivant_pendant(|| au_defaut.is_match(&texte));
        assert!(!trouve_borne && !trouve_au_defaut, "fixture : aucun [2-9] dans le texte");
        assert!(
            pic_au_defaut as usize > PLAFOND_DU_DFA_PARESSEUX,
            "fixture : au défaut de la bibliothèque, le cache doit dépasser le plafond du module ({pic_au_defaut} o)"
        );
        // Propriété structurelle : la capacité baisse de (défaut − plafond), le pic baisse d'au moins la moitié.
        assert!(
            pic_au_defaut.saturating_sub(pic_borne) >= ((CACHE_DU_DFA_PAR_DEFAUT - PLAFOND_DU_DFA_PARESSEUX) / 2) as u64,
            "pic borné {pic_borne} o contre {pic_au_defaut} o au défaut : `dfa_size_limit` ne mord pas"
        );
    }

    #[test]
    fn import_sigma_re_refuse_le_motif_que_l_udf_refuse() {
        let motif = r"\w{100}";
        assert!(regex::Regex::new(motif).is_ok(), "contre-épreuve : le défaut de la bibliothèque l'admettrait");
        // L'UDF le refuse : importée, la règle échouerait à chaque évaluation.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        install_query_udfs(&conn);
        let e = conn.query_row("SELECT regexp(?1, 'x')", [motif], |r| r.get::<_, i64>(0)).unwrap_err();
        assert!(e.to_string().contains("exceeds size limit"), "{e}");
        for cle in ["CommandLine|re", "CommandLine|re|i"] {
            let e = crate::sigma::sigma_field_tokens(cle, &serde_json::Value::String(motif.into())).unwrap_err();
            assert!(e.contains("exceeds size limit") && e.contains("non importée"), "{cle} : {e}");
        }
        // `|re|i` est jugé AVEC son préfixe `(?i)`, comme l'UDF le compilera : `k{5000}` tient nu sous le
        // plafond, et le dépasse une fois la casse repliée. Valider le motif nu laisserait passer une règle muette.
        assert!(crate::regex_de_requete::compiler_motif("k{5000}").is_ok(), "contre-épreuve : nu, le motif tient sous le plafond");
        let e = crate::sigma::sigma_field_tokens("CommandLine|re|i", &serde_json::Value::String("k{5000}".into())).unwrap_err();
        assert!(e.contains("exceeds size limit") && e.contains("non importée"), "|re|i jugé sans son préfixe : {e}");
        // Contre-épreuve : un motif ordinaire s'importe, tel quel.
        assert_eq!(
            crate::sigma::sigma_field_tokens("CommandLine|re", &serde_json::Value::String("foo.*bar".into())).unwrap(),
            vec!["CommandLine=~foo.*bar".to_string()]
        );
        // La longueur est jugée en OCTETS, comme l'UDF : 257 « é » (514 octets) refusés, 256 (512) admis.
        let (trop_long, a_la_limite) = ("é".repeat(LONGUEUR_MAX_DU_MOTIF / 2 + 1), "é".repeat(LONGUEUR_MAX_DU_MOTIF / 2));
        assert!(crate::sigma::sigma_regex_token("message", &trop_long).is_err());
        assert!(crate::sigma::sigma_regex_token("message", &a_la_limite).is_ok());
        let e = crate::sigma::sigma_field_tokens("CommandLine|re", &serde_json::Value::String(trop_long.clone())).unwrap_err();
        assert!(e.contains("trop long"), "{e}");
    }
}
