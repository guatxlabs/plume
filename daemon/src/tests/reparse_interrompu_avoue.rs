// `P10.7-f` — LE REPARSE RÉTROACTIF NE SERT PLUS UN SCAN TRONQUÉ COMME UN TOTAL.
//
// `parser_reparse` (route POST `/api/parsers/reparse`, admin) balaie la table `event` BRUTE sur une
// fenêtre (`days`, jusqu'à 3650 j) : c'est le plus long scan du dépôt sur la plus grande table, et il
// tourne sur la connexion WRITER où le plafond mémoire (`hard_heap_limit`) et le quota de déversement
// sont armés — un VOISIN qui franchit le quota interrompt l'énoncé EN VOL. L'idiome livré
// (`query_map(..).flatten()`) jetait le `Err` de `step()` et gardait le préfixe déjà lu : `scanned` et
// `matched` étaient silencieusement bas, `truncated:false` (ce champ ne couvre QUE le plafond
// d'écritures, jamais l'interruption du scan), servis comme un aperçu dry-run complet.
//
// Le scan DISTINGUE désormais la fin normale de l'interruption (`parcourir_chaque` -> `FinDeParcours`),
// et la réponse AVOUE (`interrompu` + `cause_scan`) quand l'énoncé n'est pas allé au bout. Les deux
// témoins de la famille valent ici : l'interruption est rendue DÉTERMINISTE (un rappel de progression
// qui coupe au N-ième appel, jamais un chronomètre), et le chemin NOMINAL doit rester MUET après qu'on
// a vérifié qu'il a bien tout lu (un corps qui avoue toujours n'avoue rien).
#[cfg(test)]
mod reparse_interrompu_avoue {
    use super::test_db;
    use crate::query_exec::{parcourir_chaque, FinDeParcours};
    use rusqlite::{params, Connection};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const PAS: std::os::raw::c_int = 8;
    fn couper_au_tir(conn: &Connection, tir: usize) {
        let vus = Arc::new(AtomicUsize::new(0));
        conn.progress_handler(PAS, Some(move || vus.fetch_add(1, Ordering::SeqCst) == tir));
    }
    fn ne_plus_couper(conn: &Connection) {
        conn.progress_handler(PAS, None::<fn() -> bool>);
    }

    fn base(n: i64) -> Connection {
        let conn = test_db();
        for i in 0..n {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'sshd','auth',1,?2)",
                params![1000 + i, format!("m{i}")],
            )
            .unwrap();
        }
        conn
    }

    /// Rejoue EXACTEMENT le scan de `parser_reparse` — même SELECT sur `event` brut, même parcours par
    /// `parcourir_chaque` — et rend le compte lu avec la façon dont l'énoncé s'est terminé.
    fn scan(conn: &Connection) -> (i64, FinDeParcours) {
        let mut scanned = 0i64;
        let mut stmt = conn
            .prepare("SELECT id,source,message,fields,src_ip,dst_ip FROM event WHERE ts>=?1 AND (?2 IS NULL OR source=?2) ORDER BY id")
            .unwrap();
        let rows = stmt
            .query_map(params![0i64, Option::<String>::None], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                ))
            })
            .unwrap();
        let fin = parcourir_chaque(
            rows,
            |_row: (i64, String, String, Option<String>, Option<String>, Option<String>)| {
                scanned += 1;
            },
        );
        (scanned, fin)
    }

    #[test]
    fn le_scan_du_reparse_interrompu_est_avoue() {
        const N: i64 = 60;
        let conn = base(N);

        // ① NOMINAL. L'instrument d'abord : le scan a-t-il vraiment tout lu ?
        let (scanned, fin) = scan(&conn);
        assert_eq!(scanned, N, "instrument : la fixture doit être entièrement lue, sinon « complet » ne veut rien dire");
        assert!(fin.cause().is_none(), "un scan complet ne porte AUCUNE cause");

        // ② COUPÉ EN VOL. Le tir est CHERCHÉ, pas deviné : on veut un vrai PRÉFIXE (au moins une ligne,
        // strictement moins que N) — une lecture qui n'aurait rien rendu relèverait de `P10.7-e`.
        let mut coupe: Option<(i64, FinDeParcours)> = None;
        for tir in 1..400usize {
            couper_au_tir(&conn, tir);
            let r = scan(&conn);
            ne_plus_couper(&conn);
            if r.0 > 0 && r.0 < N {
                coupe = Some(r);
                break;
            }
        }
        let (scanned, fin) = coupe.expect(
            "instrument : aucun tir n'a produit un scan TRONQUÉ — le témoin ne conclut pas plutôt que \
             de conclure sur une coupe qu'il n'a pas obtenue",
        );
        let cause = fin
            .cause()
            .unwrap_or_else(|| panic!("scan tronqué rendu SANS cause : {scanned} lignes sur {N}"));
        assert!(cause.contains("interrupted"), "la cause du MOTEUR est conservée telle qu'il l'a dite : {cause}");
        assert!(scanned < N, "le préfixe est STRICT : {scanned} lignes lues sur {N}");
    }

    /// La ROUTE `parser_reparse` construit sa réponse DEPUIS ce parcours : elle avoue l'interruption
    /// (`interrompu` + `cause_scan`) au lieu de servir un préfixe comme un total, et n'a plus de
    /// `.flatten()` muet sur son scan d'`event`. Garde de forme dérivée du source de la route.
    #[test]
    fn la_route_reparse_avoue_son_scan_interrompu() {
        let src = include_str!("../handlers/detection.rs");
        let deb = src
            .find("pub(crate) async fn parser_reparse")
            .expect("parser_reparse existe");
        let fin = deb
            + src[deb..]
                .find("\npub(crate) async fn parser_test")
                .expect("la fonction suivante borne le corps de parser_reparse");
        let corps = &src[deb..fin];
        assert!(
            corps.contains("parcourir_chaque"),
            "parser_reparse doit parcourir son scan en distinguant l'interruption de la fin normale"
        );
        assert!(
            corps.contains("cause_scan") && corps.contains("\"interrompu\""),
            "la réponse de parser_reparse doit AVOUER un scan interrompu (interrompu + cause_scan)"
        );
        assert!(
            !corps.contains(".flatten()"),
            "plus de `.flatten()` muet sur le scan d'event de parser_reparse (il jetait l'erreur d'interruption)"
        );
    }

    /// La ROUTE `suppressions_get` (`admin_ui.rs`) est durcie de la MÊME façon : son scan des
    /// auto-reports collecteurs (un `JOIN` sur `event`) passe par `parcourir_chaque`, et la réponse
    /// AVOUE `collectors_incomplets` (+ cause) quand le budget a coupé l'énoncé en vol, au lieu de
    /// servir une liste de collecteurs tronquée comme complète. Garde de forme dérivée du source ;
    /// la brique d'exécution (interruption distinguée sur un scan d'`event`) est tenue par le témoin
    /// ci-dessus.
    #[test]
    fn la_route_suppressions_avoue_son_scan_interrompu() {
        let src = include_str!("../handlers/admin_ui.rs");
        let deb = src
            .find("pub(crate) async fn suppressions_get")
            .expect("suppressions_get existe");
        let fin = deb
            + src[deb..]
                .find("\n/// POST|PUT /api/suppressions")
                .expect("la doc de suppressions_edit borne le corps de suppressions_get");
        let corps = &src[deb..fin];
        assert!(
            corps.contains("parcourir_chaque"),
            "suppressions_get doit parcourir son scan de collecteurs en distinguant l'interruption"
        );
        assert!(
            corps.contains("\"collectors_incomplets\"") && corps.contains("coll_fin"),
            "la réponse de suppressions_get doit AVOUER un scan interrompu (collectors_incomplets + cause)"
        );
        assert!(
            !corps.contains("rows.flatten()"),
            "plus de scan aplati muet des auto-reports collecteurs dans suppressions_get"
        );
    }
}
