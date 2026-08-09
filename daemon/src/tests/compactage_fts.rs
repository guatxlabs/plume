// P10.7-b — LA COMPACTION DE L'INDEX PLEIN-TEXTE : ce qu'une purge rend MORT, et ce qui le rend.
//
// CE QUE CES TESTS PROUVENT, ET DANS QUEL ORDRE :
//   1. LE DÉFAUT EXISTE — supprimer des lignes fait GROSSIR `event_fts_data`. Le test le mesure et
//      REFUSE de passer si l'index rétrécissait tout seul : sans cette assertion, tout le reste
//      garderait un mécanisme qui ne sert à rien.
//   2. LE CORRECTIF REND DES OCTETS — et le test les NOMME.
//   3. LE DÉSACTIVER LAISSE L'INDEX GONFLÉ — la mutation, nommée en octets elle aussi.
//   4. LE SIGNE DU BUDGET EST LE CORRECTIF — `merge` positif n'atteint JAMAIS le plancher (zéro octet
//      au banc, 1,3 % puis un calage à 3 segments sur la fixture de ces tests).
//      C'est la garde qui attrape la « simplification » consistant à retirer le moins.
//   5. AUCUNE ISSUE HORS `Rendue` NE PEUT ANNONCER D'OCTETS — la propriété est portée par le TYPE.
//
// AUCUN DE CES TESTS NE TOUCHE À L'ENVIRONNEMENT DU PROCESSUS. `Reglage::depuis` prend la
// configuration en paramètre, donc chaque test pose la sienne dans une `HashMap` locale : rien de
// global n'est asserté, rien ne dépend de l'ordonnancement, la suite reste sûre en parallèle.

#[cfg(test)]
mod compactage_fts_tests {
    use crate::compactage_fts::{compacter, compacter_index, index_plein_texte, octets_index, segments, Arret, Issue, Reglage};
    use crate::tmp_possede::TmpDb;
    use parking_lot::Mutex;
    use rusqlite::Connection;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// LE SCHÉMA RÉEL, pas une imitation : la vtable FTS5 à CONTENU EXTERNE et ses DEUX déclencheurs
    /// sont copiés de `db/schema.sql`. C'est `event_ad` — celui qui écrit un posting de SUPPRESSION
    /// au lieu d'en retirer un — qui fabrique le défaut ; un schéma simplifié ne le reproduirait pas.
    const SCHEMA: &str = "\
        CREATE TABLE event(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, \
          source TEXT NOT NULL, category TEXT NOT NULL DEFAULT '', message TEXT NOT NULL DEFAULT '');\
        CREATE VIRTUAL TABLE event_fts USING fts5(message, source, category, content='event', content_rowid='id');\
        CREATE TRIGGER event_ai AFTER INSERT ON event BEGIN \
          INSERT INTO event_fts(rowid,message,source,category) VALUES (new.id,new.message,new.source,new.category); \
        END;\
        CREATE TRIGGER event_ad AFTER DELETE ON event BEGIN \
          INSERT INTO event_fts(event_fts,rowid,message,source,category) \
          VALUES ('delete',old.id,old.message,old.source,old.category); \
        END;";

    /// PRNG écrit ici (splitmix64), jamais celui de la bibliothèque standard : la fixture doit rendre
    /// LES MÊMES OCTETS d'une version de Rust à l'autre, sinon les seuils cités plus bas dérivent.
    struct Rng(u64);
    impl Rng {
        fn suivant(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn borne(&mut self, n: u64) -> u64 {
            self.suivant() % n
        }
    }

    /// Un message au profil qui compte pour un index plein-texte : quelques mots TRÈS fréquents (des
    /// postings longs) et une majorité de jetons QUASI-UNIQUES (un gros dictionnaire). C'est ce mélange
    /// qui fait qu'une suppression coûte des postings de suppression au lieu de rien.
    fn message(r: &mut Rng) -> String {
        const COMMUNS: [&str; 8] = ["session", "opened", "failed", "accepted", "denied", "request", "timeout", "user"];
        let mut s = String::with_capacity(220);
        for i in 0..24 {
            if i > 0 {
                s.push(' ');
            }
            if r.borne(100) < 45 {
                s.push_str(COMMUNS[r.borne(8) as usize]);
            } else {
                s.push_str(&format!("{:08x}", r.suivant() & 0xFFFF_FFFF));
            }
        }
        s
    }

    /// Une base FICHIER (dbstat compte des PAGES : il lui faut un vrai pager) au schéma ci-dessus,
    /// peuplée de `n` événements en lots de 500. Les lots ne sont pas cosmétiques : chaque
    /// transaction qui écrit dans le FTS y dépose un segment, et c'est la MULTIPLICITÉ des segments
    /// qui donne à la fusion quelque chose à faire — exactement comme un ingest réel étalé dans le temps.
    fn base(etiquette: &str, n: i64) -> (TmpDb, Arc<Mutex<Connection>>) {
        let tmp = TmpDb::neuf(etiquette);
        let conn = Connection::open(tmp.as_str()).expect("ouverture base de fixture");
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=OFF;").expect("pragmas");
        conn.execute_batch(SCHEMA).expect("schéma");
        let mut r = Rng(0x5EED_1234);
        let mut i = 0i64;
        while i < n {
            conn.execute_batch("BEGIN").unwrap();
            for _ in 0..500.min(n - i) {
                conn.execute(
                    "INSERT INTO event(ts,source,category,message) VALUES(?1,'sshd','auth',?2)",
                    rusqlite::params![1_780_000_000i64 + i, message(&mut r)],
                )
                .expect("insert");
                i += 1;
            }
            conn.execute_batch("COMMIT").unwrap();
        }
        (tmp, Arc::new(Mutex::new(conn)))
    }

    /// La purge, telle que la rétention la fait : un `DELETE FROM event` par lots (cf. `chunked_purge`).
    fn purger(db: &Arc<Mutex<Connection>>, borne_id: i64) -> i64 {
        let conn = db.lock();
        conn.execute("DELETE FROM event WHERE id <= ?1", rusqlite::params![borne_id]).expect("purge") as i64
    }

    fn octets(db: &Arc<Mutex<Connection>>) -> i64 {
        let conn = db.lock();
        octets_index(&conn, "event_fts").expect("dbstat doit être compilé dans ce binaire")
    }

    fn compte_match(db: &Arc<Mutex<Connection>>, terme: &str) -> i64 {
        let conn = db.lock();
        conn.query_row("SELECT COUNT(*) FROM event_fts WHERE event_fts MATCH ?1", rusqlite::params![terme], |r| r.get(0))
            .expect("MATCH")
    }

    fn reglage(paires: &[(&str, &str)]) -> HashMap<String, String> {
        paires.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    // =============================================================================================
    // 1 + 2. LE DÉFAUT, PUIS LE CORRECTIF — tous deux nommés en OCTETS
    // =============================================================================================

    /// LA MESURE FONDATRICE. On ne « corrige » pas un défaut qu'on n'a pas vu : ce test échoue si la
    /// suppression ne fait PAS grossir l'index, parce qu'alors toute la mécanique de fusion serait du
    /// poids mort ajouté pour rien.
    ///
    /// MESURÉ le 2026-08-09 sur cette fixture (20 000 événements, purge de 12 000 = 60 %) :
    /// `event_fts_data` passe de **3 862 528 o à 5 730 304 o (+48,4 %)** en PERDANT 60 % de ses
    /// documents, puis la compaction le ramène à **1 564 672 o** — soit 2,5× SOUS sa taille d'avant la
    /// purge. Les assertions ne codent PAS ces nombres : elles codent les INÉGALITÉS, qui sont ce qui
    /// doit rester vrai quand la fixture change. Les nombres sont ici pour qu'un écart se voie.
    ///
    /// MUTATION : rendre `compacter_index` inerte (retirer l'exécution de la passe) ⇒ la 3ᵉ assertion
    /// passe au rouge en NOMMANT les octets restés en place.
    #[test]
    fn une_purge_fait_grossir_lindex_et_la_compaction_rend_les_octets() {
        let (_tmp, db) = base("fts-compact-rend", 20_000);
        let avant_purge = octets(&db);
        let temoin = compte_match(&db, "session");
        assert!(avant_purge > 0, "dbstat doit voir l'index (mesuré : {avant_purge} o)");

        let supprimes = purger(&db, 12_000);
        assert_eq!(supprimes, 12_000, "la fixture doit vraiment supprimer 12 000 lignes");
        let apres_purge = octets(&db);

        // (1) LE DÉFAUT : l'index a GROSSI en perdant 60 % de ses documents.
        assert!(
            apres_purge > avant_purge,
            "P10.7-b : supprimer 12 000 documents doit FAIRE GROSSIR event_fts_data \
             (avant purge {avant_purge} o, après purge {apres_purge} o). Si cette assertion tombe, \
             FTS5 rend l'espace tout seul et la compaction n'a plus de raison d'être."
        );

        // (2) LE CORRECTIF : la fusion rend les octets, et descend SOUS la taille d'avant la purge
        // (il y a 60 % de documents en moins : le plancher doit en tenir compte).
        let issues = compacter(&db, &reglage(&[("PLUME_FTS_COMPACT_PAGES", "200"), ("PLUME_FTS_COMPACT_PASSES", "500"), ("PLUME_FTS_COMPACT_REPOS_MS", "0")]));
        assert_eq!(issues.len(), 1, "un seul index FTS5 dans ce schéma");
        let rendus = issues[0].octets_rendus().unwrap_or_else(|| panic!("aucun octet rendu — issue : {}", issues[0].phrase()));
        let apres_compaction = octets(&db);

        assert!(
            apres_compaction < avant_purge,
            "après compaction l'index doit être PLUS PETIT qu'avant la purge (avant purge {avant_purge} o, \
             gonflé {apres_purge} o, compacté {apres_compaction} o, rendus {rendus} o) — {}",
            issues[0].phrase()
        );
        assert_eq!(
            rendus,
            apres_purge - apres_compaction,
            "les octets ANNONCÉS doivent être les octets CONSTATÉS (annoncés {rendus}, constatés {})",
            apres_purge - apres_compaction
        );
        assert!(
            matches!(issues[0], Issue::Rendue { arret: Arret::Convergee, .. }),
            "avec un budget de 500 passes la fusion doit CONVERGER — {}",
            issues[0].phrase()
        );

        // (3) INVARIANCE SÉMANTIQUE : la compaction ne change AUCUN résultat de recherche. Le témoin
        // est pris AVANT la purge, donc on le recompte après purge pour comparer ce qui est comparable.
        let apres = compte_match(&db, "session");
        assert!(apres > 0 && apres < temoin, "précondition : la purge a bien retiré des documents indexés ({temoin} -> {apres})");
        let (_tmp2, db2) = base("fts-compact-temoin", 20_000);
        purger(&db2, 12_000);
        assert_eq!(
            apres,
            compte_match(&db2, "session"),
            "la fusion de segments ne doit changer AUCUN résultat : le même corpus purgé mais NON compacté \
             doit rendre le même compte"
        );
    }

    // =============================================================================================
    // 3. LA MUTATION — désactiver laisse l'index gonflé, et on le dit EN OCTETS
    // =============================================================================================

    /// LE KILL-SWITCH EST RÉEL. `PLUME_FTS_COMPACT=0` ⇒ pas une passe, pas un octet, et l'index reste
    /// EXACTEMENT à sa taille gonflée — au même octet près, pas « à peu près ».
    ///
    /// C'est aussi la garde du réglage : si quelqu'un câblait la compaction en dur (en ignorant
    /// `Reglage::actif`), c'est cette égalité stricte qui tomberait.
    #[test]
    fn desactiver_la_compaction_laisse_lindex_gonfle_au_meme_octet() {
        let (_tmp, db) = base("fts-compact-off", 20_000);
        purger(&db, 12_000);
        let gonfle = octets(&db);

        let issues = compacter(&db, &reglage(&[("PLUME_FTS_COMPACT", "0")]));
        assert!(matches!(issues[0], Issue::Desactivee), "issue attendue : Desactivee — {}", issues[0].phrase());
        assert!(issues[0].octets_rendus().is_none(), "une compaction DÉSACTIVÉE ne peut annoncer aucun octet");
        assert_eq!(
            octets(&db),
            gonfle,
            "PLUME_FTS_COMPACT=0 : l'index doit rester gonflé à {gonfle} octets, à l'octet près"
        );
        assert!(
            issues[0].phrase().contains("DÉSACTIVÉE") && issues[0].phrase().contains("GARDE le poids mort"),
            "le journal doit DIRE que rien n'a été fait : {}",
            issues[0].phrase()
        );

        // ET LE MÊME CORPUS, COMPACTÉ, REND : sans ce second bras, le test ci-dessus serait vert même
        // si la compaction ne marchait pas du tout.
        let issues = compacter(&db, &reglage(&[("PLUME_FTS_COMPACT_PAGES", "200"), ("PLUME_FTS_COMPACT_PASSES", "500"), ("PLUME_FTS_COMPACT_REPOS_MS", "0")]));
        let rendus = issues[0].octets_rendus().unwrap_or(0);
        assert!(
            rendus > 0 && octets(&db) < gonfle,
            "activée, la compaction doit rendre des octets (gonflé {gonfle} o, après {} o, rendus {rendus} o)",
            octets(&db)
        );
    }

    // =============================================================================================
    // 4. LE SIGNE DU BUDGET EST LE CORRECTIF
    // =============================================================================================

    /// POURQUOI LE BUDGET EST NÉGATIF, PROUVÉ PLUTÔT QU'AFFIRMÉ.
    ///
    /// `INSERT INTO ft(ft, rank) VALUES('merge', N)` avec N POSITIF ne fusionne qu'un niveau portant au
    /// moins `usermerge` segments (défaut 4) : il ne cherche PAS le plancher, il entretient la forme de
    /// l'index. Avec `-N`, FTS5 prend son chemin d'`optimize` (`nMin=1`) borné à N pages écrites.
    ///
    /// CE QUE CE TEST OBSERVE, ET CE QU'IL N'OBSERVE PAS. À l'échelle du banc (1,2 M événements, purge
    /// de 58,4 %), le budget positif rend **exactement zéro octet en 0,00 s** — les 15 segments sont
    /// étalés sur 9 niveaux et aucun n'atteint le quota. À l'échelle de CETTE fixture (20 000
    /// événements), il en rend un peu (mesuré le 2026-08-09 : 5 730 304 → 5 656 576 o, soit **1,3 %**)
    /// puis CALE à 3 segments — 500 passes n'y changent rien. Le test n'affirme donc pas « zéro » : il
    /// affirme la propriété qui tient AUX DEUX ÉCHELLES — **le positif n'atteint pas le plancher, le
    /// négatif si** (ici 5 656 576 o contre 1 490 944 o, soit **3,8×**).
    ///
    /// Ce test exécute LES DEUX SIGNES sur DEUX COPIES du même corpus et compare. MUTATION : retirer
    /// le `-` de `let budget = -r.pages;` ⇒ 4 tests rouges, dont celui-ci en nommant les octets.
    #[test]
    fn le_budget_positif_natteint_pas_le_plancher_le_negatif_oui() {
        // Bras POSITIF : on n'a pas de réglage public pour le signe (et c'est voulu), donc on émet la
        // commande exactement comme FTS5 l'attend, avec le budget POSITIF, autant de fois que la
        // compaction en ferait.
        let (_tp, positif) = base("fts-compact-signe-pos", 20_000);
        purger(&positif, 12_000);
        let depart = octets(&positif);
        {
            let conn = positif.lock();
            for _ in 0..500 {
                conn.execute("INSERT INTO event_fts(event_fts, rank) VALUES('merge', ?1)", rusqlite::params![200i64])
                    .expect("merge positif");
            }
        }
        let apres_positif = octets(&positif);

        // Bras NÉGATIF : le chemin de production, sur un corpus identique.
        let (_tn, negatif) = base("fts-compact-signe-neg", 20_000);
        purger(&negatif, 12_000);
        assert_eq!(octets(&negatif), depart, "précondition : les deux corpus sont identiques ({depart} o)");
        let issues = compacter(&negatif, &reglage(&[("PLUME_FTS_COMPACT_PAGES", "200"), ("PLUME_FTS_COMPACT_PASSES", "500"), ("PLUME_FTS_COMPACT_REPOS_MS", "0")]));
        let apres_negatif = issues[0].octets_rendus().map(|r| depart - r).unwrap_or(depart);

        assert!(
            apres_negatif < apres_positif,
            "le budget NÉGATIF doit atteindre un plancher que le positif n'atteint pas : départ {depart} o, \
             après 500 merges POSITIFS {apres_positif} o, après compaction (budget négatif) {apres_negatif} o. \
             Si ces deux nombres se rejoignent, le signe a été perdu et la compaction ne compacte plus."
        );
    }

    // =============================================================================================
    // 5. LA PROPRIÉTÉ EST PORTÉE PAR LE TYPE
    // =============================================================================================

    /// AUCUNE ISSUE HORS `Rendue` NE PEUT ANNONCER D'OCTETS, et aucune ne peut se dire faite. La
    /// vérification est exhaustive sur les variantes : ajouter une variante qui annoncerait des octets
    /// sans en avoir rendu obligerait à toucher ce test.
    #[test]
    fn aucune_issue_hors_rendue_nannonce_doctets() {
        let echantillons = [
            Issue::Desactivee,
            Issue::AucunIndex,
            Issue::DejaCompact { nom: "event_fts".into(), octets: 123_456 },
            Issue::Echec { nom: "event_fts".into(), message: "disk I/O error".into() },
        ];
        for i in &echantillons {
            assert!(i.octets_rendus().is_none(), "cette issue ne doit annoncer AUCUN octet : {}", i.phrase());
            let p = i.phrase();
            assert!(
                !p.contains("octets rendus"),
                "une issue qui n'a rien rendu ne doit pas parler d'octets rendus : {p}"
            );
        }
        // `DejaCompact` DIT qu'elle n'a rien fait, au lieu de laisser croire à une compaction.
        assert!(echantillons[2].phrase().contains("RIEN N'A ÉTÉ FAIT"), "{}", echantillons[2].phrase());
        // `Echec` ne prétend PAS connaître l'état de l'index.
        assert!(echantillons[3].phrase().contains("AUCUN octet annoncé"), "{}", echantillons[3].phrase());
    }

    // =============================================================================================
    // LE BUDGET DU TICK — épuisé, il est DIT ; la reprise converge
    // =============================================================================================

    /// UN TICK QUI N'A PAS FINI NE DIT PAS QU'IL A FINI. Avec une seule passe, la fusion ne peut pas
    /// atteindre le plancher : l'issue reste `Rendue` (des octets ONT été rendus, c'est vrai) mais
    /// l'arrêt est `BudgetEpuise`, et la phrase annonce que du poids mort RESTE. Les ticks suivants
    /// reprennent et finissent par converger — sans que rien ne soit perdu entre eux.
    ///
    /// LA DERNIÈRE ASSERTION EST CELLE QUI JUSTIFIE TOUT L'ARBITRAGE : le plancher atteint par ticks
    /// BORNÉS est le MÊME, à l'octet près, que celui atteint d'un seul tenant. Un incrémental qui
    /// n'atteindrait jamais le plancher ne vaudrait pas mieux qu'une rafale.
    #[test]
    fn le_budget_epuise_est_dit_et_la_reprise_converge() {
        let (_tmp, db) = base("fts-compact-budget", 20_000);
        purger(&db, 12_000);
        let gonfle = octets(&db);

        let r = reglage(&[("PLUME_FTS_COMPACT_PAGES", "60"), ("PLUME_FTS_COMPACT_PASSES", "1"), ("PLUME_FTS_COMPACT_REPOS_MS", "0")]);
        let un_tick = compacter(&db, &r);
        assert!(
            matches!(un_tick[0], Issue::Rendue { arret: Arret::BudgetEpuise, passes: 1, .. }),
            "une passe ne peut pas converger sur cet index — {}",
            un_tick[0].phrase()
        );
        assert!(
            un_tick[0].phrase().contains("BUDGET DU TICK ÉPUISÉ") && un_tick[0].phrase().contains("RESTE du poids mort"),
            "un tick inachevé doit le DIRE : {}",
            un_tick[0].phrase()
        );

        // La reprise : on rejoue le MÊME tick borné jusqu'à convergence, comme la boucle horaire le fera.
        let mut ticks = 1;
        loop {
            let i = compacter(&db, &r);
            ticks += 1;
            match &i[0] {
                Issue::Rendue { arret: Arret::Convergee, .. } | Issue::DejaCompact { .. } => break,
                Issue::Rendue { arret: Arret::BudgetEpuise, .. } => {
                    assert!(ticks < 400, "la reprise doit converger, pas tourner en rond ({ticks} ticks)");
                }
                autre => panic!("issue inattendue pendant la reprise : {}", autre.phrase()),
            }
        }
        let final_ = octets(&db);
        assert!(final_ < gonfle, "la reprise par ticks bornés doit atteindre le plancher (gonflé {gonfle} o, final {final_} o, {ticks} ticks)");

        // Et le plancher atteint par ticks bornés est CELUI de la compaction d'un seul tenant : c'est
        // la propriété qui justifie de préférer l'incrémental à la rafale (mesuré au banc : 59 277 312
        // octets dans les deux cas, à l'octet près).
        let (_t2, db2) = base("fts-compact-budget-ref", 20_000);
        purger(&db2, 12_000);
        compacter(&db2, &reglage(&[("PLUME_FTS_COMPACT_PAGES", "200"), ("PLUME_FTS_COMPACT_PASSES", "500"), ("PLUME_FTS_COMPACT_REPOS_MS", "0")]));
        assert_eq!(
            final_,
            octets(&db2),
            "le plancher atteint par ticks BORNÉS doit être celui atteint d'un seul tenant"
        );
    }

    // =============================================================================================
    // LES INSTRUMENTS
    // =============================================================================================

    /// LES INDEX SONT DÉRIVÉS DU SCHÉMA, JAMAIS ÉNUMÉRÉS. Une vtable FTS5 au nom que personne n'a
    /// prévu est trouvée ; une vtable qui n'est PAS FTS5 ne l'est pas. C'est la propriété qui fait que
    /// `event_fields_fts` (Phase 1) et le prochain index sont couverts sans qu'on y pense.
    ///
    /// MUTATION : remplacer la dérivation par `vec!["event_fts"]` ⇒ la 2ᵉ assertion tombe.
    #[test]
    fn les_index_plein_texte_sont_derives_du_schema() {
        let tmp = TmpDb::neuf("fts-compact-derive");
        let conn = Connection::open(tmp.as_str()).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute_batch("CREATE VIRTUAL TABLE index_invente_demain USING fts5(x);").unwrap();
        // ... y compris écrite en MINUSCULES : le filtre ne doit pas dépendre de la casse de la DDL.
        conn.execute_batch("create virtual table index_en_minuscules using fts5(y);").unwrap();
        // Une vtable qui n'est pas FTS5 n'a ni segments ni fusion : elle ne doit PAS être ramassée.
        conn.execute_batch("CREATE VIRTUAL TABLE pas_du_fts USING dbstat;").unwrap();
        let trouves = index_plein_texte(&conn);
        assert!(trouves.contains(&"event_fts".to_string()), "{trouves:?}");
        assert!(
            trouves.contains(&"index_invente_demain".to_string()),
            "une vtable FTS5 INCONNUE aujourd'hui doit être trouvée par DÉRIVATION : {trouves:?}"
        );
        assert!(
            trouves.contains(&"index_en_minuscules".to_string()),
            "le filtre ne doit pas dépendre de la CASSE de la DDL : {trouves:?}"
        );
        assert!(!trouves.contains(&"pas_du_fts".to_string()), "une vtable non-FTS5 n'est pas un index plein-texte : {trouves:?}");
    }

    /// LE COMPTE DE SEGMENTS VIENT DE L'ENREGISTREMENT DE STRUCTURE DE FTS5, et il est la SEULE
    /// source qui ne mente pas : `COUNT(DISTINCT segid) FROM event_fts_idx` sous-évalue en silence
    /// (un segment d'une seule page n'écrit aucune ligne dans `%_idx`). On vérifie donc les deux
    /// propriétés qui comptent : la structure ne peut pas compter MOINS que `%_idx`, et un index
    /// compacté tombe à EXACTEMENT un segment.
    #[test]
    fn le_compte_de_segments_vient_de_la_structure_fts5() {
        let (_tmp, db) = base("fts-compact-segments", 20_000);
        let (avant, via_idx) = {
            let conn = db.lock();
            (
                segments(&conn, "event_fts").expect("structure FTS5 lisible"),
                conn.query_row("SELECT COUNT(DISTINCT segid) FROM event_fts_idx", [], |r| r.get::<_, i64>(0)).unwrap(),
            )
        };
        assert!(avant >= 2, "un ingest en lots doit laisser plusieurs segments (structure : {avant})");
        assert!(
            avant >= via_idx,
            "la structure est la source AUTORITAIRE : elle ne peut pas compter moins que %_idx \
             (structure {avant}, %_idx {via_idx})"
        );
        compacter(&db, &reglage(&[("PLUME_FTS_COMPACT_PAGES", "200"), ("PLUME_FTS_COMPACT_PASSES", "500"), ("PLUME_FTS_COMPACT_REPOS_MS", "0")]));
        let apres = { let conn = db.lock(); segments(&conn, "event_fts").expect("structure") };
        assert_eq!(apres, 1, "un index compacté porte EXACTEMENT un segment (mesuré : {apres})");

        // Et une fois là, la compaction CONSTATE qu'il n'y a rien à faire au lieu de lancer une passe.
        let r = Reglage::depuis(&reglage(&[]));
        let issue = compacter_index(&db, "event_fts", &r);
        assert!(matches!(issue, Issue::DejaCompact { .. }), "{}", issue.phrase());
    }

    /// LE RÉGLAGE EST BORNÉ À LA LECTURE. Une valeur aberrante écrite dans `/etc/plume/soc.conf` ne
    /// peut pas transformer une passe bornée en rafale non bornée — ni la réduire à rien.
    /// PURE : aucune base, aucun environnement.
    #[test]
    fn le_reglage_est_borne_a_la_lecture() {
        let defaut = Reglage::depuis(&reglage(&[]));
        assert!(defaut.actif, "la compaction est ACTIVE par défaut (sinon la production garde son poids mort)");
        assert_eq!((defaut.pages, defaut.passes, defaut.repos_ms), (500, 8, 200), "les défauts livrés");

        let enorme = Reglage::depuis(&reglage(&[
            ("PLUME_FTS_COMPACT_PAGES", "999999999"),
            ("PLUME_FTS_COMPACT_PASSES", "999999999"),
            ("PLUME_FTS_COMPACT_REPOS_MS", "999999999"),
        ]));
        assert_eq!((enorme.pages, enorme.passes, enorme.repos_ms), (20_000, 5_000, 60_000), "plafonds durs");

        let minuscule = Reglage::depuis(&reglage(&[
            ("PLUME_FTS_COMPACT_PAGES", "0"),
            ("PLUME_FTS_COMPACT_PASSES", "-4"),
        ]));
        assert_eq!((minuscule.pages, minuscule.passes), (50, 1), "planchers durs");

        // Une valeur ILLISIBLE retombe sur le défaut, elle ne désactive rien en silence.
        let illisible = Reglage::depuis(&reglage(&[("PLUME_FTS_COMPACT_PAGES", "beaucoup")]));
        assert_eq!(illisible.pages, 500, "une valeur illisible retombe sur le défaut livré");

        // Le kill-switch n'accepte QUE "1" comme actif : tout le reste ferme (fail-safe).
        assert!(!Reglage::depuis(&reglage(&[("PLUME_FTS_COMPACT", "0")])).actif);
        assert!(!Reglage::depuis(&reglage(&[("PLUME_FTS_COMPACT", "")])).actif);
    }

    /// UNE ERREUR SQLITE NE SE DÉGUISE PAS EN « BUDGET ÉPUISÉ ». Les deux laissent du poids mort et
    /// les deux seront retentées au tick suivant — mais l'une est le régime NORMAL d'un tick borné, et
    /// l'autre est un incident (disque plein, E/S, base en lecture seule). Les confondre derrière un
    /// booléen `convergee` aurait fait écrire « reprise au prochain tick » sur une base qui n'écrit
    /// plus : exactement la famille de défaut que ce dépôt ferme.
    ///
    /// Ici l'erreur est provoquée par `PRAGMA query_only=ON` — une base réellement non inscriptible,
    /// pas une simulation.
    #[test]
    fn une_erreur_sqlite_ne_se_deguise_pas_en_budget_epuise() {
        let (_tmp, db) = base("fts-compact-erreur", 20_000);
        purger(&db, 12_000);
        let gonfle = octets(&db);
        { let conn = db.lock(); conn.execute_batch("PRAGMA query_only=ON;").unwrap(); }

        let issues = compacter(&db, &reglage(&[("PLUME_FTS_COMPACT_PAGES", "200"), ("PLUME_FTS_COMPACT_PASSES", "8"), ("PLUME_FTS_COMPACT_REPOS_MS", "0")]));
        assert!(
            matches!(issues[0], Issue::Rendue { arret: Arret::Erreur(_), passes: 0, .. }),
            "une base non inscriptible doit rendre une ERREUR nommée — {}",
            issues[0].phrase()
        );
        let p = issues[0].phrase();
        assert!(p.contains("ARRÊTÉ SUR ERREUR SQLite"), "{p}");
        assert!(!p.contains("BUDGET DU TICK ÉPUISÉ"), "l'erreur ne doit PAS se lire comme un budget épuisé : {p}");
        assert!(!p.contains("CONVERGÉ"), "et encore moins comme une convergence : {p}");
        assert_eq!(issues[0].octets_rendus(), Some(0), "aucune passe n'a committé -> zéro octet rendu");
        assert_eq!(octets(&db), gonfle, "l'index reste gonflé à {gonfle} octets");
    }

    /// UNE BASE SANS INDEX PLEIN-TEXTE N'EST PAS UN ÉCHEC — et ne s'annonce pas compactée.
    #[test]
    fn une_base_sans_index_plein_texte_le_dit() {
        let tmp = TmpDb::neuf("fts-compact-sans");
        let conn = Connection::open(tmp.as_str()).unwrap();
        conn.execute_batch("CREATE TABLE event(id INTEGER PRIMARY KEY, message TEXT);").unwrap();
        let db = Arc::new(Mutex::new(conn));
        let issues = compacter(&db, &reglage(&[]));
        assert!(matches!(issues[0], Issue::AucunIndex), "{}", issues[0].phrase());
        assert!(issues[0].octets_rendus().is_none());
    }
}
