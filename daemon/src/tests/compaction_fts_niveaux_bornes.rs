// LA COMPACTION FTS5 NE REND PLUS L'INDEX ILLISIBLE — le nombre de NIVEAUX de la structure reste borné.
//
// LE DÉFAUT (lu dans l'amalgamation vendorée, SQLite 3.39.4) : le budget NÉGATIF de `merge` prend le chemin
// d'`optimize`, qui place tous les segments sur un niveau NEUF (`fts5IndexOptimizeStruct`, sqlite3.c:237298) puis
// fusionne ce dernier niveau vers un autre niveau neuf (`fts5IndexMergeLevel`, sqlite3.c:236853) ; aucun code du
// moteur ne retire un niveau vide, et `fts5StructureDecode` refuse au-delà de 2000 niveaux (sqlite3.c:233443) :
// l'index devient illisible et toute insertion échoue.
//
// CE QUE CES TÉMOINS TIENNENT :
//   T1  la bombe : des ticks de compaction entrelacés d'insertions et de purges laissent le nombre de niveaux sous
//       une borne écrite, quand l'ancienne stratégie (le même budget négatif SANS retrait) la dépasse largement sur
//       le même nombre de cycles ; l'issue sert les niveaux qu'on relit ; l'index pèse les mêmes octets que sous
//       l'ancienne stratégie ;
//   T5  après ces cycles, une insertion, une recherche et le contrôle d'intégrité de FTS5 réussissent ;
//   T2  le plancher : après une purge massive d'un index déjà convergé, la compaction rend les octets jusqu'au
//       plancher d'un `optimize` joué sur une base jumelle ;
//   T3  la garde : au-delà du seuil, aucune passe et rien d'écrit, phrase entière, y compris pour un index d'un
//       seul segment ; au seuil, la passe est jouée ; la garde de chaque passe en cours de séquence, et l'arrêt sur
//       une structure illisible avant une passe ; la limite du moteur et le remède, mesurés ;
//   le retrait : joué après CHAQUE passe d'un tick, même quand une ingestion s'intercale entre deux passes ; chaque
//       forme refusée, chaque issue de l'écriture (succès, rien à faire, refus à chaque pas, annulation refusée avec
//       et sans transaction restante) ;
//   T4  la santé, par la ROUTE `/api/system/health`, dans un sous-processus ; le plus grand nombre servi quelle que
//       soit la place de son index.
//
// AUCUN DE CES TÉMOINS NE POSE L'ENVIRONNEMENT du processus de test (le sous-processus de T4 reçoit le sien).

#[cfg(test)]
mod cf1_niveaux_bornes {
    use super::*;
    use crate::compactage_fts::{
        compacter, compacter_index, crochet_de_compaction, etat_de_surface_niveaux, niveaux_des_index,
        octets_index, plus_grand_nombre_de_niveaux, retirer_les_niveaux_vides, PointDeTest, retrait_des_niveaux_vides, structure,
        Arret, Issue, Reglage,
    };
    use crate::mesure_environnement::Mesure;
    use crate::tmp_possede::TmpDb;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
    use std::collections::HashMap;

    // ---------------------------------------------------------------------------------------------
    // LES VALEURS ÉCRITES ICI (jamais tirées de la production)
    // ---------------------------------------------------------------------------------------------

    /// Le seuil de la garde.
    const CF1_SEUIL: i64 = 1000;
    /// La limite du moteur (`FTS5_MAX_SEGMENT`).
    const CF1_LIMITE: i64 = 2000;
    /// L'alerte de santé.
    const CF1_ALERTE: i64 = 64;
    /// Le nombre de niveaux que le retrait conserve.
    const CF1_CONSERVES: i64 = 16;
    /// La borne de T1 : ce que le retrait conserve, plus les deux niveaux qu'une passe peut ajouter.
    const CF1_BORNE_NIVEAUX: i64 = CF1_CONSERVES + 2;
    /// Le nombre de cycles de T1.
    const CF1_CYCLES: usize = 60;
    /// Le plancher que l'ANCIENNE stratégie doit franchir sur ces cycles (contrôle : sans lui, la borne de T1 ne
    /// prouverait rien).
    const CF1_PLANCHER_ANCIEN: i64 = 80;
    /// La phrase d'une structure qu'on ne sait pas réécrire.
    const CF1_FORME: &str =
        "enregistrement de structure FTS5 de forme inconnue (tronqué, incohérent, ou format d'une autre version du moteur) : rien n'est réécrit";
    /// Le remède servi pour `event_fts`.
    const CF1_REMEDE: &str =
        "remède : reconstruire l'index depuis sa source, démon arrêté : INSERT INTO event_fts(event_fts) VALUES('rebuild')";
    /// Le remède au-delà de la limite du moteur.
    const CF1_REMEDE_LIMITE: &str =
        "remède : redémarrer le démon — la porte d'ouverture rebâtit depuis sa source un index dont la table virtuelle ne se construit plus";
    /// La fin commune des phrases d'un retrait refusé puis annulé.
    const CF1_ANNULE: &str = " ; transaction annulée, structure d'avant conservée";

    fn cf1_phrase_garde(niveaux: i64) -> String {
        format!(
            "[fts-compact] event_fts : {niveaux} NIVEAUX dans la structure FTS5, au-delà du seuil de 1000 — AUCUNE fusion \
             lancée, rien n'est écrit : le moteur refuse de lire une structure de plus de 2000 niveaux, l'index devient \
             alors illisible et toute insertion échoue ; {CF1_REMEDE}"
        )
    }

    // ---------------------------------------------------------------------------------------------
    // LA FIXTURE — le schéma réel de la vtable et de ses déclencheurs (copié de `db/schema.sql`)
    // ---------------------------------------------------------------------------------------------

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

    /// splitmix64 : les mêmes octets d'une version de Rust à l'autre.
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

    /// Un lot d'insertions dans UNE transaction : un segment déposé, comme un lot d'ingestion.
    fn inserer(conn: &Connection, r: &mut Rng, n: i64) {
        conn.execute_batch("BEGIN").expect("fixture : BEGIN");
        for _ in 0..n {
            conn.execute("INSERT INTO event(ts,source,category,message) VALUES(1,'sshd','auth',?1)", params![message(r)])
                .expect("fixture : insertion");
        }
        conn.execute_batch("COMMIT").expect("fixture : COMMIT");
    }

    /// Une base FICHIER au schéma ci-dessus, `n` événements en lots de 500.
    fn base(etiquette: &str, n: i64) -> (TmpDb, Arc<Mutex<Connection>>, Rng) {
        let tmp = TmpDb::neuf(etiquette);
        let conn = Connection::open(tmp.as_str()).expect("fixture : ouverture");
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=OFF;").expect("fixture : pragmas");
        conn.execute_batch(SCHEMA).expect("fixture : schéma");
        let mut r = Rng(0x5EED_1234);
        let mut i = 0;
        while i < n {
            inserer(&conn, &mut r, 500.min(n - i));
            i += 500;
        }
        (tmp, Arc::new(Mutex::new(conn)), r)
    }

    fn reglage(paires: &[(&str, &str)]) -> HashMap<String, String> {
        paires.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn tick(pages: &str, passes: &str) -> HashMap<String, String> {
        reglage(&[("PLUME_FTS_COMPACT_PAGES", pages), ("PLUME_FTS_COMPACT_PASSES", passes), ("PLUME_FTS_COMPACT_REPOS_MS", "0")])
    }

    // ---------------------------------------------------------------------------------------------
    // L'ENREGISTREMENT DE STRUCTURE, lu et écrit PAR LE TÉMOIN (codec indépendant de la production)
    // ---------------------------------------------------------------------------------------------

    fn cf1_varint(b: &[u8], mut i: usize) -> (u64, usize) {
        let mut v = 0u64;
        for _ in 0..8 {
            let c = b[i];
            i += 1;
            v = (v << 7) | (c & 0x7f) as u64;
            if c & 0x80 == 0 {
                return (v, i);
            }
        }
        ((v << 8) | b[i] as u64, i + 1)
    }

    fn cf1_ecrire(v: u64, sortie: &mut Vec<u8>) {
        let mut g = Vec::new();
        let mut x = v;
        loop {
            g.push((x & 0x7f) as u8);
            x >>= 7;
            if x == 0 {
                break;
            }
        }
        for (k, o) in g.iter().rev().enumerate() {
            sortie.push(if k + 1 < g.len() { o | 0x80 } else { *o });
        }
    }

    /// Un niveau : `nMerge` et ses segments (segid, première page, dernière page).
    #[derive(Clone)]
    struct Cf1Niveau {
        fusion: u64,
        segments: Vec<(u64, u64, u64)>,
    }

    struct Cf1Structure {
        cookie: [u8; 4],
        compteur: u64,
        niveaux: Vec<Cf1Niveau>,
    }

    fn cf1_decoder(b: &[u8]) -> Cf1Structure {
        let (n, i) = cf1_varint(b, 4);
        let (_s, i) = cf1_varint(b, i);
        let (compteur, mut i) = cf1_varint(b, i);
        let mut niveaux = Vec::new();
        for _ in 0..n {
            let (fusion, j) = cf1_varint(b, i);
            let (ns, mut j) = cf1_varint(b, j);
            let mut segments = Vec::new();
            for _ in 0..ns {
                let (a, k) = cf1_varint(b, j);
                let (p, k) = cf1_varint(b, k);
                let (d, k) = cf1_varint(b, k);
                segments.push((a, p, d));
                j = k;
            }
            niveaux.push(Cf1Niveau { fusion, segments });
            i = j;
        }
        assert_eq!(i, b.len(), "codec du témoin : l'enregistrement est lu en entier");
        Cf1Structure { cookie: [b[0], b[1], b[2], b[3]], compteur, niveaux }
    }

    fn cf1_encoder(s: &Cf1Structure) -> Vec<u8> {
        let mut o = s.cookie.to_vec();
        cf1_ecrire(s.niveaux.len() as u64, &mut o);
        cf1_ecrire(s.niveaux.iter().map(|n| n.segments.len() as u64).sum(), &mut o);
        cf1_ecrire(s.compteur, &mut o);
        for n in &s.niveaux {
            cf1_ecrire(n.fusion, &mut o);
            cf1_ecrire(n.segments.len() as u64, &mut o);
            for &(a, p, d) in &n.segments {
                cf1_ecrire(a, &mut o);
                cf1_ecrire(p, &mut o);
                cf1_ecrire(d, &mut o);
            }
        }
        o
    }

    fn vide() -> Cf1Niveau {
        Cf1Niveau { fusion: 0, segments: vec![] }
    }

    fn un(segid: u64) -> Cf1Niveau {
        Cf1Niveau { fusion: 0, segments: vec![(segid, 1, 3)] }
    }

    fn lire_bloc(conn: &Connection) -> Vec<u8> {
        conn.query_row("SELECT block FROM event_fts_data WHERE id=10", [], |r| r.get(0)).expect("structure lue")
    }

    fn niveaux_lus(conn: &Connection) -> i64 {
        cf1_decoder(&lire_bloc(conn)).niveaux.len() as i64
    }

    /// GONFLE la structure jusqu'à `cible` niveaux en insérant des niveaux VIDES juste après le niveau 0 (la forme
    /// que laisse le budget négatif), PAR UNE CONNEXION À PART : son écriture change `data_version` pour la
    /// connexion de la compaction, dont FTS5 relit alors la structure au lieu de servir son cache.
    fn gonfler_par(conn: &Connection, cible: i64) {
        let mut s = cf1_decoder(&lire_bloc(conn));
        assert!(s.niveaux.len() as i64 <= cible, "fixture : on ne gonfle que vers le haut ({} -> {cible})", s.niveaux.len());
        while (s.niveaux.len() as i64) < cible {
            s.niveaux.insert(1, vide());
        }
        conn.execute("UPDATE event_fts_data SET block=?1 WHERE id=10", params![cf1_encoder(&s)]).expect("fixture : gonflée");
        assert_eq!(niveaux_lus(conn), cible, "fixture : la structure porte {cible} niveaux");
    }

    fn gonfler(chemin: &str, cible: i64) {
        let c = Connection::open(chemin).expect("fixture : seconde connexion");
        gonfler_par(&c, cible);
    }

    fn compte_match(conn: &Connection, terme: &str) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM event_fts WHERE event_fts MATCH ?1", params![terme], |r| r.get(0)).expect("MATCH")
    }

    /// Le même compte, lu dans la SOURCE (un jeton entre blancs ; les jetons hexadécimaux ne contiennent pas de `s`).
    fn compte_source(conn: &Connection, terme: &str) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM event WHERE ' '||message||' ' LIKE ?1", params![format!("% {terme} %")], |r| r.get(0))
            .expect("compte de la source")
    }

    /// L'ANCIENNE STRATÉGIE, rejouée telle quelle : le budget négatif, sans retrait.
    fn tick_ancien(conn: &Connection, pages: i64, passes: usize) {
        for _ in 0..passes {
            if structure(conn, "event_fts").expect("structure").segments < 2 {
                break;
            }
            conn.execute("INSERT INTO event_fts(event_fts, rank) VALUES('merge', ?1)", params![-pages]).expect("passe");
        }
    }

    // =============================================================================================
    // T1 + T5 — LA BOMBE
    // =============================================================================================

    /// T1 — SOUS DES TICKS RÉPÉTÉS, ENTRELACÉS D'INSERTIONS ET DE PURGES, LE NOMBRE DE NIVEAUX RESTE BORNÉ.
    /// `CF1_CYCLES` cycles « tick de compaction (huit passes), lot de 500 insertions, purge des 1 000 plus anciens
    /// tous les cinq cycles ». CONTRÔLE : la même séquence jouée par l'ancienne stratégie (budget négatif, sans
    /// retrait) franchit `CF1_PLANCHER_ANCIEN` ; la nouvelle ne dépasse JAMAIS `CF1_BORNE_NIVEAUX`, relevée après
    /// chaque geste. À chaque tick, les niveaux que l'issue annonce sont ceux qu'on relit.
    ///
    /// T5 — APRÈS CES CYCLES, l'insertion d'un événement, une recherche (comptée contre la source) et
    /// `integrity-check` de FTS5 réussissent : c'est le symptôme à ne plus revoir.
    ///
    /// MUTATIONS : `CF1_SANS_RETRAIT` (le retrait n'est pas appelé) -> niveaux au-delà de la borne : ROUGE ;
    /// `CF1_NIVEAUX_FAUX_SANS_SONDE` (un niveau de trop écrit, et la sonde de FTS5 sautée) -> structure refusée par
    /// le moteur, l'insertion de T5 échoue : ROUGE ; `CF1_UNE_PASSE_DE_MOINS` (le tick s'arrête une passe avant son
    /// budget) -> l'index ne pèse plus les octets de l'ancienne stratégie : ROUGE.
    #[test]
    fn t1_t5_le_nombre_de_niveaux_reste_borne_et_l_index_se_lit() {
        // Le contrôle : l'ancienne stratégie, même séquence.
        let (_ta, ancien, mut ra) = base("cf1-bombe-ancien", 20_000);
        let mut purge = 0i64;
        for cycle in 1..=CF1_CYCLES {
            let c = ancien.lock();
            tick_ancien(&c, 200, 8);
            inserer(&c, &mut ra, 500);
            if cycle % 5 == 0 {
                purge += 1000;
                c.execute("DELETE FROM event WHERE id <= ?1", params![purge]).expect("purge");
            }
        }
        let niveaux_anciens = niveaux_lus(&ancien.lock());
        assert!(
            niveaux_anciens > CF1_PLANCHER_ANCIEN,
            "contrôle : l'ancienne stratégie doit franchir {CF1_PLANCHER_ANCIEN} niveaux en {CF1_CYCLES} cycles (mesuré : \
             {niveaux_anciens}) — sinon la borne ci-dessous ne prouverait rien"
        );

        // La stratégie de production.
        let (tmp, db, mut r) = base("cf1-bombe", 20_000);
        let mut purge = 0i64;
        let mut pire = 0i64;
        let mut rendues = 0usize;
        for cycle in 1..=CF1_CYCLES {
            let issues = compacter(&db, &tick("200", "8"));
            assert_eq!(issues.len(), 1, "un seul index");
            let relus = niveaux_lus(&db.lock());
            if let Issue::Rendue { niveaux_apres, .. } = &issues[0] {
                rendues += 1;
                assert_eq!(*niveaux_apres, relus, "cycle {cycle} : l'issue annonce les niveaux qu'on relit — {}", issues[0].phrase());
            }
            pire = pire.max(relus);
            let c = db.lock();
            inserer(&c, &mut r, 500);
            if cycle % 5 == 0 {
                purge += 1000;
                c.execute("DELETE FROM event WHERE id <= ?1", params![purge]).expect("purge");
            }
            pire = pire.max(niveaux_lus(&c));
        }
        assert!(rendues >= CF1_CYCLES / 2, "contrôle : la compaction a réellement fusionné ({rendues} ticks rendus)");
        assert!(
            pire <= CF1_BORNE_NIVEAUX,
            "T1 : le nombre de niveaux reste sous {CF1_BORNE_NIVEAUX} sur {CF1_CYCLES} cycles (pire relevé : {pire} ; \
             l'ancienne stratégie : {niveaux_anciens})"
        );
        // LES MÊMES OCTETS : le retrait ne change que l'enregistrement de structure, la fusion fait le même travail
        // que l'ancienne stratégie sur la même histoire (mêmes données, mêmes passes).
        let (octets_neufs, octets_anciens) =
            (octets_index(&db.lock(), "event_fts").expect("dbstat"), octets_index(&ancien.lock(), "event_fts").expect("dbstat"));
        assert_eq!(
            octets_neufs, octets_anciens,
            "T1 : après {CF1_CYCLES} cycles, l'index pèse les mêmes octets que sous l'ancienne stratégie"
        );

        // T5 — l'insertion et la recherche, sur la connexion de la compaction ET sur une connexion neuve.
        let c = db.lock();
        c.execute("INSERT INTO event(ts,source,category,message) VALUES(2,'sshd','auth','cf1sonde session')", [])
            .expect("T5 : une insertion d'événement réussit");
        assert_eq!(compte_match(&c, "cf1sonde"), 1, "T5 : la recherche trouve l'événement inséré");
        assert_eq!(compte_match(&c, "session"), compte_source(&c, "session"), "T5 : la recherche rend le compte de la source");
        c.execute("INSERT INTO event_fts(event_fts) VALUES('integrity-check')", []).expect("T5 : l'index est intègre pour FTS5");
        drop(c);
        let neuve = Connection::open(tmp.as_str()).expect("connexion neuve");
        assert_eq!(compte_match(&neuve, "cf1sonde"), 1, "T5 : une connexion neuve lit l'index");
    }

    // =============================================================================================
    // T2 — LE PLANCHER
    // =============================================================================================

    /// Un index CONVERGÉ (un segment, par `optimize`), puis deux lots d'ingestion, puis la purge des 12 000 plus
    /// anciens : le poids mort est dans le plus ancien segment, seul à son niveau.
    fn base_convergee_puis_purgee(etiquette: &str) -> (TmpDb, Arc<Mutex<Connection>>) {
        let (tmp, db, mut r) = base(etiquette, 20_000);
        {
            let c = db.lock();
            c.execute("INSERT INTO event_fts(event_fts) VALUES('optimize')", []).expect("fixture : optimize");
            inserer(&c, &mut r, 500);
            inserer(&c, &mut r, 500);
            c.execute("DELETE FROM event WHERE id <= 12000", []).expect("fixture : purge");
        }
        (tmp, db)
    }

    /// T2 — APRÈS UNE PURGE MASSIVE D'UN INDEX CONVERGÉ, LA COMPACTION ATTEINT LE PLANCHER D'UN `optimize` JOUÉ SUR
    /// UNE BASE JUMELLE (même histoire, mêmes octets au départ), à 2 % près. Contrôle : la purge a gonflé l'index
    /// d'au moins moitié au-dessus de ce plancher (sinon l'égalité serait vraie sans rien rendre).
    ///
    /// MUTATION : `CF1_BUDGET_POSITIF` (le budget passé positif) -> la fusion ne touche pas le segment le plus ancien,
    /// seul à son niveau, et l'index reste gonflé : ROUGE.
    #[test]
    fn t2_le_plancher_reste_atteint_apres_une_purge_massive() {
        let (_ta, a) = base_convergee_puis_purgee("cf1-plancher-a");
        let (_tb, b) = base_convergee_puis_purgee("cf1-plancher-b");
        let gonfle = octets_index(&a.lock(), "event_fts").expect("dbstat");
        assert_eq!(gonfle, octets_index(&b.lock(), "event_fts").expect("dbstat"), "contrôle : bases jumelles");
        b.lock().execute("INSERT INTO event_fts(event_fts) VALUES('optimize')", []).expect("optimize");
        let plancher = octets_index(&b.lock(), "event_fts").expect("dbstat");
        assert!(gonfle > plancher + plancher / 2, "contrôle : la purge a gonflé l'index ({gonfle} o, plancher {plancher} o)");
        let issues = compacter(&a, &tick("200", "500"));
        assert!(matches!(issues[0], Issue::Rendue { arret: Arret::Convergee, .. }), "convergence : {}", issues[0].phrase());
        let final_ = octets_index(&a.lock(), "event_fts").expect("dbstat");
        assert!(
            (final_ - plancher).abs() <= plancher / 50,
            "T2 : le plancher est atteint à 2 % près (gonflé {gonfle} o, compacté {final_} o, optimize {plancher} o) — {}",
            issues[0].phrase()
        );
        assert_eq!(issues[0].octets_rendus(), Some(gonfle - final_), "les octets annoncés sont les octets constatés");
    }

    // =============================================================================================
    // T3 — LA GARDE
    // =============================================================================================

    /// Une base à plusieurs segments (ingestion en lots, purge) et son chemin.
    fn base_a_fusionner(etiquette: &str) -> (TmpDb, Arc<Mutex<Connection>>) {
        let (tmp, db, _r) = base(etiquette, 20_000);
        db.lock().execute("DELETE FROM event WHERE id <= 12000", []).expect("fixture : purge");
        assert!(structure(&db.lock(), "event_fts").expect("structure").segments >= 2, "fixture : plusieurs segments");
        (tmp, db)
    }

    /// T3 — À L'ENTRÉE : au-delà du seuil (1 001 niveaux), AUCUNE passe, RIEN d'écrit (l'enregistrement de structure
    /// et les octets de l'index sont ceux d'avant, à l'octet), l'issue `NiveauxAuSeuil` sans octet annoncé et sa
    /// phrase ENTIÈRE ; AU SEUIL (1 000), la passe est jouée et le retrait ramène la structure à `CF1_CONSERVES`.
    ///
    /// MUTATIONS : `CF1_SEUIL_IGNORE` (garde d'entrée retirée) -> la garde de passe rend `Rendue` à zéro passe au lieu
    /// de l'issue typée : ROUGE ; `CF1_SEUIL_INVERSE` (`<` au lieu de `>`) -> idem à 1 001, refus à 1 000 : ROUGE ;
    /// `CF1_SEUIL_INCLUS` (`>=`) -> refus au seuil : ROUGE.
    /// `CF1_NIVEAUX_NON_SUIVIS` (l'issue garde les niveaux d'avant le retrait) -> 1 002 annoncés au lieu de 16 :
    /// ROUGE.
    #[test]
    fn t3_au_dela_du_seuil_aucune_passe_au_seuil_la_passe_est_jouee() {
        let r = Reglage::depuis(&tick("200", "8"));
        let (ta, a) = base_a_fusionner("cf1-garde-au-dela");
        gonfler(ta.as_str(), CF1_SEUIL + 1);
        let (bloc_avant, octets_avant) = { let c = a.lock(); (lire_bloc(&c), octets_index(&c, "event_fts").unwrap()) };
        let issue = compacter_index(&a, "event_fts", &r);
        assert!(matches!(issue, Issue::NiveauxAuSeuil { niveaux: 1001, .. }), "au-delà du seuil : issue typée — {}", issue.phrase());
        assert_eq!(issue.phrase(), cf1_phrase_garde(1001), "la phrase entière");
        assert_eq!(issue.octets_rendus(), None, "aucun octet annoncé");
        let c = a.lock();
        assert_eq!(lire_bloc(&c), bloc_avant, "rien n'est écrit : structure à l'octet");
        assert_eq!(octets_index(&c, "event_fts").unwrap(), octets_avant, "rien n'est écrit : index à l'octet");
        drop(c);

        // UNE seule passe permise : c'est la passe qui ajoute des niveaux, et son retrait, que l'issue doit dire.
        let (tb, b) = base_a_fusionner("cf1-garde-au-seuil");
        gonfler(tb.as_str(), CF1_SEUIL);
        let issue = compacter_index(&b, "event_fts", &Reglage::depuis(&tick("200", "1")));
        match &issue {
            Issue::Rendue { passes, niveaux_avant, niveaux_apres, .. } => {
                assert_eq!(*passes, 1, "au seuil : la passe est jouée — {}", issue.phrase());
                assert_eq!(*niveaux_avant, CF1_SEUIL, "au seuil : niveaux d'entrée annoncés");
                assert_eq!(*niveaux_apres, CF1_CONSERVES, "au seuil : le retrait ramène à {CF1_CONSERVES} — {}", issue.phrase());
            }
            autre => panic!("au seuil, une passe est jouée : {}", autre.phrase()),
        }
        assert_eq!(niveaux_lus(&b.lock()), CF1_CONSERVES, "relu");
    }

    /// T3 — LA GARDE PASSE AVANT « DÉJÀ COMPACT » : un index d'UN SEUL segment (après `optimize`) porté à 1 001
    /// niveaux rend `NiveauxAuSeuil`, phrase entière, rien d'écrit — pas « RIEN N'A ÉTÉ FAIT », qui tairait un index à
    /// mi-chemin de la limite du moteur. Contrôle : le même index à 1 000 niveaux est `DejaCompact`.
    ///
    /// MUTATION : `CF1_DEJA_COMPACT_D_ABORD` (le constat d'un segment testé avant la garde) -> « DÉJÀ COMPACT » à
    /// 1 001 : ROUGE.
    #[test]
    fn t3_un_index_d_un_segment_au_dela_du_seuil_rend_l_issue_de_la_garde() {
        let r = Reglage::depuis(&tick("200", "8"));
        for (cible, garde) in [(CF1_SEUIL + 1, true), (CF1_SEUIL, false)] {
            let (t, db, _r) = base(&format!("cf1-garde-un-segment-{cible}"), 2_000);
            db.lock().execute("INSERT INTO event_fts(event_fts) VALUES('optimize')", []).expect("fixture : optimize");
            gonfler(t.as_str(), cible);
            let bloc = lire_bloc(&db.lock());
            assert_eq!(structure(&db.lock(), "event_fts").expect("structure").segments, 1, "fixture : un seul segment");
            let issue = compacter_index(&db, "event_fts", &r);
            if garde {
                assert!(matches!(issue, Issue::NiveauxAuSeuil { niveaux: 1001, .. }), "1 001 niveaux, un segment : {}", issue.phrase());
                assert_eq!(issue.phrase(), cf1_phrase_garde(1001), "la phrase entière");
            } else {
                assert!(matches!(issue, Issue::DejaCompact { .. }), "contrôle : 1 000 niveaux, un segment : {}", issue.phrase());
            }
            assert_eq!(lire_bloc(&db.lock()), bloc, "{cible} : rien n'est écrit");
        }
    }

    /// T3 — AVANT CHAQUE PASSE DE LA SÉQUENCE : le crochet gonfle la structure à 1 001 niveaux juste après la
    /// première passe ; la deuxième n'est pas lancée, l'issue `Rendue` porte UNE passe et l'arrêt `NiveauxAuSeuil`,
    /// phrase entière ; gonflée à 1 000, la deuxième passe est jouée.
    ///
    /// MUTATIONS : `CF1_GARDE_DE_PASSE_IGNOREE` -> la deuxième passe est jouée à 1 001 : ROUGE ;
    /// `CF1_GARDE_DE_PASSE_INCLUSE` (`>=`) -> refus à 1 000 : ROUGE.
    #[test]
    fn t3_la_garde_relit_les_niveaux_avant_chaque_passe() {
        let r = Reglage::depuis(&tick("60", "8"));
        for (cible, refusee) in [(CF1_SEUIL + 1, true), (CF1_SEUIL, false)] {
            let (t, db) = base_a_fusionner(&format!("cf1-garde-de-passe-{cible}"));
            let chemin = t.as_str().to_string();
            let mut fois = 0usize;
            crochet_de_compaction::armer(PointDeTest::EntreLesPasses, Box::new(move |_c: &Connection| {
                fois += 1;
                if fois == 1 {
                    gonfler(&chemin, cible);
                }
            }));
            let issue = compacter_index(&db, "event_fts", &r);
            crochet_de_compaction::desarmer();
            match (&issue, refusee) {
                (
                    Issue::Rendue {
                        nom, octets_avant, octets_apres, segments_avant, segments_apres, niveaux_avant, niveaux_apres, docs,
                        passes: 1, duree_ms, arret: Arret::NiveauxAuSeuil { niveaux: 1001 },
                    },
                    true,
                ) => {
                    let mio = |o: i64| o as f64 / (1024.0 * 1024.0);
                    let rendus = octets_avant - octets_apres;
                    let pct = rendus as f64 * 100.0 / *octets_avant as f64;
                    let attendue = format!(
                        "[fts-compact] {nom} : {:.2} -> {:.2} Mio ({rendus} octets rendus à la freelist, {pct:.1} %) | \
                         segments {segments_avant} -> {segments_apres} | niveaux {niveaux_avant} -> {niveaux_apres} | docs {} | \
                         1 passe(s) en {duree_ms} ms | ARRÊTÉ : 1001 niveaux dans la structure, au-delà du seuil de 1000 — la \
                         passe suivante n'est PAS lancée (le moteur refuse de lire une structure de plus de 2000 niveaux) ; \
                         {CF1_REMEDE}",
                        mio(*octets_avant),
                        mio(*octets_apres),
                        docs.expect("docsize")
                    );
                    assert_eq!(issue.phrase(), attendue, "la phrase entière");
                    assert_eq!(niveaux_lus(&db.lock()), 1001, "la structure gonflée n'est pas touchée");
                }
                (Issue::Rendue { passes, arret, .. }, false) => {
                    assert!(*passes >= 2, "à 1 000 la deuxième passe est jouée — {}", issue.phrase());
                    assert!(!matches!(arret, Arret::NiveauxAuSeuil { .. }), "{}", issue.phrase());
                }
                (autre, _) => panic!("gonflée à {cible} entre deux passes : issue inattendue : {}", autre.phrase()),
            }
        }
    }

    /// AVANT CHAQUE PASSE, UNE STRUCTURE QUE PLUME NE SAIT PAS LIRE ARRÊTE LA SÉQUENCE : le crochet remplace
    /// l'enregistrement par un en-tête tronqué (`x'00000001'`, quatre octets : le cookie SEUL, sans aucun varint)
    /// juste après la première passe, par une connexion à part. FTS5 lirait le nombre de niveaux et de segments dans
    /// le remplissage à zéro qui suit l'enregistrement (sqlite3.c:233574 pose ce remplissage, sqlite3.c:233441-233442
    /// y lisent les deux varints), décoderait donc une structure vide et jouerait la passe ; la compaction ne la lance pas : UNE passe, arrêt `StructureIllisible`, phrase de l'arrêt, et
    /// l'enregistrement laissé tel quel.
    ///
    /// MUTATION : `CF1_ILLISIBLE_IGNOREE` (une structure illisible avant la passe lue comme vide) -> deux passes :
    /// ROUGE.
    #[test]
    fn une_structure_illisible_avant_la_passe_arrete_la_sequence() {
        let (t, db) = base_a_fusionner("cf1-illisible-avant-la-passe");
        let chemin = t.as_str().to_string();
        let mut fois = 0usize;
        crochet_de_compaction::armer(PointDeTest::EntreLesPasses, Box::new(move |_c: &Connection| {
            fois += 1;
            if fois == 1 {
                Connection::open(&chemin)
                    .expect("seconde connexion")
                    .execute("UPDATE event_fts_data SET block=x'00000001' WHERE id=10", [])
                    .expect("fixture : en-tête tronqué");
            }
        }));
        let issue = compacter_index(&db, "event_fts", &Reglage::depuis(&tick("60", "8")));
        crochet_de_compaction::desarmer();
        assert!(
            matches!(issue, Issue::Rendue { passes: 1, arret: Arret::StructureIllisible, .. }),
            "une passe, puis l'arrêt avant la suivante : {}",
            issue.phrase()
        );
        assert!(issue.phrase().contains(" | 1 passe(s) en "), "une passe dite : {}", issue.phrase());
        assert!(
            issue.phrase().ends_with(
                "| ARRÊTÉ : structure FTS5 devenue ILLISIBLE en cours de fusion — on ne sait plus combien de segments \
                 restent, la suite n'est pas tentée"
            ),
            "la phrase de l'arrêt : {}",
            issue.phrase()
        );
        assert_eq!(lire_bloc(&db.lock()), vec![0u8, 0, 0, 1], "l'enregistrement illisible n'est pas réécrit");
    }

    /// Les niveaux relevés après chaque passe du témoin suivant, fabriqués : le premier relevé (la fixture), puis
    /// deux niveaux de plus par passe (le chemin d'`optimize` repris à chaque segment déposé entre deux passes),
    /// jusqu'à `CF1_CONSERVES` où le retrait les arrête.
    const CF1_PREMIER_RELEVE: i64 = 8;
    const CF1_PASSES_DU_TICK: i64 = 8;

    /// APRÈS CHAQUE PASSE, ET PAS SEULEMENT LA PREMIÈRE DU TICK, LE RETRAIT : le crochet `EntreLesPasses` relève le
    /// nombre de niveaux (après la passe et son retrait) puis dépose un lot de 200 insertions par une SECONDE
    /// connexion, comme l'ingestion que la respiration laisse passer. Chaque passe suivante reprend alors le chemin
    /// d'`optimize` et ajoute deux niveaux : sans retrait, le tick franchirait `CF1_BORNE_NIVEAUX`. Relevés exacts :
    /// `CF1_PREMIER_RELEVE`, puis deux de plus par passe, plafonnés à `CF1_CONSERVES` ; aucun au-delà de
    /// `CF1_BORNE_NIVEAUX` ; le budget entier joué (huit passes, huit relevés, arrêt `BudgetEpuise`) ; l'issue annonce
    /// le dernier relevé.
    ///
    /// CONTRÔLE (sans lui la borne ne prouverait rien), tenu par l'égalité exacte des relevés : ils montent de deux
    /// par passe (l'ingestion intercalée rouvre bien le chemin d'`optimize`) et trois passes suivent celle qui atteint
    /// `CF1_CONSERVES` — sans le retrait à ces passes, elles porteraient la structure au-delà de la borne.
    ///
    /// MUTATION : le retrait joué à la seule première passe du tick -> relevés au-delà de `CF1_BORNE_NIVEAUX` : ROUGE.
    #[test]
    fn le_retrait_suit_chaque_passe_quand_l_ingestion_s_intercale() {
        let (t, db, r) = base("cf1-ingestion-entre-les-passes", 20_000);
        db.lock().execute("DELETE FROM event WHERE id <= 12000", []).expect("fixture : purge");
        let chemin = t.as_str().to_string();
        let releves: std::rc::Rc<std::cell::RefCell<Vec<i64>>> = Default::default();
        let note = releves.clone();
        let mut r = r;
        crochet_de_compaction::armer(PointDeTest::EntreLesPasses, Box::new(move |c: &Connection| {
            note.borrow_mut().push(niveaux_lus(c));
            let autre = Connection::open(&chemin).expect("seconde connexion");
            inserer(&autre, &mut r, 200);
        }));
        let issue = compacter_index(&db, "event_fts", &Reglage::depuis(&tick("60", &CF1_PASSES_DU_TICK.to_string())));
        crochet_de_compaction::desarmer();
        let releves = releves.borrow().clone();
        let attendus: Vec<i64> =
            (0..CF1_PASSES_DU_TICK).map(|k| (CF1_PREMIER_RELEVE + 2 * k).min(CF1_CONSERVES)).collect();
        println!("CF1-INGESTION-ENTRE-LES-PASSES releves={releves:?} attendus={attendus:?} — {}", issue.phrase());
        assert!(
            releves.iter().all(|&n| n <= CF1_BORNE_NIVEAUX),
            "après CHAQUE passe, le retrait : aucun relevé au-delà de {CF1_BORNE_NIVEAUX} — relevés {releves:?} — {}",
            issue.phrase()
        );
        assert_eq!(releves, attendus, "les niveaux relevés après chaque passe — {}", issue.phrase());
        match &issue {
            Issue::Rendue { passes, niveaux_apres, arret: Arret::BudgetEpuise, .. } => {
                assert_eq!(*passes, CF1_PASSES_DU_TICK, "le budget entier est joué — {}", issue.phrase());
                assert_eq!(*niveaux_apres, CF1_CONSERVES, "l'issue annonce le dernier relevé — {}", issue.phrase());
            }
            autre => panic!("ingestion entre les passes : issue inattendue : {}", autre.phrase()),
        }
    }

    /// JUSTE APRÈS UNE PASSE, UNE STRUCTURE QUI NE SE RELIT PAS ARRÊTE LA SÉQUENCE : un autorisateur refuse la SEULE
    /// lecture de `event_fts_data.block` qui suit la première passe (la relecture sous le verrou de la passe ; FTS5
    /// lit ses pages par des poignées de blob, que l'autorisateur ne voit pas). UNE passe, arrêt `StructureIllisible`,
    /// phrase de l'arrêt ; l'enregistrement, lui, est intact et se relit une fois l'autorisateur retiré.
    /// Contrôle : la lecture a été refusée UNE fois, et c'était bien la relecture d'après la passe (la passe a été
    /// préparée avant elle).
    ///
    /// MUTATION : la relecture d'après la passe, illisible, prise pour « rien à dire » (la séquence continue) ->
    /// plusieurs passes : ROUGE.
    #[test]
    fn une_structure_illisible_juste_apres_la_passe_arrete_la_sequence() {
        use std::sync::atomic::{AtomicU8, Ordering};
        use std::sync::Arc as ArcStd;
        let (_t, db) = base_a_fusionner("cf1-illisible-apres-la-passe");
        // 0 : avant la passe ; 1 : la passe est préparée ; 2 : la relecture qui la suit a été refusée.
        let etape = ArcStd::new(AtomicU8::new(0));
        let refus = ArcStd::new(AtomicU8::new(0));
        let (e, n) = (etape.clone(), refus.clone());
        db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } if table_name == "event_fts" && e.load(Ordering::SeqCst) == 0 => {
                e.store(1, Ordering::SeqCst);
                Authorization::Allow
            }
            AuthAction::Read { table_name, column_name }
                if table_name == "event_fts_data" && column_name == "block" && e.load(Ordering::SeqCst) == 1 =>
            {
                e.store(2, Ordering::SeqCst);
                n.fetch_add(1, Ordering::SeqCst);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        let issue = compacter_index(&db, "event_fts", &Reglage::depuis(&tick("60", "8")));
        sans_autorisateur(&db.lock());
        assert_eq!(refus.load(Ordering::SeqCst), 1, "contrôle : la relecture d'après la passe a été refusée une fois");
        assert!(
            matches!(issue, Issue::Rendue { passes: 1, arret: Arret::StructureIllisible, .. }),
            "une passe, puis l'arrêt sur la relecture refusée : {}",
            issue.phrase()
        );
        assert!(issue.phrase().contains(" | 1 passe(s) en "), "une passe dite : {}", issue.phrase());
        assert!(
            issue.phrase().ends_with(
                "| ARRÊTÉ : structure FTS5 devenue ILLISIBLE en cours de fusion — on ne sait plus combien de segments \
                 restent, la suite n'est pas tentée"
            ),
            "la phrase de l'arrêt : {}",
            issue.phrase()
        );
        assert!(structure(&db.lock(), "event_fts").is_some(), "l'enregistrement est intact : il se relit sans autorisateur");
    }

    /// CONTRÔLE DU MOTEUR (aucun mutant possible : c'est le moteur qu'on mesure) : à 2 000 niveaux une insertion
    /// réussit, à 2 001 elle ÉCHOUE en corruption. C'est le fait que la garde, la santé et leurs phrases citent.
    #[test]
    fn le_moteur_refuse_une_structure_de_plus_de_deux_mille_niveaux() {
        let (t, db, _r) = base("cf1-limite", 2_000);
        gonfler(t.as_str(), CF1_LIMITE);
        db.lock().execute("INSERT INTO event(ts,source,category,message) VALUES(3,'sshd','auth','limite')", [])
            .expect("à 2 000 niveaux l'insertion réussit");
        gonfler(t.as_str(), CF1_LIMITE + 1);
        let e = db.lock()
            .execute("INSERT INTO event(ts,source,category,message) VALUES(4,'sshd','auth','limite')", [])
            .expect_err("à 2 001 niveaux l'insertion échoue");
        assert_eq!(e.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseCorrupt), "en corruption : {e}");
    }

    /// LE REMÈDE, MESURÉ. (1) Au-delà du seuil, `rebuild` ramène la structure à deux niveaux et la compaction reprend.
    /// (2) La porte d'ouverture du démon NE reconstruit PAS un index de 1 500 niveaux (il se lit) — c'est pourquoi le
    /// remède nommé sous la limite est `rebuild` et non un redémarrage ; (3) elle reconstruit celui de 2 001 niveaux
    /// (sa table virtuelle ne se construit plus), compte de reconstructions à 1 — c'est le remède nommé au-delà.
    #[test]
    fn le_remede_nomme_est_celui_qui_retire_les_niveaux() {
        let (t, db) = base_a_fusionner("cf1-remede");
        gonfler(t.as_str(), CF1_SEUIL + 1);
        db.lock().execute("INSERT INTO event_fts(event_fts) VALUES('rebuild')", []).expect("rebuild");
        assert_eq!(niveaux_lus(&db.lock()), 2, "rebuild : une structure neuve, deux niveaux (mesuré)");
        let issue = compacter_index(&db, "event_fts", &Reglage::depuis(&tick("200", "8")));
        assert!(!matches!(issue, Issue::NiveauxAuSeuil { .. }), "après rebuild la compaction reprend : {}", issue.phrase());

        let tmp = crate::tmp_possede::TmpPossede::neuf("cf1-porte");
        let chemin = tmp.sous("plume.db").chemin().to_str().unwrap().to_string();
        drop(crate::db_open::PreparedDb::open(&chemin).expect("base neuve"));
        {
            let c = crate::db_open::open_db(&chemin).unwrap();
            for i in 0..3 {
                c.execute("INSERT INTO event(ts,source,severity,message) VALUES(?1,'cf1',1,'porte sonde')", params![i]).unwrap();
            }
            gonfler_par(&c, 1500);
        }
        let compte = |p: &str| {
            crate::db_open::open_db(p)
                .unwrap()
                .query_row("SELECT value FROM meta WHERE key='index_derive_reconstruit_event_fts'", [], |r| r.get::<_, String>(0))
                .ok()
        };
        drop(crate::db_open::PreparedDb::open(&chemin).expect("la porte ouvre un index de 1 500 niveaux"));
        assert_eq!(compte(&chemin), None, "la porte ne reconstruit pas un index qui se lit");
        assert_eq!(niveaux_lus(&crate::db_open::open_db(&chemin).unwrap()), 1500, "ses niveaux restent");
        gonfler_par(&crate::db_open::open_db(&chemin).unwrap(), CF1_LIMITE + 1);
        drop(crate::db_open::PreparedDb::open(&chemin).expect("la porte reconstruit puis sert"));
        assert_eq!(compte(&chemin).as_deref(), Some("1"), "la porte a reconstruit l'index devenu illisible");
        assert!(niveaux_lus(&crate::db_open::open_db(&chemin).unwrap()) <= 1, "reconstruit : structure neuve");
    }

    // =============================================================================================
    // LE RETRAIT, PUR
    // =============================================================================================

    fn structure_de(niveaux: Vec<Cf1Niveau>) -> Cf1Structure {
        Cf1Structure { cookie: [0, 0, 0, 7], compteur: 300, niveaux }
    }

    /// LE RETRAIT, PUR : les PLUS HAUTS vides d'abord jusqu'à `conserves`, jamais le niveau 0, segments et ordre
    /// recopiés à l'octet (enregistrement attendu écrit par le codec du témoin) ; un niveau en fusion reste devant son
    /// successeur ; rien à retirer -> `None` (assez peu de niveaux, ou aucun vide au-dessus du niveau 0) ; un nombre
    /// de niveaux écrit sur deux octets (au-delà de 127).
    ///
    /// MUTATIONS : `CF1_RETRAIT_PAR_LE_BAS` (vides retirés du bas) -> ROUGE ; `CF1_RETRAIT_DU_NIVEAU_ZERO` (boucle
    /// jusqu'au niveau 0) -> ROUGE ; `CF1_RETRAIT_SANS_PLANCHER` (tous les vides retirés) -> ROUGE ;
    /// `CF1_VARINT_SUR_UN_OCTET` (nombre de niveaux tronqué à 7 bits) -> ROUGE.
    #[test]
    fn le_retrait_pur_retire_les_plus_hauts_vides_et_rien_d_autre() {
        // 1 + 30 vides + 1 : on garde 16 = le niveau 0, les 14 vides les plus BAS, le sommet.
        let mut niv = vec![un(1)];
        niv.extend((0..30).map(|_| vide()));
        niv.push(Cf1Niveau { fusion: 0, segments: vec![(2, 1, 900), (3, 901, 950)] });
        let entree = cf1_encoder(&structure_de(niv));
        let mut attendu = vec![un(1)];
        attendu.extend((0..14).map(|_| vide()));
        attendu.push(Cf1Niveau { fusion: 0, segments: vec![(2, 1, 900), (3, 901, 950)] });
        let (neuf, avant, apres) = retrait_des_niveaux_vides(&entree, CF1_CONSERVES).expect("forme lue").expect("à retirer");
        assert_eq!((avant, apres), (32, 16));
        assert_eq!(neuf, cf1_encoder(&structure_de(attendu)), "l'enregistrement attendu, à l'octet");

        // Des vides AU MILIEU et un niveau en fusion : 0 vide, 1 en fusion -> 2 (son successeur), 3..=20 vides, 21.
        let mut niv = vec![vide(), Cf1Niveau { fusion: 1, segments: vec![(4, 1, 2)] }, Cf1Niveau { fusion: 0, segments: vec![(5, 1, 1)] }];
        niv.extend((0..18).map(|_| vide()));
        niv.push(un(6));
        let (neuf, avant, apres) = retrait_des_niveaux_vides(&cf1_encoder(&structure_de(niv.clone())), CF1_CONSERVES).unwrap().unwrap();
        assert_eq!((avant, apres), (22, 16));
        let mut attendu = niv[..3].to_vec();
        attendu.extend((0..12).map(|_| vide()));
        attendu.push(un(6));
        assert_eq!(neuf, cf1_encoder(&structure_de(attendu)), "le niveau 0 vide reste, la fusion reste devant son successeur");

        // DEUX plages de vides séparées par un niveau peuplé : les 7 retirés le sont dans la plage HAUTE.
        let mut niv = vec![un(1)];
        niv.extend((0..5).map(|_| vide()));
        niv.push(un(2));
        niv.extend((0..15).map(|_| vide()));
        niv.push(un(3));
        let (neuf, avant, apres) = retrait_des_niveaux_vides(&cf1_encoder(&structure_de(niv)), CF1_CONSERVES).unwrap().unwrap();
        assert_eq!((avant, apres), (23, 16));
        let mut attendu = vec![un(1)];
        attendu.extend((0..5).map(|_| vide()));
        attendu.push(un(2));
        attendu.extend((0..8).map(|_| vide()));
        attendu.push(un(3));
        assert_eq!(neuf, cf1_encoder(&structure_de(attendu)), "les plus hauts vides d'abord");

        // Rien à retirer.
        let mut peu = vec![un(1)];
        peu.extend((0..14).map(|_| vide()));
        peu.push(un(2));
        assert_eq!(retrait_des_niveaux_vides(&cf1_encoder(&structure_de(peu)), CF1_CONSERVES), Ok(None), "16 niveaux : rien");
        let pleins: Vec<Cf1Niveau> = (1..=20).map(un).collect();
        assert_eq!(retrait_des_niveaux_vides(&cf1_encoder(&structure_de(pleins)), CF1_CONSERVES), Ok(None), "aucun vide : rien");
        let mut seul_zero = vec![vide()];
        seul_zero.extend((1..=19).map(un));
        assert_eq!(retrait_des_niveaux_vides(&cf1_encoder(&structure_de(seul_zero)), CF1_CONSERVES), Ok(None), "seul le niveau 0 est vide : rien");

        // Un nombre de niveaux sur deux octets : 300 niveaux, on en garde 200.
        let mut grand = vec![un(1)];
        grand.extend((0..298).map(|_| vide()));
        grand.push(un(2));
        let (neuf, avant, apres) = retrait_des_niveaux_vides(&cf1_encoder(&structure_de(grand)), 200).unwrap().unwrap();
        assert_eq!((avant, apres), (300, 200));
        let mut attendu = vec![un(1)];
        attendu.extend((0..198).map(|_| vide()));
        attendu.push(un(2));
        assert_eq!(neuf, cf1_encoder(&structure_de(attendu)), "nombre de niveaux sur deux octets");
    }

    /// LES FORMES REFUSÉES, UNE PAR UNE, chacune avec la même phrase : trop court ; varint tronqué ; un octet de
    /// trop ; somme des segments différente de `nSegment` ; `nMerge > nSeg` ; des nombres de niveaux ou de segments
    /// énormes (refusés sans allocation ni débordement).
    ///
    /// MUTATIONS : `CF1_SANS_FIN_EXACTE`, `CF1_SANS_SOMME`, `CF1_SANS_FUSION_BORNEE` (chaque contrôle retiré) -> la
    /// forme correspondante passe : ROUGE.
    #[test]
    fn le_retrait_refuse_chaque_forme_incoherente() {
        let mut niv = vec![un(1)];
        niv.extend((0..30).map(|_| vide()));
        niv.push(un(2));
        let bon = cf1_encoder(&structure_de(niv));
        assert!(retrait_des_niveaux_vides(&bon, CF1_CONSERVES).unwrap().is_some(), "contrôle : la forme saine se retire");
        let refus = |b: &[u8], quoi: &str| {
            assert_eq!(retrait_des_niveaux_vides(b, CF1_CONSERVES), Err(CF1_FORME), "{quoi} : refusée");
        };
        refus(&bon[..5], "trop court");
        refus(&bon[..bon.len() - 1], "tronquée");
        let mut trop = bon.clone();
        trop.push(0);
        refus(&trop, "un octet de trop");
        // nSegment annoncé 3 pour 2 segments réels (l'octet de nSegment est le sixième : nLevel=32 tient un octet).
        let mut somme = bon.clone();
        assert_eq!(somme[5], 2, "contrôle du codec : nSegment");
        somme[5] = 3;
        refus(&somme, "somme des segments");
        // nMerge = 2 pour un niveau d'un segment.
        let mut fusion = bon.clone();
        let debut_niveaux = 4 + 1 + 1 + 2; // cookie, nLevel, nSegment, nWriteCounter (300 : deux octets)
        assert_eq!((fusion[debut_niveaux], fusion[debut_niveaux + 1]), (0, 1), "contrôle du codec : niveau 0");
        fusion[debut_niveaux] = 2;
        refus(&fusion, "nMerge > nSeg");
        // Des nombres énormes (varints de neuf octets) : refusés sans allocation ni débordement, au premier varint
        // manquant.
        let enorme = [0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut niveaux = vec![0, 0, 0, 7];
        niveaux.extend_from_slice(&enorme);
        niveaux.extend_from_slice(&[0, 0]);
        refus(&niveaux, "niveaux au-delà de l'enregistrement");
        let mut segments = vec![0, 0, 0, 7, 1, 0, 0, 0];
        segments.extend_from_slice(&enorme);
        refus(&segments, "segments au-delà de l'enregistrement");
    }

    // =============================================================================================
    // LE RETRAIT, ÉCRIT — chaque issue
    // =============================================================================================

    fn sans_autorisateur(c: &Connection) {
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// LE RETRAIT ÉCRIT RÉUSSIT : 40 niveaux -> 16, segments et documents intacts, FTS5 lit, la recherche rend le même
    /// compte, `integrity-check` passe ; rejoué, rien à retirer et l'enregistrement ne bouge pas.
    #[test]
    fn le_retrait_ecrit_reussit_puis_n_a_plus_rien_a_faire() {
        let (_t, db) = base_a_fusionner("cf1-retrait-ok");
        let c = db.lock();
        let avant = compte_match(&c, "session");
        let segs = structure(&c, "event_fts").unwrap().segments;
        gonfler_par(&c, 40);
        assert_eq!(retirer_les_niveaux_vides(&c, "event_fts"), Ok(Some((40, CF1_CONSERVES))));
        assert_eq!(niveaux_lus(&c), CF1_CONSERVES);
        assert_eq!(structure(&c, "event_fts").unwrap().segments, segs, "segments intacts");
        assert_eq!(compte_match(&c, "session"), avant, "même recherche");
        c.execute("INSERT INTO event_fts(event_fts) VALUES('integrity-check')", []).expect("intègre");
        assert!(c.is_autocommit(), "transaction refermée");
        let bloc = lire_bloc(&c);
        assert_eq!(retirer_les_niveaux_vides(&c, "event_fts"), Ok(None), "rejoué : rien à retirer");
        assert_eq!(lire_bloc(&c), bloc, "rien d'écrit");
    }

    /// CHAQUE REFUS DU RETRAIT ÉCRIT, phrase entière, structure d'avant conservée à l'octet, connexion hors transaction :
    /// structure non relue ; forme inconnue ; transaction déjà ouverte ; première sonde refusée ;
    /// réécriture refusée ; seconde sonde refusée ; validation refusée ; et l'annulation elle-même refusée (dite,
    /// connexion encore en transaction).
    ///
    /// MUTATIONS : `CF1_SANS_SONDE` (seconde sonde sautée) -> la seconde sonde refusée ne refuse plus : ROUGE ;
    /// `CF1_ANNULATION_MUETTE` (pas de ROLLBACK sur refus) -> connexion restée en transaction : ROUGE.
    #[test]
    fn chaque_refus_du_retrait_ecrit_laisse_la_structure_d_avant() {
        let (_t, db) = base_a_fusionner("cf1-retrait-refus");
        let c = db.lock();
        gonfler_par(&c, 40);
        let bloc = lire_bloc(&c);
        let juge = |c: &Connection, attendu: String, quoi: &str| {
            assert_eq!(retirer_les_niveaux_vides(c, "event_fts"), Err(attendu), "{quoi}");
            sans_autorisateur(c);
            assert!(c.is_autocommit(), "{quoi} : connexion hors transaction");
            assert_eq!(lire_bloc(c), bloc, "{quoi} : structure d'avant à l'octet");
        };
        c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == "event_fts_data" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        juge(&c, format!("structure non relue (access to event_fts_data.block is prohibited){CF1_ANNULE}"), "lecture refusée");

        let etrangere = "begin refusé fts-compact transaction_etrangere";
        let avant = crate::comptes_de_transaction::compte_des_temoins(&c, etrangere);
        c.execute_batch("BEGIN").unwrap();
        assert_eq!(
            retirer_les_niveaux_vides(&c, "event_fts"),
            Err("transaction du retrait non ouverte (cannot start a transaction within a transaction)".into()),
            "transaction déjà ouverte"
        );
        assert_eq!(crate::comptes_de_transaction::compte_des_temoins(&c, etrangere), avant + 1, "le refus est compté, cause nommée");
        c.execute_batch("ROLLBACK").unwrap();

        c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update { table_name, .. } if table_name == "event_fts_data" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        juge(&c, format!("structure non réécrite (not authorized){CF1_ANNULE}"), "réécriture refusée");

        c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } if table_name == "event_fts" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        juge(&c, format!("cache de structure de FTS5 non vidé (not authorized){CF1_ANNULE}"), "première sonde refusée");
        // La SECONDE sonde seule refusée : la première passe, la réécriture aussi, la seconde est refusée.
        let sondes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let compte = sondes.clone();
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } if table_name == "event_fts" => {
                if compte.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 { Authorization::Allow } else { Authorization::Deny }
            }
            _ => Authorization::Allow,
        }));
        juge(&c, format!("structure réécrite REFUSÉE par FTS5 (not authorized){CF1_ANNULE}"), "seconde sonde refusée");
        assert_eq!(sondes.load(std::sync::atomic::Ordering::SeqCst), 2, "contrôle : deux sondes préparées");

        c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        juge(&c, format!("retrait non validé (not authorized){CF1_ANNULE}"), "validation refusée");

        c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update { table_name, .. } if table_name == "event_fts_data" => Authorization::Deny,
            AuthAction::Transaction { operation: TransactionOperation::Rollback } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        assert_eq!(
            retirer_les_niveaux_vides(&c, "event_fts"),
            Err("structure non réécrite (not authorized) ; ANNULATION REFUSÉE (not authorized) — connexion encore en transaction : OUI".into()),
            "annulation refusée : dite"
        );
        sans_autorisateur(&c);
        assert!(!c.is_autocommit(), "contrôle : la connexion est bien restée en transaction");
        c.execute_batch("ROLLBACK").unwrap();
        assert_eq!(lire_bloc(&c), bloc, "structure d'avant");

        // Forme inconnue : un octet de trop (FTS5 l'ignorerait ; le retrait refuse, et annule).
        let mut trop = bloc.clone();
        trop.push(0);
        c.execute("UPDATE event_fts_data SET block=?1 WHERE id=10", params![trop]).unwrap();
        assert_eq!(retirer_les_niveaux_vides(&c, "event_fts"), Err(format!("{CF1_FORME}{CF1_ANNULE}")), "forme inconnue");
        assert!(c.is_autocommit());
        assert_eq!(lire_bloc(&c), trop, "rien d'écrit");
    }

    const CF1_ENFANT_BEGIN: &str = "CF1_ENFANT_BEGIN_REFUSE";

    /// UN `BEGIN` REFUSÉ DU RETRAIT EST DIT AU JOURNAL, ligne ENTIÈRE, une fois — capturée sur la sortie d'erreur
    /// d'un SOUS-PROCESSUS qui ne joue que ce témoin : la connexion porte déjà une transaction (celle d'un autre
    /// geste), le retrait ne l'ouvre ni ne la ferme, la ligne nomme le journal `fts-compact`, le geste et la cause.
    ///
    /// MUTATION : `CF1_BEGIN_NU` (un `BEGIN IMMEDIATE` nu au lieu de la forme commune) -> aucune ligne, aucun compte :
    /// ROUGE (ici et dans `chaque_refus_du_retrait_ecrit_laisse_la_structure_d_avant`).
    #[test]
    fn un_begin_refuse_du_retrait_est_dit_au_journal() {
        if std::env::var(CF1_ENFANT_BEGIN).is_ok() {
            let (_t, db) = base_a_fusionner("cf1-begin-journal");
            let c = db.lock();
            gonfler_par(&c, 40);
            c.execute_batch("BEGIN").unwrap();
            let r = retirer_les_niveaux_vides(&c, "event_fts");
            assert!(!c.is_autocommit(), "la transaction de l'autre geste reste la sienne");
            c.execute_batch("ROLLBACK").unwrap();
            println!("CF1-BEGIN:{r:?}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::cf1_niveaux_bornes::un_begin_refuse_du_retrait_est_dit_au_journal"])
            .env(CF1_ENFANT_BEGIN, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(
            stdout.contains("CF1-BEGIN:Err(\"transaction du retrait non ouverte (cannot start a transaction within a transaction)\")"),
            "contrôle : le retrait a été refusé à l'ouverture : {stdout}"
        );
        let ligne = "[fts-compact] ERREUR retrait des niveaux vides NON pris(e) : l'écrivain porte une transaction qui n'est \
                     pas la sienne (cannot start a transaction within a transaction) — rien n'est écrit, validé ni annulé à sa \
                     place ; l'écrivain reste bloqué tant que son geste ne la ferme pas";
        assert_eq!(stderr.lines().filter(|l| *l == ligne).count(), 1, "la ligne entière, une fois : {stderr}");
        assert_eq!(stderr.lines().filter(|l| l.starts_with("[fts-compact]")).count(), 1, "et aucune autre : {stderr}");
    }

    /// RIEN À RETIRER, ET LA TRANSACTION NE SE REFERME PAS : dit, avec l'état relu (l'annulation de secours est
    /// refusée elle aussi), puis refermée par le témoin ; rien d'écrit.
    #[test]
    fn rien_a_retirer_et_une_fermeture_refusee_est_dite() {
        let (_t, db) = base_a_fusionner("cf1-retrait-rien");
        let c = db.lock();
        let bloc = lire_bloc(&c);
        c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Rollback } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let r = retirer_les_niveaux_vides(&c, "event_fts");
        sans_autorisateur(&c);
        assert_eq!(
            r,
            Err("rien à retirer, transaction non refermée (not authorized) ; ANNULATION REFUSÉE (not authorized) — connexion \
                 encore en transaction : OUI".into())
        );
        assert!(!c.is_autocommit(), "contrôle : restée en transaction");
        c.execute_batch("ROLLBACK").unwrap();
        assert_eq!(lire_bloc(&c), bloc, "rien d'écrit");
    }

    /// UNE ANNULATION REFUSÉE PARCE QUE SQLITE A DÉJÀ TOUT ANNULÉ EST DITE AVEC L'ÉTAT RELU : « non ». La réécriture
    /// de la structure est INTERROMPUE (gestionnaire de progression armé au moment où elle est préparée, désarmé dès
    /// qu'il a interrompu) ; une écriture interrompue dans une transaction explicite fait annuler TOUTE la transaction
    /// par SQLite lui-même (`sqlite3VdbeHalt`, sqlite3.c:84253 — le cas de `SQLITE_FULL` et `SQLITE_IOERR`), et le
    /// `ROLLBACK` du retrait est alors refusé : plus aucune transaction. Phrase entière, connexion hors transaction,
    /// structure d'avant à l'octet.
    ///
    /// MUTATION : `CF1_ANNULATION_OUI_EN_DUR` (« OUI » écrit sans relire l'état) -> ROUGE.
    #[test]
    fn une_annulation_deja_faite_par_sqlite_est_dite_hors_transaction() {
        let (_t, db) = base_a_fusionner("cf1-retrait-interrompu");
        let c = db.lock();
        gonfler_par(&c, 40);
        let bloc = lire_bloc(&c);
        let arme = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let a_l_ecriture = arme.clone();
        c.authorizer(Some(move |ctx: AuthContext<'_>| {
            if let AuthAction::Update { table_name, .. } = ctx.action {
                if table_name == "event_fts_data" {
                    a_l_ecriture.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            Authorization::Allow
        }));
        let interrompre = arme.clone();
        c.progress_handler(1, Some(move || interrompre.swap(false, std::sync::atomic::Ordering::SeqCst)));
        let r = retirer_les_niveaux_vides(&c, "event_fts");
        sans_autorisateur(&c);
        c.progress_handler(0, None::<fn() -> bool>);
        assert_eq!(
            r,
            Err("structure non réécrite (interrupted) ; ANNULATION REFUSÉE (cannot rollback - no transaction is active) — \
                 connexion encore en transaction : non"
                .into())
        );
        assert!(c.is_autocommit(), "contrôle : SQLite a annulé la transaction lui-même");
        assert_eq!(lire_bloc(&c), bloc, "structure d'avant à l'octet");
    }

    /// LA LECTURE ET LA RÉÉCRITURE SOUS LE MÊME VERROU : au point situé juste après la lecture de la structure, une
    /// SECONDE connexion (attente nulle) tente d'insérer un événement — donc de déposer un segment. Elle est refusée
    /// (base occupée), le retrait aboutit, aucun segment n'est perdu (compte relu, `integrity-check` de FTS5) ; la
    /// même insertion, rejouée après, réussit.
    ///
    /// MUTATION : `CF1_LECTURE_HORS_TRANSACTION` (structure lue avant `BEGIN IMMEDIATE`, crochet compris) -> la
    /// seconde connexion insère, son segment est effacé de la structure par la réécriture : ROUGE.
    #[test]
    fn la_structure_est_lue_et_reecrite_sous_le_meme_verrou() {
        let (t, db) = base_a_fusionner("cf1-retrait-course");
        let chemin = t.as_str().to_string();
        let c = db.lock();
        gonfler_par(&c, 40);
        let segments = structure(&c, "event_fts").unwrap().segments;
        let concurrente: Arc<std::sync::Mutex<Option<Result<usize, rusqlite::Error>>>> = Arc::new(std::sync::Mutex::new(None));
        let note = concurrente.clone();
        crochet_de_compaction::armer(
            PointDeTest::ApresLaLectureDuRetrait,
            Box::new(move |_c: &Connection| {
                let autre = Connection::open(&chemin).expect("seconde connexion");
                autre.busy_timeout(std::time::Duration::ZERO).unwrap();
                let r = autre.execute("INSERT INTO event(ts,source,category,message) VALUES(5,'sshd','auth','course concurrente')", []);
                *note.lock().unwrap() = Some(r);
            }),
        );
        let r = retirer_les_niveaux_vides(&c, "event_fts");
        crochet_de_compaction::desarmer();
        let vue = concurrente.lock().unwrap().take().expect("le crochet a joué");
        assert_eq!(
            vue.as_ref().err().and_then(|e| e.sqlite_error_code()),
            Some(rusqlite::ErrorCode::DatabaseBusy),
            "l'insertion concurrente est refusée, base occupée : {vue:?}"
        );
        assert_eq!(r, Ok(Some((40, CF1_CONSERVES))));
        assert_eq!(structure(&c, "event_fts").unwrap().segments, segments, "aucun segment perdu");
        c.execute("INSERT INTO event_fts(event_fts) VALUES('integrity-check')", []).expect("intègre");
        c.execute("INSERT INTO event(ts,source,category,message) VALUES(5,'sshd','auth','course concurrente')", []).expect("rejouée");
        assert_eq!(compte_match(&c, "concurrente"), 1);
    }

    /// LA SECONDE SONDE DÉCODE CE QUI EST SUR LE DISQUE, MÊME QUAND LE CACHE DE STRUCTURE DE LA CONNEXION EST PLEIN.
    /// Le cache est rempli par une recherche ; puis, par la MÊME connexion (donc sans que `data_version` bouge),
    /// l'enregistrement est remplacé par une forme que le moteur refuse et que le découpage du retrait accepte : le
    /// premier niveau peuplé « en fusion » suivi de quarante niveaux vides (sqlite3.c:233493) — il en reste après le
    /// retrait, la forme reste refusée.
    /// Le retrait doit être REFUSÉ par FTS5, phrase entière, et l'enregistrement laissé tel quel.
    ///
    /// MUTATION : `CF1_SANS_VIDAGE` (la première sonde sautée) -> la seconde décode le cache, valide, et la forme
    /// refusée est commitée : ROUGE.
    #[test]
    fn la_seconde_sonde_decode_le_disque_meme_cache_plein() {
        let (_t, db) = base_a_fusionner("cf1-sonde-cache");
        let c = db.lock();
        assert!(compte_match(&c, "session") > 0, "fixture : une recherche remplit le cache de structure");
        let mut s = cf1_decoder(&lire_bloc(&c));
        let peuple = s.niveaux.iter().position(|n| !n.segments.is_empty()).expect("fixture : un niveau peuplé");
        s.niveaux[peuple].fusion = 1;
        for _ in 0..40 {
            s.niveaux.insert(peuple + 1, vide());
        }
        let refusee = cf1_encoder(&s);
        c.execute("UPDATE event_fts_data SET block=?1 WHERE id=10", params![refusee]).unwrap();
        assert_eq!(
            retirer_les_niveaux_vides(&c, "event_fts"),
            Err(format!("structure réécrite REFUSÉE par FTS5 (database disk image is malformed){CF1_ANNULE}")),
        );
        assert!(c.is_autocommit());
        assert_eq!(lire_bloc(&c), refusee, "l'enregistrement d'avant le retrait, à l'octet");
    }

    /// PAR LE POINT D'ENTRÉE : un retrait refusé arrête la séquence après la passe qui l'appelait, sous l'arrêt
    /// `NiveauxNonRetires`, phrase entière (la réécriture de la structure est refusée ; les écritures de FTS5, des
    /// insertions et des suppressions, passent).
    ///
    /// MUTATION : `CF1_RETRAIT_IGNORE` (le refus du retrait ignoré, la séquence continue) -> plus d'une passe : ROUGE.
    #[test]
    fn un_retrait_refuse_arrete_la_sequence_et_le_dit() {
        let (t, db) = base_a_fusionner("cf1-retrait-sequence");
        gonfler(t.as_str(), CF1_CONSERVES);
        db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update { table_name, .. } if table_name == "event_fts_data" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let issue = compacter_index(&db, "event_fts", &Reglage::depuis(&tick("60", "8")));
        sans_autorisateur(&db.lock());
        match &issue {
            Issue::Rendue {
                nom, octets_avant, octets_apres, segments_avant, segments_apres, niveaux_avant, niveaux_apres, docs,
                passes: 1, duree_ms, arret: Arret::NiveauxNonRetires(_),
            } => {
                assert_eq!(*niveaux_avant, CF1_CONSERVES);
                assert_eq!(*niveaux_apres, niveaux_lus(&db.lock()), "les niveaux relus après la passe, retrait refusé");
                assert!(*niveaux_apres > CF1_CONSERVES, "contrôle : la passe a ajouté des niveaux");
                let mio = |o: i64| o as f64 / (1024.0 * 1024.0);
                let rendus = octets_avant - octets_apres;
                let pct = rendus as f64 * 100.0 / *octets_avant as f64;
                let attendue = format!(
                    "[fts-compact] {nom} : {:.2} -> {:.2} Mio ({rendus} octets rendus à la freelist, {pct:.1} %) | \
                     segments {segments_avant} -> {segments_apres} | niveaux {niveaux_avant} -> {niveaux_apres} | docs {} | \
                     1 passe(s) en {duree_ms} ms | ARRÊTÉ : la dernière passe a committé mais ses niveaux vides n'ont PAS \
                     été retirés (structure non réécrite (not authorized){CF1_ANNULE}) — la suite n'est pas tentée",
                    mio(*octets_avant),
                    mio(*octets_apres),
                    docs.expect("docsize")
                );
                assert_eq!(issue.phrase(), attendue, "la phrase entière");
            }
            autre => panic!("un retrait refusé arrête la séquence après une passe : {}", autre.phrase()),
        }
    }

    // =============================================================================================
    // LA SANTÉ — pur (deux index, catalogue, filtre de nom)
    // =============================================================================================

    /// DEUX INDEX : chacun en cause ajoute SA phrase, dans l'ordre, le rouge l'emporte sur le jaune ; le plus grand
    /// est servi ; aucun index -> un vrai zéro ; une mesure illisible jaunit sans effacer un rouge du disque.
    ///
    /// MUTATIONS : `CF1_ALERTE_INCLUSE` (`>=`) -> 64 jaunit : ROUGE ; `CF1_LIMITE_INCLUSE` (`>=`) -> 2 000 rougit :
    /// ROUGE ; `CF1_PLUS_PETIT` (min au lieu de max) -> ROUGE ; `CF1_PREMIER_SEUL` (arrêt au premier index en cause)
    /// -> ROUGE.
    #[test]
    fn la_surface_des_niveaux_pour_plusieurs_index() {
        const D: &str = "disque données 40% utilisé (600 Mo libres / 1000 Mo)";
        let lus = Mesure::Lue(vec![("a_fts".to_string(), 2001), ("b_fts".to_string(), 65), ("c_fts".to_string(), 64)]);
        let (etat, detail) = etat_de_surface_niveaux("green", D.into(), &lus);
        assert_eq!(etat, "red");
        assert_eq!(
            detail,
            format!(
                "{D} ; `a_fts` : 2001 niveaux, AU-DELÀ de la limite du moteur (2000) : l'index ne se lit plus et toute insertion \
                 échoue ; {CF1_REMEDE_LIMITE} ; `b_fts` : 65 niveaux dans la structure de l'index plein-texte (alerte au-delà de \
                 64, compaction suspendue au-delà de 1000, illisible au-delà de 2000) ; remède : reconstruire l'index depuis sa \
                 source, démon arrêté : INSERT INTO b_fts(b_fts) VALUES('rebuild')"
            )
        );
        assert_eq!(plus_grand_nombre_de_niveaux(&lus), Mesure::Lue(2001));
        let bord = Mesure::Lue(vec![("a_fts".to_string(), 2000), ("c_fts".to_string(), 64)]);
        let (etat, _) = etat_de_surface_niveaux("green", D.into(), &bord);
        assert_eq!(etat, "yellow", "2 000 : jaune, pas rouge");
        let calme = Mesure::Lue(vec![("c_fts".to_string(), 64)]);
        assert_eq!(etat_de_surface_niveaux("green", D.into(), &calme), ("green", D.to_string()), "64 : rien");
        assert_eq!(plus_grand_nombre_de_niveaux(&Mesure::Lue(vec![])), Mesure::Lue(0), "aucun index : un vrai zéro");
        let illisible: Mesure<Vec<(String, i64)>> = Mesure::Illisible { cause: "source_illisible", detail: "x".into() };
        assert_eq!(etat_de_surface_niveaux("red", D.into(), &illisible).0, "red", "un rouge reste rouge");
    }

    /// `fts_levels` SERT LE PLUS GRAND NOMBRE, QUELLE QUE SOIT SA PLACE dans le catalogue (rangé par nom) : avec
    /// `PLUME_FTS_FIELDS=1`, `event_fields_fts` se range avant `event_fts`. Pur (le maximum au milieu, puis en dernier),
    /// puis par la lecture réelle d'une base aux deux index où le premier par nom porte le moins de niveaux.
    ///
    /// MUTATION : `CF1_PREMIER_INDEX` (le nombre du premier index au lieu du plus grand) -> 5 servi au lieu de 70 :
    /// ROUGE.
    #[test]
    fn le_plus_grand_nombre_de_niveaux_est_servi_quelle_que_soit_sa_place() {
        let lus = |v: &[(&str, i64)]| Mesure::Lue(v.iter().map(|(n, k)| (n.to_string(), *k)).collect::<Vec<_>>());
        assert_eq!(plus_grand_nombre_de_niveaux(&lus(&[("event_fields_fts", 5), ("event_fts", 70)])), Mesure::Lue(70), "en dernier");
        assert_eq!(plus_grand_nombre_de_niveaux(&lus(&[("a_fts", 3), ("b_fts", 900), ("c_fts", 7)])), Mesure::Lue(900), "au milieu");

        let (t, db, _r) = base("cf1-plus-grand-deux-index", 1_000);
        {
            let c = db.lock();
            c.execute_batch(
                "CREATE VIRTUAL TABLE event_fields_fts USING fts5(x); INSERT INTO event_fields_fts(x) VALUES('champ');",
            )
            .expect("fixture : un second index, premier par nom");
        }
        gonfler(t.as_str(), 70);
        let c = db.lock();
        let premier: Vec<u8> = c.query_row("SELECT block FROM event_fields_fts_data WHERE id=10", [], |r| r.get(0)).expect("structure");
        let n_premier = cf1_decoder(&premier).niveaux.len() as i64;
        assert!(n_premier < 70, "contrôle : le premier index par nom porte moins de niveaux ({n_premier})");
        let mesure = niveaux_des_index(&c);
        assert_eq!(mesure, Mesure::Lue(vec![("event_fields_fts".to_string(), n_premier), ("event_fts".to_string(), 70)]), "ordre du catalogue");
        assert_eq!(plus_grand_nombre_de_niveaux(&mesure), Mesure::Lue(70), "le plus grand, servi");
    }

    /// LA LECTURE DES NIVEAUX PAR INDEX : le catalogue non lu rend ILLISIBLE (jamais une liste vide) ; un index dont
    /// le nom n'est pas un identifiant sûr n'est pas lu ; une structure de forme inconnue est dite comme telle.
    ///
    /// MUTATIONS : `CF1_CATALOGUE_VIDE` (catalogue raté -> liste vide) -> ROUGE ; `CF1_SANS_FILTRE_DE_NOM` -> la
    /// table au nom non sûr est interpolée, la lecture échoue : ROUGE.
    #[test]
    fn la_lecture_des_niveaux_avoue_ce_qu_elle_n_a_pas_lu() {
        let (_t, db, _r) = base("cf1-lecture-niveaux", 1_000);
        let c = db.lock();
        c.execute_batch("CREATE VIRTUAL TABLE \"nom non sur\" USING fts5(x); INSERT INTO \"nom non sur\"(x) VALUES('a');").unwrap();
        let n = niveaux_lus(&c);
        assert_eq!(niveaux_des_index(&c), Mesure::Lue(vec![("event_fts".to_string(), n)]), "le nom non sûr est écarté");
        c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == "sqlite_master" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let lu = niveaux_des_index(&c);
        sans_autorisateur(&c);
        assert_eq!(
            lu,
            Mesure::Illisible { cause: "source_illisible", detail: "catalogue des index plein-texte non lu (access to sqlite_master.name is prohibited)".into() }
        );
    }

    // =============================================================================================
    // T4 — LA SANTÉ, PAR LA ROUTE
    // =============================================================================================

    const CF1_ENFANT: &str = "CF1_ENFANT_SANTE";
    const CF1_RENDU: &str = "CF1-RENDU:";
    const CF1_FIN: &str = "CF1-FIN:";
    const CF1_SEUIL_DISQUE: &str = "99";
    const CF1_NON_SUIVI: &str = "0";

    async fn cf1_get(addr: std::net::SocketAddr) -> (u16, Value) {
        let (code, brut) = router_probe_corps(addr, "GET", "/api/system/health", Some(&viewer_authz()), &[]).await;
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).expect("trame chunked")).expect("UTF-8")
        } else {
            corps.to_string()
        };
        (code, serde_json::from_str(&corps).unwrap_or(Value::Null))
    }

    /// T4 — PAR LA ROUTE `/api/system/health` (routeur réel, jeton du lecteur), DANS UN SOUS-PROCESSUS (posture
    /// isolée des comptes du processus de la suite) : AVANT, `store` est vert et sert `fts_levels` (le nombre relu par
    /// le codec du témoin) et `fts_levels_by_index`, posture VERTE (les autres composants verts ou inactifs, contrôlé
    /// à chaque issue) ; 64 niveaux : vert ; 65 : jaune, phrase entière, posture jaune ; 1 000 (le seuil) : jaune ;
    /// 2 000 : jaune ; 2 001 : ROUGE, phrase entière, posture rouge ; structure de forme inconnue : jaune, verdict
    /// `illisible`, cause `forme_inconnue`, aucune valeur servie ; structure non lue (lecture refusée) : jaune,
    /// cause `source_illisible`. Les clés du composant sont jugées EN ENTIER à chaque issue.
    ///
    /// MUTATION : `CF1_SANTE_IGNORE` (la surface rend l'état et le détail tels quels) -> vert à 65 : ROUGE.
    #[tokio::test]
    async fn t4_la_sante_servie_voit_les_niveaux() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CF1_ENFANT).is_ok() {
            let (mut st, _base) = router_test_state("cf1-sante");
            let file = crate::tmp_possede::TmpPossede::neuf("cf1-spool");
            st.spool = Arc::new(file.racine().as_str().to_string());
            let chemin = st.db_path.as_ref().clone();
            open_db(&chemin)
                .expect("fixture : base")
                .execute("INSERT INTO event(ts,source,severity,message,host,src_ip) VALUES(?1,'cf1',1,'cf1 sonde','cf1-h',NULL)", params![now()])
                .expect("fixture : un événement frais");
            let addr = router_serve(st.clone()).await;
            let mut rendus: Vec<Value> = Vec::new();
            let relu = niveaux_lus(&open_db(&chemin).unwrap());
            rendus.push(json!(["avant", relu, cf1_get(addr).await.1]));
            for cible in [CF1_ALERTE, CF1_ALERTE + 1, CF1_SEUIL, CF1_LIMITE, CF1_LIMITE + 1] {
                gonfler_par(&open_db(&chemin).unwrap(), cible);
                rendus.push(json!([format!("n{cible}"), cible, cf1_get(addr).await.1]));
            }
            let sain = lire_bloc(&open_db(&chemin).unwrap());
            open_db(&chemin).unwrap().execute("UPDATE event_fts_data SET block=x'00000001' WHERE id=10", []).unwrap();
            rendus.push(json!(["forme", 0, cf1_get(addr).await.1]));
            open_db(&chemin).unwrap().execute("UPDATE event_fts_data SET block=?1 WHERE id=10", params![sain]).unwrap();
            st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Read { table_name, .. } if table_name == "event_fts_data" => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            rendus.push(json!(["non_lue", 0, cf1_get(addr).await.1]));
            sans_autorisateur(&st.db.lock());
            for r in &rendus {
                println!("{CF1_RENDU}{r}");
            }
            println!("{CF1_FIN} {}", rendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::cf1_niveaux_bornes::t4_la_sante_servie_voit_les_niveaux"])
            .env(CF1_ENFANT, "1")
            .env("PLUME_DISK_WARN_PCT", CF1_SEUIL_DISQUE)
            .env(crate::copie_hors_site::REGLAGE_AGE_MAX_HEURES, CF1_NON_SUIVI)
            .env(crate::exercice_de_restauration::CLE_AGE_MAX_JOURS, CF1_NON_SUIVI)
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{CF1_FIN} 8")), "contrôle : huit issues jouées : {stdout}\n{stderr}");
        let rendus: Vec<Value> = stdout
            .lines()
            .filter_map(|l| l.split_once(CF1_RENDU))
            .map(|(_, v)| serde_json::from_str(v).expect("ligne de rendu lisible"))
            .collect();
        assert_eq!(rendus.len(), 8, "une ligne par issue");
        let rendu = |issue: &str| rendus.iter().find(|r| r[0] == issue).cloned().unwrap_or_else(|| panic!("{issue} rendu"));
        let store_de = |s: &Value| -> Value {
            let t: Vec<Value> = s["components"].as_array().expect("composants").iter().filter(|c| c["component"] == "store").cloned().collect();
            assert_eq!(t.len(), 1, "store une fois : {s}");
            t[0].clone()
        };
        let cles = |v: &Value| -> Vec<String> {
            let mut k: Vec<String> = v.as_object().expect("objet").keys().cloned().collect();
            k.sort();
            k
        };
        let attendues = |extra: &[&str]| -> Vec<String> {
            let mut v: Vec<String> = ["component", "db_size_bytes", "db_size_bytes_cause", "db_size_bytes_verdict", "detail",
                "disk_used_pct", "disk_used_pct_cause", "disk_used_pct_verdict", "state", "support_errors"]
                .iter().chain(extra.iter()).map(|s| s.to_string()).collect();
            v.sort();
            v
        };
        let lues = ["fts_levels", "fts_levels_by_index", "fts_levels_cause", "fts_levels_verdict"];
        let posture = |issue: &str, s: &Value, attendue: &str| {
            let comps = s["components"].as_array().expect("composants");
            assert!(comps.len() >= 2, "contrôle : {issue} : plusieurs composants");
            for c in comps.iter().filter(|c| c["component"] != "store") {
                assert!(c["state"] == "green" || c["state"] == "idle", "contrôle : {issue} : {} vert ou inactif : {s}", c["component"]);
            }
            assert_eq!(s["posture"], attendue, "{issue} : la posture suit `store` : {s}");
        };
        let disque = |store: &Value| -> String {
            let d = store["detail"].as_str().expect("détail");
            assert!(d.starts_with("disque données "), "le détail du disque en tête : {store}");
            d.split_once(" ; ").map(|(a, _)| a.to_string()).unwrap_or_else(|| d.to_string())
        };
        // VERT : avant et à 64.
        for issue in ["avant", "n64"] {
            let r = rendu(issue);
            let n = r[1].as_i64().expect("niveaux écrits");
            let s = &r[2];
            let store = store_de(s);
            assert_eq!(cles(&store), attendues(&lues), "{issue} : clés exactes : {store}");
            assert_eq!(store["fts_levels"], n, "{issue} : le nombre servi : {store}");
            assert_eq!(store["fts_levels_by_index"], json!({ "event_fts": n }), "{issue} : par index : {store}");
            assert_eq!((store["fts_levels_verdict"].as_str(), store["fts_levels_cause"].as_str()), (Some("lu"), Some("aucune")));
            assert_eq!(store["state"], "green", "{issue} : vert : {store}");
            assert_eq!(store["detail"].as_str().unwrap(), disque(&store), "{issue} : le détail du disque seul");
            posture(issue, s, "green");
        }
        assert!(rendu("avant")[1].as_i64().unwrap() < CF1_ALERTE, "contrôle : l'état d'avant est sous l'alerte");
        // JAUNE : 65, 1 000, 2 000.
        for (issue, n) in [("n65", 65i64), ("n1000", 1000), ("n2000", 2000)] {
            let s = &rendu(issue)[2];
            let store = store_de(s);
            assert_eq!(cles(&store), attendues(&lues), "{issue} : clés exactes : {store}");
            assert_eq!(store["fts_levels"], n);
            assert_eq!(store["state"], "yellow", "{issue} : jaune : {store}");
            assert_eq!(
                store["detail"].as_str().unwrap(),
                format!(
                    "{} ; `event_fts` : {n} niveaux dans la structure de l'index plein-texte (alerte au-delà de 64, compaction \
                     suspendue au-delà de 1000, illisible au-delà de 2000) ; {CF1_REMEDE}",
                    disque(&store)
                ),
                "{issue} : phrase entière"
            );
            posture(issue, s, "yellow");
        }
        // ROUGE : 2 001.
        let s = &rendu("n2001")[2];
        let store = store_de(s);
        assert_eq!(store["fts_levels"], 2001);
        assert_eq!(store["state"], "red", "2 001 : rouge : {store}");
        assert_eq!(
            store["detail"].as_str().unwrap(),
            format!(
                "{} ; `event_fts` : 2001 niveaux, AU-DELÀ de la limite du moteur (2000) : l'index ne se lit plus et toute \
                 insertion échoue ; {CF1_REMEDE_LIMITE}",
                disque(&store)
            )
        );
        posture("n2001", s, "red");
        // ILLISIBLE : forme inconnue, puis non lue.
        for (issue, cause, quoi) in [
            ("forme", "forme_inconnue", "structure de `event_fts` de forme inconnue"),
            ("non_lue", "source_illisible", "structure de `event_fts` non lue (access to event_fts_data.block is prohibited)"),
        ] {
            let s = &rendu(issue)[2];
            let store = store_de(s);
            assert_eq!(cles(&store), attendues(&["fts_levels_cause", "fts_levels_detail", "fts_levels_verdict"]), "{issue} : aucune valeur servie : {store}");
            assert_eq!((store["fts_levels_verdict"].as_str(), store["fts_levels_cause"].as_str()), (Some("illisible"), Some(cause)));
            assert_eq!(store["fts_levels_detail"], quoi);
            assert_eq!(store["state"], "yellow", "{issue} : jaune : {store}");
            assert_eq!(
                store["detail"].as_str().unwrap(),
                format!(
                    "{} ; niveaux de l'index plein-texte NON LUS ({quoi}) : impossible de dire si une structure approche la \
                     limite du moteur (2000 niveaux)",
                    disque(&store)
                )
            );
            posture(issue, s, "yellow");
        }
    }
}
