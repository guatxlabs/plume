    // ================================================================================================
    // LA FLOTTE — `event.dedup` CLOISONNÉ PAR HÔTE (cf. le bandeau de `ingest/store.rs`).
    //
    // CE QUE CES TESTS MESURENT, ET DANS QUEL ORDRE :
    //   1. la PERTE elle-même, par le VRAI chemin d'ingestion (`ingest_once` sur un vrai spool, avec le
    //      marqueur `#H#` que pose un jeton d'agent lié) — deux hôtes, une clé identique ;
    //   2. ce que le cloisonnement NE DOIT PAS casser : la réémission du spool (même hôte), le dédup
    //      horaire des signaux du daemon, le dédup VOLONTAIREMENT global de `alert` ;
    //   3. les propriétés de la fonction (injectivité, disjonction d'avec les clés héritées) ;
    //   4. la GARDE de source : aucune écriture de `event.dedup` ne peut se soustraire à la règle.
    // ================================================================================================

    /// Une enveloppe spool `kind=events` telle qu'un capteur en écrit une (`emit_event` de
    /// `collectors/lib.sh`). La FORME est celle mesurée le 2026-08-02 en faisant tourner les 36 capteurs
    /// livrés sur deux hôtes : `plume_report_availability` produit `avail-<capteur>-<cksum>-<ts/3600>`,
    /// où PAS UN SEUL des composants ne dépend de la machine — d'où l'identité des clés entre hôtes.
    fn enveloppe_avail(host: &str, ts: i64, capteur: &str) -> String {
        let fields = format!(
            "{{\"type\":\"collector-availability\",\"collector\":\"{capteur}\",\"collect_status\":\"unavailable\",\"reason\":\"binaire absent\",\"detail\":\"\"}}"
        );
        // clé VERBATIM du capteur : aucun hôte dedans (c'est le défaut mesuré).
        let dedup = format!("avail-{capteur}-1093417320-{}", ts / 3600);
        json!({
            "ts": ts, "host": host, "kind": "events",
            "events": [ {
                "ts": ts, "source": capteur, "category": "config", "severity": 2,
                "message": format!("capteur {capteur} unavailable : binaire absent — "),
                "dedup": dedup,
                "fields": serde_json::from_str::<Value>(&fields).unwrap()
            } ]
        })
        .to_string()
    }

    /// Dépose une enveloppe dans le spool AVEC le marqueur `#H#<host>#H#` — c'est ce que produit
    /// `ingest_post` pour un agent dont le jeton est LIÉ à un hôte, donc le host est ATTESTÉ côté
    /// serveur (`forced_host` ÉCRASE le host déclaré). Le nom porte un compteur pour que deux fichiers
    /// de la même seconde ne s'écrasent pas.
    fn depose_spool(spool: &std::path::Path, host: &str, n: u32, contenu: &str) -> std::path::PathBuf {
        let p = spool.join(format!("ingest-{}-{n}#H#{host}#H#.json", now()));
        std::fs::write(&p, contenu).unwrap();
        p
    }

    fn compte(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    /// (1) LA PERTE — DEUX HÔTES, MÊME PRÉREQUIS MANQUANT, MÊME CLÉ ÉMETTEUR.
    ///
    /// C'est le cas le plus COURANT d'un parc (les machines d'un même rôle manquent du même prérequis)
    /// et le plus grave : `avail-*` est la clé de l'aveu « capteur aveugle ». AVANT le cloisonnement,
    /// ce test rend 1 ligne au lieu de 2 — le second hôte disparaît sans un mot, et le SOC croit que
    /// UNE seule machine est aveugle. Le chemin est le VRAI : fichiers spool -> `ingest_once` ->
    /// `ingest_events_batch` -> `store().insert_event`.
    #[test]
    fn flotte_deux_hotes_meme_cle_les_deux_lignes_atterrissent() {
        let (st, spool) = ing_state_with_spool();
        let ts = 1_785_600_000i64;
        // 6 capteurs indisponibles, à l'identique sur les deux machines (parc homogène).
        let capteurs = ["auditd", "clamav", "suricata", "falco", "yara", "vuln"];
        for (i, c) in capteurs.iter().enumerate() {
            depose_spool(&spool, "web01", i as u32, &enveloppe_avail("web01", ts, c));
            depose_spool(&spool, "web02", 100 + i as u32, &enveloppe_avail("web02", ts, c));
        }
        ingest_once(&st.tenants, &st.spool);
        let conn = st.db.lock();
        let total = compte(&conn, "SELECT COUNT(*) FROM event WHERE category='config'");
        assert_eq!(
            total, 12,
            "12 aveux « capteur aveugle » ENVOYÉS (2 hôtes x 6 capteurs) -> 12 STOCKÉS. \
             Un total de 6 = la moitié de la flotte a disparu en silence (clé dedup sans hôte)."
        );
        for h in ["web01", "web02"] {
            assert_eq!(
                compte(&conn, &format!("SELECT COUNT(*) FROM event WHERE host='{h}' AND category='config'")),
                6,
                "chaque hôte doit être représenté par SES 6 aveux — {h}"
            );
        }
        // et l'hôte est celui ATTESTÉ par le marqueur, pas un host déclaré : la portée du dédup et la
        // colonne `host` sont la MÊME valeur, elles ne peuvent donc pas diverger.
        assert_eq!(compte(&conn, "SELECT COUNT(DISTINCT host) FROM event WHERE category='config'"), 2);
        drop(conn);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// (2a) CE QUE ÇA NE CASSE PAS — LA RÉÉMISSION DU SPOOL. Le spool REJOUE après une panne
    /// (`agent/src/buffer.rs`, quarantaine `ingest_once`) : un MÊME hôte qui réémet la MÊME clé doit
    /// rester dédoublonné. C'est l'argument qui impose le côté SERVEUR : le cloisonnement est une
    /// fonction PURE de `(host, dedup)`, donc la réémission reproduit la même clé cloisonnée.
    #[test]
    fn flotte_reemission_du_spool_reste_dedupliquee() {
        let (st, spool) = ing_state_with_spool();
        let ts = 1_785_600_000i64;
        let env = enveloppe_avail("web01", ts, "auditd");
        depose_spool(&spool, "web01", 1, &env);
        ingest_once(&st.tenants, &st.spool);
        // MÊME hôte, MÊME clé, 3 réémissions (contenu strictement identique) -> toujours 1 ligne.
        for n in 2..5 {
            depose_spool(&spool, "web01", n, &env);
        }
        ingest_once(&st.tenants, &st.spool);
        let conn = st.db.lock();
        assert_eq!(
            compte(&conn, "SELECT COUNT(*) FROM event WHERE category='config'"), 1,
            "4 émissions du MÊME hôte avec la MÊME clé -> 1 seule ligne (le dédup fait toujours son travail)"
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// (2b) CE QUE ÇA NE CASSE PAS — LE DÉDUP HORAIRE DES SIGNAUX DU DAEMON. `plume-disk` /
    /// `plume-ledger` / `plume-backup` / cold-aging émettent `…-<ts/3600>` avec `host='plume-daemon'`
    /// CONSTANT : le cloisonnement y est un no-op SÉMANTIQUE (toujours 1 signal/heure), et c'est
    /// vérifié plutôt que supposé. Ces dédups-là sont volontairement globaux À L'ÉCHELLE DU DAEMON.
    #[test]
    fn dedup_daemon_controle_reste_horaire() {
        let conn = test_db();
        let base = 1_785_600_000i64;
        // même heure -> 1 seule ligne, malgré 5 tentatives (crashloop de boot).
        for i in 0..5 {
            emit_ledger_unsigned(&conn, base + i * 60, "/vault/secrets/ledger.key");
        }
        assert_eq!(
            compte(&conn, "SELECT COUNT(*) FROM event WHERE source='plume-config' AND category='health'"), 1,
            "5 tentatives dans la MÊME heure -> 1 signal (rate-limit horaire préservé)"
        );
        // heure suivante -> une deuxième ligne (le rate-limit n'est pas devenu un bâillon).
        emit_ledger_unsigned(&conn, base + 3600, "/vault/secrets/ledger.key");
        assert_eq!(
            compte(&conn, "SELECT COUNT(*) FROM event WHERE source='plume-config' AND category='health'"), 2,
            "heure suivante -> le signal repasse (1/heure, pas 1 pour toujours)"
        );
    }

    /// (2c) `alert.dedup` N'EST PAS TOUCHÉ, ET C'EST UNE DÉCISION.
    ///
    /// Les clés de `alert` sont fabriquées PAR LE DAEMON, qui voit TOUTE la flotte, avec un grain
    /// DÉCLARÉ : `rule-{id}` = une alerte par ÉPISODE de règle ; l'opérateur qui veut du par-entité
    /// pose un `throttle_field` et obtient `rule-{id}::{unité}` (`host` compris). Cloisonner ça par
    /// hôte détruirait une décision au lieu d'en réparer une : une règle qui tire produirait N alertes
    /// identiques. Le test PROUVE la séparation des deux tables : la même clé nue sur `event` donne
    /// deux lignes (une par hôte), sur `alert` elle en donne UNE (portée flotte, voulue).
    #[test]
    fn dedup_alert_reste_global_par_decision() {
        let conn = test_db();
        let ts = 1_785_600_000i64;
        for h in ["web01", "web02"] {
            store()
                .insert_event(&conn, &EventRow {
                    ts, source: "auditd".into(), category: "config".into(), severity: 2,
                    message: "capteur aveugle".into(), host: Some(h.into()),
                    src_ip: None, dst_ip: None, url: None,
                    dedup: Some("cle-nue".into()), fields: None,
                    engagement_id: String::new(), origin: String::new(), env_id: None,
                })
                .unwrap();
            conn.execute(
                "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,host) VALUES(?1,'r',3,'t','d','cle-nue',?2)",
                params![ts, h],
            )
            .unwrap();
        }
        assert_eq!(compte(&conn, "SELECT COUNT(*) FROM event"), 2, "event : la portée d'unicité est l'HÔTE");
        assert_eq!(compte(&conn, "SELECT COUNT(*) FROM alert"), 1, "alert : la portée d'unicité reste la FLOTTE (voulu)");
    }

    /// (3a) INJECTIVITÉ — le cloisonnement ne peut pas rouvrir le trou qu'il ferme.
    ///
    /// Le host est LIBRE quand il est auto-déclaré (`/api/ingest` sans jeton lié), donc fabricable, et
    /// la clé émetteur l'est toujours. Avec un simple séparateur, `("a", "b␁c")` et `("a␁b", "c")`
    /// donneraient la même chaîne — une machine pourrait éteindre l'aveu d'une autre. Le préfixe de
    /// longueur rend l'encodage injectif pour TOUTE paire, y compris hostile : on le vérifie sur un
    /// produit cartésien de valeurs adverses (séparateurs, chiffres, vide, préfixes l'un de l'autre).
    #[test]
    fn dedup_cloisonnement_injectif() {
        let hotes = ["", "a", "a\u{1}b", "ab", "1", "1\u{1}", "web01", "web0", "\u{1}"];
        let cles = ["", "k", "b\u{1}c", "\u{1}k", "1\u{1}a\u{1}k", "avail-auditd-1-2"];
        let mut vus: std::collections::HashMap<String, (&str, &str)> = std::collections::HashMap::new();
        for h in hotes {
            for c in cles {
                let k = dedup_scoped_by_host(Some(h), Some(c)).unwrap();
                if let Some(prec) = vus.insert(k.clone(), (h, c)) {
                    panic!("COLLISION : ({prec:?}) et ({h:?}, {c:?}) produisent la MÊME clé {k:?}");
                }
            }
        }
        assert_eq!(vus.len(), hotes.len() * cles.len(), "toutes les paires distinctes -> clés distinctes");
        // `None` traverse : pas de clé émetteur = pas de dédup (comportement historique, jamais un dédup fabriqué).
        assert_eq!(dedup_scoped_by_host(Some("web01"), None), None);
        // host absent -> UNE portée partagée (chaîne vide), jamais moins de dédup qu'avant.
        assert_eq!(dedup_scoped_by_host(None, Some("k")), dedup_scoped_by_host(Some(""), Some("k")));
    }

    /// (3b) LES LIGNES DÉJÀ EN BASE — aucune migration n'est nécessaire, et c'est démontré, pas affirmé.
    ///
    /// Une clé HÉRITÉE (posée avant ce changement, donc SANS hôte) ne peut pas collisionner avec une
    /// clé cloisonnée : `json_escape` (collectors/lib.sh) supprime `\000-\037` de tout ce que les
    /// capteurs shell émettent, et les clés du daemon/des agents/journald sont de l'ASCII imprimable —
    /// aucune ne contient `\u{1}`. Les deux espaces sont donc DISJOINTS : la ligne ancienne reste, la
    /// nouvelle s'insère, RIEN n'est perdu. Prix exact et borné du changement : à la bascule, une
    /// ré-affirmation par (hôte, clé encore vivante).
    #[test]
    fn dedup_cloisonne_ne_collisionne_pas_avec_lheritage() {
        let conn = test_db();
        let ts = 1_785_600_000i64;
        // ligne HÉRITÉE : écrite en SQL direct avec la clé NUE, comme les millions déjà en base.
        conn.execute(
            "INSERT INTO event(ts,source,category,message,host,dedup) VALUES(?1,'auditd','config','ancien','web01','avail-auditd-1-2')",
            params![ts],
        )
        .unwrap();
        // la MÊME clé, ré-émise après la bascule, par le MÊME hôte.
        let n = store()
            .insert_event(&conn, &EventRow {
                ts: ts + 1, source: "auditd".into(), category: "config".into(), severity: 2,
                message: "nouveau".into(), host: Some("web01".into()),
                src_ip: None, dst_ip: None, url: None,
                dedup: Some("avail-auditd-1-2".into()), fields: None,
                engagement_id: String::new(), origin: String::new(), env_id: None,
            })
            .unwrap();
        assert_eq!(n, 1, "la clé cloisonnée ne heurte AUCUNE clé héritée -> la ligne s'écrit");
        assert_eq!(compte(&conn, "SELECT COUNT(*) FROM event"), 2, "l'ancienne ligne est INTACTE, la nouvelle est là");
        assert_eq!(
            compte(&conn, "SELECT COUNT(*) FROM event WHERE dedup='avail-auditd-1-2'"), 1,
            "la ligne héritée garde sa clé telle quelle (aucune migration, aucune réécriture)"
        );
        // et à partir de là, le dédup reprend NORMALEMENT sur la clé cloisonnée (pas de re-écriture en boucle).
        let n2 = store()
            .insert_event(&conn, &EventRow {
                ts: ts + 2, source: "auditd".into(), category: "config".into(), severity: 2,
                message: "nouveau bis".into(), host: Some("web01".into()),
                src_ip: None, dst_ip: None, url: None,
                dedup: Some("avail-auditd-1-2".into()), fields: None,
                engagement_id: String::new(), origin: String::new(), env_id: None,
            })
            .unwrap();
        assert_eq!(n2, 0, "2ᵉ passage du même hôte -> dédoublonné (le prix de la bascule est UNE ligne, pas une boucle)");
    }

    /// (3c) LES ÉMETTEURS WINDOWS DÉJÀ CORRIGÉS RESTENT CORRECTS. `Add-Event` (plume-collector.ps1) et
    /// `winxml_to_event` (agent/src/source/windows.rs) préfixent DÉJÀ l'hôte à leur clé. Le
    /// cloisonnement serveur produit alors un hôte redondant — redondant n'est pas cassé : la clé reste
    /// DÉTERMINISTE (réémission dédoublonnée) et distincte entre hôtes. On le prouve avec les clés
    /// EXACTES que ces deux émetteurs produisent (`<host>-<canal>-<EventRecordID>`).
    #[test]
    fn dedup_windows_deja_corrige_reste_correct() {
        let ts = 1_785_600_000i64;
        let k1 = dedup_scoped_by_host(Some("win-ep01"), Some("win-ep01-Security-91234"));
        let k2 = dedup_scoped_by_host(Some("win-ep02"), Some("win-ep02-Security-91234"));
        assert_ne!(k1, k2, "deux postes Windows, même EventRecordID -> clés distinctes (inchangé)");
        assert_eq!(k1, dedup_scoped_by_host(Some("win-ep01"), Some("win-ep01-Security-91234")),
                   "déterministe -> une réémission du même poste reste dédoublonnée");
        // AUCUNE régression de « double préfixe » : l'hôte apparaît deux fois, la clé reste une clé.
        let conn = test_db();
        for (h, d) in [("win-ep01", "win-ep01-Security-91234"), ("win-ep02", "win-ep02-Security-91234")] {
            for _ in 0..3 {
                let _ = store().insert_event(&conn, &EventRow {
                    ts, source: "WinEventLog:Security".into(), category: "exec".into(), severity: 1,
                    message: "4688".into(), host: Some(h.into()),
                    src_ip: None, dst_ip: None, url: None, dedup: Some(d.into()), fields: None,
                    engagement_id: String::new(), origin: String::new(), env_id: None,
                });
            }
        }
        assert_eq!(compte(&conn, "SELECT COUNT(*) FROM event"), 2, "2 postes x 3 envois -> 2 lignes (1 par poste)");
    }

    /// (3d) LA VOIE JOURNALD passe par le MÊME point d'écriture. Le curseur `__CURSOR` est déjà unique
    /// par hôte (il porte l'identifiant du fichier de journal), donc rien ne CHANGE ici — mais rien
    /// n'en dépendait non plus : la garantie vient du store, pas d'une propriété de journald. Deux
    /// hôtes qui présenteraient le MÊME curseur (journal cloné, image dorée, restauration de VM)
    /// atterrissent tous les deux.
    #[test]
    fn journald_deux_hotes_meme_curseur_les_deux_atterrissent() {
        let (st, spool) = ing_state_with_spool();
        let ligne = json!({ "__REALTIME_TIMESTAMP": "1785600000000000", "_COMM": "sshd",
                            "MESSAGE": "Failed password for invalid user root from 1.2.3.4 port 22",
                            "PRIORITY": "5", "__CURSOR": "s=abc;i=1;b=2;m=3;t=4;x=5" })
            .to_string();
        // marqueur `#H#` = hôte ATTESTÉ par le jeton d'agent -> deux machines, un curseur identique
        // (journal cloné : image dorée, restauration de VM).
        let poser = |n: u32, h: &str| {
            std::fs::write(spool.join(format!("jrnl-{}-{n}#H#{h}#H#.ndjson", now())), format!("{ligne}\n")).unwrap();
        };
        poser(1, "web01");
        poser(2, "web02");
        ingest_once(&st.tenants, &st.spool);
        {
            let conn = st.db.lock();
            assert_eq!(compte(&conn, "SELECT COUNT(*) FROM event"), 2, "un curseur cloné ne fait plus disparaître le 2ᵉ hôte");
        }
        // rejeu du MÊME hôte (contrat at-least-once de l'agent) -> toujours dédoublonné.
        poser(3, "web01");
        ingest_once(&st.tenants, &st.spool);
        {
            let conn = st.db.lock();
            assert_eq!(compte(&conn, "SELECT COUNT(*) FROM event"), 2, "rejeu du même hôte -> toujours dédoublonné");
        }
        let _ = std::fs::remove_dir_all(&spool);
    }

    // ------------------------------------------------------------------------------------------------
    // (4) LA GARDE DE SOURCE — ce que le compilateur ne ferme pas.
    //
    // Le COMPILATEUR ferme déjà le cas principal : `dedup_scoped_by_host(host, dedup)` prend l'hôte en
    // ARGUMENT, donc un appel qui l'oublie ne compile pas. Ce qu'il ne peut PAS fermer, c'est un
    // NOUVEAU `INSERT ... INTO event(…, dedup, …)` écrit ailleurs avec la clé nue — rien dans le type
    // système ne l'interdit. C'est exactement la forme du défaut qu'on répare (une écriture oubliée),
    // donc on la ferme par une lecture des SOURCES, dans les deux sens :
    //   (A) tout fichier de PRODUCTION qui écrit la colonne `dedup` de `event` doit AUSSI appeler le
    //       cloisonnement — sinon il expose la flotte, et le test le NOMME ;
    //   (B) anti-rot : l'extracteur doit continuer à VOIR des écritures (sinon un `INSERT` reformaté
    //       le rendrait aveugle et la garde passerait au vert en ne trouvant plus rien).
    // Le texte de test (`daemon/src/tests/`) et les items `#[cfg(test)]` en colonne 0 sont exclus :
    // une fixture qui plante une ligne à la main n'est pas un chemin d'écriture de production.
    // ------------------------------------------------------------------------------------------------

    /// Les `.rs` sous `racine`, récursivement (miroir du scanner de `db_open.rs`).
    fn dedup_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                dedup_rs_files(&p, out);
            } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }

    /// Les modules de test FICHIER, DÉRIVÉS des sources (`#[cfg(test)] mod x;`) et non listés à la main :
    /// pour chaque déclaration trouvée, `x.rs` ET `x/` (module-dossier) à côté du déclarant. C'est ainsi
    /// que `src/tests/` et `src/cold_store/tests.rs` sortent du périmètre sans être nommés — le jour où
    /// quelqu'un ajoute un troisième module de test, il sort tout seul.
    fn dedup_fichiers_de_test(fichiers: &[std::path::PathBuf]) -> std::collections::BTreeSet<std::path::PathBuf> {
        let mut out = std::collections::BTreeSet::new();
        for f in fichiers {
            let src = std::fs::read_to_string(f).unwrap();
            let l: Vec<&str> = src.lines().collect();
            for i in 0..l.len() {
                if l[i] != "#[cfg(test)]" {
                    continue;
                }
                let Some(decl) = l.get(i + 1) else { continue };
                let Some(reste) = decl.strip_prefix("mod ") else { continue };
                let Some(nom) = reste.strip_suffix(';') else { continue };
                let parent = f.parent().unwrap();
                out.insert(parent.join(format!("{nom}.rs")));
                out.insert(parent.join(nom));
            }
        }
        assert!(!out.is_empty(), "précondition : au moins un module de test FICHIER est déclaré");
        out
    }

    /// Texte de PRODUCTION : tout item `#[cfg(test)]` en colonne 0 est retiré (fail-closed si l'item
    /// n'est refermé ni par `;` ni par un `}` en colonne 0).
    fn dedup_texte_prod(f: &std::path::Path, src: &str) -> String {
        let l: Vec<&str> = src.lines().collect();
        let (mut out, mut i) = (String::new(), 0usize);
        while i < l.len() {
            if l[i] == "#[cfg(test)]" {
                let mut j = i + 1;
                while j < l.len() && l[j].starts_with("#[") {
                    j += 1;
                }
                assert!(j < l.len(), "{} : `#[cfg(test)]` sans item derrière", f.display());
                if l[j].ends_with(';') {
                    i = j + 1;
                    continue;
                }
                while j < l.len() && l[j] != "}" {
                    j += 1;
                }
                assert!(j < l.len(), "{} : item `#[cfg(test)]` non refermé en colonne 0 (fail-closed)", f.display());
                i = j + 1;
                continue;
            }
            out.push_str(l[i]);
            out.push('\n');
            i += 1;
        }
        out
    }

    /// L'ordre SQL commençant à `pos` écrit-il la colonne `dedup` de `event` ? On lit la LISTE DE
    /// COLONNES entre parenthèses (ClickHouse la termine par `VALUES` sans parenthèses, d'où la borne
    /// sur `)` OU sur la fin du littéral) et on y cherche la colonne, en séparateur exact — `dedup`
    /// entouré de `(,`/`,)`. Une sous-chaîne quelconque ne suffit pas (`dedup_key`, `deduped`…).
    fn ecrit_la_colonne_dedup(txt: &str, pos: usize) -> bool {
        let reste = &txt[pos..];
        let fin = reste.find(')').unwrap_or(reste.len().min(400));
        reste[..fin]
            .split(|c: char| matches!(c, '(' | ',' | ' ' | '\\' | '=' | '\n' | '?'))
            .any(|c| c.trim() == "dedup")
    }

    /// GARDE — AUCUNE écriture de `event.dedup` ne peut se soustraire au cloisonnement par hôte.
    #[test]
    fn event_dedup_toujours_cloisonne() {
        let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        dedup_rs_files(&racine, &mut fichiers);
        assert!(fichiers.len() > 20, "précondition : le scanner voit les sources ({})", fichiers.len());

        let marques = dedup_fichiers_de_test(&fichiers);
        let (mut ecritures, mut violations) = (Vec::<String>::new(), Vec::<String>::new());
        for f in &fichiers {
            if marques.iter().any(|m| f == m || f.starts_with(m)) {
                continue; // fixtures : pas un chemin d'écriture de production
            }
            let src = std::fs::read_to_string(f).unwrap();
            let txt = dedup_texte_prod(f, &src);
            let scope = txt.contains("dedup_scoped_by_host");
            // toutes les formes d'ordre d'écriture sur `event` : `INSERT [OR IGNORE|OR REPLACE] INTO event(`
            // et `UPDATE event SET` (aucune aujourd'hui ; la garde la couvre d'avance).
            let mut cherche = |motif: &str| {
                let mut d = 0usize;
                while let Some(p) = txt[d..].find(motif) {
                    let abs = d + p + motif.len() - 1; // sur la parenthèse ouvrante / le mot-clé
                    if ecrit_la_colonne_dedup(&txt, abs) {
                        let nom = f.file_name().unwrap().to_string_lossy().to_string();
                        ecritures.push(nom.clone());
                        if !scope {
                            violations.push(nom);
                        }
                    }
                    d = d + p + motif.len();
                }
            };
            cherche("INTO event(");
            cherche("UPDATE event SET");
        }

        assert!(
            violations.is_empty(),
            "ces fichiers écrivent `event.dedup` SANS appeler `dedup_scoped_by_host` -> ils exposent la \
             flotte à la perte silencieuse qu'on vient de fermer (deux machines, une clé, une ligne \
             jetée). Appelez `ingest::store::dedup_scoped_by_host(host, dedup)` sur la valeur écrite : \
             {violations:?}"
        );
        // ANTI-ROT — la garde ci-dessus est VACUE si l'extracteur ne voit plus rien : `violations` serait
        // vide parce qu'on n'a rien regardé, et le vert ne voudrait rien dire. On fixe donc CE QUE
        // L'EXTRACTEUR DOIT VOIR, mesuré le 2026-08-02 :
        //   store.rs (tier chaud SQLite) · duckdb_store.rs (WARM) · clickhouse_store.rs (COLD) · seeds.rs x2 (démo).
        ecritures.sort();
        assert_eq!(
            ecritures,
            vec!["clickhouse_store.rs", "duckdb_store.rs", "seeds.rs", "seeds.rs", "store.rs"],
            "ANTI-ROT : l'ensemble des écritures de `event.dedup` VUES par l'extracteur a changé. \
             (a) si un `INSERT` a été reformaté et n'est plus reconnu -> c'est l'EXTRACTEUR qu'il faut \
             réparer, sinon la garde passe au vert en ne regardant rien ; (b) si un backend a été ajouté \
             ou retiré LÉGITIMEMENT -> vérifiez qu'il appelle `dedup_scoped_by_host` et mettez cette liste à jour."
        );
    }

    /// GARDE P3.6-b — AUCUNE SURFACE D'INGESTION N'ÉCRIT DANS `event` EN DIRECT.
    ///
    /// LE DÉFAUT QU'ELLE FERME, VÉRIFIÉ LE 2026-08-04 : `loki_push` écrivait un `INSERT` à 7 colonnes
    /// directement dans `event`, donc il SAUTAIT `ingest_events_batch`. Conséquence RÉELLE : les
    /// processeurs d'ingestion — DROP, **MASK (redaction PII)** et ROUTE — ne s'appliquaient PAS aux
    /// logs entrés par Loki, pendant que `processors.rs` affirmait le contraire en nommant Loki parmi
    /// les surfaces couvertes.
    ///
    /// POURQUOI LA GARDE VOISINE NE POUVAIT PAS LE VOIR (P3.6-c) : `event_dedup_toujours_cloisonne`
    /// ne se déclenche QUE si l'ordre MENTIONNE la colonne `dedup`. Elle contrôle **la FORME de la
    /// clé**, jamais **la PRÉSENCE du mécanisme** — un chemin qui omet tout lui est invisible.
    ///
    /// LA PARTITION EST FERMÉE PAR LE RÉPERTOIRE, PAS PAR UNE LISTE DE FICHIERS : tout `.rs` de
    /// production sous `src/ingest/` est concerné, donc une surface ajoutée demain est couverte sans
    /// que personne ait à s'en souvenir. L'EXEMPTION est STRUCTURELLE et non nominative : seul un
    /// fichier qui IMPLÉMENTE le SPI (`EventStore for`) a le droit d'écrire — c'est sa définition
    /// même. Un backend ajouté demain est donc exempté par construction ; une surface d'ingestion qui
    /// écrit en direct ne l'est jamais.
    ///
    /// SCANNER RÉUTILISÉ (`db_open::door_tests`) plutôt que recopié : il retire AUSSI les
    /// commentaires, ce que `dedup_texte_prod` ne fait pas — sans quoi un commentaire citant
    /// `INTO event(` (il y en a un, qui documente précisément ce défaut) ferait rougir la garde.
    #[test]
    fn aucune_surface_dingestion_necrit_dans_event_en_direct() {
        use crate::db_open::door_tests::{est_test, fichiers_de_test, rs_files, texte_de_production};
        let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src").join("ingest");
        let mut fichiers = Vec::new();
        rs_files(&racine, &mut fichiers);
        assert!(fichiers.len() > 5, "précondition : le scanner voit src/ingest ({})", fichiers.len());

        let marques = fichiers_de_test(&fichiers);
        let (mut ecrivains, mut violations) = (Vec::<String>::new(), Vec::<String>::new());
        for f in &fichiers {
            if est_test(f, &marques) {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            let txt: String = texte_de_production(f, &src)
                .into_iter()
                .map(|(_, l)| l)
                .collect::<Vec<_>>()
                .join("\n");
            if !txt.contains("INTO event(") {
                continue;
            }
            let nom = f.file_name().unwrap().to_string_lossy().to_string();
            ecrivains.push(nom.clone());
            if !txt.contains("EventStore for") {
                violations.push(nom);
            }
        }

        // ANTI-ROT : sans ce contrôle, la garde serait VACUE le jour où le scanner ne reconnaît plus
        // les `INSERT` — `violations` vide parce qu'on n'a rien regardé, et le vert ne voudrait rien
        // dire. Mesuré le 2026-08-04 : SEULES les trois implémentations du SPI écrivent.
        ecrivains.sort();
        assert_eq!(
            ecrivains,
            vec!["clickhouse_store.rs", "duckdb_store.rs", "store.rs"],
            "ANTI-ROT : l'ensemble des fichiers de `src/ingest` qui écrivent dans `event` a changé. \
             (a) si un `INSERT` n'est plus reconnu -> réparer l'EXTRACTEUR, sinon la garde passe au \
             vert en ne regardant rien ; (b) si un BACKEND a été ajouté légitimement -> il doit \
             implémenter `EventStore` et cette liste se met à jour."
        );
        assert!(
            violations.is_empty(),
            "une SURFACE D'INGESTION écrit dans `event` SANS passer par le point de passage unique : \
             les processeurs (DROP / MASK-redaction-PII / ROUTE) ne s'y appliqueront PAS, et \
             `processors.rs` affirme pourtant qu'ils couvrent toutes les surfaces. Passez par \
             `ingest_events_batch(_env)` — ou, s'il s'agit d'un backend de store, implémentez \
             `EventStore`. Fichiers fautifs : {violations:?}"
        );
    }

