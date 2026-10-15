// `P10.33-g` — UNE SOUS-COMMANDE NE FAIT PAS NAÎTRE LA BASE, DONC NE LA FAIT PAS NAÎTRE EN CLAIR
// ================================================================================================
// LE DÉFAUT. Huit sites de sous-commande ouvrent la base par `PreparedDb::open`, qui n'applique que la
// clé de l'environnement (`db_key()` : clé explicite, ou clé auto DÉJÀ posée). Sur une base absente et
// sans clé explicite, `Connection::open` crée le fichier, la porte y écrit le schéma EN CLAIR. Au
// démarrage suivant, `decision_at_rest` voit « aucune clé, base `Existante` » et rend `RienAFaire` :
// la base reste en clair pour de bon, sans un mot. Le témoin ③ le MESURE (en-tête `SQLite format 3`).
// SEPT de ces huit sites y arrivaient en clair. Le huitième, le signal de posture APRÈS une sauvegarde
// (`backup --compress`), ne s'atteint qu'après `backup_compressed`, qui EXIGE `PLUME_DB_KEY`
// (backup/dump_restauration.rs) : la porte y aurait créé la base CHIFFRÉE. La garde y est défensive.
//
// CE QUI ÉTAIT FAUX DANS L'ÉNONCÉ : « sept sites ». Il y en a HUIT — le huitième est le responder
// local (`handlers/actions.rs::respond_run`), lancé en ROOT par un minuteur, le plus atteignable.
//
// LE REMÈDE : `refuser_une_base_absente` (crypto/mod.rs), appelée AVANT chaque ouverture, refuse une
// base `Neuve` en nommant le geste non fait. Écarté : appeler `ensure_encrypted` depuis la CLI (la clé
// auto naîtrait propriété de root, illisible par le démon ; `exit(78)` et la destruction d'une copie
// en clair, dans une CLI lancée à côté d'un démon vivant). La SEULE naissance admise est celle du
// démon (`server::open_and_migrate_db`), précédée de `ensure_encrypted` : le balayage ② la nomme.
//
// MUTANTS JOUÉS (par variable d'environnement, retirés avant le commit) : T1_NEUVE_OK,
// T1_ZERO_OCTET_OK, T1_INDECIDABLE_REFUSE, T1_SANS_GESTE (dans l'aide), T1_SITE_ABSENT ; puis, sur le
// texte lu par le balayage : un refus suivi d'un `else {}` vide (token, retention, signal post-
// sauvegarde), une sortie conditionnelle, une sortie en 0 (retention), en 1 au lieu de 2 (purge), une
// sous-commande neuve par `open_with_prelude`, la naissance du démon privée de `ensure_encrypted` ; et
// dans le balayage lui-même : sans le contrôle du `else` refermé, sans le code de sortie, sans
// `open_with_prelude`. Puis : un site qui refuse SANS LE DIRE (token, respond, signal post-sauvegarde :
// leur `eprintln!` retiré), un refus neutralisé par un repli (`.or_else(…)` derrière PLUME_FORCE),
// une sortie sous `#[cfg(…)]`, le chemin redéfini entre la garde et l'ouverture, la naissance du démon
// conditionnelle sur une ligne ; dans le balayage : sans le refus DIT, sans l'ordre « dit puis sort »,
// la forme assouplie (sous-chaîne `if let Err(e) = …(<chemin>,` puis `…(<chemin>,` seule), sans le
// contrôle des attributs, sans celui de la redéfinition, la naissance jugée par `contains` ; et à
// l'exécution ④ : l'aide qui laisse passer une base neuve, un site qui écrit sa phrase sans l'erreur.
//
// CE QUE CE FICHIER NE TIENT PAS : deux sous-commandes seulement sont EXÉCUTÉES de bout en bout (④ :
// `token` et `respond`, par `main` en sous-processus) ; les six autres prennent des arguments que
// libtest refuserait (`purge --since …`) ou un état préalable (sauvegarde, dépôt Sigma) : leur câblage
// est tenu par le balayage de source ②, qui lit la FORME et non le sens (une erreur `e` vidée avant
// son `eprintln!` lui échapperait, ④ l'attrape pour les deux sites exécutés) ; une base DÉJÀ née en clair reste
// en clair, sans relevé ni alerte (`RienAFaire` par conception) ; une ouverture par un autre chemin que
// `PreparedDb::open`/`open_with_prelude` (les `open_keyed*` portent leur clé, `open_db_without_schema_contract`
// n'écrit aucun octet) ; la propriété root des fichiers créés par une CLI sous `sudo`.
mod sous_commandes_refusent_une_base_absente {
    use super::*;
    use crate::db_open::door_tests::{est_test, fichiers_de_test, rs_files, texte_de_production};

    /// Comment une ouverture par la porte est gardée.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Garde {
        /// La branche du refus sort du processus, avec ce code (jamais 0 : `$?` le lirait comme un succès).
        Sort(i32),
        /// L'ouverture vit dans le `else` du refus (site best-effort, qui ne doit pas casser le geste fait).
        Else,
        /// Naissance par le démon : `ensure_encrypted` la précède dans le même bloc.
        Naissance,
    }

    /// L'ENSEMBLE NOMMÉ des ouvertures par la porte en production : (fichier relatif à `src/`, bras de
    /// `main` ou fonction englobante, garde ET code de sortie). Jugé dans les DEUX sens : un site neuf
    /// non listé rougit, un site listé qui disparaît rougit, un code de sortie qui change rougit.
    const SITES_ATTENDUS: [(&str, &str, Garde); 9] = [
        ("handlers/actions.rs", "respond_run", Garde::Sort(1)),
        ("main.rs", "backup", Garde::Else),
        ("main.rs", "fts-compact", Garde::Sort(1)),
        ("main.rs", "restore-drill", Garde::Sort(1)),
        ("main.rs", "retention", Garde::Sort(1)),
        ("main.rs", "sigma-import", Garde::Sort(1)),
        ("main.rs", "token", Garde::Sort(1)),
        ("purge.rs", "purge_cli", Garde::Sort(2)),
        ("server/mod.rs", "open_and_migrate_db", Garde::Naissance),
    ];

    /// Les deux ouvertures qui n'appliquent QUE la clé de l'environnement (`raw_env`, db_open.rs).
    const OUVERTURES: [&str; 2] = ["PreparedDb::open(", "PreparedDb::open_with_prelude("];

    const ENTETE_EN_CLAIR: &[u8; 16] = b"SQLite format 3\0";

    // ── ① L'AIDE, SUR DE VRAIS FICHIERS ─────────────────────────────────────────────────────────

    /// MUTANTS : T1_NEUVE_OK (absent accepté), T1_ZERO_OCTET_OK (0 octet accepté),
    /// T1_INDECIDABLE_REFUSE (incertitude refusée), T1_SANS_GESTE (message muet sur le geste).
    #[test]
    fn p10_33g_l_aide_refuse_une_base_neuve_et_laisse_passer_le_reste() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-aide");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let p = |n: &str| dir.join(n).to_string_lossy().into_owned();

        // Absent : refus, qui nomme le fichier, le geste non fait et le remède.
        let absente = p("absente.db");
        assert_eq!(etat_du_fichier_de_base(&absente), EtatDuFichierDeBase::Neuve, "fixture : absente = Neuve");
        let e = refuser_une_base_absente(&absente, "geste-p1033g").expect_err("base ABSENTE : la sous-commande refuse");
        assert!(e.contains(&absente), "le refus nomme le fichier : {e}");
        assert!(e.contains("geste-p1033g NON exécuté"), "le refus nomme le geste NON exécuté : {e}");
        assert!(e.contains("Démarrez le démon une première fois"), "le refus dit le remède : {e}");
        assert!(!std::path::Path::new(&absente).exists(), "l'aide ne crée rien");

        // 0 octet : c'est encore une base neuve (le démarrage y engendrerait la clé) -> refus.
        let vide = p("vide.db");
        std::fs::write(&vide, b"").unwrap();
        assert_eq!(etat_du_fichier_de_base(&vide), EtatDuFichierDeBase::Neuve, "fixture : 0 octet = Neuve");
        assert!(refuser_une_base_absente(&vide, "g").is_err(), "fichier de 0 octet : refus");

        // 0 octet MAIS un WAL non vide : quelque chose a vécu ici -> on laisse passer.
        std::fs::write(format!("{vide}-wal"), b"des octets qui prouvent une vie").unwrap();
        assert_eq!(etat_du_fichier_de_base(&vide), EtatDuFichierDeBase::Existante, "fixture : WAL non vide");
        assert!(refuser_une_base_absente(&vide, "g").is_ok(), "0 octet + WAL non vide : Existante, accepté");

        // Non vide : accepté.
        let pleine = p("pleine.db");
        std::fs::write(&pleine, b"des octets").unwrap();
        assert!(refuser_une_base_absente(&pleine, "g").is_ok(), "fichier non vide : accepté");

        // Indécidable (un composant du chemin est un FICHIER) : on ne conclut pas, l'ouverture dira.
        let sous_un_fichier = format!("{pleine}/impossible.db");
        assert_eq!(etat_du_fichier_de_base(&sous_un_fichier), EtatDuFichierDeBase::Indecidable, "fixture : Indecidable");
        assert!(refuser_une_base_absente(&sous_un_fichier, "g").is_ok(), "Indecidable : pas de refus inventé");
    }

    // ── ② LE CÂBLAGE : BALAYAGE DU TEXTE DE PRODUCTION ─────────────────────────────────────────

    /// Retire le contenu des littéraux `"…"` : une accolade dans un message ne compte pas.
    fn hors_litteraux(l: &str) -> String {
        let (mut out, mut dans, mut echap) = (String::new(), false, false);
        for c in l.chars() {
            if dans {
                if echap {
                    echap = false;
                } else if c == '\\' {
                    echap = true;
                } else if c == '"' {
                    dans = false;
                    out.push('"');
                }
                continue;
            }
            if c == '"' {
                dans = true;
            }
            out.push(c);
        }
        out
    }

    /// Le nom du site : le bras de dispatch de `main` le plus proche au-dessus, ou la fonction englobante.
    fn nom_du_site(lignes: &[String], k: usize) -> String {
        const BRAS: &str = r#"args.get(1).map(String::as_str) == Some(""#;
        for l in lignes[..k].iter().rev() {
            if let Some(i) = l.find(BRAS) {
                let reste = &l[i + BRAS.len()..];
                return reste[..reste.find('"').unwrap_or(reste.len())].to_string();
            }
            if let Some(i) = l.find("fn ") {
                let reste = &l[i + 3..];
                if let Some(f) = reste.find('(') {
                    let nom = reste[..f].trim();
                    if !nom.is_empty() && nom.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        return nom.to_string();
                    }
                }
            }
        }
        "<inconnu>".into()
    }

    /// La fin du premier motif d'ouverture de la ligne, s'il y en a un.
    fn ouverture(l: &str) -> Option<usize> {
        OUVERTURES
            .iter()
            .filter_map(|m| l.find(m).map(|i| i + m.len()))
            .min()
    }

    /// L'ouverture de la ligne `k` est-elle GARDÉE, et comment ? La garde doit précéder dans le MÊME
    /// bloc (la profondeur ne redescend jamais sous celle de l'appel), porter sur le MÊME chemin (que
    /// rien ne redéfinit entre la garde et l'ouverture), et aucune autre ouverture ne s'intercale. Aucun
    /// attribut (`#[cfg(…)]`) ne conditionne la garde ni une instruction de sa branche. Deux gardes :
    /// - le refus, écrit EXACTEMENT `if let Err(e) = refuser_une_base_absente(<chemin>, "<geste>") {`
    ///   (rien entre la parenthèse fermante et l'accolade : un `.or_else(…)`, un `.ok()`, un `.is_ok()`
    ///   neutraliseraient le refus). Sa branche DIT le refus — `eprintln!("{e}…")` en instruction
    ///   DIRECTE (profondeur 1), avant la sortie — puis SOIT sort du processus par une instruction
    ///   directe avec un code NON NUL, SOIT se termine par `} else {` et l'ouverture vit DANS ce `else`
    ///   (il n'est pas refermé avant elle : un `else {}` vide puis l'ouverture serait une ouverture
    ///   après le refus) ;
    /// - la naissance par le démon : une ligne qui COMMENCE par `ensure_encrypted(&conf, <chemin>);`
    ///   (un `if … { ensure_encrypted(…); }` sur une ligne la rendrait conditionnelle).
    fn ouverture_gardee(lignes: &[String], k: usize) -> Result<Garde, String> {
        let l = &lignes[k];
        let i = ouverture(l).ok_or("aucune ouverture sur cette ligne")?;
        let arg = &l[i..i + l[i..].find(|c: char| c == ',' || c == ')').ok_or("argument illisible")?];
        let Some(g) = (0..k).rev().find(|&j| {
            let lj = &lignes[j];
            lj.contains("refuser_une_base_absente(") || lj.contains("ensure_encrypted(") || ouverture(lj).is_some()
        }) else {
            return Err("aucun refus avant l'ouverture".into());
        };
        let garde = &lignes[g];
        if ouverture(garde).is_some() {
            return Err(format!("une autre ouverture (ligne {}) s'intercale sans refus", g + 1));
        }
        let garde_nue = hors_litteraux(garde);
        let garde_nue = garde_nue.trim();
        let naissance = garde.contains("ensure_encrypted(");
        if naissance {
            let forme_ok = garde_nue.starts_with(&format!("ensure_encrypted(&conf, {arg});"));
            if !forme_ok {
                return Err(format!("naissance conditionnelle ou sur un autre chemin : `{}` (attendu : une ligne qui commence par `ensure_encrypted(&conf, {arg});`)", garde.trim()));
            }
        } else {
            let forme_ok = garde_nue == format!("if let Err(e) = refuser_une_base_absente({arg}, \"\") {{");
            if !forme_ok {
                return Err(format!("refus de forme ou de chemin inattendus : `{}` (attendu exactement `if let Err(e) = refuser_une_base_absente({arg}, \"<geste>\") {{`)", garde.trim()));
            }
        }
        let attribut_avant = g > 0 && lignes[g - 1].trim().starts_with("#[");
        if attribut_avant {
            return Err(format!("un attribut conditionne la garde : `{}`", lignes[g - 1].trim()));
        }
        // LE MÊME CHEMIN, AU SENS DU PROGRAMME : rien ne le redéfinit entre la garde et l'ouverture.
        let nom = arg.trim().trim_start_matches('&').trim();
        let redefinit = |t: &str| -> bool {
            let t = t.trim();
            let apres_let = [format!("let {nom}"), format!("let mut {nom}")]
                .iter()
                .any(|p| t.starts_with(p.as_str()) && !t[p.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_'));
            let reste = t.strip_prefix(nom).map(str::trim_start).unwrap_or("");
            apres_let || (reste.starts_with('=') && !reste.starts_with("=="))
        };
        let redefini = if nom.is_empty() { None } else { (g + 1..k).find(|&j| redefinit(&lignes[j])) };
        if let Some(j) = redefini {
            return Err(format!("le chemin `{nom}` est redéfini entre la garde et l'ouverture (ligne {}) : `{}`", j + 1, lignes[j].trim()));
        }
        // Profondeur relative depuis la garde, caractère par caractère (`} else {` referme la branche
        // puis rouvre le `else`) : jamais négative jusqu'à l'ouverture. On retient la profondeur au
        // DÉBUT de chaque ligne, la ligne où la branche se referme, et si le `else` se referme ensuite.
        let (mut d, mut fin, mut else_referme) = (0i64, None, false);
        let mut prof_debut = vec![0i64; k - g];
        for j in g..k {
            prof_debut[j - g] = d;
            for c in hors_litteraux(&lignes[j]).chars() {
                match c {
                    '{' => d += 1,
                    '}' => d -= 1,
                    _ => continue,
                }
                if d < 0 {
                    return Err(format!("la garde vit dans un bloc fermé avant l'ouverture (ligne {})", j + 1));
                }
                if d == 0 {
                    if fin.is_none() {
                        fin = Some(j);
                    } else {
                        else_referme = true;
                    }
                }
            }
        }
        if naissance {
            return Ok(Garde::Naissance);
        }
        let fin = fin.ok_or("la branche du refus n'est pas refermée avant l'ouverture")?;
        let directes: Vec<usize> = (g + 1..fin).filter(|&j| prof_debut[j - g] == 1).collect();
        let attribut = directes.iter().find(|&&j| lignes[j].trim().starts_with("#["));
        if let Some(&j) = attribut {
            return Err(format!("un attribut conditionne une instruction de la branche du refus (ligne {}) : `{}`", j + 1, lignes[j].trim()));
        }
        // LE REFUS EST DIT : l'erreur de `refuser_une_base_absente` (fichier, geste NON exécuté, remède)
        // est écrite sur stderr par la branche, en instruction directe. Sans elle, le site sort en 1 sans
        // un mot — et le compilateur ne le refuse pas (`e` inutilisée n'est qu'un avertissement).
        const DIT: &str = "eprintln!(\"{e}";
        let dit = directes.iter().copied().find(|&j| lignes[j].trim().starts_with(DIT));
        let Some(dit) = dit else {
            return Err("le refus n'est pas DIT : la branche n'écrit pas l'erreur reçue (`eprintln!(\"{e}…\")` en instruction directe)".into());
        };
        const SORTIE: &str = "std::process::exit(";
        let sortie = directes.iter().copied().find(|&j| lignes[j].trim().starts_with(SORTIE));
        if let Some(js) = sortie {
            let s = lignes[js].trim();
            let reste = &s[SORTIE.len()..];
            let code: i32 = reste[..reste.find(')').ok_or("code de sortie illisible")?]
                .trim()
                .parse()
                .map_err(|_| format!("code de sortie illisible : `{s}`"))?;
            if code == 0 {
                return Err(format!("la branche du refus sort en 0 : un refus lu comme un succès par `$?` (`{s}`)"));
            }
            let ordre_ok = dit < js;
            if !ordre_ok {
                return Err(format!("le refus est écrit après la sortie (ligne {}) : il ne sera jamais dit", dit + 1));
            }
            return Ok(Garde::Sort(code));
        }
        if lignes[fin].trim() == "} else {" {
            if else_referme {
                return Err("le `else` du refus se referme AVANT l'ouverture : elle a lieu même après le refus".into());
            }
            return Ok(Garde::Else);
        }
        let branche = lignes[g..=fin].join("\n");
        Err(format!("la branche du refus ne sort pas (sortie directe, code non nul) et l'ouverture n'est pas dans son `else` :\n{branche}"))
    }

    /// Rend (site, verdict) pour chaque ouverture par la porte d'un texte de production.
    fn sites(rel: &str, lignes: &[String]) -> Vec<((String, String), Result<Garde, String>)> {
        (0..lignes.len())
            .filter(|&k| ouverture(&lignes[k]).is_some())
            .map(|k| ((rel.to_string(), nom_du_site(lignes, k)), ouverture_gardee(lignes, k)))
            .collect()
    }

    fn lignes(txt: &str) -> Vec<String> {
        txt.lines().map(str::to_string).collect()
    }


    /// MUTANTS : T1_SITE_ABSENT ; S_TOKEN_ELSE_VIDE, S_RETENTION_ELSE_VIDE, S_BACKUP_ELSE_VIDE,
    /// S_TOKEN_SORTIE_CONDITIONNELLE, S_RETENTION_EXIT0, S_PURGE_EXIT1, S_NEUF_PRELUDE,
    /// S_SERVEUR_SANS_ENSURE ; S_TOKEN_MUET, S_RESPOND_MUET, S_BACKUP_MUET, S_TOKEN_REPLI,
    /// S_TOKEN_EXIT_CFG, S_TOKEN_SHADOW, S_SERVEUR_ENSURE_UNE_LIGNE (texte lu par le balayage).
    #[test]
    fn p10_33g_chaque_ouverture_par_la_porte_est_precedee_du_refus() {
        let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        rs_files(&racine, &mut fichiers);
        let marques = fichiers_de_test(&fichiers);
        let mut vus: Vec<(String, String, Garde)> = Vec::new();
        let mut non_gardes: Vec<String> = Vec::new();
        for f in &fichiers {
            if est_test(f, &marques) {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            let rel = f.strip_prefix(&racine).unwrap().to_string_lossy().replace('\\', "/");
            let prod: Vec<String> = texte_de_production(f, &src).into_iter().map(|(_, l)| l).collect();
            for ((fichier, site), verdict) in sites(&rel, &prod) {
                match verdict {
                    Ok(garde) => vus.push((fichier, site, garde)),
                    Err(e) => non_gardes.push(format!("{fichier}::{site} — {e}")),
                }
            }
        }
        assert!(non_gardes.is_empty(), "ouverture(s) par la porte SANS garde (une base absente y naîtrait en clair) :\n{}", non_gardes.join("\n"));
        vus.sort();
        let attendus: Vec<(String, String, Garde)> = SITES_ATTENDUS.iter().map(|(a, b, g)| (a.to_string(), b.to_string(), *g)).collect();
        assert_eq!(vus, attendus, "l'ensemble des ouvertures par la porte (site, garde, code de sortie) a changé : un site neuf doit passer par le refus ET se nommer ici, et le code de sortie d'un refus est celui de son site");
    }

    /// LE SCANNER EST MESURÉ sur des extraits FABRIQUÉS : il attrape ce qu'il prétend attraper.
    /// MUTANTS du balayage : SC_SANS_ELSE_REFERME, SC_SANS_CODE, SC_SANS_PRELUDE ; SC_SANS_DIT,
    /// SC_DIT_SANS_ORDRE, SC_FORME_ANCIENNE, SC_FORME_SOUS_CHAINE, SC_SANS_ATTRIBUT,
    /// SC_SANS_REDEFINITION, SC_NAISSANCE_CONTIENT.
    #[test]
    fn p10_33g_le_balayage_attrape_ce_qu_il_pretend_attraper() {
        let bon = lignes(concat!(
            "    if args.get(1).map(String::as_str) == Some(\"x\") {\n",
            "        if let Err(e) = refuser_une_base_absente(&db_path, \"x\") {\n",
            "            eprintln!(\"{e} — rien. {{\");\n",
            "            std::process::exit(1);\n",
            "        }\n",
            "        let conn = match PreparedDb::open(&db_path) {\n",
        ));
        let v = sites("main.rs", &bon);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, ("main.rs".to_string(), "x".to_string()), "le nom vient du bras de dispatch");
        assert_eq!(v[0].1, Ok(Garde::Sort(1)), "forme nominale acceptée, code lu");

        // Briques des extraits : fonction, garde nominale, refus DIT, sortie, fin de branche, ouverture.
        const FN: &str = "fn f() {\n";
        const GARDE: &str = "    if let Err(e) = refuser_une_base_absente(&db_path, \"x\") {\n";
        const DIT: &str = "        eprintln!(\"{e} — rien.\");\n";
        const SORT: &str = "        std::process::exit(1);\n";
        const FIN: &str = "    }\n";
        const OUVRE: &str = "    let c = PreparedDb::open(&db_path);\n";

        let code_2 = [FN, GARDE, DIT, "        std::process::exit(2);\n", FIN, OUVRE].concat();
        assert_eq!(sites("a.rs", &lignes(&code_2))[0].1, Ok(Garde::Sort(2)), "le code de sortie du site est lu tel quel");

        let en_else = lignes(concat!(
            "fn f() {\n",
            "    if let Err(e) = refuser_une_base_absente(&db_path, \"x\") {\n",
            "        eprintln!(\"{e}\");\n",
            "    } else {\n",
            "        match PreparedDb::open(&db_path) {\n",
        ));
        let v = sites("a.rs", &en_else);
        assert_eq!(v[0].0 .1, "f", "le nom vient de la fonction englobante");
        assert_eq!(v[0].1, Ok(Garde::Else), "ouverture dans le `else` du refus : acceptée");

        let naissance = "fn f() {\n    ensure_encrypted(&conf, &db_path);   // commentaire\n    let conn = match PreparedDb::open_with_prelude(&db_path, tune) {\n";
        assert_eq!(sites("a.rs", &lignes(naissance))[0].1, Ok(Garde::Naissance), "naissance par le démon : reconnue");

        let usage_du_chemin = [FN, GARDE, DIT, SORT, FIN, "    let deja = db_path == autre;\n", "    db_path == autre || panic!();\n", OUVRE].concat();
        assert_eq!(sites("a.rs", &lignes(&usage_du_chemin))[0].1, Ok(Garde::Sort(1)), "lire le chemin (`==`) n'est pas le redéfinir");

        // Chaque extrait est refusé POUR SA RAISON (fragment du verdict) : un contrôle assoupli qui
        // laisserait un autre contrôle refuser l'extrait à sa place ne passerait pas inaperçu.
        let refus = |avant: &str, branche: &[&str], apres: &str| -> String {
            let mut s = format!("{FN}{avant}{GARDE}");
            for b in branche {
                s.push_str(b);
            }
            s.push_str(FIN);
            s.push_str(apres);
            s.push_str(OUVRE);
            s
        };
        let cas: Vec<(&str, String, &str)> = vec![
            ("aucun refus", [FN, OUVRE].concat(), "aucun refus"),
            ("résultat jeté", [FN, "    let _ = refuser_une_base_absente(&db_path, \"x\");\n", OUVRE].concat(), "forme ou de chemin"),
            ("autre chemin", [FN, "    if let Err(e) = refuser_une_base_absente(&autre, \"x\") {\n", DIT, SORT, FIN, OUVRE].concat(), "forme ou de chemin"),
            ("repli neutralisé", [FN, "    if let Err(e) = refuser_une_base_absente(&db_path, \"x\").or_else(|e| std::env::var_os(\"F\").map(|_| ()).ok_or(e)) {\n", DIT, SORT, FIN, OUVRE].concat(), "forme ou de chemin"),
            ("repli par .ok()", [FN, "    if let Err(e) = refuser_une_base_absente(&db_path, \"x\").ok().ok_or(\"\") {\n", DIT, SORT, FIN, OUVRE].concat(), "forme ou de chemin"),
            ("contrôle de forme assoupli (refus inversé)", [FN, "    if refuser_une_base_absente(&db_path, \"x\").is_ok() {\n", DIT, SORT, FIN, OUVRE].concat(), "forme ou de chemin"),
            ("garde sous attribut", refus("    #[cfg(feature = \"cold_tier\")]\n", &[DIT, SORT], ""), "attribut"),
            ("sortie sous attribut", refus("", &[DIT, "        #[cfg(feature = \"cold_tier\")]\n", SORT], ""), "attribut"),
            ("chemin redéfini", refus("", &[DIT, SORT], "    let db_path = format!(\"{db_path}-autre\");\n"), "redéfini"),
            ("chemin réassigné", refus("", &[DIT, SORT], "    db_path = autre;\n"), "redéfini"),
            ("refus muet", refus("", &[SORT], ""), "pas DIT"),
            ("refus muet en else", [FN, GARDE, "    } else {\n", "        match PreparedDb::open(&db_path) {\n"].concat(), "pas DIT"),
            ("message sans l'erreur", refus("", &["        eprintln!(\"refus\");\n", SORT], ""), "pas DIT"),
            ("refus dit sous condition", refus("", &["        if verbeux {\n", "            eprintln!(\"{e}\");\n", "        }\n", SORT], ""), "pas DIT"),
            ("refus dit après la sortie", refus("", &[SORT, DIT], ""), "après la sortie"),
            ("bloc fermé", [FN, "    if dry {\n", GARDE, DIT, SORT, FIN, "    }\n", OUVRE].concat(), "bloc fermé"),
            ("branche qui ne sort pas", refus("", &[DIT], ""), "ne sort pas"),
            ("ouverture intercalée", refus("", &[DIT, SORT], OUVRE), "s'intercale"),
            ("else vide puis ouverture", [FN, GARDE, DIT, "    } else {\n", FIN, OUVRE].concat(), "se referme AVANT"),
            ("else vide sur une ligne", [FN, GARDE, DIT, "    } else {}\n", OUVRE].concat(), "ne sort pas"),
            ("sortie conditionnelle", refus("", &[DIT, "        if e.is_empty() {\n", "            std::process::exit(1);\n", "        }\n"], ""), "ne sort pas"),
            ("sortie en 0", refus("", &[DIT, "        std::process::exit(0);\n"], ""), "sort en 0"),
            ("prélude sans refus", [FN, "    let c = PreparedDb::open_with_prelude(&db_path, |_| {});\n"].concat(), "aucun refus"),
            ("naissance hors bloc", [FN, "    if x {\n", "        ensure_encrypted(&conf, &db_path);\n", "    }\n", "    let c = PreparedDb::open_with_prelude(&db_path, tune);\n"].concat(), "bloc fermé"),
            ("naissance conditionnelle sur une ligne", [FN, "    if conf.is_empty() { ensure_encrypted(&conf, &db_path); }\n", "    let c = PreparedDb::open_with_prelude(&db_path, tune);\n"].concat(), "naissance conditionnelle"),
            ("naissance sous attribut", [FN, "    #[cfg(feature = \"cold_tier\")]\n", "    ensure_encrypted(&conf, &db_path);\n", "    let c = PreparedDb::open_with_prelude(&db_path, tune);\n"].concat(), "attribut"),
            ("naissance sur un autre chemin", [FN, "    ensure_encrypted(&conf, &autre);\n", "    let c = PreparedDb::open_with_prelude(&db_path, tune);\n"].concat(), "naissance conditionnelle ou sur un autre chemin"),
        ];
        for (motif, txt, raison) in &cas {
            let v = sites("a.rs", &lignes(txt));
            assert!(
                v.iter().any(|(_, r)| matches!(r, Err(e) if e.contains(raison))),
                "extrait fabriqué « {motif} » : le balayage doit le refuser POUR SA RAISON (« {raison} »), rendu {v:?}"
            );
        }
    }


    // ── ③ LA CONTRE-ÉPREUVE ET LE DÉFAUT MESURÉ ────────────────────────────────────────────────

    /// Ce que fait la porte sur une base absente sans clé : elle la CRÉE EN CLAIR, et le démarrage
    /// suivant la garde en clair (`RienAFaire`). Après cette naissance, l'aide laisse passer : elle ne
    /// bloque que la naissance, jamais une base qui existe.
    #[test]
    fn p10_33g_la_porte_cree_une_base_en_clair_et_l_aide_ne_bloque_que_la_naissance() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-naissance");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("neuve.db").to_string_lossy().into_owned();
        assert!(db_key().is_none(), "fixture : aucune clé ambiante (déploiement livré tel quel)");
        assert!(refuser_une_base_absente(&base, "g").is_err(), "avant : base absente -> refus");

        drop(PreparedDb::open(&base).expect("la porte prépare une base neuve"));
        let tete = std::fs::read(&base).unwrap();
        assert_eq!(&tete[..16], ENTETE_EN_CLAIR, "LE DÉFAUT : la base née par la porte sans clé est EN CLAIR");
        let etat = etat_du_fichier_de_base(&base);
        assert_eq!(etat, EtatDuFichierDeBase::Existante);
        assert_eq!(decision_at_rest(false, false, None, etat), DecisionAtRest::RienAFaire,
            "…et le démarrage suivant la garde en clair, sans un mot");

        assert!(refuser_une_base_absente(&base, "g").is_ok(), "après : base existante -> l'aide laisse passer");
    }

    // ── ④ LE REFUS EXÉCUTÉ : `main` EN SOUS-PROCESSUS, SUR UNE BASE ABSENTE ────────────────────
    // Le binaire de test contient `main` : l'enfant l'appelle, et ses arguments sont ceux de libtest,
    // dont les arguments libres (`token`, nom, hôte) sont aussi des FILTRES — aucun test ne s'appelle
    // ainsi avec `--exact`, seul l'enfant joue. Le parent lit le code de sortie, stderr, et le
    // répertoire de la base. MUTANTS : T1_NEUVE_OK (aide qui laisse passer : la base naît, en clair) ;
    // T1_EXEC_MUET (le site écrit sa phrase sans l'erreur du refus).

    const T1_ENFANT: &str = "P1033G_ENFANT_MAIN";
    const T1_MARQUE_ENFANT: &str = "P1033G-ENFANT-APPELLE-MAIN";

    /// Le refus tel que l'exploitant le lit : sortie en 1, la phrase de `refuser_une_base_absente`
    /// suivie de celle du site sur stderr, et AUCUN fichier créé à côté de la base.
    fn t1_juger_le_refus(geste: &str, phrase_du_site: &str, sortie: &std::process::Output, dir: &std::path::Path, base: &str) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stderr.contains(T1_MARQUE_ENFANT), "contrôle : l'enfant a atteint `main` : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(1), "base absente : `{geste}` sort en 1 (`$?` voit l'échec) : {stdout}\n{stderr}");
        let restes: Vec<String> = std::fs::read_dir(dir)
            .expect("répertoire de la base lisible")
            .map(|e| e.expect("entrée lisible").file_name().to_string_lossy().into_owned())
            .collect();
        assert!(restes.is_empty(), "base absente : `{geste}` ne crée RIEN (ni base en clair, ni -wal, ni -shm) : {restes:?}\n{stderr}");
        assert!(!std::path::Path::new(base).exists(), "la base reste absente");
        let refus = refuser_une_base_absente(base, geste).expect_err("contrôle : la base est toujours absente");
        let attendu = format!("{refus} — {phrase_du_site}");
        assert!(stderr.lines().any(|l| l == attendu), "le refus est DIT sur stderr, sur une ligne, tel que l'aide le rédige puis ce que le site n'a pas fait :\nattendu : {attendu}\nstderr :\n{stderr}");
    }

    #[test]
    fn p10_33g_token_sur_une_base_absente_refuse_le_dit_et_ne_cree_rien() {
        if std::env::var_os(T1_ENFANT).is_some() {
            eprintln!("{T1_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-token");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("absente.db").to_string_lossy().into_owned();
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "token",
                "p1033g-agent",
                "hote-p1033g",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::sous_commandes_refusent_une_base_absente::p10_33g_token_sur_une_base_absente_refuse_le_dit_et_ne_cree_rien",
            ])
            .env(T1_ENFANT, "1")
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .output()
            .expect("ré-exécution du binaire de test");
        t1_juger_le_refus("token", "token NON créé. Arrêt propre.", &sortie, &dir, &base);
    }

    #[test]
    fn p10_33g_respond_sur_une_base_absente_refuse_le_dit_et_ne_cree_rien() {
        if std::env::var_os(T1_ENFANT).is_some() {
            eprintln!("{T1_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-respond");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("absente.db").to_string_lossy().into_owned();
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "respond",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::sous_commandes_refusent_une_base_absente::p10_33g_respond_sur_une_base_absente_refuse_le_dit_et_ne_cree_rien",
            ])
            .env(T1_ENFANT, "1")
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .output()
            .expect("ré-exécution du binaire de test");
        t1_juger_le_refus("respond", "AUCUNE action exécutée. Arrêt propre.", &sortie, &dir, &base);
    }
}
