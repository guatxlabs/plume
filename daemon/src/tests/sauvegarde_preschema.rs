    // ============================================================================================
    // P4.4-l — LA SAUVEGARDE NOMMÉE D'AVANT UN FRANCHISSEMENT DE SCHÉMA, ET CE QUE LA RÉTENTION EN FAIT.
    //
    // LE CONSTAT. La porte de déploiement à sens unique exige une sauvegarde prise À CHAUD par l'outil de
    // l'exploitant (`tools/plume-sauvegarde-a-chaud.sh` du dépôt des manifestes), nommée
    // `plume-<TS>-preschema<N>.db.age` (N = schéma de destination) et déposée À LA RACINE du préfixe de
    // sauvegarde — le même endroit que les `plume-<TS>.db.age` de routine. Le sidecar y passe son listage
    // (`grep -E '^plume-.*\.db\.age$'`) à `backup-prune-plan` : l'objet ARRIVE donc dans l'analyseur, qui
    // le rendait `Unparseable` -> jamais proposé à la suppression (invariant 3) -> un objet de la taille
    // d'une sauvegarde de routine par franchissement de schéma, à jamais.
    //
    // LE CORRECTIF. Une classe `PreSchema { ts, schema }` dans le SEUL analyseur de noms, et la MÊME
    // politique que le jumeau automatique `premigrate-<sha>-<TS>` : garder les N plus récents, N lu dans
    // `PLUME_BACKUP_PREMIGRATE_KEEP`. Les QUOTAS restent SÉPARÉS : un `preschema` n'entre ni dans le compte
    // des sauvegardes de routine (ses paliers) ni dans celui des `premigrate` (la mutation qui le rangerait
    // dans `Premigrate` fait rougir `preschema_hors_quota_routine_et_premigrate`).
    //
    // Réutilise les aides de detection.rs (même module `tests`) : gfs_reg / gfs_fmt_ts / gfs_premig.
    // ============================================================================================

    /// Nom d'un objet `preschema` à l'instant `secs` (secondes Unix), schéma de destination `schema`.
    fn gfs_preschema(schema: u32, secs: i64) -> String {
        format!("plume-{}-preschema{}.db.age", gfs_fmt_ts(secs), schema)
    }

    fn gfs_params_keep(premigrate_keep: usize) -> crate::backup::GfsParams {
        crate::backup::GfsParams { dense_days: 2, daily_days: 14, weekly_days: 90, premigrate_keep }
    }

    /// TÉMOIN 1 — la forme de l'outil de l'exploitant est RECONNUE : horodatage ET schéma extraits.
    /// Une clé complète (`dir/plume-...`) est routée par son base-name, comme les autres classes.
    #[test]
    fn preschema_forme_reconnue_ts_et_schema_extraits() {
        let secs = crate::backup::days_from_civil(2026, 8, 22) * 86400 + 10 * 3600 + 15 * 60;
        let name = gfs_preschema(116, secs);
        assert_eq!(name, "plume-20260822T101500Z-preschema116.db.age", "forme exacte de l'outil");
        // MESURÉ le 2026-08-22, avant correctif : cette assertion rendait `left: Unparseable`.
        assert_ne!(crate::backup::classify_backup_name(&name), crate::backup::ParsedBackup::Unparseable,
                   "la forme de l'outil ne doit pas être rendue Unparseable");
        assert_eq!(crate::backup::classify_backup_name(&name),
                   crate::backup::ParsedBackup::PreSchema { ts: secs, schema: 116 });
        assert_eq!(crate::backup::classify_backup_name(&format!("plume/{name}")),
                   crate::backup::ParsedBackup::PreSchema { ts: secs, schema: 116 },
                   "clé complète routée par le base-name");
        // la routine reste la routine : le réaménagement de l'analyseur ne la déplace pas.
        assert_eq!(crate::backup::classify_backup_name(&gfs_reg(secs)), crate::backup::ParsedBackup::Regular(secs));
        // un numéro hors u32 n'est pas un schéma.
        assert_eq!(crate::backup::classify_backup_name("plume-20260822T101500Z-preschema99999999999.db.age"),
                   crate::backup::ParsedBackup::Unparseable);
    }

    /// TÉMOIN 2 — les formes VOISINES sont refusées (`Unparseable`, donc jamais supprimées) : `preschema`
    /// sans nombre, nombre sans `preschema`, suffixe `.db.age` absent ou prolongé, horodatage invalide,
    /// nombre suivi d'autre chose. Un voisin accepté serait un objet supprimable dont personne n'a décidé
    /// la politique.
    #[test]
    fn preschema_formes_voisines_refusees() {
        let ts = "20260822T101500Z";
        for voisin in [
            format!("plume-{ts}-preschema.db.age"),        // `preschema` sans nombre
            format!("plume-{ts}-116.db.age"),              // nombre sans `preschema`
            format!("plume-{ts}-preschema116"),            // `.db.age` absent
            format!("plume-{ts}-preschema116.db.age.tmp"), // en vol : suffixe prolongé
            format!("plume-{ts}-preschema116.db"),         // suffixe tronqué
            format!("plume-{ts}-preschema116x.db.age"),    // nombre suivi d'autre chose
            format!("plume-{ts}-preschema-116.db.age"),    // séparateur en trop
            format!("plume-{ts}-Preschema116.db.age"),     // casse
            format!("plume-{ts}--preschema116.db.age"),    // séparateur doublé
            "plume-20261301T101500Z-preschema116.db.age".to_string(), // mois 13
            "plume-2026082T101500Z-preschema116.db.age".to_string(),  // horodatage court
            format!("premigrate-{ts}-preschema116.db.age"),            // préfixe de l'autre classe
            format!("plume-{ts}-a-chaud.db.age"),          // l'autre marque de l'outil : hors de cette classe
        ] {
            assert_eq!(crate::backup::classify_backup_name(&voisin), crate::backup::ParsedBackup::Unparseable,
                       "voisin refusé : {voisin}");
        }
    }

    /// TÉMOIN 3 — PLAN DE PURGE : avec N+1 objets `preschema`, le plus ancien est proposé et les N récents
    /// non ; avec N objets, rien ; N=0 est borné à 1 (le plus récent survit toujours). Le schéma n'entre
    /// pas dans la règle : c'est l'horodatage qui ordonne, comme le `<sha>` des `premigrate` n'y entre pas.
    #[test]
    fn preschema_plan_de_purge_garde_les_n_plus_recents() {
        let now = crate::backup::days_from_civil(2026, 8, 22) * 86400 + 12 * 3600;
        let d = 86400;
        let (n, a, b) = (2usize, gfs_preschema(114, now - 40 * d), gfs_preschema(116, now - 3 * d));
        let c = gfs_preschema(118, now - 3600);
        let names = vec![gfs_reg(now), a.clone(), b.clone(), c.clone()];
        let plan = crate::backup::backup_prune_plan(&names, now, &gfs_params_keep(n));
        assert_eq!(plan, vec![a.clone()], "N+1 objets : le plus ancien seul est proposé (N={n})");
        // N objets -> aucun proposé.
        let plan = crate::backup::backup_prune_plan(&[gfs_reg(now), b.clone(), c.clone()], now, &gfs_params_keep(n));
        assert!(plan.is_empty(), "N objets : rien à supprimer (obtenu {plan:?})");
        // N=0 -> borné à 1 : le plus récent survit, les autres partent.
        let plan = crate::backup::backup_prune_plan(&names, now, &gfs_params_keep(0));
        assert_eq!(plan, vec![a.clone(), b.clone()], "N=0 borné à 1 : le plus récent seul survit");
        // un schéma plus GRAND sur un objet plus ANCIEN ne le sauve pas : l'ordre est chronologique.
        let vieux_grand = gfs_preschema(130, now - 60 * d);
        let plan = crate::backup::backup_prune_plan(&[vieux_grand.clone(), b.clone(), c.clone()], now, &gfs_params_keep(n));
        assert_eq!(plan, vec![vieux_grand], "l'horodatage ordonne, pas le numéro de schéma");
    }

    /// TÉMOIN 4 — UN `preschema` N'ENTRE DANS AUCUN AUTRE QUOTA. Avec N=2 : deux `premigrate` ET deux
    /// `preschema` -> rien n'est supprimé (rangé dans `Premigrate`, le plan en proposerait deux) ; un
    /// `preschema` vieux de 200 jours n'est pas emporté par le palier hebdomadaire (rangé dans `Regular`,
    /// il le serait) ; et sa présence ne déplace pas le keep-set des routines (même plan avec et sans).
    #[test]
    fn preschema_hors_quota_routine_et_premigrate() {
        let now = crate::backup::days_from_civil(2026, 8, 22) * 86400 + 12 * 3600;
        let d = 86400;
        let p = gfs_params_keep(2);
        // (a) deux premigrate + deux preschema, N=2 -> plan vide.
        let names = vec![
            gfs_reg(now),
            gfs_premig("aaa", now - 3600), gfs_premig("bbb", now - 5 * d),
            gfs_preschema(116, now - 2 * 3600), gfs_preschema(114, now - 30 * d),
        ];
        let plan = crate::backup::backup_prune_plan(&names, now, &p);
        assert!(plan.is_empty(), "quotas SÉPARÉS : 2 premigrate + 2 preschema sous N=2 -> rien (obtenu {plan:?})");
        // (b) un preschema de 200 j, seul de sa classe, avec des routines : jamais emporté par les paliers.
        let vieux = gfs_preschema(110, now - 200 * d);
        let names = vec![gfs_reg(now), gfs_reg(now - 200 * d), vieux.clone()];
        let plan = crate::backup::backup_prune_plan(&names, now, &p);
        assert_eq!(plan, vec![gfs_reg(now - 200 * d)], "la routine de 200 j part, le preschema de 200 j reste");
        // (c) le keep-set des routines est le même avec et sans preschema dans le flux.
        let mut routines: Vec<String> = Vec::new();
        let mut t = now;
        while now - t <= 120 * d { routines.push(gfs_reg(t)); t -= 7200; }
        let plan_sans = crate::backup::backup_prune_plan(&routines, now, &p);
        let mut avec = routines.clone();
        avec.push(gfs_preschema(116, now - 3600));
        avec.push(gfs_preschema(114, now - 20 * d));
        let plan_avec = crate::backup::backup_prune_plan(&avec, now, &p);
        assert_eq!(plan_sans, plan_avec, "un preschema ne déplace aucun palier des routines");
    }

    /// TÉMOIN 5 — IDEMPOTENT avec la nouvelle classe : rejouer le plan sur les survivants ne propose plus rien.
    #[test]
    fn preschema_plan_idempotent() {
        let now = crate::backup::days_from_civil(2026, 8, 22) * 86400 + 12 * 3600;
        let d = 86400;
        let p = gfs_params_keep(2);
        let mut names: Vec<String> = Vec::new();
        let mut t = now;
        while now - t <= 30 * d { names.push(gfs_reg(t)); t -= 7200; }
        for (i, off) in [3600i64, 2 * d, 9 * d, 25 * d].iter().enumerate() {
            names.push(gfs_preschema(110 + 2 * i as u32, now - off));
        }
        let plan1 = crate::backup::backup_prune_plan(&names, now, &p);
        assert_eq!(plan1.iter().filter(|n| n.contains("-preschema")).count(), 2, "4 preschema sous N=2 -> 2 proposés");
        let s1: std::collections::HashSet<&String> = plan1.iter().collect();
        let survivants: Vec<String> = names.iter().filter(|n| !s1.contains(n)).cloned().collect();
        let plan2 = crate::backup::backup_prune_plan(&survivants, now, &p);
        assert!(plan2.is_empty(), "idempotent (obtenu {plan2:?})");
    }

    /// TÉMOIN 6 — l'ordonnanceur NATIF (`backup_keep_recent_plan`, hôte/Docker) ne supprime que la routine :
    /// un `preschema` y est hors périmètre, comme un `premigrate`, quel que soit KEEP.
    #[test]
    fn preschema_hors_perimetre_du_plan_keep_n_natif() {
        let now = crate::backup::days_from_civil(2026, 8, 22) * 86400 + 12 * 3600;
        let names = vec![gfs_preschema(116, now - 86400 * 10), gfs_reg(now), gfs_reg(now - 7200), gfs_reg(now - 14400)];
        let plan = crate::backup::backup_keep_recent_plan(&names, 1);
        assert_eq!(plan, vec![gfs_reg(now - 7200), gfs_reg(now - 14400)], "seules les routines excédentaires partent");
    }

    // ============================================================================================
    // P4.4-n — LA CLASSE D'UN NOM, DEMANDÉE AU PRODUIT AU LIEU D'ÊTRE RECOPIÉE CHEZ L'APPELANT.
    //
    // LE CONSTAT. La porte de déploiement refuse un objet d'acquittement que la rétention ne saurait
    // pas classer, et jusqu'ici elle le DÉRIVAIT : faute de sous-commande rendant la classe d'un nom,
    // elle accompagnait le candidat de NOMS DE RÉFÉRENCE écrits dans l'outillage, un par classe, puis
    // lisait ce que `backup-prune-plan` décidait de supprimer. Ces noms de référence sont une
    // TRANSCRIPTION des formes que `classify_backup_name` connaît — exactement la source de divergence
    // que `P4.4-l` avait fermée ailleurs.
    //
    // LE CORRECTIF CÔTÉ PRODUIT : `plume-daemon backup-classify <nom>…`, dont la décision est PURE
    // (`backup_classify_rendu`) et donc éprouvée ici, sans binaire, sans cluster et sans base.
    // ============================================================================================

    /// TÉMOIN 7 — CHAQUE VARIANTE A SON MOT, ET LES MOTS SONT DISTINCTS. Le `match` de `mot_de_classe`
    /// est exhaustif : une variante ajoutée demain ne compile pas tant que personne ne l'a nommée.
    /// Ce témoin tient l'autre moitié — que deux variantes ne se cachent pas derrière un même mot,
    /// ce qui rendrait la sortie ambiguë sans faire rougir le compilateur.
    #[test]
    fn classify_chaque_classe_a_un_mot_distinct_et_seul_inclassable_n_est_pas_bornee() {
        use crate::backup::ParsedBackup as P;
        let toutes = [P::Regular(0), P::Premigrate(0), P::PreSchema { ts: 0, schema: 1 }, P::Unparseable];
        let mots: Vec<&str> = toutes.iter().map(|c| c.mot_de_classe()).collect();
        assert_eq!(mots, vec!["regulier", "premigrate", "preschema", "inclassable"]);
        let uniques: std::collections::HashSet<&&str> = mots.iter().collect();
        assert_eq!(uniques.len(), mots.len(), "deux variantes partagent un mot : la sortie serait ambiguë");
        // `est_bornee` est FAUX pour `Unparseable` et pour lui seul — c'est ce que le code 3 porte.
        for c in toutes {
            assert_eq!(c.est_bornee(), c != P::Unparseable, "borne mal rendue pour {c:?}");
        }
    }

    /// TÉMOIN 8 — LA SORTIE EST UNE LIGNE PAR NOM, DANS L'ORDRE D'ENTRÉE, LE NOM RENDU VERBATIM.
    /// Les trois formes que l'outil de l'exploitant et le sidecar produisent sont classées ; une clé
    /// complète est routée par son base-name, comme partout ailleurs.
    #[test]
    fn classify_rend_une_ligne_par_nom_dans_l_ordre() {
        let secs = crate::backup::days_from_civil(2026, 8, 22) * 86400 + 10 * 3600 + 15 * 60;
        let noms: Vec<String> = vec![
            gfs_reg(secs),
            gfs_preschema(116, secs),
            gfs_premig("82c168b", secs),
            format!("plume/{}", gfs_preschema(117, secs)),
        ];
        let (out, imperissables, code) = crate::backup::backup_classify_rendu(&noms);
        assert_eq!(imperissables, 0);
        assert_eq!(code, 0, "toutes bornées -> succès");
        let lignes: Vec<&str> = out.lines().collect();
        assert_eq!(lignes.len(), noms.len(), "une ligne par nom, ni plus ni moins");
        assert_eq!(lignes[0], format!("{} regulier", noms[0]));
        assert_eq!(lignes[1], format!("{} preschema", noms[1]));
        assert_eq!(lignes[2], format!("{} premigrate", noms[2]));
        assert_eq!(lignes[3], format!("{} preschema", noms[3]), "clé complète routée par le base-name");
    }

    /// TÉMOIN 9 — UN NOM IMPÉRISSABLE SORT EN 3, ET LE NOM RESTE LISIBLE. C'est le cas que la porte
    /// doit refuser : `Unparseable` n'est jamais proposé à la suppression (invariant 3), donc un tel
    /// objet acquitté resterait au dépôt pour toujours. Le code 3 le dit SANS que l'appelant ait à
    /// connaître le mot « inclassable » — c'est ce qui le dispense de le transcrire.
    #[test]
    fn classify_un_nom_imperissable_sort_en_3() {
        let secs = crate::backup::days_from_civil(2026, 8, 22) * 86400;
        let inconnu = "plume-20260822T101500Z-a-chaud.db.age".to_string();
        let (out, n, code) = crate::backup::backup_classify_rendu(&[inconnu.clone()]);
        assert_eq!(out, format!("{inconnu} inclassable\n"));
        assert_eq!((n, code), (1, 3));
        // MÉLANGE : un seul intrus suffit à faire sortir en 3, et les bonnes lignes sortent quand même.
        let melange = vec![gfs_reg(secs), inconnu.clone(), gfs_preschema(116, secs)];
        let (out2, n2, code2) = crate::backup::backup_classify_rendu(&melange);
        assert_eq!((n2, code2), (1, 3), "un intrus sur trois suffit");
        assert_eq!(out2.lines().count(), 3, "les noms classés sortent quand même");
        // TÉMOIN INVERSE : les mêmes noms SANS l'intrus sortent en 0. Sans lui, le 3 ci-dessus ne
        // prouverait pas que c'est l'intrus qui l'a produit.
        let sans = vec![gfs_reg(secs), gfs_preschema(116, secs)];
        assert_eq!(crate::backup::backup_classify_rendu(&sans).2, 0);
    }

    /// TÉMOIN 10 — AUCUN NOM LU SORT EN 2, ET NE REND AUCUNE LIGNE. « Je n'ai rien mesuré » n'est pas
    /// « tout est classé » : recopier le patron de `backup-prune-plan` (où l'entrée vide est un vrai
    /// vide, « rien à supprimer ») aurait rendu 0 sur une porte qui n'a rien lu.
    #[test]
    fn classify_entree_vide_refuse_de_conclure() {
        let (out, n, code) = crate::backup::backup_classify_rendu(&[]);
        assert_eq!(out, "", "aucune ligne : rien n'a été classé");
        assert_eq!((n, code), (0, 2), "2 = rien mesuré, JAMAIS 0");
        // Et le 2 se distingue du 0 : un seul nom classable rend 0.
        let secs = crate::backup::days_from_civil(2026, 8, 22) * 86400;
        assert_eq!(crate::backup::backup_classify_rendu(&[gfs_reg(secs)]).2, 0);
    }
