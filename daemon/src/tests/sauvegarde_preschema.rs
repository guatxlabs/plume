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
