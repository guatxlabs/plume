    /// `P7.20-f` — LES TROIS MODES METTENT LES JOURS FROIDS À L'ABRI, ET LES TEXTES NE DISENT PLUS LE CONTRAIRE.
    /// Textuel, dans le profil par défaut (le module gaté n'existe pas ici) : l'unité hôte joue `cold-escrow`
    /// par son script et son unité peut lire les jours froids et écrire la destination ; le planificateur natif
    /// (conteneur, cluster) appelle l'exécutant après chaque cycle ; l'aide nomme la sous-commande dans les DEUX
    /// formes du binaire ; et le runbook de restauration ne renvoie plus à un sidecar qui n'existe pas.
    #[test]
    fn p7_20f_les_trois_modes_mettent_les_jours_froids_a_l_abri() {
        let script = include_str!("../../../collectors/backup.sh");
        assert!(script.contains("plume-daemon cold-escrow \"$DIR\""), "l'unité hôte joue cold-escrow sur le répertoire des sauvegardes");
        assert!(script.contains("aucun jour froid à mettre à l'abri"), "et dit ce qu'un binaire sans la feature ne fait pas");
        let unite = include_str!("../../../systemd/plume-backup.service");
        assert!(unite.contains("ReadWritePaths=/var/lib/plume/db /var/lib/plume/backups"), "l'unité lit les jours froids et écrit la destination");
        let planificateur = include_str!("../server/sauvegarde_planifiee.rs");
        assert_eq!(
            planificateur.matches("mettre_a_l_abri_les_jours_froids_apres_le_cycle(db, &cold_dir, d);").count(), 2,
            "le cycle natif appelle l'exécutant sur ses deux formes (destination locale, destination objet)"
        );
        assert!(crate::SUBCOMMANDS_COLD.iter().any(|(n, _)| *n == "cold-escrow"), "l'aide nomme cold-escrow dans cette forme du binaire");
        let runbook = include_str!("../../../docs/DR-plume-restore.md");
        assert!(!runbook.contains("sidecar `backup` par `plume-daemon cold-backup-plan`"), "le runbook ne renvoie plus à un sidecar qui n'existe pas");
        assert!(runbook.contains("plume-daemon cold-escrow <destination>"), "le runbook nomme l'exécutant du mode hôte");
    }
