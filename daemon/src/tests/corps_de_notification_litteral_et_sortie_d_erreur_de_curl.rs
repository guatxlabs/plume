// =====================================================================================
// `P10.33-s` (sécurité) — LE CORPS D'UNE NOTIFICATION PART EN LITTÉRAL : `--data-raw`, JAMAIS `-d`.
// Et, pour `P10.33-n`, les deux promesses de `curl_send` que le premier témoin ne jouait pas : la sortie
// d'erreur de curl repliée sur UNE ligne, et RIEN émis quand curl n'a rien écrit ; plus le stdin fermé.
//
// LE DÉFAUT (pré-existant, déjà présent à la publication initiale). `curl -d @chemin` LIT le fichier local
// `chemin` et en envoie le contenu au service. Deux sites de `notify_send` passaient un corps dont le DÉBUT
// n'est pas tenu par le démon : le détail ntfy (il vient de la requête de la règle) et le gabarit `generic`
// qui commence par {{title}}, {{host}} ou {{detail}}. Un détail « @/chemin » exfiltrait un fichier du démon
// vers le canal. webhook et slack sérialisent un objet JSON (le corps commence par « { ») ; pagerduty passe
// son corps JSON par la config sur stdin : ces trois-là ne sont pas exposés.
//
// LE TÉMOIN joue un SOUS-PROCESSUS dont le `PATH` commence par un faux `curl` (aucun réseau : adresse de
// documentation RFC 5737). Le faux binaire écrit ses arguments et son stdin dans des fichiers par appel,
// REFUSE `-d` (code 2) et EXIGE `--data-raw` ; selon le titre ntfy il se tait ou écrit deux lignes sur sa
// sortie d'erreur, la seconde imitant une ligne du journal du démon.
//
// Même famille : un `auth_header` « @chemin » du canal `generic` (config curl `header = "@…"`) faisait LIRE
// le fichier et en envoyer les lignes en en-têtes ; il est refusé avant curl (forme `Nom: valeur` exigée).
// Relevé à la vérification finale de la vague V avec le vrai curl 8.14.1. Mutation : `entete_fichier_admis`.
//
// CE QU'IL NE TIENT PAS : le comportement du VRAI curl devant `-d @…` (établi à part, curl 8.14.1, par le
// vérificateur) ; le plafond de LECTURE de la sortie d'erreur (borne mémoire, inobservable).
// MUTATIONS JOUÉES (VERIF_MUT, retirées du source avant le commit) : `donnees_d_ntfy`, `donnees_d_generic`,
// `sans_repli`, `vide_emis`, `stdin_herite`.
// =====================================================================================
mod corps_de_notification_litteral_et_sortie_d_erreur_de_curl {
    use super::*;

    const P1033S_URL: &str = "http://192.0.2.11/p1033s";
    const P1033S_MARQUE_STDIN: &str = "STDIN-DU-DEMON-p1033s";
    const P1033S_FAUX_CURL: &str = "#!/bin/sh\n\
d=\"$P1033S_BAC\"\n\
echo appel >> \"$d/appels\"\n\
i=$(($(wc -l < \"$d/appels\")))\n\
for a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$d/args-$i\"\n\
cat > \"$d/stdin-$i\"\n\
case \"$*\" in\n\
  *'Title: p1033s-muet'*) exit 0 ;;\n\
  *'Title: p1033s-deux-lignes'*) printf 'curl: (22) premiere-ligne-p1033s\\n[plume] LIGNE-FORGEE-p1033s\\n' >&2; exit 0 ;;\n\
esac\n\
for a in \"$@\"; do if [ \"$a\" = \"-d\" ]; then echo 'curl: (2) -d refuse par le temoin' >&2; exit 2; fi; done\n\
for a in \"$@\"; do if [ \"$a\" = \"--data-raw\" ]; then exit 0; fi; done\n\
echo 'curl: (2) --data-raw absent' >&2\n\
exit 2\n";

    /// CE QU'IL TIENT, sur un sous-processus à faux `curl` en tête de `PATH` :
    ///  * ntfy dont le détail commence par « @ » et `generic` au gabarit `{{detail}}` passent leur corps par
    ///    `--data-raw` suivi du littéral « @… », et aucun argument n'est `-d` (le faux curl refuse `-d`) ;
    ///  * un curl MUET n'engendre aucune ligne « curl a écrit sur sa sortie d'erreur » ;
    ///  * deux lignes de curl sur sa sortie d'erreur sont réémises sur UNE ligne : la seconde, qui imite le
    ///    journal du démon (« [plume] … »), n'ouvre jamais une ligne à elle ;
    ///  * un envoi sans configuration secrète ne lit pas le stdin du démon (le parent en remplit un).
    /// CONTRÔLE POSITIF : quatre appels du faux binaire, et une ligne d'erreur réémise (celle à deux lignes).
    /// LES MUTATIONS QUI LE FONT ROUGIR : `donnees_d_ntfy`, `donnees_d_generic` (`-d` rendu au site),
    /// `vide_emis` (sortie vide émise), `sans_repli` (sauts gardés), `stdin_herite` (stdin hérité sans config).
    #[test]
    fn p10_33s_le_corps_part_en_litteral_et_la_sortie_d_erreur_de_curl_tient_sur_une_ligne() {
        const ENFANT: &str = "P1033S_TEMOIN_ENFANT";
        const ENVOIS: &str = "P1033S-ENVOIS:";
        let _env = VERROU_ENV_PROCESSUS.read();
        if let Ok(bac) = std::env::var("P1033S_BAC") {
            if std::env::var(ENFANT).is_ok() {
                let fichier = format!("@{bac}/fichier-local-p1033s");
                let un = |kind: &str, config: Value, titre: &str, detail: &str| {
                    notify_send(kind, P1033S_URL, &config, 3, titre, detail, "", 1)
                };
                let ntfy = un("ntfy", json!({}), "p1033s-donnees", &fichier);
                let generic = un("generic", json!({ "template": "{{detail}}" }), "p1033s-generic", &fichier);
                let muet = un("ntfy", json!({}), "p1033s-muet", "detail-p1033s");
                let deux = un("ntfy", json!({}), "p1033s-deux-lignes", "detail-p1033s");
                // En-tête d'auth « @chemin » : refusé AVANT curl. Puis le contrôle positif `Nom: valeur`.
                let entete_fichier = un("generic", json!({ "auth_header": fichier }), "p1033s-entete-fichier", "detail-p1033s");
                let entete_admis = un("generic", json!({ "auth_header": "Authorization: Bearer p1033s-jeton" }), "p1033s-entete-admis", "detail-p1033s");
                println!("{ENVOIS}{ntfy}/{generic}/{muet}/{deux}/{entete_fichier}/{entete_admis}");
                return;
            }
        }
        let bac = crate::tmp_possede::TmpPossede::neuf("p1033s-faux-curl");
        let faux = bac.join("curl");
        std::fs::write(&faux, P1033S_FAUX_CURL).expect("fixture : faux curl écrit");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&faux, std::fs::Permissions::from_mode(0o755)).expect("fixture : faux curl exécutable");
        }
        let path = format!("{}:{}", bac.display(), std::env::var("PATH").unwrap_or_default());
        let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::corps_de_notification_litteral_et_sortie_d_erreur_de_curl::p10_33s_le_corps_part_en_litteral_et_la_sortie_d_erreur_de_curl_tient_sur_une_ligne",
            ])
            .env(ENFANT, "1")
            .env("PATH", &path)
            .env("P1033S_BAC", bac.as_os_str())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("ré-exécution du binaire de test");
        {
            use std::io::Write;
            let mut si = enfant.stdin.take().expect("stdin de l'enfant");
            si.write_all(format!("{P1033S_MARQUE_STDIN}\n").as_bytes()).expect("stdin de l'enfant rempli");
        } // fermé : un curl qui hériterait de ce stdin lirait la marque puis EOF
        let sortie = enfant.wait_with_output().expect("sortie de l'enfant");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let lire = |nom: String| std::fs::read_to_string(bac.join(&nom)).unwrap_or_default();
        let nb_appels = lire("appels".into()).lines().count();
        assert_eq!(nb_appels, 5, "le faux curl est appelé cinq fois, jamais pour l'en-tête « @… » : {stdout}\n{stderr}");
        assert!(
            stdout.contains(&format!("{ENVOIS}true/true/true/true/false/true")),
            "les quatre envois et l'en-tête admis rendent succès, l'en-tête « @… » est refusé : {stdout}\n{stderr}"
        );
        // Contrôle positif : l'en-tête `Nom: valeur` part par la config sur stdin, et lui seul.
        let cfg_admis = lire("stdin-5".into());
        assert_eq!(cfg_admis, "header = \"Authorization: Bearer p1033s-jeton\"\n", "en-tête admis, sur stdin : {cfg_admis:?}");
        assert!(
            stderr.contains("auth_header refusé, forme « Nom: valeur » exigée") && !stderr.contains("fichier-local-p1033s"),
            "le refus est dit, sans jamais écrire la valeur (un secret) : {stderr}"
        );
        let fichier = format!("@{}/fichier-local-p1033s", bac.display());
        for (i, site) in [(1, "ntfy"), (2, "generic")] {
            let args: Vec<String> = lire(format!("args-{i}")).lines().map(str::to_string).collect();
            assert!(!args.iter().any(|a| a == "-d"), "{site} : aucun `-d` (lecture de fichier local) : {args:?}");
            let pos = args.iter().position(|a| a == "--data-raw").unwrap_or_else(|| panic!("{site} : `--data-raw` présent : {args:?}"));
            assert_eq!(args.get(pos + 1), Some(&fichier), "{site} : le corps « @… » part en littéral : {args:?}");
        }
        for i in 1..=4 {
            let lu = lire(format!("stdin-{i}"));
            assert!(!lu.contains(P1033S_MARQUE_STDIN), "appel {i} : curl sans config ne lit pas le stdin du démon : {lu:?}");
        }
        let reemises: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[plume] notification : curl")).collect();
        assert_eq!(reemises.len(), 1, "un curl muet n'engendre aucune ligne ; seule la sortie à deux lignes est réémise : {stderr}");
        assert!(
            reemises[0].ends_with("premiere-ligne-p1033s [plume] LIGNE-FORGEE-p1033s"),
            "les deux lignes de curl tiennent sur UNE ligne : {}",
            reemises[0]
        );
        assert!(
            !stderr.lines().any(|l| l.starts_with("[plume] LIGNE-FORGEE")),
            "une ligne de curl n'ouvre jamais une ligne du journal du démon : {stderr}"
        );
    }

    /// `P10.33-s` — la forme d'un en-tête d'auth, jugée seule : un « @ » de tête (avec ou sans « : » plus loin),
    /// un nom vide ou qui porte une espace, une valeur sans « : » sont refusés ; `Nom: valeur` est admis, blancs
    /// de bord retirés et CR/LF neutralisés. MUTATIONS : `nom_non_controle` (le contrôle du nom retiré), et
    /// `garde_ouverte` (tout admis) — le témoin à faux curl ne voit que la seconde, son chemin n'a pas de « : ».
    #[test]
    fn p10_33s_un_en_tete_d_auth_n_est_admis_que_sous_la_forme_nom_valeur() {
        for refuse in ["@/etc/passwd", "@/chemin/local: x", " @/chemin: x", ": x", "Mauvais Nom: x", "SansDeuxPoints", ""] {
            assert_eq!(en_tete_d_auth_admis(refuse), None, "refusé : {refuse:?}");
        }
        assert_eq!(en_tete_d_auth_admis(" Authorization: Bearer x "), Some("Authorization: Bearer x".into()));
        assert_eq!(en_tete_d_auth_admis("X-Api_Key: a\r\nb"), Some("X-Api_Key: a  b".into()));
    }
}
