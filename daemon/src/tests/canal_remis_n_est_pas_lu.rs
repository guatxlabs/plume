// =====================================================================================
// `P10.33-n` — UN CANAL QUI « RÉUSSIT » N'A PAS ÉTÉ LU : LE DÉMON DIT « REMIS AU SERVICE, AUCUN
// ACCUSÉ DE LECTURE CONNU », JAMAIS « LU ». ET LA RÉPONSE DU SERVICE NE VA PLUS DANS SON JOURNAL.
//
// LE DÉFAUT, RE-LU SUR L'ARBRE `7c16769`. `notify_send` rend `true` quand curl sort en zéro (`-fsS`) :
// pour ntfy, le service a accepté la publication — un sujet sans abonné l'accepte aussi. L'essai d'un
// canal servait `{ "ok": ok }` et rien d'autre ; la liste des canaux ne disait rien de ce qu'un succès
// établit. Le démon ne PEUT pas savoir si quelqu'un lit : il dit donc ce qu'il sait, sans fabriquer
// d'échec — `accuse_de_lecture` (« inconnu » pour un canal réseau, « local » pour `lookup`,
// « sans_objet » pour un genre que l'envoi ne connaît pas), `remis_au_service`, et une phrase servie
// SEULEMENT sur un succès.
//
// LA TROUVAILLE VOISINE, JOUÉE ICI : `curl_send` (et le canal `webhook`, qui appelait curl à part)
// héritaient de la sortie standard du démon, et `-s` n'y retire que la barre de progression : le CORPS
// de réponse y était imprimé. ntfy répond par le message publié — détail d'alerte et nom d'hôte dans le
// journal du démon. Le témoin le joue par un FAUX `curl` en tête de `PATH`, dans un sous-processus :
// il imprime ses arguments (donc le détail et l'hôte) sur sa sortie standard et une longue ligne sur
// sa sortie d'erreur. Aucun réseau : l'adresse est de documentation (RFC 5737), la garde d'égress la
// laisse passer, et c'est le faux binaire qui répond.
//
// CE QU'ILS NE TIENNENT PAS : le plafond de LECTURE de la sortie d'erreur (`STDERR_CURL_LU_MAX`, une
// borne mémoire) n'est pas observable de l'extérieur — seul le plafond d'ÉMISSION l'est ; aucun compte
// d'abonnés n'est demandé au service (l'API de publication ntfy n'est pas établie comme en servant
// un) ; et la console (`web/detection_admin.js`) ignore les champs neufs : elle peint toujours
// « envoyé » sur `ok` seul.
// =====================================================================================
mod canal_remis_n_est_pas_lu {
    use super::*;
    use axum::response::IntoResponse;

    const P1033N_GENRES_RESEAU: [&str; 6] = ["ntfy", "webhook", "email", "slack", "pagerduty", "generic"];

    async fn p1033n_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    fn p1033n_canal(st: &AppState, nom: &str, kind: &str, url: &str, config: &str) -> i64 {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO notifier(name,kind,url,enabled,min_severity,config) VALUES(?1,?2,?3,1,2,?4)",
            params![nom, kind, url, config],
        )
        .unwrap_or_else(|e| panic!("fixture : canal {nom} non écrit ({e})"));
        conn.last_insert_rowid()
    }

    /// Le mot « lu » (et ses formes) n'apparaît dans aucun texte servi.
    fn p1033n_sans_le_mot_lu(texte: &str) -> bool {
        !texte
            .split(|c: char| !c.is_alphanumeric())
            .any(|m| matches!(m.to_lowercase().as_str(), "lu" | "lue" | "lus" | "lues" | "read"))
    }

    /// CE QU'IL TIENT : chaque genre réseau rend « remis au service, sans accusé de lecture » (code
    /// `inconnu`), `lookup` rend `local`, un genre inconnu `sans_objet` ; aucun code ni la phrase ne
    /// disent « lu ». Contrôle de l'instrument : le filtre de mot refuse bien « lu ».
    /// LA MUTATION QUI LE FAIT ROUGIR : `code()` rend `"lu"` pour un canal réseau.
    #[test]
    fn p10_33n_aucun_genre_ne_rend_lu() {
        let _env = VERROU_ENV_PROCESSUS.read();
        assert!(!p1033n_sans_le_mot_lu("message lu"), "instrument : le filtre doit voir le mot");
        for k in P1033N_GENRES_RESEAU {
            assert_eq!(accuse_du_canal(k), AccuseDuCanal::RemisAuServiceSansAccuseDeLecture, "genre {k}");
            assert_eq!(accuse_du_canal(k).code(), "inconnu", "genre {k} : aucun accusé de lecture connu");
        }
        assert_eq!(accuse_du_canal("lookup"), AccuseDuCanal::Local);
        assert_eq!(accuse_du_canal("lookup").code(), "local");
        assert_eq!(accuse_du_canal("pigeon"), AccuseDuCanal::GenreInconnu);
        assert_eq!(accuse_du_canal("pigeon").code(), "sans_objet");
        for a in [AccuseDuCanal::RemisAuServiceSansAccuseDeLecture, AccuseDuCanal::Local, AccuseDuCanal::GenreInconnu] {
            assert!(p1033n_sans_le_mot_lu(a.code()), "aucun code ne dit « lu » : {a:?} -> {}", a.code());
        }
        assert!(p1033n_sans_le_mot_lu(PHRASE_REMIS_AU_SERVICE_SANS_ACCUSE_DE_LECTURE), "la phrase ne dit pas « lu »");
        assert!(PHRASE_REMIS_AU_SERVICE_SANS_ACCUSE_DE_LECTURE.contains("accusé de lecture"), "la phrase nomme l'absence d'accusé");
    }

    /// CE QU'IL TIENT : l'essai d'un canal qui ÉCHOUE (genre inconnu, `lookup` qui n'émet rien par
    /// `notify_send`, ntfy vers une adresse de bouclage refusée par la garde d'égress) sert toujours `ok`
    /// à faux, `remis_au_service` à faux, son `accuse_de_lecture`, et AUCUNE phrase de remise.
    /// LES MUTATIONS QUI LE FONT ROUGIR : la phrase servie sur un échec (`phrase_sur_echec`) ; `ok` retiré
    /// au profit de `remis_au_service` (`ok_remplace`).
    #[tokio::test]
    async fn p10_33n_un_essai_rate_ne_porte_aucune_phrase_de_remise() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _p) = sp_state("p1033n-essai");
        let adm = sp_au("adm", "admin");
        for (nom, kind, url, accuse) in [
            ("p1033n-pigeon", "pigeon", "https://ntfy.example/p", "sans_objet"),
            ("p1033n-lookup", "lookup", "", "local"),
            ("p1033n-bouclage", "ntfy", "http://127.0.0.1:9/p1033n", "inconnu"),
        ] {
            let id = p1033n_canal(&st, nom, kind, url, "{}");
            let (statut, corps) = p1033n_corps(notifier_test(State(st.clone()), Extension(adm.clone()), Path(id)).await.into_response()).await;
            assert_eq!(statut, 200, "{nom} : un essai qui a eu lieu est servi en deux cents : {corps}");
            assert_eq!(corps["ok"], json!(false), "{nom} : `ok` reste servi, à faux : {corps}");
            assert_eq!(corps["remis_au_service"], json!(false), "{nom} : rien n'est remis : {corps}");
            assert_eq!(corps["accuse_de_lecture"], json!(accuse), "{nom} : {corps}");
            assert!(corps.get("remise").is_none(), "{nom} : un échec reste un échec, sans phrase de remise : {corps}");
        }
    }

    /// CE QU'IL TIENT : la liste des canaux porte `accuse_de_lecture` sur CHAQUE canal, dérivé du genre.
    /// LA MUTATION QUI LE FAIT ROUGIR : le champ retiré de la liste (`liste_sans_champ`).
    #[tokio::test]
    async fn p10_33n_la_liste_des_canaux_porte_l_accuse_de_lecture() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _p) = sp_state("p1033n-liste");
        let adm = sp_au("adm", "admin");
        p1033n_canal(&st, "p1033n-ntfy", "ntfy", "https://ntfy.example/soc", "{}");
        p1033n_canal(&st, "p1033n-lookup", "lookup", "", "{}");
        p1033n_canal(&st, "p1033n-pigeon", "pigeon", "https://ntfy.example/p", "{}");
        let (statut, corps) = p1033n_corps(notifiers_list(State(st.clone()), Extension(adm)).await).await;
        assert_eq!(statut, 200);
        assert!(corps.get("error").is_none(), "chemin nominal : {corps}");
        let lignes = corps["notifiers"].as_array().cloned().unwrap_or_default();
        assert!(lignes.len() >= 3, "contrôle positif : les trois canaux sont servis : {corps}");
        for l in &lignes {
            assert!(l.get("accuse_de_lecture").and_then(|v| v.as_str()).is_some(), "chaque canal porte le champ : {l}");
        }
        for (nom, attendu) in [("p1033n-ntfy", "inconnu"), ("p1033n-lookup", "local"), ("p1033n-pigeon", "sans_objet")] {
            let l = lignes.iter().find(|l| l["name"] == json!(nom)).unwrap_or_else(|| panic!("canal {nom} servi : {corps}"));
            assert_eq!(l["accuse_de_lecture"], json!(attendu), "{nom} : {l}");
        }
    }

    const P1033N_DETAIL: &str = "detail-du-temoin-p1033n-confidentiel";
    const P1033N_HOTE: &str = "hote-du-temoin-p1033n";
    const P1033N_JETON: &str = "jeton-du-temoin";
    const P1033N_URL: &str = "http://192.0.2.10/p1033n";
    const P1033N_FAUX_CURL: &str = "#!/bin/sh\n\
echo appel >> \"$P1033N_APPELS\"\n\
cat > /dev/null\n\
printf 'REPONSE-DU-SERVICE %s\\n' \"$*\"\n\
{ printf 'curl: (0) sortie-d-erreur-du-temoin '; i=0; while [ \"$i\" -lt 100 ]; do printf '%s' xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; i=$((i+1)); done; printf '\\n'; } >&2\n\
exit 0\n";

    /// CE QU'IL TIENT, sur la sortie d'un SOUS-PROCESSUS dont le `PATH` commence par un faux `curl` :
    ///  * ntfy sans authentification (stdin fermé), ntfy avec jeton (config sur stdin) et webhook rendent
    ///    `true`, et l'essai d'un canal ntfy sert `ok`, `remis_au_service`, `inconnu` et la phrase ;
    ///  * CONTRÔLE POSITIF : le faux binaire a été appelé quatre fois (fichier d'appels) — sans lui, une
    ///    sortie muette prouverait seulement que curl n'a pas tourné ;
    ///  * ni la réponse du service, ni le détail, ni l'hôte, ni le texte de l'essai n'atteignent la sortie
    ///    standard ou d'erreur du démon ;
    ///  * la sortie d'erreur de curl est réémise, UNE ligne par appel, bornée.
    /// LES MUTATIONS QUI LE FONT ROUGIR : sortie standard héritée (`stdout_herite`) ; webhook rendu à son
    /// appel direct (`webhook_direct`) ; ligne d'erreur non bornée (`stderr_non_borne`).
    #[tokio::test]
    async fn p10_33n_la_reponse_du_service_ne_va_pas_au_journal() {
        const ENFANT: &str = "P1033N_TEMOIN_ENFANT";
        const ESSAI: &str = "P1033N-ESSAI:";
        const ENVOIS: &str = "P1033N-ENVOIS:";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let un = |kind: &str, config: Value| notify_send(kind, P1033N_URL, &config, 3, "titre-du-temoin", P1033N_DETAIL, P1033N_HOTE, 1);
            let sans_auth = un("ntfy", json!({}));
            let avec_jeton = un("ntfy", json!({ "token": P1033N_JETON }));
            let webhook = un("webhook", json!({}));
            println!("{ENVOIS}{sans_auth}/{avec_jeton}/{webhook}");
            let (st, _p) = sp_state("p1033n-enfant");
            let id = p1033n_canal(&st, "p1033n-essai", "ntfy", P1033N_URL, "{}");
            let (statut, corps) = p1033n_corps(notifier_test(State(st.clone()), Extension(sp_au("adm", "admin")), Path(id)).await.into_response()).await;
            println!("{ESSAI}{statut}:{corps}");
            return;
        }
        let bac = crate::tmp_possede::TmpPossede::neuf("p1033n-faux-curl");
        let appels = bac.join("appels");
        let faux = bac.join("curl");
        std::fs::write(&faux, P1033N_FAUX_CURL).expect("fixture : faux curl écrit");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&faux, std::fs::Permissions::from_mode(0o755)).expect("fixture : faux curl exécutable");
        }
        let path = format!("{}:{}", bac.display(), std::env::var("PATH").unwrap_or_default());
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::canal_remis_n_est_pas_lu::p10_33n_la_reponse_du_service_ne_va_pas_au_journal",
            ])
            .env(ENFANT, "1")
            .env("PATH", &path)
            .env("P1033N_APPELS", &appels)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let nb_appels = std::fs::read_to_string(&appels).unwrap_or_default().lines().count();
        assert_eq!(nb_appels, 4, "contrôle positif : le faux curl est appelé quatre fois : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{ENVOIS}true/true/true")), "les trois envois rendent succès : {stdout}");
        let essai = stdout
            .lines()
            .find_map(|l| l.split_once(ESSAI).map(|(_, r)| r.to_string()))
            .unwrap_or_else(|| panic!("contrôle : l'essai est imprimé : {stdout}"));
        let (statut, corps) = essai.split_once(':').expect("statut:corps");
        assert_eq!(statut, "200", "{essai}");
        let corps: Value = serde_json::from_str(corps).expect("corps JSON");
        assert_eq!(corps["ok"], json!(true), "{corps}");
        assert_eq!(corps["remis_au_service"], json!(true), "{corps}");
        assert_eq!(corps["accuse_de_lecture"], json!("inconnu"), "{corps}");
        assert_eq!(corps["remise"], json!(PHRASE_REMIS_AU_SERVICE_SANS_ACCUSE_DE_LECTURE), "un succès porte la phrase de remise : {corps}");
        for (flux, texte) in [("standard", &stdout), ("d'erreur", &stderr)] {
            for interdit in ["REPONSE-DU-SERVICE", P1033N_DETAIL, P1033N_HOTE, P1033N_JETON, "Notification de test depuis Plume"] {
                assert!(!texte.contains(interdit), "sortie {flux} du démon : la réponse du service n'y va pas ({interdit}) :\n{texte}");
            }
        }
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[plume] notification : curl")).collect();
        assert_eq!(lignes.len(), 4, "une ligne d'erreur réémise par appel : {stderr}");
        for l in lignes {
            assert!(l.contains("sortie-d-erreur-du-temoin"), "la cause de curl est réémise : {l}");
            assert!(l.ends_with("[tronqué]"), "la ligne est bornée et le dit : {l}");
            assert!(l.chars().count() <= STDERR_CURL_EMIS_MAX + 120, "ligne bornée : {} caractères", l.chars().count());
        }
    }
}
