// =====================================================================================
// `P7.20-a` — LA CONFIDENTIALITÉ ACTIVE PAR DÉFAUT SUR LA GARDE D'ÉGRESS, ET L'HÔTE STRICT DIT AU DÉMARRAGE
// (décision de l'exploitant, 2026-10-26 : confidentialité active par défaut, performance au cas par cas).
//
// (1) Garde d'égress (daemon/src/ledger.rs) : sans `PLUME_SSRF_BLOCK_PRIVATE`, une adresse privée (10/8, 172.16/12,
//     192.168/16) est REFUSÉE pour une cible de l'API et ADMISE pour une cible de configuration. DE CONFIGURATION : une
//     cible INSCRITE POUR L'OBJET QUI ÉMET — le canal semé par `PLUME_NOTIFY_NTFY_URL` (son URL exacte, sous son
//     identifiant), un objet d'une surcouche `config.d` validé puis écrit (ses propres cibles, sous l'identifiant de la
//     ligne écrite, la famille REMPLACÉE à chaque chargement) — et les fournisseurs d'identité et d'IA selon le site
//     unique `ORIGINE_DES_FOURNISSEURS_D_IDENTITE_ET_D_IA` (décision en attente de l'exploitant, de configuration à ce
//     jour). Le registre n'est JAMAIS consulté par URL globale : base, famille ET identifiant de l'objet (revue de
//     sécurité de la vague AY) — un objet de l'API qui reprend l'URL exacte d'une surcouche d'un AUTRE objet reste de
//     l'API. Un endpoint OIDC rendu par le document de découverte n'est de configuration que s'il partage l'hôte et le
//     port de `discovery_url` (revue de sécurité). Chaque envoi est jugé par la VRAIE chaîne : canaux (essai, dispatch,
//     rapport planifié, escalade SLA, multi-niveau), destinations (`build_wire` puis transport, fond et envoi manuel),
//     connecteurs (fond, essai, poll manuel ; pages suivantes TAXII `added_after`/`next`, `@odata.nextLink` Graph).
// (2) Démarrage (daemon/src/overlays_oac.rs) : le canal semé est inscrit, puis une ligne dit la politique retenue, puis
//     une ligne par objet stocké dont la cible privée sera refusée (genre, id, champ, hôte — jamais l'URL entière), et
//     les aveux de ce qui n'a pas pu être lu.
// (3) Allowlist d'hôte (daemon/src/server/mod.rs, daemon/src/auth.rs) : le défaut reste NON STRICT, même avec
//     `PLUME_HOST` déclaré ; l'état retenu est dit au démarrage ; `PLUME_HOST_STRICT=1` (environnement ou fichier)
//     l'active ; `/healthz` et `/readyz` restent servis quelle que soit l'autorité présentée.
// (4) `.env.example`, copié tel quel en `.env` par l'installation Docker, ne pose jamais `PLUME_SSRF_BLOCK_PRIVATE` ni
//     `PLUME_HOST_STRICT` à une valeur qui désarme un défaut.
//
// CE QU'IL NE TIENT PAS : le relais de ces réglages par `docker-compose.yml`, leurs lignes du README et de
// `docs/CONNECTOR-PRESETS.md`, leur semis dans `deploy/k3s.yaml` (zone de la console, phrases remises à l'intégrateur) ;
// l'égress d'IA lui-même (feature `ai`, hors de la suite par défaut) : seule sa garde est jouée ici.
//
// MUTANTS JOUÉS (posés sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : M_REG_ID, M_REG_FAMILLE,
// M_REG_BASE, M_REG_SOURCE (registre) ; M_GARDE_OBJET_CONFIG ; M_FOURNISSEURS_API ; M_TAXII_PAGE (page entière inscrite) ;
// M_DEFENDER_SANS_CIBLES ; M_ID_TOUJOURS_INSERTION, M_ID_TOUJOURS_PLAN (identifiant de la ligne écrite) ;
// M_INVENTAIRE_SANS_CIBLES ; M_ENV_NON_INSCRIT, M_ENV_VIDE_GARDE, M_ENV_SANS_NOM, M_ENV_ABSENT_GARDE, M_ENV_ERR_GARDE,
// M_ENV_AVEU_MUET (canal semé) ; M_HEC_SANS_TRIM, M_SYSLOG_API, M_FOND_DESTINATION_SANS_CIBLES, M_FLUSH_SANS_CIBLES
// (destinations) ; M_FOND_CONNECTEUR_SANS_CIBLES, M_ESSAI_CONNECTEUR_SANS_CIBLES, M_POLL_SANS_CIBLES, M_MAJ_TYPE_HTTP,
// M_MAJ_TYPE_TAXII, M_MAJ_TYPE_DEFENDER (connecteurs) ; M_DISPATCH_SANS_CIBLES, M_ESSAI_CANAL_SANS_CIBLES,
// M_CANAL_DROP_VIDE, M_RAPPORT_SANS_CIBLES, M_ESCALADE_SANS_CANAL, M_MULTI_SANS_CANAL (canaux) ; M_IDP_TOUT_CONFIG,
// M_IDP_OVERRIDE_IGNORE, M_IDP_HOTE_SEUL, M_IDP_DECOUVERTE_API (fournisseur d'identité) ; et, par le texte,
// l'ordre du démarrage permuté, `.env.example` à `PLUME_SSRF_BLOCK_PRIVATE=0` puis à `PLUME_HOST_STRICT=0`.
//
// Les politiques sont figées au premier usage (OnceLock) : chaque chaîne réglage -> garde se joue dans un
// SOUS-PROCESSUS, environnement `PLUME_*` vidé, puis réglé.
// =====================================================================================
mod cibles_privees_selon_leur_origine_et_hote_dit_au_demarrage {
    use super::*;
    use crate::ledger::{
        ligne_de_la_politique_des_adresses_privees, origine_de_l_url, politique_des_adresses_privees, prive_bloque_pour,
        ssrf_check_host_selon, url_relevant_de, valeur_des_adresses_privees_non_reconnue, CibleDeConfiguration,
        OrigineDeLaCible, PolitiqueDesAdressesPrivees,
    };
    use crate::server::hote_strict_au_demarrage;

    const MODULE: &str = "tests::cibles_privees_selon_leur_origine_et_hote_dit_au_demarrage::";
    const HOTE_DECLARE: &str = "soc.exemple.test";
    const CIBLE_DE_CONFIGURATION: &str = "http://10.0.0.7:8080/plume-alertes";
    const CIBLE_API_PRIVEE: &str = "http://10.0.0.9/canal-saisi";
    /// Un NOM (forme décimale d'inet_aton) qui RÉSOUT vers 10.0.0.9 sans réseau : jugé au site « IP résolue ».
    const CIBLE_API_NOM_PRIVE: &str = "http://167772169/canal-saisi";
    const CIBLE_METADONNEES: &str = "http://169.254.169.254/latest";
    // Surcouches `config.d`.
    const CANAL_DE_SURCOUCHE: &str = "http://10.0.0.12:8088/plume";
    const SLACK_DE_SURCOUCHE: &str = "http://10.0.0.14/hooks/p720a";
    /// Le relais SMTP interne d'une installation sur site, et un canal générique, écrits en surcouche.
    const EMAIL_DE_SURCOUCHE: &str = "smtp://10.0.0.33:25";
    const GENERIQUE_DE_SURCOUCHE: &str = "http://10.0.0.34/generique";
    const DESTINATION_WEBHOOK_DE_SURCOUCHE: &str = "http://10.0.0.35/entree";
    const DESTINATION_SYSLOG_DE_SURCOUCHE: &str = "tcp://10.0.0.11:6514";
    /// L'endpoint HEC finit par « / » : l'URL d'émission le retire (`build_wire`).
    const DESTINATION_HEC_DE_SURCOUCHE: &str = "https://10.0.0.13:8088/";
    const HEC_D_EMISSION: &str = "https://10.0.0.13:8088/services/collector/event";
    const CONNECTEUR_PAR_URL: &str = "http://10.0.0.15/api/v1/alertes";
    const CONNECTEUR_PAR_RACINE: &str = "http://10.0.0.16/racine/";
    const JETON_DU_CONNECTEUR: &str = "http://10.0.0.17/oauth/jeton";
    const RACINE_TAXII: &str = "http://10.0.0.18/taxii2/api1/";
    const CONNECTEUR_REJETE: &str = "http://10.0.0.19/rejete";
    const DESTINATION_ECRITURE_REFUSEE: &str = "tcp://10.0.0.20:6514";
    const CANAL_ECRITURE_REFUSEE: &str = "http://10.0.0.27/refuse";
    const CONNECTEUR_ECRITURE_REFUSEE: &str = "http://10.0.0.28/refuse";
    const DEFENDER_LOGIN: &str = "10.0.0.41";
    const DEFENDER_GRAPH: &str = "10.0.0.42";
    const DEFENDER_JETON: &str = "https://10.0.0.41/t-1/oauth2/v2.0/token";
    const DEFENDER_PAGE_SUIVANTE: &str = "https://10.0.0.42/v1.0/security/alerts_v2?$skiptoken=p720a";
    /// Le filigrane d'un connecteur TAXII déjà passé : sa première page n'est pas celle d'un démarrage à froid.
    const FILIGRANE_TAXII: &str = "2026-01-01T00:00:00Z";
    /// Noms des variables que les références `env:` des surcouches lisent (aucune valeur secrète : celle du témoin).
    const VARIABLE_JETON_HEC: &str = "P720A_HEC_JETON";
    const VARIABLE_CLIENT: &str = "P720A_CLIENT";
    const VARIABLE_SLACK: &str = "P720A_WEBHOOK_SLACK";
    const VALEUR_DU_TEMOIN: &str = "p720a-valeur-du-temoin";
    const LIGNE_VALEUR_NON_RECONNUE: &str = "[ssrf] PLUME_SSRF_BLOCK_PRIVATE : valeur non reconnue, traitée comme absente \
(adresses privées refusées pour une cible venue de l'API) ; formes admises : 1/true/yes/on, 0/false/no/off";
    const LEVIERS: &str = "PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée";
    const PHRASE_URL_REFUSEE: &str =
        "URL invalide : http(s):// (ntfy/webhook/generic) ou smtp(s):// (email) requis, et cible non-interne (SSRF)";
    const PHRASE_URL_REFUSEE_MAJ: &str = "URL invalide : schéma non autorisé ou cible interne refusée (SSRF)";
    const PHRASE_CANAL_PRIVE: &str = "URL refusée : adresse privée (10/8, 172.16/12, 192.168/16) pour un canal saisi par \
l'API — PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée ; un canal écrit \
en surcouche config.d est admis";
    const PHRASE_ENDPOINT_REFUSE: &str =
        "endpoint invalide (webhook/hec: http(s):// ; syslog: tcp://host:port ; cible métadonnées interdite)";
    const PHRASE_ENDPOINT_REFUSE_MAJ: &str = "endpoint invalide pour ce type de sink";
    const PHRASE_CONNECTEUR_PRIVE: &str = "connecteur refusé : adresse privée (10/8, 172.16/12, 192.168/16) pour un \
connecteur saisi par l'API — PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse \
privée ; un connecteur écrit en surcouche config.d est admis";
    const PHRASE_DESTINATION_PRIVEE: &str = "endpoint refusé : adresse privée (10/8, 172.16/12, 192.168/16) pour une \
destination saisie par l'API — PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse \
privée ; une destination écrite en surcouche config.d est admise";
    const LIGNE_POLITIQUE_PAR_DEFAUT: &str = "[ssrf] adresses privées (10/8, 172.16/12, 192.168/16) : REFUSÉES pour un \
canal, une destination ou un connecteur saisi par l'API ; ADMISES pour le canal semé par PLUME_NOTIFY_NTFY_URL (son URL \
exacte), les objets écrits en surcouche config.d (leurs propres cibles) et les fournisseurs d'identité et d'IA (réservés \
à l'administrateur) — PLUME_SSRF_BLOCK_PRIVATE=0 les admet partout, =1 les refuse partout, PLUME_SSRF_ALLOW exempte un \
hôte ou un CIDR";
    const LIGNE_POLITIQUE_BLOQUEE: &str = "[ssrf] PLUME_SSRF_BLOCK_PRIVATE posé à 1 : adresses privées (10/8, 172.16/12, \
192.168/16) REFUSÉES pour toute cible, configuration, surcouches et fournisseurs d'identité et d'IA compris — \
PLUME_SSRF_ALLOW exempte un hôte ou un CIDR";
    const LIGNE_POLITIQUE_ADMISE: &str = "[ssrf] PLUME_SSRF_BLOCK_PRIVATE posé à 0 : adresses privées (10/8, 172.16/12, \
192.168/16) ADMISES pour toute cible, y compris un canal, une destination ou un connecteur saisi par l'API";
    const LIGNE_CANAL_NON_INSCRIT: &str = "[ssrf] canal semé par PLUME_NOTIFY_NTFY_URL NON inscrit : sa ligne n'a pas pu \
être lue — ses envois vers une adresse privée seront refusés jusqu'au prochain démarrage (no such table: notifier)";
    const LIGNE_HOTE_INACTIVE_DECLARE: &str = "[host] allowlist Host stricte INACTIVE : FQDN de PLUME_HOST (soc.exemple.test) \
et loopback acceptés ; PLUME_HOST_STRICT=1 la restreint aux FQDN de PLUME_HOST";
    const LIGNE_HOTE_INACTIVE_DEFAUT: &str = "[host] allowlist Host stricte INACTIVE : FQDN de PLUME_HOST (plume.localhost) \
et loopback acceptés ; PLUME_HOST_STRICT=1 la restreint aux FQDN de PLUME_HOST";
    const LIGNE_HOTE_AUTRE_VALEUR: &str = "[host] PLUME_HOST_STRICT posé à une valeur autre que 1 : allowlist Host stricte \
INACTIVE — FQDN de PLUME_HOST (soc.exemple.test) et loopback acceptés ; seule la valeur 1 l'active";
    const LIGNE_HOTE_EXPLICITE: &str = "[host] PLUME_HOST_STRICT=1 : allowlist Host restreinte aux FQDN de PLUME_HOST \
(soc.exemple.test) — loopback NON auto-accepté";
    const PHRASE_HOTE_REFUSE: &str = "hôte non autorisé : cette instance n'accepte que les autorités déclarées par son réglage \
PLUME_HOST (PLUME_HOST_STRICT en restreint encore l'ensemble). Visez l'autorité déclarée pour \
cette instance, ou ajoutez celle que vous employez à PLUME_HOST, puis redémarrez le démon.";
    const SIGNATURE_DE_SESSION: &str = "temoin-p720a-signature-de-session";

    /// Le refus d'une adresse privée littérale, tel que la garde le rend.
    fn refus_prive(hote: &str) -> String {
        format!("SSRF: adresse privée refusée ({hote}) — {LEVIERS}")
    }

    fn carte(paires: &[(&str, &str)]) -> HashMap<String, String> {
        paires.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn premisse_sans_environnement(cles: &[&str]) {
        for cle in cles {
            assert!(std::env::var(cle).is_err(), "prémisse : {cle} absent de l'environnement du processus de test");
        }
    }

    /// La valeur de la ligne `CLE:valeur` de l'enfant, présente une seule fois.
    fn lu(stdout: &str, cle: &str) -> String {
        let prefixe = format!("{cle}:");
        let trouves: Vec<&str> = stdout.lines().filter_map(|l| l.strip_prefix(prefixe.as_str())).collect();
        assert_eq!(trouves.len(), 1, "une seule ligne {cle} : {stdout}");
        trouves[0].to_string()
    }

    fn lignes_qui_commencent_par(texte: &str, prefixe: &str) -> Vec<String> {
        texte.lines().filter(|l| l.starts_with(prefixe)).map(str::to_string).collect()
    }

    fn issue(r: Result<(), String>) -> &'static str {
        if r.is_ok() { "admis" } else { "refuse" }
    }

    fn admis_si(ok: bool) -> &'static str {
        if ok { "admis" } else { "refuse" }
    }


    // ------------------------------------------------------------------ (1) cœurs purs

    #[test]
    fn p720a_lecture_du_reglage_des_adresses_privees() {
        assert_eq!(politique_des_adresses_privees(""), PolitiqueDesAdressesPrivees::ParDefaut, "absent : défaut");
        assert_eq!(politique_des_adresses_privees("   "), PolitiqueDesAdressesPrivees::ParDefaut, "vide : défaut");
        for v in ["1", "true", "yes", "on", "TRUE", " On "] {
            assert_eq!(politique_des_adresses_privees(v), PolitiqueDesAdressesPrivees::BloqueesPartout, "valeur explicite {v:?} : bloque partout");
        }
        for v in ["0", "false", "no", "off", " OFF "] {
            assert_eq!(politique_des_adresses_privees(v), PolitiqueDesAdressesPrivees::AdmisesPartout, "valeur explicite {v:?} : admet partout (sens d'avant)");
            assert!(!valeur_des_adresses_privees_non_reconnue(v));
        }
        // Une valeur non reconnue ne donne jamais MOINS que l'absence : elle vaut défaut, et elle est signalée.
        for v in ["oui", "enabled", "desactive", "2"] {
            assert_eq!(politique_des_adresses_privees(v), PolitiqueDesAdressesPrivees::ParDefaut, "valeur non reconnue {v:?} : défaut");
            assert!(valeur_des_adresses_privees_non_reconnue(v), "{v:?} est dite non reconnue");
        }
        assert!(!valeur_des_adresses_privees_non_reconnue(""), "absent : rien à dire");
        assert!(!valeur_des_adresses_privees_non_reconnue(" true "));
    }

    #[test]
    fn p720a_le_prive_selon_la_politique_et_l_origine() {
        use OrigineDeLaCible::{Api, Configuration};
        use PolitiqueDesAdressesPrivees::{AdmisesPartout, BloqueesPartout, ParDefaut};
        assert!(prive_bloque_pour(ParDefaut, Api), "défaut : cible de l'API refusée");
        assert!(!prive_bloque_pour(ParDefaut, Configuration), "défaut : cible de configuration admise");
        assert!(prive_bloque_pour(BloqueesPartout, Api));
        assert!(prive_bloque_pour(BloqueesPartout, Configuration), "valeur 1 : la configuration aussi est refusée");
        assert!(!prive_bloque_pour(AdmisesPartout, Api), "valeur 0 : l'API aussi est admise");
        assert!(!prive_bloque_pour(AdmisesPartout, Configuration));
    }

    /// Un refus d'adresse privée nomme ses deux leviers ; le never-egress garde son refus d'avant, quel que soit le
    /// drapeau — au site du littéral comme au site de l'IP résolue.
    #[test]
    fn p720a_jugement_d_une_adresse_et_refus_qui_nomme_ses_leviers() {
        assert_eq!(
            ssrf_check_host_selon("10.0.0.9", 80, true),
            Err(format!("SSRF: adresse privée refusée (10.0.0.9) — {LEVIERS}"))
        );
        assert_eq!(ssrf_check_host_selon("10.0.0.9", 80, false), Ok(()));
        for drapeau in [true, false] {
            assert_eq!(ssrf_check_host_selon("127.0.0.1", 80, drapeau), Err("SSRF: cible interne interdite (127.0.0.1)".to_string()));
            assert_eq!(ssrf_check_host_selon("169.254.169.254", 80, drapeau), Err("SSRF: cible interne interdite (169.254.169.254)".to_string()));
            // 2130706433 = 127.0.0.1 en forme décimale : un NOM résolu vers le loopback.
            assert_eq!(
                ssrf_check_host_selon("2130706433", 80, drapeau),
                Err("SSRF: '2130706433' résout vers une adresse interne (127.0.0.1) — refus".to_string())
            );
        }
        assert_eq!(ssrf_check_host_selon("192.0.2.9", 80, true), Ok(()), "une adresse hors RFC1918 passe");
        assert_eq!(
            ssrf_check_host_selon("167772169", 80, true),
            Err(format!("SSRF: adresse privée refusée : '167772169' résout vers 10.0.0.9 — {LEVIERS}"))
        );
        assert_eq!(ssrf_check_host_selon("167772169", 80, false), Ok(()), "drapeau levé : le nom résolu privé passe");
    }

    /// L'URL exacte décide ; la requête n'est admise que pour une cible qui la déclare (base des pages d'un
    /// connecteur), avec le séparateur que la base appelle ; jamais un autre chemin, jamais le même hôte:port seul.
    #[test]
    fn p720a_une_url_relevant_d_une_cible_inscrite() {
        let exacte = CibleDeConfiguration::exacte(" http://10.0.0.7:8080/a ");
        assert_eq!(exacte.url, "http://10.0.0.7:8080/a", "blancs de bord retirés à l'inscription");
        assert!(url_relevant_de("http://10.0.0.7:8080/a", &exacte));
        assert!(url_relevant_de("  http://10.0.0.7:8080/a\t", &exacte), "blancs de bord de l'URL d'égress retirés");
        assert!(!url_relevant_de("http://10.0.0.7:8080/a?x=1", &exacte), "exacte : pas de requête ajoutée");
        assert!(!url_relevant_de("http://10.0.0.7:8080/ab", &exacte), "exacte : pas de suffixe");
        assert!(!url_relevant_de("http://10.0.0.7:8080/", &exacte), "même hôte:port, autre chemin");
        let base = CibleDeConfiguration::suivie_d_une_requete("http://10.0.0.15/api");
        assert!(url_relevant_de("http://10.0.0.15/api", &base), "la base elle-même");
        assert!(url_relevant_de("http://10.0.0.15/api?limit=50&offset=0", &base), "la base suivie de ses paramètres");
        assert!(!url_relevant_de("http://10.0.0.15/api&limit=50", &base), "sans requête dans la base, le séparateur est ?");
        assert!(!url_relevant_de("http://10.0.0.15/apix?limit=1", &base), "un autre chemin qui commence pareil");
        assert!(!url_relevant_de("http://10.0.0.15/api/autre", &base), "un sous-chemin");
        let avec_requete = CibleDeConfiguration::suivie_d_une_requete("http://10.0.0.15/api?cle=v");
        assert!(url_relevant_de("http://10.0.0.15/api?cle=v&limit=50", &avec_requete), "base avec requête : suite par &");
        assert!(!url_relevant_de("http://10.0.0.15/api?cle=v?limit=50", &avec_requete), "base avec requête : pas de second ?");
        let cibles = vec![exacte.clone(), base.clone()];
        assert_eq!(origine_de_l_url("http://10.0.0.15/api?page=2", &cibles), OrigineDeLaCible::Configuration);
        assert_eq!(origine_de_l_url("http://10.0.0.7:8080/a", &cibles), OrigineDeLaCible::Configuration);
        assert_eq!(origine_de_l_url("http://10.0.0.7:8080/b", &cibles), OrigineDeLaCible::Api);
        assert_eq!(origine_de_l_url("http://10.0.0.7:8080/a", &[]), OrigineDeLaCible::Api);
    }


    #[test]
    fn p720a_ligne_de_la_politique_par_reglage() {
        assert_eq!(ligne_de_la_politique_des_adresses_privees(PolitiqueDesAdressesPrivees::ParDefaut), LIGNE_POLITIQUE_PAR_DEFAUT);
        assert_eq!(ligne_de_la_politique_des_adresses_privees(PolitiqueDesAdressesPrivees::BloqueesPartout), LIGNE_POLITIQUE_BLOQUEE);
        assert_eq!(ligne_de_la_politique_des_adresses_privees(PolitiqueDesAdressesPrivees::AdmisesPartout), LIGNE_POLITIQUE_ADMISE);
    }


    /// (C) La décision en attente tient en UN site : la constante, que la ligne du démarrage suit.
    #[test]
    fn p720a_fournisseurs_d_identite_et_d_ia_de_configuration_en_un_seul_site() {
        assert_eq!(
            crate::ledger::ORIGINE_DES_FOURNISSEURS_D_IDENTITE_ET_D_IA,
            OrigineDeLaCible::Configuration,
            "décision en attente de l'exploitant : les fournisseurs restent de configuration (limite P5.8-a)"
        );
    }

    // ------------------------------------------------------------------ (1) le registre, borné à l'objet

    /// Le registre ne rend que les cibles de l'objet nommé — base, famille ET identifiant —, et chaque source remplace
    /// les siennes seules. Bases propres à ce témoin (le registre est global au processus).
    #[test]
    fn p720a_le_registre_ne_rend_que_les_cibles_de_l_objet() {
        use crate::ledger::FamilleDeSurcouche::{Canaux, Destinations};
        use crate::ledger::{remplacer_le_canal_de_l_environnement, remplacer_les_cibles_de_surcouche, ssrf_cibles_de_l_objet};
        let base = "p720a-registre-temoin-base";
        let autre_base = "p720a-registre-temoin-autre-base";
        let canal = CibleDeConfiguration::exacte(CANAL_DE_SURCOUCHE);
        let semee = CibleDeConfiguration::exacte(CIBLE_DE_CONFIGURATION);
        let destination = CibleDeConfiguration::exacte(DESTINATION_WEBHOOK_DE_SURCOUCHE);
        remplacer_les_cibles_de_surcouche(base, Canaux, vec![(5, canal.clone())]);
        remplacer_les_cibles_de_surcouche(autre_base, Canaux, vec![(9, canal.clone())]);
        remplacer_le_canal_de_l_environnement(base, Some((7, semee.clone())));
        remplacer_les_cibles_de_surcouche(base, Destinations, vec![(6, destination.clone())]);
        assert_eq!(ssrf_cibles_de_l_objet(base, Canaux, 5), vec![canal.clone()], "l'objet inscrit : ses cibles");
        assert_eq!(ssrf_cibles_de_l_objet(base, Canaux, 6), Vec::<CibleDeConfiguration>::new(), "même famille, autre identifiant : rien");
        assert_eq!(ssrf_cibles_de_l_objet(base, Destinations, 5), Vec::<CibleDeConfiguration>::new(), "même identifiant, autre famille : rien");
        assert_eq!(ssrf_cibles_de_l_objet(autre_base, Canaux, 5), Vec::<CibleDeConfiguration>::new(), "même identifiant, autre base : rien");
        assert_eq!(ssrf_cibles_de_l_objet(autre_base, Canaux, 9), vec![canal.clone()]);
        assert_eq!(ssrf_cibles_de_l_objet(base, Canaux, 7), vec![semee.clone()], "le canal semé, sous son identifiant");
        // L'URL exacte d'une surcouche, émise par un AUTRE objet : de l'API.
        assert_eq!(origine_de_l_url(CANAL_DE_SURCOUCHE, &ssrf_cibles_de_l_objet(base, Canaux, 6)), OrigineDeLaCible::Api);
        assert_eq!(origine_de_l_url(CANAL_DE_SURCOUCHE, &ssrf_cibles_de_l_objet(base, Canaux, 5)), OrigineDeLaCible::Configuration);
        // Un rechargement des canaux de surcouche remplace les siens — jamais le canal semé, une autre famille, une autre base.
        remplacer_les_cibles_de_surcouche(base, Canaux, vec![(8, canal.clone())]);
        assert_eq!(ssrf_cibles_de_l_objet(base, Canaux, 5), Vec::<CibleDeConfiguration>::new(), "rechargement : l'inscription d'avant est retirée");
        assert_eq!(ssrf_cibles_de_l_objet(base, Canaux, 8), vec![canal.clone()]);
        assert_eq!(ssrf_cibles_de_l_objet(base, Canaux, 7), vec![semee.clone()], "le canal semé survit au rechargement des surcouches");
        assert_eq!(ssrf_cibles_de_l_objet(base, Destinations, 6), vec![destination.clone()], "une autre famille survit");
        assert_eq!(ssrf_cibles_de_l_objet(autre_base, Canaux, 9), vec![canal.clone()], "une autre base survit");
        remplacer_le_canal_de_l_environnement(base, None);
        assert_eq!(ssrf_cibles_de_l_objet(base, Canaux, 7), Vec::<CibleDeConfiguration>::new(), "le canal semé retiré");
        assert_eq!(ssrf_cibles_de_l_objet(base, Canaux, 8), vec![canal], "les canaux de surcouche survivent au retrait du canal semé");
        remplacer_les_cibles_de_surcouche(base, Canaux, Vec::new());
        remplacer_les_cibles_de_surcouche(base, Destinations, Vec::new());
        remplacer_les_cibles_de_surcouche(autre_base, Canaux, Vec::new());
    }

    /// Le canal semé est inscrit sous l'identifiant de la ligne `ntfy (env)` (la lecture du semis) ; réglage vide ou
    /// ligne absente : l'inscription d'avant est retirée. Base sur disque propre à ce témoin.
    #[test]
    fn p720a_le_canal_seme_est_inscrit_sous_son_identifiant() {
        use crate::ledger::{ssrf_cibles_de_l_objet, FamilleDeSurcouche::Canaux};
        use crate::overlays_oac::inscrire_le_canal_de_l_environnement;
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // cfg lit l'environnement avant la carte
        premisse_sans_environnement(&["PLUME_NOTIFY_NTFY_URL"]);
        let dossier = crate::tmp_possede::TmpPossede::neuf("p720a-canal-seme");
        let c = base_complete(&dossier.join("plume.db"));
        let base = crate::ledger::base_de(&c);
        assert!(!base.is_empty(), "instrument : une base sur disque a un nom");
        // Une ligne de l'API PLUS ANCIENNE (identifiant plus petit) qui vise la même URL : jamais inscrite.
        c.execute("INSERT INTO notifier(id,name,kind,enabled,url,config) VALUES(3,'p720a-api','ntfy',1,?1,'{}')", params![CIBLE_DE_CONFIGURATION])
            .expect("ligne de l'API");
        c.execute("INSERT INTO notifier(id,name,kind,enabled,url,config) VALUES(4,'ntfy (env)','ntfy',1,?1,'{}')", params![CIBLE_DE_CONFIGURATION])
            .expect("ligne semée");
        let conf = carte(&[("PLUME_NOTIFY_NTFY_URL", CIBLE_DE_CONFIGURATION)]);
        inscrire_le_canal_de_l_environnement(&c, &conf);
        assert_eq!(ssrf_cibles_de_l_objet(&base, Canaux, 4), vec![CibleDeConfiguration::exacte(CIBLE_DE_CONFIGURATION)], "la ligne semée");
        assert_eq!(ssrf_cibles_de_l_objet(&base, Canaux, 3), Vec::<CibleDeConfiguration>::new(), "la ligne de l'API qui vise la même URL");
        inscrire_le_canal_de_l_environnement(&c, &carte(&[]));
        assert_eq!(ssrf_cibles_de_l_objet(&base, Canaux, 4), Vec::<CibleDeConfiguration>::new(), "réglage vide : inscription retirée");
        inscrire_le_canal_de_l_environnement(&c, &conf);
        assert_eq!(ssrf_cibles_de_l_objet(&base, Canaux, 4).len(), 1, "contrôle : de nouveau inscrit");
        c.execute("DELETE FROM notifier WHERE id=4", []).expect("ligne retirée");
        inscrire_le_canal_de_l_environnement(&c, &conf);
        assert_eq!(ssrf_cibles_de_l_objet(&base, Canaux, 4), Vec::<CibleDeConfiguration>::new(), "ligne absente : inscription retirée");
    }

    /// Lecture refusée : rien d'inscrit, et la ligne du journal le dit, ENTIÈRE (sous-processus : sortie d'erreur lue).
    #[test]
    fn p720a_le_canal_seme_non_lu_est_dit() {
        const ENFANT: &str = "P720A_ENFANT_CANAL_NON_LU";
        const FIN: &str = "P720A-CANAL-NON-LU-A-JOUE";
        if std::env::var(ENFANT).is_ok() {
            println!();
            let c = test_db();
            let base = crate::ledger::base_de(&c);
            crate::ledger::remplacer_le_canal_de_l_environnement(&base, Some((4, CibleDeConfiguration::exacte(CIBLE_DE_CONFIGURATION))));
            c.execute_batch("DROP TABLE notifier;").expect("table retirée");
            crate::overlays_oac::inscrire_le_canal_de_l_environnement(&c, &carte(&[("PLUME_NOTIFY_NTFY_URL", CIBLE_DE_CONFIGURATION)]));
            println!("P720A-INSCRITES:{}", crate::ledger::ssrf_cibles_de_l_objet(&base, crate::ledger::FamilleDeSurcouche::Canaux, 4).len());
            println!("{FIN}");
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}p720a_le_canal_seme_non_lu_est_dit"));
        for (nom, _) in std::env::vars_os() {
            if nom.to_string_lossy().starts_with("PLUME_") {
                commande.env_remove(&nom);
            }
        }
        commande.env(ENFANT, "1");
        let sortie = commande.output().expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(lu(&stdout, "P720A-INSCRITES"), "0", "lecture refusée : l'inscription d'avant est retirée");
        assert_eq!(lignes_qui_commencent_par(&stderr, "[ssrf]"), vec![LIGNE_CANAL_NON_INSCRIT.to_string()], "la ligne du journal, entière");
    }

    /// (A) L'origine d'un endpoint OIDC : écrit par l'administrateur, ou rendu par la découverte sur l'hôte ET le port de
    /// `discovery_url` -> celle d'un fournisseur ; tout autre -> de l'API.
    #[test]
    fn p720a_origine_d_un_endpoint_oidc() {
        let fournisseur = crate::ledger::ORIGINE_DES_FOURNISSEURS_D_IDENTITE_ET_D_IA;
        let api = OrigineDeLaCible::Api;
        let decouverte = "https://10.0.0.5/.well-known/openid-configuration";
        assert_eq!(origine_d_un_endpoint_oidc("", "https://10.0.0.5/jwks", decouverte), fournisseur, "même hôte et port que la découverte");
        assert_eq!(origine_d_un_endpoint_oidc("", "https://10.0.0.5:443/jwks", decouverte), fournisseur, "port par défaut écrit : même autorité");
        assert_eq!(origine_d_un_endpoint_oidc("", "https://10.0.0.6/jwks", decouverte), api, "rendu par la découverte, autre hôte : de l'API");
        assert_eq!(origine_d_un_endpoint_oidc("", "https://10.0.0.5:8443/jwks", decouverte), api, "même hôte, autre port : de l'API");
        assert_eq!(origine_d_un_endpoint_oidc("https://10.0.0.6/jwks", "https://10.0.0.6/jwks", decouverte), fournisseur, "écrit par l'administrateur");
        assert_eq!(origine_d_un_endpoint_oidc(" https://10.0.0.6/jwks ", "https://10.0.0.6/jwks", decouverte), fournisseur, "blancs de bord");
        assert_eq!(origine_d_un_endpoint_oidc("https://10.0.0.6/autre", "https://10.0.0.6/jwks", decouverte), api, "écrit, mais un autre : rien d'hérité");
        assert_eq!(origine_d_un_endpoint_oidc("", "ftp://10.0.0.5/jwks", decouverte), api, "endpoint illisible : de l'API");
        assert_eq!(origine_d_un_endpoint_oidc("", "https://10.0.0.5/jwks", "pas une url"), api, "découverte illisible : de l'API");
    }

    // ------------------------------------------------------------------ (4) le fichier d'exemple ne désarme rien

    /// Un fichier du dépôt, lu À L'EXÉCUTION (la racine est le parent du crate).
    fn fichier_du_depot(relatif: &str) -> String {
        let chemin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(relatif);
        std::fs::read_to_string(&chemin).unwrap_or_else(|e| panic!("instrument : {} illisible ({e})", chemin.display()))
    }

    /// Les affectations `CLE=valeur` non commentées d'un fichier d'environnement (`export ` et guillemets retirés).
    fn affectations(texte: &str) -> Vec<(String, String)> {
        texte
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.strip_prefix("export ").unwrap_or(l).trim())
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.trim().to_string(), v.trim().trim_matches(|c| c == '"' || c == '\'').to_string()))
            .collect()
    }

    /// Les réglages qu'un fichier d'environnement pose à une valeur qui DÉSARME un défaut : `PLUME_SSRF_BLOCK_PRIVATE` à
    /// une forme qui admet partout, `PLUME_HOST_STRICT` à autre chose que vide ou `1`.
    fn defauts_desarmes(texte: &str) -> Vec<String> {
        affectations(texte)
            .into_iter()
            .filter(|(cle, valeur)| match cle.as_str() {
                "PLUME_SSRF_BLOCK_PRIVATE" => politique_des_adresses_privees(valeur) == PolitiqueDesAdressesPrivees::AdmisesPartout,
                "PLUME_HOST_STRICT" => !(valeur.is_empty() || valeur == "1"),
                _ => false,
            })
            .map(|(cle, valeur)| format!("{cle}={valeur}"))
            .collect()
    }

    /// `.env.example` est copié tel quel en `.env` par l'installation Docker : il ne pose jamais un réglage qui désarme
    /// la garde d'égress ou l'allowlist d'hôte, et il les pose tous deux (vides) pour qu'on les trouve.
    #[test]
    fn p720a_le_fichier_d_exemple_ne_desarme_aucun_defaut() {
        // L'instrument, éprouvé sur chaque forme.
        assert_eq!(defauts_desarmes("PLUME_SSRF_BLOCK_PRIVATE=0\n"), vec!["PLUME_SSRF_BLOCK_PRIVATE=0".to_string()]);
        assert_eq!(defauts_desarmes("PLUME_SSRF_BLOCK_PRIVATE=off\n"), vec!["PLUME_SSRF_BLOCK_PRIVATE=off".to_string()]);
        assert_eq!(defauts_desarmes("export PLUME_SSRF_BLOCK_PRIVATE=\"false\"\n"), vec!["PLUME_SSRF_BLOCK_PRIVATE=false".to_string()]);
        assert_eq!(defauts_desarmes("PLUME_HOST_STRICT=0\n"), vec!["PLUME_HOST_STRICT=0".to_string()]);
        assert_eq!(defauts_desarmes("PLUME_HOST_STRICT='no'\n"), vec!["PLUME_HOST_STRICT=no".to_string()]);
        assert_eq!(defauts_desarmes("PLUME_SSRF_BLOCK_PRIVATE=\nPLUME_HOST_STRICT=\n"), Vec::<String>::new(), "vides : le défaut");
        assert_eq!(defauts_desarmes("PLUME_SSRF_BLOCK_PRIVATE=1\nPLUME_HOST_STRICT=1\n"), Vec::<String>::new(), "durcis : admis");
        assert_eq!(defauts_desarmes("# PLUME_SSRF_BLOCK_PRIVATE=0\n"), Vec::<String>::new(), "un commentaire ne pose rien");
        let exemple = fichier_du_depot(".env.example");
        let poses: Vec<String> = affectations(&exemple).into_iter().map(|(cle, _)| cle).collect();
        for cle in ["PLUME_SSRF_BLOCK_PRIVATE", "PLUME_HOST_STRICT", "PLUME_SSRF_ALLOW"] {
            assert!(poses.iter().any(|p| p == cle), ".env.example pose {cle} (vide), pour qu'on le trouve");
        }
        assert_eq!(defauts_desarmes(&exemple), Vec::<String>::new(), ".env.example ne désarme aucun défaut");
    }

    // ------------------------------------------------------------------ (2) la garde d'égress, par la vraie chaîne

    /// Une base complète sur disque (schéma et chaîne de migrations).
    fn base_complete(chemin: &std::path::Path) -> Connection {
        let c = open_db(&chemin.to_string_lossy()).expect("base du témoin");
        c.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma");
        assert!(migrate(&c), "fixture : migrations complètes");
        c
    }

    /// Écrit les surcouches du témoin : un canal, un slack (webhook par référence), un email (relais SMTP interne), un
    /// générique ; trois destinations actives (syslog, HEC à slash final avec jeton par référence, webhook) ; quatre
    /// connecteurs actifs (par `url`, par `api_root`+`path` avec point de jeton OAuth2, taxii2, defender sur des hôtes
    /// privés) ; un connecteur REJETÉ (secret en clair) et, par genre, un objet dont l'ÉCRITURE sera refusée.
    fn ecrire_les_surcouches(racine: &std::path::Path, avec_le_canal: bool) {
        for sous in ["notifiers", "destinations", "connectors"] {
            std::fs::create_dir_all(racine.join(sous)).expect("dossier de surcouche");
        }
        let ecrire = |sous: &str, fichier: &str, v: Value| {
            std::fs::write(racine.join(sous).join(fichier), v.to_string()).expect("surcouche du témoin");
        };
        if avec_le_canal {
            ecrire("notifiers", "canal.json", json!({ "name": "p720a-canal", "kind": "webhook", "url": CANAL_DE_SURCOUCHE, "min_severity": 0 }));
        }
        ecrire("notifiers", "slack.json", json!({ "name": "p720a-slack", "kind": "slack", "config": { "webhook_url": format!("env:{VARIABLE_SLACK}") } }));
        ecrire("notifiers", "refuse.json", json!({ "name": "p720a-canal-refuse", "kind": "webhook", "url": CANAL_ECRITURE_REFUSEE }));
        ecrire("notifiers", "email.json", json!({ "name": "p720a-email", "kind": "email", "url": EMAIL_DE_SURCOUCHE }));
        ecrire("notifiers", "generique.json", json!({ "name": "p720a-generique", "kind": "generic", "url": GENERIQUE_DE_SURCOUCHE }));
        ecrire("destinations", "syslog.json", json!({ "name": "p720a-syslog", "type": "syslog", "enabled": true, "endpoint": DESTINATION_SYSLOG_DE_SURCOUCHE }));
        ecrire("destinations", "hec.json", json!({ "name": "p720a-hec", "type": "hec", "enabled": true, "endpoint": DESTINATION_HEC_DE_SURCOUCHE,
            "config": { "hec_token": format!("env:{VARIABLE_JETON_HEC}") } }));
        ecrire("destinations", "refusee.json", json!({ "name": "p720a-destination-refusee", "type": "syslog", "enabled": true, "endpoint": DESTINATION_ECRITURE_REFUSEE }));
        ecrire("destinations", "webhook.json", json!({ "name": "p720a-webhook", "type": "webhook", "enabled": true, "endpoint": DESTINATION_WEBHOOK_DE_SURCOUCHE }));
        let carte_des_champs = json!({ "message": "msg" });
        ecrire("connectors", "par-url.json", json!({ "name": "p720a-par-url", "type": "http_pull", "enabled": true,
            "config": { "url": CONNECTEUR_PAR_URL, "records_path": "items", "field_map": carte_des_champs,
                        "pagination": { "kind": "offset", "param": "offset", "size": 50, "size_param": "limit" } } }));
        ecrire("connectors", "par-racine.json", json!({ "name": "p720a-par-racine", "type": "http_pull", "enabled": true,
            "secret_ref": format!("env:{VARIABLE_CLIENT}"),
            "config": { "api_root": CONNECTEUR_PAR_RACINE, "path": "/evenements", "records_path": "items", "field_map": carte_des_champs,
                        "auth": { "kind": "oauth2_client_credentials", "token_url": JETON_DU_CONNECTEUR, "client_id": "p720a" } } }));
        ecrire("connectors", "taxii.json", json!({ "name": "p720a-taxii", "type": "taxii2", "enabled": true,
            "config": { "api_root": RACINE_TAXII, "collection_id": "c-1" } }));
        ecrire("connectors", "defender.json", json!({ "name": "p720a-defender", "type": "defender", "enabled": true,
            "secret_ref": format!("env:{VARIABLE_CLIENT}"),
            "config": { "azure_tenant": "t-1", "client_id": "c-1", "graph_host": DEFENDER_GRAPH, "login_host": DEFENDER_LOGIN } }));
        ecrire("connectors", "rejete.json", json!({ "name": "p720a-rejete", "type": "http_pull", "secret": "en-clair",
            "config": { "url": CONNECTEUR_REJETE, "records_path": "items", "field_map": carte_des_champs } }));
        ecrire("connectors", "refuse.json", json!({ "name": "p720a-connecteur-refuse", "type": "http_pull",
            "config": { "url": CONNECTEUR_ECRITURE_REFUSEE, "records_path": "items", "field_map": carte_des_champs } }));
    }

    /// Charge les trois familles de surcouches dans `c`, déclencheurs de refus d'écriture posés.
    fn charger_les_surcouches(c: &Connection, racine: &std::path::Path, cle: &str) {
        c.execute_batch(
            "CREATE TEMP TRIGGER IF NOT EXISTS p720a_canal_refuse BEFORE INSERT ON main.notifier WHEN NEW.name='p720a-canal-refuse' \
               BEGIN SELECT RAISE(ABORT, 'p720a : écriture refusée'); END; \
             CREATE TEMP TRIGGER IF NOT EXISTS p720a_destination_refusee BEFORE INSERT ON main.destination WHEN NEW.name='p720a-destination-refusee' \
               BEGIN SELECT RAISE(ABORT, 'p720a : écriture refusée'); END; \
             CREATE TEMP TRIGGER IF NOT EXISTS p720a_connecteur_refuse BEFORE INSERT ON main.connector WHEN NEW.name='p720a-connecteur-refuse' \
               BEGIN SELECT RAISE(ABORT, 'p720a : écriture refusée'); END;",
        )
        .expect("déclencheurs du témoin");
        let n = crate::overlays_oac::load_overlay_notifiers(c, &racine.join("notifiers"));
        let d = crate::overlays_oac::load_overlay_destinations(c, &racine.join("destinations"));
        let k = crate::overlays_oac::load_overlay_connectors(c, &racine.join("connectors"));
        println!("P720A-{cle}:{}/{}/{}", n.charges, d.charges, k.charges);
    }

    /// Les JUMEAUX de l'API : une ligne par genre, recopiée d'une surcouche (même URL, même configuration), sous un autre
    /// identifiant et sans `managed`. Aucune n'est inscrite : chacune doit être jugée de l'API à l'envoi.
    fn poser_les_jumeaux_de_l_api(c: &Connection) {
        c.execute_batch(
            "INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) \
               SELECT 141,'p720a-jumeau-canal',kind,1,url,0,config FROM notifier WHERE name='p720a-canal'; \
             INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) \
               SELECT 142,'p720a-jumeau-slack',kind,1,url,0,config FROM notifier WHERE name='p720a-slack'; \
             INSERT INTO destination(id,type,name,enabled,endpoint,config,filter,batch_max,interval_s) \
               SELECT 151,type,'p720a-jumeau-webhook',1,endpoint,config,filter,batch_max,interval_s FROM destination WHERE name='p720a-webhook'; \
             INSERT INTO destination(id,type,name,enabled,endpoint,config,filter,batch_max,interval_s) \
               SELECT 152,type,'p720a-jumeau-syslog',1,endpoint,config,filter,batch_max,interval_s FROM destination WHERE name='p720a-syslog'; \
             INSERT INTO destination(id,type,name,enabled,endpoint,config,filter,batch_max,interval_s) \
               SELECT 153,type,'p720a-jumeau-hec',1,endpoint,config,filter,batch_max,interval_s FROM destination WHERE name='p720a-hec'; \
             INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) \
               SELECT 161,type,'p720a-jumeau-par-url',1,config_json,secret,interval_s,env_id FROM connector WHERE name='p720a-par-url'; \
             INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) \
               SELECT 162,type,'p720a-jumeau-taxii',1,config_json,secret,interval_s,env_id FROM connector WHERE name='p720a-taxii'; \
             INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id) \
               SELECT 163,type,'p720a-jumeau-defender',1,config_json,secret,interval_s,env_id FROM connector WHERE name='p720a-defender';",
        )
        .expect("jumeaux de l'API");
    }

    /// Ce que le témoin de l'égress répond, par URL : jetons, pages TAXII (la première annonce une suite), pages Graph (la
    /// première porte un `@odata.nextLink`), sinon un corps vide de collecte.
    fn repondre_au_temoin(_methode: &str, url: &str) -> Result<HttpResp, String> {
        let corps = if url.contains("/oauth2/v2.0/token") || url.ends_with("/oauth/jeton") {
            r#"{"access_token":"p720a-jeton","expires_in":3600}"#.to_string()
        } else if url.contains("/taxii2/") && url.contains("&next=") {
            r#"{"objects":[],"more":false}"#.to_string()
        } else if url.contains("/taxii2/") {
            r#"{"objects":[],"more":true,"next":"c2"}"#.to_string()
        } else if url.contains("/v1.0/security/") && url.contains("$skiptoken=") {
            r#"{"value":[]}"#.to_string()
        } else if url.contains("/v1.0/security/") {
            format!(r#"{{"value":[],"@odata.nextLink":"{DEFENDER_PAGE_SUIVANTE}"}}"#)
        } else {
            r#"{"items":[]}"#.to_string()
        };
        Ok(crate::ledger::temoin_de_l_egress::reponse(200, &[], &corps))
    }

    /// `last_error` de chaque ligne `p720a-%` d'une table, ou « ok ».
    fn etats(c: &Connection, table: &str) -> Vec<(String, String)> {
        let mut st = c.prepare(&format!("SELECT name, COALESCE(last_error,'') FROM {table} WHERE name LIKE 'p720a-%' ORDER BY name")).expect("lecture des états");
        let lignes = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .expect("lecture des états")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("états lisibles");
        lignes.into_iter().map(|(nom, e)| (nom, if e.is_empty() { "ok".to_string() } else { e })).collect()
    }

    fn id_de(c: &Connection, table: &str, nom: &str) -> Option<i64> {
        use rusqlite::OptionalExtension as _;
        c.query_row(&format!("SELECT id FROM {table} WHERE name=?1"), params![nom], |r| r.get(0)).optional().expect("id lisible")
    }

    /// Corps (statut, texte) d'une réponse.
    async fn corps(r: Response) -> (u16, String) {
        let code = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (code, String::from_utf8_lossy(&b).into_owned())
    }

    /// Le corps JSON d'une réponse de route, une ligne.
    async fn corps_json(r: Response) -> String {
        let (code, texte) = corps(r).await;
        let v: Value = serde_json::from_str(&texte).unwrap_or(Value::String(texte));
        format!("{code} {v}")
    }

    /// L'enfant du témoin d'égress : canal semé, garde sans objet, fournisseurs, puis surcouches et jumeaux jugés par la
    /// vraie chaîne d'envoi (destinations, connecteurs, de fond et par les routes), puis rechargement.
    fn jouer_l_egress_dans_l_enfant() {
        use crate::ledger::temoin_de_l_egress;
        let bases = std::path::PathBuf::from(std::env::var("P720A_BASES").expect("dossier des bases"));
        let chemin = bases.join("principale.db");
        let chemin_s = chemin.to_string_lossy().to_string();
        let c = base_complete(&chemin);
        // Le canal semé par l'environnement, et une ligne de l'API PLUS ANCIENNE qui vise la même URL.
        c.execute("INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) VALUES(41,'p720a-api-meme-url','ntfy',1,?1,0,'{}')",
            params![CIBLE_DE_CONFIGURATION]).expect("ligne de l'API");
        let conf = load_config();
        seed_env_notifier(&c, &conf);
        crate::overlays_oac::inscrire_le_canal_de_l_environnement(&c, &conf);
        let canal = |c: &Connection, id: Option<i64>, url: &str| -> String {
            match id {
                Some(id) => {
                    let (k, u, cf): (String, String, String) = c
                        .query_row("SELECT kind,url,config FROM notifier WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                        .expect("ligne du canal");
                    admis_si(egress_url_ok_pour_l_objet(url, &cibles_inscrites_du_canal(c, id, &k, &u, &cf))).to_string()
                }
                None => "absent".to_string(),
            }
        };
        let id_seme = id_de(&c, "notifier", "ntfy (env)");
        println!("P720A-CONF:{}", canal(&c, id_seme, CIBLE_DE_CONFIGURATION));
        println!("P720A-CONF-REQUETE:{}", canal(&c, id_seme, &format!("{CIBLE_DE_CONFIGURATION}?x=1")));
        println!("P720A-CONF-API:{}", canal(&c, Some(41), CIBLE_DE_CONFIGURATION));
        println!("P720A-CONF-SANS-OBJET:{}", issue(ssrf_guard(CIBLE_DE_CONFIGURATION)));
        println!("P720A-CONF-SAISIE:{}", admis_si(egress_url_ok_pour_une_saisie_de_l_api(CIBLE_DE_CONFIGURATION)));
        let api = ssrf_guard(CIBLE_API_PRIVEE);
        // Le fetch sans objet n'est joué que si la garde refuse : admise, la requête partirait sur le réseau.
        let connecteur = if api.is_err() {
            match crate::handlers::connectors::guarded_http_call("GET", CIBLE_API_PRIVEE, &[], None) {
                Ok(_) => "admis".to_string(),
                Err(e) => e,
            }
        } else {
            "non-joue".to_string()
        };
        println!("P720A-API:{}", issue(api));
        println!("P720A-API-CONNECTEUR:{connecteur}");
        println!("P720A-API-NOM:{}", issue(ssrf_guard(CIBLE_API_NOM_PRIVE)));
        println!("P720A-API-DESTINATION:{}", admis_si(dest_endpoint_ok("webhook", CIBLE_API_PRIVEE)));
        println!("P720A-IDP-IA:{}", issue(crate::ledger::ssrf_guard_d_un_fournisseur(CIBLE_API_PRIVEE)));
        println!("P720A-IDP-IA-METADONNEES:{}", issue(crate::ledger::ssrf_guard_d_un_fournisseur(CIBLE_METADONNEES)));
        println!("P720A-IA-PRESET-OLLAMA:{}", issue(crate::ledger::ssrf_guard_d_un_fournisseur("http://10.0.0.5:11434/api/chat")));

        // Surcouches, puis jumeaux de l'API.
        let racine = std::path::PathBuf::from(std::env::var("P720A_SURCOUCHES").expect("dossier des surcouches"));
        charger_les_surcouches(&c, &racine.join("premier"), "CHARGES");
        let compte = |sql: &str| -> i64 { c.query_row(sql, [], |r| r.get(0)).expect("compte lisible") };
        println!("P720A-POSES:{}/{}/{}", compte("SELECT COUNT(*) FROM notifier WHERE name LIKE 'p720a-%' AND managed=1"),
            compte("SELECT COUNT(*) FROM destination WHERE name LIKE 'p720a-%' AND managed=1"),
            compte("SELECT COUNT(*) FROM connector WHERE name LIKE 'p720a-%' AND managed=1"));
        poser_les_jumeaux_de_l_api(&c);
        // Canaux : chaque objet jugé avec SES cibles inscrites.
        for (cle, nom, url) in [
            ("CANAL", "p720a-canal", CANAL_DE_SURCOUCHE), ("SLACK", "p720a-slack", SLACK_DE_SURCOUCHE),
            ("EMAIL", "p720a-email", EMAIL_DE_SURCOUCHE), ("GENERIQUE", "p720a-generique", GENERIQUE_DE_SURCOUCHE),
            ("CANAL-REFUSE", "p720a-canal-refuse", CANAL_ECRITURE_REFUSEE),
            ("JUMEAU-CANAL", "p720a-jumeau-canal", CANAL_DE_SURCOUCHE), ("JUMEAU-SLACK", "p720a-jumeau-slack", SLACK_DE_SURCOUCHE),
        ] {
            println!("P720A-ENVOI-{cle}:{}", canal(&c, id_de(&c, "notifier", nom), url));
        }
        // Destinations et connecteurs : le filigrane TAXII d'un passage antérieur, un événement à transmettre.
        c.execute("UPDATE connector SET watermark=?1 WHERE name IN ('p720a-taxii','p720a-jumeau-taxii')", params![FILIGRANE_TAXII]).expect("filigrane TAXII");
        c.execute("INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,'p720a','auth',3,'h1','m')", params![now()]).expect("événement");
        let db = Arc::new(Mutex::new(c));
        let arme = temoin_de_l_egress::armer(repondre_au_temoin);
        let _ = run_due_destinations(&db, &chemin_s);
        let _ = run_due_connectors(&db, &chemin_s);
        let vus = temoin_de_l_egress::vus();
        let vu = |methode: &str, url: &str| vus.iter().filter(|(m, u)| m == methode && u == url).count();
        let vu_debut = |methode: &str, debut: &str| vus.iter().filter(|(m, u)| m == methode && u.starts_with(debut)).count();
        let taxii = crate::handlers::connectors::TaxiiCfg::from_json(&json!({ "api_root": RACINE_TAXII, "collection_id": "c-1" }));
        println!("P720A-VU-SYSLOG:{}", vu("TCP", DESTINATION_SYSLOG_DE_SURCOUCHE));
        println!("P720A-VU-HEC:{}", vu("POST", HEC_D_EMISSION));
        println!("P720A-VU-WEBHOOK:{}", vu("POST", DESTINATION_WEBHOOK_DE_SURCOUCHE));
        println!("P720A-VU-TAXII-1:{}", vu("GET", &crate::handlers::connectors::taxii_objects_url(&taxii, Some(FILIGRANE_TAXII), None)));
        println!("P720A-VU-TAXII-2:{}", vu("GET", &crate::handlers::connectors::taxii_objects_url(&taxii, Some(FILIGRANE_TAXII), Some("c2"))));
        println!("P720A-VU-JETON:{}", vu("POST", JETON_DU_CONNECTEUR));
        println!("P720A-VU-PAGE-PAR-RACINE:{}", vu_debut("GET", "http://10.0.0.16/racine/evenements"));
        println!("P720A-VU-PAGE-PAR-URL:{}", vu_debut("GET", CONNECTEUR_PAR_URL));
        println!("P720A-VU-DEFENDER-JETON:{}", vu("POST", DEFENDER_JETON));
        println!("P720A-VU-DEFENDER-PAGE-1:{}", vu_debut("GET", "https://10.0.0.42/v1.0/security/alerts_v2?$filter="));
        println!("P720A-VU-DEFENDER-PAGE-2:{}", vu("GET", DEFENDER_PAGE_SUIVANTE));
        println!("P720A-VUS:{}", vus.len());
        drop(arme);
        {
            let c = db.lock();
            for (nom, etat) in etats(&c, "destination").into_iter().chain(etats(&c, "connector")) {
                println!("P720A-ETAT-{nom}:{etat}");
            }
        }

        // Les routes : essai, poll manuel et envoi manuel, pour une surcouche et pour son jumeau.
        let st = ds_file_state(&chemin_s);
        let ids: Vec<(String, Option<i64>)> = {
            let c = db.lock();
            ["p720a-taxii", "p720a-jumeau-taxii", "p720a-par-url", "p720a-jumeau-par-url", "p720a-defender", "p720a-jumeau-defender"]
                .iter()
                .map(|n| (n.to_string(), id_de(&c, "connector", n)))
                .chain(["p720a-webhook", "p720a-jumeau-webhook"].iter().map(|n| (n.to_string(), id_de(&c, "destination", n))))
                .collect()
        };
        db.lock().execute("INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,'p720a','auth',3,'h1','m2')", params![now()]).expect("second événement");
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime de l'enfant");
        let arme = temoin_de_l_egress::armer(repondre_au_temoin);
        rt.block_on(async {
            for (nom, id) in &ids {
                let Some(id) = *id else {
                    println!("P720A-ROUTE-{nom}:absent");
                    continue;
                };
                if nom.contains("webhook") {
                    let _ = destination_flush(State(st.clone()), Extension(ergo_au("admin")), Path(id)).await;
                } else {
                    let r = crate::handlers::connectors::connector_test(State(st.clone()), Extension(ergo_au("admin")), Path(id)).await;
                    println!("P720A-ESSAI-{nom}:{}", corps_json(r).await);
                    if nom.contains("par-url") {
                        db.lock().execute("UPDATE connector SET last_error='p720a-avant-le-poll' WHERE id=?1", params![id]).expect("marque avant le poll");
                        let _ = crate::handlers::connectors::connector_poll(State(st.clone()), Extension(ergo_au("admin")), Path(id)).await;
                    }
                }
            }
        });
        let vus_routes = temoin_de_l_egress::vus();
        drop(arme);
        println!("P720A-VU-ROUTE-WEBHOOK:{}", vus_routes.iter().filter(|(m, u)| m == "POST" && u == DESTINATION_WEBHOOK_DE_SURCOUCHE).count());
        {
            let c = db.lock();
            for (nom, etat) in etats(&c, "destination").into_iter().chain(etats(&c, "connector")) {
                if nom.contains("webhook") || nom.contains("par-url") {
                    println!("P720A-APRES-ROUTE-{nom}:{etat}");
                }
            }
        }

        // Rechargement sans le canal : son inscription est retirée ; ce qui reste (mis à jour, même identifiant) est inscrit.
        {
            let c = db.lock();
            charger_les_surcouches(&c, &racine.join("second"), "RECHARGES");
            println!("P720A-RECHARGE-CANAL:{}", canal(&c, id_de(&c, "notifier", "p720a-canal"), CANAL_DE_SURCOUCHE));
            println!("P720A-RECHARGE-SLACK:{}", canal(&c, id_de(&c, "notifier", "p720a-slack"), SLACK_DE_SURCOUCHE));
            println!("P720A-RECHARGE-JUMEAU-SLACK:{}", canal(&c, id_de(&c, "notifier", "p720a-jumeau-slack"), SLACK_DE_SURCOUCHE));
        }
    }

    /// Les routes de saisie : création et modification d'un canal, d'une destination et d'un connecteur, corps entier.
    fn jouer_les_routes_de_saisie() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime de l'enfant");
        rt.block_on(async {
            let st = sso_test_state("admins", "editors", "supers");
            let creer_canal = |url: &str| notifier_create(State(st.clone()), Extension(ergo_au("admin")), Json(json!({ "kind": "webhook", "url": url, "name": "p720a" })));
            println!("P720A-CREATION-PRIVEE:{:?}", corps(creer_canal(CIBLE_API_PRIVEE).await).await);
            println!("P720A-CREATION-EXACTE:{:?}", corps(creer_canal(CIBLE_DE_CONFIGURATION).await).await);
            println!("P720A-CREATION-METADONNEES:{:?}", corps(creer_canal(CIBLE_METADONNEES).await).await);
            let r = notifier_create(State(st.clone()), Extension(ergo_au("admin")), Json(json!({ "kind": "slack", "url": CIBLE_API_PRIVEE, "name": "p720a-sans-url-requise" }))).await;
            println!("P720A-CREATION-FACULTATIVE:{:?}", corps(r).await);
            let r = notifier_create(State(st.clone()), Extension(ergo_au("admin")), Json(json!({ "kind": "slack", "url": CIBLE_DE_CONFIGURATION, "name": "p720a-facultative-exacte" }))).await;
            println!("P720A-CREATION-FACULTATIVE-EXACTE:{:?}", corps(r).await);
            let r = notifier_update(State(st.clone()), Extension(ergo_au("admin")), Path(1), Json(json!({ "url": CIBLE_DE_CONFIGURATION }))).await;
            println!("P720A-MAJ-CANAL-EXACTE:{:?}", corps(r).await);
            let config_slack = json!({ "webhook_url": CIBLE_API_PRIVEE }).to_string();
            let r = notifier_create(State(st.clone()), Extension(ergo_au("admin")), Json(json!({ "kind": "slack", "name": "p720a-slack-saisi", "config": config_slack }))).await;
            println!("P720A-CREATION-SLACK-PRIVE:{:?}", corps(r).await);
            let r = notifier_update(State(st.clone()), Extension(ergo_au("admin")), Path(1), Json(json!({ "config": config_slack }))).await;
            println!("P720A-MAJ-SLACK-PRIVE:{:?}", corps(r).await);
            let r = notifier_update(State(st.clone()), Extension(ergo_au("admin")), Path(1), Json(json!({ "url": CIBLE_API_PRIVEE }))).await;
            println!("P720A-MAJ-CANAL-PRIVEE:{:?}", corps(r).await);
            let r = notifier_update(State(st.clone()), Extension(ergo_au("admin")), Path(1), Json(json!({ "url": CIBLE_METADONNEES }))).await;
            println!("P720A-MAJ-CANAL-METADONNEES:{:?}", corps(r).await);
            let creer_destination = |dtype: &str, endpoint: &str| {
                destination_create(State(st.clone()), Extension(ergo_au("admin")), Json(json!({ "type": dtype, "name": "p720a-d", "endpoint": endpoint })))
            };
            println!("P720A-DESTINATION-WEBHOOK-PRIVEE:{:?}", corps(creer_destination("webhook", CIBLE_API_PRIVEE).await).await);
            println!("P720A-DESTINATION-SYSLOG-PRIVEE:{:?}", corps(creer_destination("syslog", "tcp://10.0.0.9:514").await).await);
            println!("P720A-DESTINATION-METADONNEES:{:?}", corps(creer_destination("webhook", CIBLE_METADONNEES).await).await);
            println!("P720A-DESTINATION-EXACTE:{:?}", corps(creer_destination("webhook", CIBLE_DE_CONFIGURATION).await).await);
            println!("P720A-DESTINATION-HEC-PRIVEE:{:?}", corps(creer_destination("hec", "https://10.0.0.9:8088").await).await);
            println!("P720A-DESTINATION-SCHEMA:{:?}", corps(creer_destination("webhook", "ftp://10.0.0.9/x").await).await);
            let creer_connecteur = |ctype: &str, config: Value| {
                crate::handlers::connectors::connector_create(State(st.clone()), Extension(ergo_au("admin")), Json(json!({ "type": ctype, "name": "p720a-k", "config": config })))
            };
            let carte_des_champs = json!({ "message": "msg" });
            let r = creer_connecteur("http_pull", json!({ "url": "http://10.0.0.9/api", "records_path": "items", "field_map": carte_des_champs })).await;
            println!("P720A-CONNECTEUR-PRIVE:{:?}", corps(r).await);
            let r = creer_connecteur("http_pull", json!({ "url": format!("{CONNECTEUR_PAR_URL}?filtre=tout"), "records_path": "items", "field_map": carte_des_champs })).await;
            println!("P720A-CONNECTEUR-BASE-DE-SURCOUCHE:{:?}", corps(r).await);
            let r = creer_connecteur("http_pull", json!({ "url": "https://192.0.2.10/api", "records_path": "items", "field_map": carte_des_champs,
                "auth": { "kind": "oauth2_client_credentials", "token_url": "http://10.0.0.9/jeton", "client_id": "p720a" } })).await;
            println!("P720A-CONNECTEUR-JETON-PRIVE:{:?}", corps(r).await);
            let r = creer_connecteur("taxii2", json!({ "api_root": "http://10.0.0.9/taxii2/", "collection_id": "c" })).await;
            println!("P720A-CONNECTEUR-TAXII-PRIVE:{:?}", corps(r).await);
            let r = creer_connecteur("defender", json!({ "azure_tenant": "t", "client_id": "c", "graph_host": "10.0.0.9" })).await;
            println!("P720A-CONNECTEUR-DEFENDER-GRAPH-PRIVE:{:?}", corps(r).await);
            let r = creer_connecteur("defender", json!({ "azure_tenant": "t", "client_id": "c", "login_host": "10.0.0.9" })).await;
            println!("P720A-CONNECTEUR-DEFENDER-LOGIN-PRIVE:{:?}", corps(r).await);
            let (st_fichier, base) = router_test_state("p720a-destination");
            {
                let c = open_db(&base).expect("base du témoin");
                c.execute("INSERT INTO destination(id,type,name,endpoint) VALUES(7,'webhook','p720a-existante','https://192.0.2.10/in')", [])
                    .expect("destination existante");
                c.execute_batch(
                    "INSERT INTO connector(id,type,name,config_json) VALUES(9,'http_pull','p720a-existant','{}'); \
                     INSERT INTO connector(id,type,name,config_json) VALUES(10,'taxii2','p720a-taxii-existant','{}'); \
                     INSERT INTO connector(id,type,name,config_json) VALUES(11,'defender','p720a-defender-existant','{}');",
                )
                .expect("connecteurs existants");
            }
            let maj = |endpoint: &str| {
                destination_update(State(st_fichier.clone()), Extension(ergo_au("admin")), Path(7), Json(json!({ "endpoint": endpoint })))
            };
            println!("P720A-MAJ-DESTINATION-PRIVEE:{:?}", corps(maj(CIBLE_API_PRIVEE).await).await);
            println!("P720A-MAJ-DESTINATION-METADONNEES:{:?}", corps(maj(CIBLE_METADONNEES).await).await);
            println!("P720A-MAJ-DESTINATION-EXACTE:{:?}", corps(maj(CIBLE_DE_CONFIGURATION).await).await);
            // Modification d'un connecteur, un témoin par TYPE lu en base : la config de chacun vers une adresse privée.
            let maj_connecteur = |id: i64, config: Value| {
                crate::handlers::connectors::connector_update(State(st_fichier.clone()), Extension(ergo_au("admin")), Path(id), Json(json!({ "config": config })))
            };
            let r = maj_connecteur(9, json!({ "url": "http://10.0.0.9/api", "records_path": "items", "field_map": { "message": "msg" } })).await;
            println!("P720A-MAJ-CONNECTEUR-PRIVE:{:?}", corps(r).await);
            let r = maj_connecteur(10, json!({ "api_root": "http://10.0.0.9/taxii2/", "collection_id": "c" })).await;
            println!("P720A-MAJ-CONNECTEUR-TAXII-PRIVE:{:?}", corps(r).await);
            let r = maj_connecteur(11, json!({ "azure_tenant": "t", "client_id": "c", "graph_host": "10.0.0.9" })).await;
            println!("P720A-MAJ-CONNECTEUR-DEFENDER-PRIVE:{:?}", corps(r).await);
            // Contrôle positif : une config publique passe et s'écrit.
            let r = maj_connecteur(10, json!({ "api_root": "https://192.0.2.10/taxii2/", "collection_id": "c" })).await;
            println!("P720A-MAJ-CONNECTEUR-TAXII-PUBLIC:{}", corps(r).await.0);
            let ecrite: String = open_db(&base).expect("base du témoin").query_row("SELECT config_json FROM connector WHERE id=10", [], |r| r.get(0)).expect("config relue");
            println!("P720A-MAJ-CONNECTEUR-TAXII-PUBLIC-ECRITE:{}", ecrite.contains("192.0.2.10"));
        });
    }

    /// Chaque chaîne réglage -> garde -> envoi, dans un enfant par réglage.
    #[test]
    fn p720a_la_garde_d_egress_selon_le_reglage_et_l_origine() {
        const ENFANT: &str = "P720A_ENFANT_EGRESS";
        const FIN: &str = "P720A-EGRESS-A-JOUE";
        if std::env::var(ENFANT).is_ok() {
            println!(); // la première ligne de l'enfant suit l'en-tête de libtest
            jouer_l_egress_dans_l_enfant();
            jouer_les_routes_de_saisie();
            println!("{FIN}");
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // le parent lit l'environnement pour le vider chez l'enfant
        let dossier = crate::tmp_possede::TmpPossede::neuf("p720a-configuration-egress");
        let fichier_vide = dossier.join("vide.conf");
        std::fs::write(&fichier_vide, "# aucune cible\n").expect("configuration vide du témoin");
        let fichier_avec_cible = dossier.join("avec-cible.conf");
        std::fs::write(&fichier_avec_cible, format!("PLUME_NOTIFY_NTFY_URL={CIBLE_DE_CONFIGURATION}\n")).expect("configuration du témoin");
        let fichier_admet = dossier.join("admet.conf");
        std::fs::write(&fichier_admet, "PLUME_SSRF_BLOCK_PRIVATE=0\n").expect("configuration du témoin");
        let surcouches = dossier.join("config.d");
        ecrire_les_surcouches(&surcouches.join("premier"), true);
        ecrire_les_surcouches(&surcouches.join("second"), false);
        let numero = std::cell::Cell::new(0u32);
        let jouer = |configuration: &std::path::Path, reglages: &[(&str, &str)]| -> (String, String) {
            numero.set(numero.get() + 1);
            let bases = dossier.join(format!("bases-{}", numero.get()));
            std::fs::create_dir_all(&bases).expect("dossier des bases");
            let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}p720a_la_garde_d_egress_selon_le_reglage_et_l_origine"));
            for (nom, _) in std::env::vars_os() {
                if nom.to_string_lossy().starts_with("PLUME_") {
                    commande.env_remove(&nom);
                }
            }
            commande
                .env(ENFANT, "1")
                .env("PLUME_CONFIG", configuration)
                .env("P720A_SURCOUCHES", &surcouches)
                .env("P720A_BASES", &bases)
                .env(VARIABLE_SLACK, SLACK_DE_SURCOUCHE)
                .env(VARIABLE_JETON_HEC, VALEUR_DU_TEMOIN)
                .env(VARIABLE_CLIENT, VALEUR_DU_TEMOIN);
            for (k, v) in reglages {
                commande.env(k, v);
            }
            let sortie = commande.output().expect("ré-exécution du binaire de test");
            let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
            assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout ({reglages:?}) : {stdout}\n{stderr}");
            assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 ({reglages:?}) : {stdout}\n{stderr}");
            (stdout, stderr)
        };
        let refus = |phrase: &str| format!("{:?}", (400u16, json!({ "error": phrase }).to_string()));

        // (a) DÉFAUT, canal semé par l'ENVIRONNEMENT.
        let (a, a_err) = jouer(&fichier_vide, &[("PLUME_NOTIFY_NTFY_URL", CIBLE_DE_CONFIGURATION)]);
        assert_eq!(lu(&a, "P720A-CONF"), "admis", "défaut : le canal semé, privé, part vers son URL exacte");
        assert_eq!(lu(&a, "P720A-CONF-REQUETE"), "refuse", "le canal semé est exact : une requête ajoutée en sort");
        assert_eq!(lu(&a, "P720A-CONF-API"), "refuse", "une ligne de l'API qui vise la même URL : de l'API (registre borné à l'objet)");
        assert_eq!(lu(&a, "P720A-CONF-SANS-OBJET"), "refuse", "sans objet nommé : de l'API");
        assert_eq!(lu(&a, "P720A-CONF-SAISIE"), "refuse", "saisie par l'API, l'URL déclarée elle-même est jugée de l'API");
        assert_eq!(lu(&a, "P720A-API"), "refuse");
        assert_eq!(lu(&a, "P720A-API-CONNECTEUR"), refus_prive("10.0.0.9"), "le fetch sans objet refuse PAR LA GARDE, leviers nommés");
        assert_eq!(lu(&a, "P720A-API-NOM"), "refuse", "défaut : un nom qui résout vers le RFC1918 est refusé");
        assert_eq!(lu(&a, "P720A-API-DESTINATION"), "refuse");
        assert_eq!(lu(&a, "P720A-IDP-IA"), "admis", "fournisseurs d'identité et d'IA : de configuration, privée admise");
        assert_eq!(lu(&a, "P720A-IDP-IA-METADONNEES"), "refuse", "le never-egress reste refusé pour un fournisseur");
        assert_eq!(lu(&a, "P720A-IA-PRESET-OLLAMA"), "admis", "preset ollama-local : une side-box RFC1918 reste admise par défaut");
        assert_eq!(lu(&a, "P720A-CHARGES"), "4/3/4", "chargés : quatre canaux, trois destinations, quatre connecteurs (rejeté et refusés exclus)");
        assert_eq!(lu(&a, "P720A-POSES"), "4/3/4");
        let envois = [
            ("CANAL", "admis"), ("SLACK", "admis"), ("EMAIL", "admis"), ("GENERIQUE", "admis"),
            ("CANAL-REFUSE", "absent"), ("JUMEAU-CANAL", "refuse"), ("JUMEAU-SLACK", "refuse"),
        ];
        for (cle, attendu) in envois {
            assert_eq!(lu(&a, &format!("P720A-ENVOI-{cle}")), attendu, "canal {cle}");
        }
        // La vraie chaîne d'envoi : une fois chacune pour la surcouche, jamais pour son jumeau (refusé avant le réseau).
        let vus = [
            ("SYSLOG", "1"), ("HEC", "1"), ("WEBHOOK", "1"), ("TAXII-1", "1"), ("TAXII-2", "1"), ("JETON", "1"),
            ("PAGE-PAR-RACINE", "1"), ("PAGE-PAR-URL", "1"), ("DEFENDER-JETON", "1"), ("DEFENDER-PAGE-1", "1"), ("DEFENDER-PAGE-2", "1"),
        ];
        for (cle, attendu) in vus {
            assert_eq!(lu(&a, &format!("P720A-VU-{cle}")), attendu, "envoi {cle} vu par le témoin de l'égress");
        }
        assert_eq!(lu(&a, "P720A-VUS"), "11", "rien d'autre n'est parti");
        let etats_attendus = [
            ("p720a-hec", "ok".to_string()), ("p720a-syslog", "ok".to_string()), ("p720a-webhook", "ok".to_string()),
            ("p720a-jumeau-hec", refus_prive("10.0.0.13")), ("p720a-jumeau-syslog", refus_prive("10.0.0.11")),
            ("p720a-jumeau-webhook", refus_prive("10.0.0.35")),
            ("p720a-defender", "ok".to_string()), ("p720a-par-racine", "ok".to_string()), ("p720a-par-url", "ok".to_string()),
            ("p720a-taxii", "ok".to_string()),
            ("p720a-jumeau-defender", refus_prive(DEFENDER_LOGIN)), ("p720a-jumeau-par-url", refus_prive("10.0.0.15")),
            ("p720a-jumeau-taxii", refus_prive("10.0.0.18")),
        ];
        for (nom, attendu) in &etats_attendus {
            assert_eq!(&lu(&a, &format!("P720A-ETAT-{nom}")), attendu, "état de {nom} après le passage de fond");
        }
        // Les routes : essai, poll et envoi manuel jugent avec les cibles de LEUR objet.
        let ok_taxii = "200 {\"error\":null,\"ok\":true,\"sample_count\":0,\"skipped\":0}";
        let ok_http = "200 {\"error\":null,\"ok\":true,\"sample\":[],\"sample_count\":0}";
        let ok_defender = "200 {\"error\":null,\"ok\":true,\"sample_count\":0}";
        let refus_essai = |hote: &str, avec_echantillon: bool| {
            if avec_echantillon {
                format!("200 {}", json!({ "error": refus_prive(hote), "ok": false, "sample": [], "sample_count": 0 }))
            } else {
                format!("200 {}", json!({ "error": refus_prive(hote), "ok": false, "sample_count": 0 }))
            }
        };
        assert_eq!(lu(&a, "P720A-ESSAI-p720a-taxii"), ok_taxii);
        assert_eq!(lu(&a, "P720A-ESSAI-p720a-jumeau-taxii"), refus_essai("10.0.0.18", false));
        assert_eq!(lu(&a, "P720A-ESSAI-p720a-par-url"), ok_http);
        assert_eq!(lu(&a, "P720A-ESSAI-p720a-jumeau-par-url"), refus_essai("10.0.0.15", true));
        assert_eq!(lu(&a, "P720A-ESSAI-p720a-defender"), ok_defender);
        assert_eq!(lu(&a, "P720A-ESSAI-p720a-jumeau-defender"), refus_essai(DEFENDER_LOGIN, false));
        assert_eq!(lu(&a, "P720A-APRES-ROUTE-p720a-par-url"), "ok", "poll manuel de la surcouche : passé");
        assert_eq!(lu(&a, "P720A-APRES-ROUTE-p720a-jumeau-par-url"), refus_prive("10.0.0.15"), "poll manuel du jumeau : refusé par la garde");
        assert_eq!(lu(&a, "P720A-VU-ROUTE-WEBHOOK"), "1", "envoi manuel : la surcouche part une fois, son jumeau jamais");
        assert_eq!(lu(&a, "P720A-APRES-ROUTE-p720a-webhook"), "ok");
        assert_eq!(lu(&a, "P720A-APRES-ROUTE-p720a-jumeau-webhook"), refus_prive("10.0.0.35"));
        assert_eq!(lu(&a, "P720A-RECHARGES"), "3/3/4", "second chargement : le canal retiré, le reste remis");
        assert_eq!(lu(&a, "P720A-RECHARGE-CANAL"), "refuse", "second chargement sans le canal : son inscription est retirée");
        assert_eq!(lu(&a, "P720A-RECHARGE-SLACK"), "admis", "second chargement : la ligne mise à jour est inscrite sous son identifiant");
        assert_eq!(lu(&a, "P720A-RECHARGE-JUMEAU-SLACK"), "refuse");
        // Routes de saisie, corps entier.
        assert_eq!(lu(&a, "P720A-CREATION-PRIVEE"), refus(PHRASE_CANAL_PRIVE), "la route nomme les leviers, corps entier");
        assert_eq!(lu(&a, "P720A-CREATION-EXACTE"), refus(PHRASE_CANAL_PRIVE), "la route refuse l'URL déclarée elle-même");
        assert_eq!(lu(&a, "P720A-CREATION-METADONNEES"), refus(PHRASE_URL_REFUSEE), "never-egress : la phrase d'avant");
        assert_eq!(lu(&a, "P720A-CREATION-FACULTATIVE"), refus(PHRASE_CANAL_PRIVE), "url facultative mais posée : même jugement");
        assert_eq!(lu(&a, "P720A-MAJ-CANAL-PRIVEE"), refus(PHRASE_CANAL_PRIVE));
        assert_eq!(lu(&a, "P720A-MAJ-CANAL-METADONNEES"), refus(PHRASE_URL_REFUSEE_MAJ));
        assert_eq!(lu(&a, "P720A-DESTINATION-WEBHOOK-PRIVEE"), refus(PHRASE_DESTINATION_PRIVEE));
        assert_eq!(lu(&a, "P720A-DESTINATION-SYSLOG-PRIVEE"), refus(PHRASE_DESTINATION_PRIVEE));
        assert_eq!(lu(&a, "P720A-DESTINATION-METADONNEES"), refus(PHRASE_ENDPOINT_REFUSE));
        assert_eq!(lu(&a, "P720A-MAJ-DESTINATION-PRIVEE"), refus(PHRASE_DESTINATION_PRIVEE));
        assert_eq!(lu(&a, "P720A-MAJ-DESTINATION-METADONNEES"), refus(PHRASE_ENDPOINT_REFUSE_MAJ));
        assert_eq!(lu(&a, "P720A-CREATION-FACULTATIVE-EXACTE"), refus(PHRASE_CANAL_PRIVE), "url facultative = cible déclarée : de l'API");
        assert_eq!(lu(&a, "P720A-MAJ-CANAL-EXACTE"), refus(PHRASE_CANAL_PRIVE), "modification d'un canal vers la cible déclarée : de l'API");
        assert_eq!(lu(&a, "P720A-DESTINATION-EXACTE"), refus(PHRASE_DESTINATION_PRIVEE), "création d'une destination vers la cible déclarée : de l'API");
        assert_eq!(lu(&a, "P720A-MAJ-DESTINATION-EXACTE"), refus(PHRASE_DESTINATION_PRIVEE), "modification d'une destination vers la cible déclarée : de l'API");
        assert_eq!(lu(&a, "P720A-CREATION-SLACK-PRIVE"), refus(PHRASE_CANAL_PRIVE), "webhook_url d'un slack saisie par l'API");
        assert_eq!(lu(&a, "P720A-MAJ-SLACK-PRIVE"), refus(PHRASE_CANAL_PRIVE));
        assert_eq!(lu(&a, "P720A-DESTINATION-HEC-PRIVEE"), refus(PHRASE_DESTINATION_PRIVEE), "un HEC privé nomme ses leviers");
        assert_eq!(lu(&a, "P720A-DESTINATION-SCHEMA"), refus(PHRASE_ENDPOINT_REFUSE), "schéma refusé : jamais dit « adresse privée »");
        assert_eq!(lu(&a, "P720A-CONNECTEUR-PRIVE"), refus(PHRASE_CONNECTEUR_PRIVE), "connecteur saisi par l'API vers une adresse privée");
        assert_eq!(lu(&a, "P720A-CONNECTEUR-BASE-DE-SURCOUCHE"), refus(PHRASE_CONNECTEUR_PRIVE), "la base d'une surcouche suivie d'une requête, saisie par l'API : de l'API");
        assert_eq!(lu(&a, "P720A-CONNECTEUR-JETON-PRIVE"), refus(PHRASE_CONNECTEUR_PRIVE), "point de jeton privé");
        assert_eq!(lu(&a, "P720A-CONNECTEUR-TAXII-PRIVE"), refus(PHRASE_CONNECTEUR_PRIVE), "racine TAXII privée");
        assert_eq!(lu(&a, "P720A-CONNECTEUR-DEFENDER-GRAPH-PRIVE"), refus(PHRASE_CONNECTEUR_PRIVE), "defender, graph_host privé");
        assert_eq!(lu(&a, "P720A-CONNECTEUR-DEFENDER-LOGIN-PRIVE"), refus(PHRASE_CONNECTEUR_PRIVE), "defender, login_host privé");
        assert_eq!(lu(&a, "P720A-MAJ-CONNECTEUR-PRIVE"), refus(PHRASE_CONNECTEUR_PRIVE), "modification d'un http_pull");
        assert_eq!(lu(&a, "P720A-MAJ-CONNECTEUR-TAXII-PRIVE"), refus(PHRASE_CONNECTEUR_PRIVE), "modification d'un taxii2");
        assert_eq!(lu(&a, "P720A-MAJ-CONNECTEUR-DEFENDER-PRIVE"), refus(PHRASE_CONNECTEUR_PRIVE), "modification d'un defender");
        assert_eq!(lu(&a, "P720A-MAJ-CONNECTEUR-TAXII-PUBLIC"), "200", "contrôle positif : une config publique passe");
        assert_eq!(lu(&a, "P720A-MAJ-CONNECTEUR-TAXII-PUBLIC-ECRITE"), "true", "et s'écrit");
        assert!(lignes_qui_commencent_par(&a_err, "[ssrf]").is_empty(), "réglage absent : rien à dire : {a_err}");

        // (b) DÉFAUT, canal semé par le FICHIER de configuration (mode natif).
        let (b, _) = jouer(&fichier_avec_cible, &[]);
        assert_eq!(lu(&b, "P720A-CONF"), "admis", "défaut : le canal semé depuis le fichier part");
        assert_eq!(lu(&b, "P720A-CONF-API"), "refuse");

        // (c) DÉFAUT, rien de semé : aucune ligne `ntfy (env)`, la ligne de l'API reste de l'API.
        let (c, _) = jouer(&fichier_vide, &[]);
        assert_eq!(lu(&c, "P720A-CONF"), "absent", "sans réglage, aucun canal semé");
        assert_eq!(lu(&c, "P720A-CONF-API"), "refuse");
        assert_eq!(lu(&c, "P720A-IDP-IA"), "admis", "sans déclaration, les fournisseurs restent de configuration");

        // (d) VALEUR EXPLICITE 1 : refusé partout, canal semé, surcouches et fournisseurs compris.
        let (d, _) = jouer(&fichier_vide, &[("PLUME_NOTIFY_NTFY_URL", CIBLE_DE_CONFIGURATION), ("PLUME_SSRF_BLOCK_PRIVATE", "1")]);
        assert_eq!(lu(&d, "P720A-CONF"), "refuse", "valeur 1 : le canal semé aussi est refusé");
        assert_eq!(lu(&d, "P720A-IDP-IA"), "refuse", "valeur 1 : les fournisseurs aussi");
        assert_eq!(lu(&d, "P720A-POSES"), "4/0/4", "valeur 1 : les destinations privées de surcouche sont ignorées à la validation");
        assert_eq!(lu(&d, "P720A-ENVOI-CANAL"), "refuse", "valeur 1 : le canal privé de surcouche ne part pas");
        assert_eq!(lu(&d, "P720A-ETAT-p720a-taxii"), refus_prive("10.0.0.18"), "valeur 1 : le connecteur privé de surcouche ne part pas");
        assert_eq!(lu(&d, "P720A-VUS"), "0", "valeur 1 : rien ne part");
        assert_eq!(lu(&d, "P720A-CREATION-PRIVEE"), refus(PHRASE_CANAL_PRIVE), "valeur 1 : le refus nomme encore ses leviers");

        // (e) VALEUR EXPLICITE 0 : admis partout (sens d'avant), jumeaux compris, y compris par la route.
        let (e, _) = jouer(&fichier_vide, &[("PLUME_SSRF_BLOCK_PRIVATE", "0")]);
        assert_eq!(lu(&e, "P720A-API"), "admis", "valeur 0 : l'API privée est admise");
        assert_eq!(lu(&e, "P720A-API-CONNECTEUR"), "non-joue");
        assert_eq!(lu(&e, "P720A-API-NOM"), "admis", "valeur 0 : le nom résolu privé est admis");
        assert_eq!(lu(&e, "P720A-API-DESTINATION"), "admis");
        assert_eq!(lu(&e, "P720A-CONF-SAISIE"), "admis");
        assert_eq!(lu(&e, "P720A-ENVOI-JUMEAU-CANAL"), "admis", "valeur 0 : le jumeau de l'API part aussi");
        assert_eq!(lu(&e, "P720A-ETAT-p720a-jumeau-taxii"), "ok");
        assert_eq!(lu(&e, "P720A-VUS"), "20", "valeur 0 : les onze envois et ceux des neuf jumeaux (trois destinations, une page, deux TAXII, trois defender)");
        assert!(lu(&e, "P720A-CREATION-PRIVEE").starts_with("(200, "), "valeur 0 : la route crée le canal : {e}");
        assert_eq!(lu(&e, "P720A-CREATION-METADONNEES"), refus(PHRASE_URL_REFUSEE), "valeur 0 : le never-egress reste refusé");
        assert!(lu(&e, "P720A-CONNECTEUR-PRIVE").starts_with("(200, "), "valeur 0 : la route crée le connecteur privé : {e}");
        assert!(lu(&e, "P720A-CREATION-SLACK-PRIVE").starts_with("(200, "), "valeur 0 : la route crée le slack privé : {e}");

        // (f) LEVIER NATIF : `PLUME_SSRF_BLOCK_PRIVATE=0` écrit dans le FICHIER, environnement vide.
        let (f, _) = jouer(&fichier_admet, &[]);
        assert_eq!(lu(&f, "P720A-API"), "admis", "fichier, valeur 0 : l'API privée est admise");
        assert_eq!(lu(&f, "P720A-API-DESTINATION"), "admis");

        // (g) VALEUR NON RECONNUE : vaut absence (jamais moins), et elle est dite une fois.
        let (g, g_err) = jouer(&fichier_vide, &[("PLUME_NOTIFY_NTFY_URL", CIBLE_DE_CONFIGURATION), ("PLUME_SSRF_BLOCK_PRIVATE", "oui")]);
        assert_eq!(lu(&g, "P720A-API"), "refuse", "valeur non reconnue : l'API privée reste refusée");
        assert_eq!(lu(&g, "P720A-CONF"), "admis", "valeur non reconnue : le canal semé reste admis");
        assert_eq!(lignes_qui_commencent_par(&g_err, "[ssrf]"), vec![LIGNE_VALEUR_NON_RECONNUE.to_string()], "la valeur non reconnue est dite, ligne entière");
    }

    // ------------------------------------------------------------------ (2) les envois de canal, par la vraie chaîne

    /// Un faux `curl` : il note chaque appel et réussit (aucun réseau).
    const FAUX_CURL: &str = "#!/bin/sh\necho appel >> \"$P720A_BAC/appels\"\ncat > /dev/null\nexit 0\n";

    fn appels_du_faux_curl(bac: &std::path::Path) -> usize {
        std::fs::read_to_string(bac.join("appels")).map(|t| t.lines().count()).unwrap_or(0)
    }

    /// Chaque site qui fait émettre un canal juge avec les cibles de CE canal : essai (route), dispatch d'une alerte,
    /// rapport planifié, escalade SLA, multi-niveau. Une surcouche part (le faux `curl` est appelé), son jumeau de l'API
    /// — même URL, autre identifiant — est refusé avant `curl`. Le compte d'appels est relevé après chaque geste.
    #[test]
    fn p720a_les_envois_de_canal_jugent_les_cibles_de_leur_canal() {
        const ENFANT: &str = "P720A_ENFANT_CANAUX";
        const FIN: &str = "P720A-CANAUX-A-JOUE";
        if let Ok(bac) = std::env::var("P720A_BAC") {
            if std::env::var(ENFANT).is_ok() {
                println!();
                let bac = std::path::PathBuf::from(bac);
                let (st, base) = router_test_state("p720a-canaux");
                let racine = std::path::PathBuf::from(std::env::var("P720A_SURCOUCHES").expect("dossier des surcouches"));
                let (id_canal, id_jumeau) = {
                    let c = open_db(&base).expect("base du témoin");
                    let n = crate::overlays_oac::load_overlay_notifiers(&c, &racine.join("notifiers"));
                    assert_eq!(n.charges, 1, "contrôle : le canal de surcouche est posé (et inscrit)");
                    c.execute_batch(
                        "INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) \
                           SELECT 141,'p720a-jumeau-canal',kind,1,url,0,config FROM notifier WHERE name='p720a-canal';",
                    )
                    .expect("jumeau de l'API");
                    (id_de(&c, "notifier", "p720a-canal").expect("id du canal"), 141i64)
                };
                let appels = || appels_du_faux_curl(&bac);
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime de l'enfant");
                rt.block_on(async {
                    for (cle, id) in [("CANAL", id_canal), ("JUMEAU", id_jumeau)] {
                        let r = notifier_test(State(st.clone()), Extension(ergo_au("admin")), Path(id)).await;
                        let (_, texte) = corps(r).await;
                        let ok = serde_json::from_str::<Value>(&texte).ok().and_then(|v| v.get("ok").and_then(|x| x.as_bool()));
                        println!("P720A-ESSAI-{cle}:{ok:?}/{}", appels());
                    }
                });
                // Dispatch : une alerte, les deux canaux actifs.
                st.db.lock().execute(
                    "INSERT INTO alert(id,ts,rule,severity,title,detail,status,mitre,sources,host) VALUES(901,?1,'r.p720a',3,'A','','new','','','h1')",
                    params![now()],
                ).expect("alerte");
                dispatch_notifications(&st.db);
                println!("P720A-DISPATCH:{}", appels());
                // Rapport planifié vers chacun des deux canaux.
                st.db.lock().execute_batch(
                    "INSERT INTO event(ts,source,category,severity,host,message) VALUES(strftime('%s','now'),'p720a','auth',3,'h1','m'); \
                     INSERT INTO dataset(id,name,soql) VALUES(951,'p720a-ds','search | table message'); \
                     INSERT INTO scheduled_report(id,name,dataset_id,notifier_id,interval_s) VALUES(952,'p720a-rapport-canal',951,0,3600); \
                     INSERT INTO scheduled_report(id,name,dataset_id,notifier_id,interval_s) VALUES(953,'p720a-rapport-jumeau',951,141,3600);",
                ).expect("rapports");
                st.db.lock().execute("UPDATE scheduled_report SET notifier_id=?1 WHERE id=952", params![id_canal]).expect("canal du rapport");
                let chemin = base.to_string();
                for (cle, id) in [("CANAL", 952i64), ("JUMEAU", 953)] {
                    let issue = deliver_report(&st.db, &chemin, id);
                    let livre = matches!(issue, Ok(IssueDuRapport::Envoye { delivered: true, .. }));
                    println!("P720A-RAPPORT-{cle}:{livre}/{}", appels());
                }
                // Escalade SLA d'un dossier en retard : tous les canaux actifs (la surcouche et son jumeau).
                {
                    let c = st.db.lock();
                    let id = dossier_seme(&c, "alice", "p720a-en-retard", 4, "", None, 1);
                    c.execute("UPDATE incident SET sla_due=?1 WHERE id=?2", params![now() - 200, id]).expect("échéance dépassée");
                }
                escalate_overdue_cases(&st.db);
                println!("P720A-ESCALADE:{}", appels());
                // Multi-niveau : une politique active, un acquittement dû et dépassé.
                {
                    let c = st.db.lock();
                    c.execute(
                        "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('p720a',1,60,600,1,0,'root',0)",
                        [],
                    )
                    .expect("politique");
                    let id = dossier_seme(&c, "alice", "p720a-acquittement", 4, "", None, 1);
                    c.execute("UPDATE incident SET ack_due=?1 WHERE id=?2", params![now() - 200, id]).expect("acquittement dépassé");
                }
                sla_multilevel_tick(&st.db);
                println!("P720A-MULTI-NIVEAU:{}", appels());
                println!("{FIN}");
                return;
            }
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let dossier = crate::tmp_possede::TmpPossede::neuf("p720a-canaux");
        let bac = dossier.join("bac");
        std::fs::create_dir_all(&bac).expect("bac du faux curl");
        let faux = bac.join("curl");
        std::fs::write(&faux, FAUX_CURL).expect("faux curl");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&faux, std::fs::Permissions::from_mode(0o755)).expect("faux curl exécutable");
        }
        let surcouches = dossier.join("config.d");
        std::fs::create_dir_all(surcouches.join("notifiers")).expect("dossier des canaux");
        std::fs::write(
            surcouches.join("notifiers").join("canal.json"),
            json!({ "name": "p720a-canal", "kind": "webhook", "url": CANAL_DE_SURCOUCHE, "min_severity": 0 }).to_string(),
        )
        .expect("surcouche de canal");
        let chemin_systeme = std::env::var("PATH").unwrap_or_default();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}p720a_les_envois_de_canal_jugent_les_cibles_de_leur_canal"));
        for (nom, _) in std::env::vars_os() {
            if nom.to_string_lossy().starts_with("PLUME_") {
                commande.env_remove(&nom);
            }
        }
        commande
            .env(ENFANT, "1")
            .env("P720A_BAC", &bac)
            .env("P720A_SURCOUCHES", &surcouches)
            .env("PATH", format!("{}:{chemin_systeme}", bac.display()));
        let sortie = commande.output().expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(lu(&stdout, "P720A-ESSAI-CANAL"), "Some(true)/1", "essai de la surcouche : curl appelé");
        assert_eq!(lu(&stdout, "P720A-ESSAI-JUMEAU"), "Some(false)/1", "essai du jumeau de l'API : refusé avant curl");
        assert_eq!(lu(&stdout, "P720A-DISPATCH"), "2", "dispatch : la surcouche part, son jumeau non");
        assert_eq!(lu(&stdout, "P720A-RAPPORT-CANAL"), "true/3", "rapport vers la surcouche : livré");
        assert_eq!(lu(&stdout, "P720A-RAPPORT-JUMEAU"), "false/3", "rapport vers le jumeau : refusé avant curl");
        assert_eq!(lu(&stdout, "P720A-ESCALADE"), "4", "escalade SLA : la surcouche part, son jumeau non");
        assert_eq!(lu(&stdout, "P720A-MULTI-NIVEAU"), "5", "multi-niveau : la surcouche part, son jumeau non");
    }

    /// Le canal posé par `canal_qui_emet` est celui que lit l'envoi d'un tick de dossier, et lui seul : gardien lâché,
    /// celui d'avant revient.
    #[test]
    fn p720a_le_canal_qui_emet_est_pose_le_temps_de_l_envoi() {
        let un = vec![CibleDeConfiguration::exacte(CANAL_DE_SURCOUCHE)];
        assert!(cibles_du_canal_qui_emet().is_empty(), "hors d'un envoi : aucune cible");
        {
            let _canal = canal_qui_emet(un.clone());
            assert_eq!(cibles_du_canal_qui_emet(), un);
            {
                let _autre = canal_qui_emet(Vec::new());
                assert!(cibles_du_canal_qui_emet().is_empty(), "un canal sans inscription : aucune cible");
            }
            assert_eq!(cibles_du_canal_qui_emet(), un, "gardien lâché : le canal d'avant revient");
        }
        assert!(cibles_du_canal_qui_emet().is_empty(), "hors d'un envoi : aucune cible");
    }

    // ------------------------------------------------------------------ (2) le fournisseur d'identité

    /// La découverte, les JWKS et le point de jeton d'un fournisseur OIDC sur adresse privée, joués par les fonctions
    /// qu'appelle `oidc_callback`, le réseau remplacé par le témoin de l'égress : la découverte (issuer écrit par
    /// l'administrateur) passe ; un endpoint rendu par la découverte sur un AUTRE hôte privé, ou un autre port, est
    /// refusé avant le réseau ; écrit par l'administrateur, il passe.
    #[test]
    fn p720a_l_egress_du_fournisseur_d_identite_selon_l_origine_de_l_endpoint() {
        const ENFANT: &str = "P720A_ENFANT_IDP";
        const FIN: &str = "P720A-IDP-A-JOUE";
        if std::env::var(ENFANT).is_ok() {
            println!();
            use crate::ledger::temoin_de_l_egress;
            let document = json!({
                "issuer": "https://10.0.0.5",
                "authorization_endpoint": "https://10.0.0.5/auth",
                "token_endpoint": "https://10.0.0.5/token",
                "jwks_uri": "https://10.0.0.6/jwks",
            });
            let corps_du_document = document.to_string();
            let _arme = temoin_de_l_egress::armer(move |_m, url| {
                let corps = if url.ends_with("/.well-known/openid-configuration") { corps_du_document.clone() } else { r#"{"keys":[]}"#.to_string() };
                Ok(temoin_de_l_egress::reponse(200, &[], &corps))
            });
            let issue = |r: Result<String, String>| match r {
                Ok(_) => "admis".to_string(),
                Err(e) => e,
            };
            let cfg = OidcCfg::from_json(&json!({ "issuer": "https://10.0.0.5", "client_id": "c", "redirect_uri": "https://soc.exemple.test/cb" }));
            let ep = oidc_endpoints_for(&cfg);
            println!("P720A-DECOUVERTE:{}", issue(ep.as_ref().map(|_| String::new()).map_err(|e| e.clone())));
            let ep = ep.unwrap_or_default();
            println!("P720A-JWKS-AUTRE-HOTE:{}", issue(jwks_du_fournisseur(&cfg, &ep.jwks_uri).map(|_| String::new())));
            println!("P720A-JETON-MEME-HOTE:{}", issue(echange_au_point_de_jeton(&cfg, &ep.token_endpoint, "corps").map(|_| String::new())));
            println!("P720A-JWKS-AUTRE-PORT:{}", issue(jwks_du_fournisseur(&cfg, "https://10.0.0.5:8443/jwks").map(|_| String::new())));
            println!("P720A-JETON-AUTRE-HOTE:{}", issue(echange_au_point_de_jeton(&cfg, "https://10.0.0.6/token", "corps").map(|_| String::new())));
            let ecrit = OidcCfg::from_json(&json!({ "issuer": "https://10.0.0.5", "client_id": "c", "redirect_uri": "https://soc.exemple.test/cb",
                "jwks_uri": "https://10.0.0.6/jwks", "token_endpoint": "https://10.0.0.6/token", "authorization_endpoint": "https://10.0.0.5/auth" }));
            println!("P720A-JWKS-ECRIT:{}", issue(jwks_du_fournisseur(&ecrit, "https://10.0.0.6/jwks").map(|_| String::new())));
            println!("P720A-JETON-ECRIT:{}", issue(echange_au_point_de_jeton(&ecrit, "https://10.0.0.6/token", "corps").map(|_| String::new())));
            let vus: Vec<String> = temoin_de_l_egress::vus().into_iter().map(|(m, u)| format!("{m} {u}")).collect();
            println!("P720A-IDP-VUS:{}", vus.join(" | "));
            println!("{FIN}");
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let jouer = |reglages: &[(&str, &str)]| -> String {
            let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}p720a_l_egress_du_fournisseur_d_identite_selon_l_origine_de_l_endpoint"));
            for (nom, _) in std::env::vars_os() {
                if nom.to_string_lossy().starts_with("PLUME_") {
                    commande.env_remove(&nom);
                }
            }
            commande.env(ENFANT, "1").env("PLUME_CONFIG", "/nonexistent");
            for (k, v) in reglages {
                commande.env(k, v);
            }
            let sortie = commande.output().expect("ré-exécution du binaire de test");
            let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
            assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout ({reglages:?}) : {stdout}\n{stderr}");
            stdout
        };
        let defaut = jouer(&[]);
        assert_eq!(lu(&defaut, "P720A-DECOUVERTE"), "admis", "la découverte d'un IdP sur site (issuer privé) passe");
        assert_eq!(lu(&defaut, "P720A-JWKS-AUTRE-HOTE"), refus_prive("10.0.0.6"), "JWKS rendu par la découverte sur un autre hôte privé : refusé");
        assert_eq!(lu(&defaut, "P720A-JETON-MEME-HOTE"), "admis", "point de jeton rendu par la découverte sur l'hôte de l'issuer : passe");
        assert_eq!(lu(&defaut, "P720A-JWKS-AUTRE-PORT"), refus_prive("10.0.0.5"), "même hôte, autre port : refusé");
        assert_eq!(lu(&defaut, "P720A-JETON-AUTRE-HOTE"), refus_prive("10.0.0.6"), "point de jeton hors de l'hôte de l'issuer : refusé");
        assert_eq!(lu(&defaut, "P720A-JWKS-ECRIT"), "admis", "écrit par l'administrateur : passe");
        assert_eq!(lu(&defaut, "P720A-JETON-ECRIT"), "admis");
        assert_eq!(
            lu(&defaut, "P720A-IDP-VUS"),
            "GET https://10.0.0.5/.well-known/openid-configuration | POST https://10.0.0.5/token | GET https://10.0.0.6/jwks | POST https://10.0.0.6/token",
            "seuls les appels admis atteignent le réseau, dans l'ordre"
        );
        let bloque = jouer(&[("PLUME_SSRF_BLOCK_PRIVATE", "1")]);
        assert_eq!(lu(&bloque, "P720A-DECOUVERTE"), refus_prive("10.0.0.5"), "valeur 1 : la découverte privée est refusée");
        assert_eq!(lu(&bloque, "P720A-JWKS-ECRIT"), refus_prive("10.0.0.6"), "valeur 1 : l'endpoint écrit aussi");
        assert_eq!(lu(&bloque, "P720A-IDP-VUS"), "", "valeur 1 : rien ne part");
    }

    // ------------------------------------------------------------------ (2) ce que le démarrage dit

    /// Les objets stockés du témoin : identifiants fixes, une cible par champ jugé.
    fn poser_les_objets_stockes(c: &Connection) {
        c.execute_batch(&format!(
            "INSERT INTO notifier(id,name,kind,url,config) VALUES \
               (40,'ntfy (env)','ntfy','{CIBLE_DE_CONFIGURATION}','{{}}'), \
               (41,'p720a-api','webhook','{CIBLE_API_PRIVEE}','{{}}'), \
               (42,'p720a-slack-api','slack','','{{\"webhook_url\":\"http://10.0.0.25/hooks/p720a-chemin-secret\"}}'), \
               (43,'p720a-public','webhook','https://192.0.2.10/public','{{}}'), \
               (44,'p720a-boucle','webhook','http://127.0.0.1/boucle','{{}}'), \
               (45,'p720a-email-api','email','smtp://10.0.0.36:25','{{}}'), \
               (46,'p720a-generique-api','generic','http://10.0.0.37/g','{{}}'), \
               (47,'p720a-jumeau-canal','webhook','{CANAL_DE_SURCOUCHE}','{{}}'); \
             INSERT INTO destination(id,type,name,endpoint) VALUES \
               (50,'syslog','p720a-syslog-api','tcp://10.0.0.21:514'), \
               (51,'hec','p720a-hec-api','https://10.0.0.26:8088'), \
               (52,'webhook','p720a-webhook-api','http://10.0.0.38/in'); \
             INSERT INTO connector(id,type,name,config_json) VALUES \
               (60,'http_pull','p720a-source-api','{{\"url\":\"http://10.0.0.22/api\",\"auth\":{{\"kind\":\"oauth2_client_credentials\",\"token_url\":\"http://10.0.0.23/jeton\"}}}}'), \
               (61,'taxii2','p720a-taxii-api','{{\"api_root\":\"http://10.0.0.24/taxii2/\",\"collection_id\":\"c\"}}'), \
               (62,'http_pull','p720a-nom-api','{{\"url\":\"http://167772169/nom\"}}'), \
               (63,'defender','p720a-defender-api','{{\"azure_tenant\":\"t\",\"client_id\":\"c\",\"login_host\":\"10.0.0.43\",\"graph_host\":\"10.0.0.44\"}}');"
        ))
        .expect("objets stockés du témoin");
    }

    fn ligne_d_inventaire(genre: &str, id: i64, champ: &str, hote: &str) -> String {
        format!("[ssrf] cible privée refusée à l'envoi : {genre} #{id} ({champ}) vers l'hôte {hote:?} — {LEVIERS}")
    }

    /// Le point d'entrée du démarrage — inscription du canal semé puis `dire_l_egress_au_demarrage`, dans l'ordre de
    /// `open_and_migrate_db` —, joué dans un enfant par réglage : la ligne de la politique, puis une ligne par cible
    /// stockée refusée pour sa seule adresse privée, lignes ENTIÈRES, dans l'ordre.
    #[test]
    fn p720a_le_demarrage_dit_la_politique_et_les_cibles_privees_stockees() {
        const ENFANT: &str = "P720A_ENFANT_DEMARRAGE";
        const FIN: &str = "P720A-DEMARRAGE-A-JOUE";
        if let Ok(cas) = std::env::var(ENFANT) {
            println!();
            let c = test_db();
            if cas == "aveux" {
                c.execute_batch(
                    "INSERT INTO notifier(id,name,kind,url) VALUES(70,'p720a-blob','webhook',X'00FF'), (71,'p720a-lisible','webhook','http://10.0.0.31/x'); \
                     DROP TABLE destination; \
                     INSERT INTO connector(id,type,name,config_json) VALUES(80,'http_pull','p720a-json','pas du json'), \
                       (81,'http_pull','p720a-lisible','{\"url\":\"http://10.0.0.32/y\"}');",
                )
                .expect("fixture des aveux");
            } else {
                let racine = std::path::PathBuf::from(std::env::var("P720A_SURCOUCHES").expect("dossier des surcouches"));
                let n = crate::overlays_oac::load_overlay_notifiers(&c, &racine.join("notifiers"));
                assert_eq!(n.charges, 1, "contrôle : le canal de surcouche est posé (et inscrit)");
                let id: i64 = c.query_row("SELECT id FROM notifier WHERE name='p720a-canal'", [], |r| r.get(0)).expect("id du canal de surcouche");
                println!("P720A-ID-CANAL:{id}");
                poser_les_objets_stockes(&c);
            }
            crate::overlays_oac::inscrire_le_canal_de_l_environnement(&c, &load_config());
            crate::overlays_oac::dire_l_egress_au_demarrage(&c).join().expect("fil de l'inventaire");
            println!("{FIN}");
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let dossier = crate::tmp_possede::TmpPossede::neuf("p720a-demarrage");
        let fichier_vide = dossier.join("vide.conf");
        std::fs::write(&fichier_vide, "# rien\n").expect("configuration vide du témoin");
        let surcouches = dossier.join("config.d");
        std::fs::create_dir_all(surcouches.join("notifiers")).expect("dossier des canaux");
        std::fs::write(
            surcouches.join("notifiers").join("canal.json"),
            json!({ "name": "p720a-canal", "kind": "webhook", "url": CANAL_DE_SURCOUCHE }).to_string(),
        )
        .expect("surcouche de canal");
        let jouer = |cas: &str, reglages: &[(&str, &str)]| -> (String, Vec<String>) {
            let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            commande.args(["--exact", "--nocapture", "--test-threads=1"])
                .arg(format!("{MODULE}p720a_le_demarrage_dit_la_politique_et_les_cibles_privees_stockees"));
            for (nom, _) in std::env::vars_os() {
                if nom.to_string_lossy().starts_with("PLUME_") {
                    commande.env_remove(&nom);
                }
            }
            commande.env(ENFANT, cas).env("PLUME_CONFIG", &fichier_vide).env("P720A_SURCOUCHES", &surcouches);
            for (k, v) in reglages {
                commande.env(k, v);
            }
            let sortie = commande.output().expect("ré-exécution du binaire de test");
            let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
            assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout ({cas}) : {stdout}\n{stderr}");
            assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 ({cas}) : {stdout}\n{stderr}");
            (stdout, lignes_qui_commencent_par(&stderr, "[ssrf]"))
        };

        // DÉFAUT, canal semé : la politique, puis les seules cibles privées refusées — pas le canal semé (inscrit sous
        // son identifiant), ni le canal de surcouche, ni l'adresse publique, ni le loopback (refusé d'office, pas pour son
        // adresse privée) ; le jumeau de l'API du canal de surcouche (même URL) EST dit.
        let (_, defaut) = jouer("objets", &[("PLUME_NOTIFY_NTFY_URL", CIBLE_DE_CONFIGURATION)]);
        assert_eq!(
            defaut,
            vec![
                LIGNE_POLITIQUE_PAR_DEFAUT.to_string(),
                ligne_d_inventaire("canal", 41, "url", "10.0.0.9"),
                ligne_d_inventaire("canal", 42, "webhook_url", "10.0.0.25"),
                ligne_d_inventaire("canal", 45, "url", "10.0.0.36"),
                ligne_d_inventaire("canal", 46, "url", "10.0.0.37"),
                ligne_d_inventaire("canal", 47, "url", "10.0.0.12"),
                ligne_d_inventaire("destination", 50, "endpoint", "10.0.0.21"),
                ligne_d_inventaire("destination", 51, "endpoint", "10.0.0.26"),
                ligne_d_inventaire("destination", 52, "endpoint", "10.0.0.38"),
                ligne_d_inventaire("connecteur", 60, "url", "10.0.0.22"),
                ligne_d_inventaire("connecteur", 60, "auth.token_url", "10.0.0.23"),
                ligne_d_inventaire("connecteur", 61, "api_root", "10.0.0.24"),
                ligne_d_inventaire("connecteur", 62, "url", "167772169"),
                ligne_d_inventaire("connecteur", 63, "login_host", "10.0.0.43"),
                ligne_d_inventaire("connecteur", 63, "graph_host", "10.0.0.44"),
            ],
            "le démarrage, lignes entières"
        );
        assert!(defaut.iter().all(|l| !l.contains("chemin-secret") && !l.contains("/hooks")), "jamais l'URL entière");

        // SANS RÉGLAGE : la ligne `ntfy (env)` n'est plus semée, elle est dite comme toute ligne de l'API.
        let (_, sans_reglage) = jouer("objets", &[]);
        assert!(sans_reglage.contains(&ligne_d_inventaire("canal", 40, "url", "10.0.0.7")), "sans réglage : la ligne est dite : {sans_reglage:?}");

        // VALEUR 1 : le canal semé et le canal de surcouche sont refusés à leur tour, et dits.
        let (sortie_bloquee, bloque) = jouer("objets", &[("PLUME_NOTIFY_NTFY_URL", CIBLE_DE_CONFIGURATION), ("PLUME_SSRF_BLOCK_PRIVATE", "1")]);
        let id_du_canal: i64 = lu(&sortie_bloquee, "P720A-ID-CANAL").parse().expect("id lisible");
        assert_eq!(bloque.first().map(String::as_str), Some(LIGNE_POLITIQUE_BLOQUEE));
        assert!(bloque.contains(&ligne_d_inventaire("canal", 40, "url", "10.0.0.7")), "valeur 1 : le canal semé est dit : {bloque:?}");
        assert!(bloque.contains(&ligne_d_inventaire("canal", id_du_canal, "url", "10.0.0.12")), "valeur 1 : le canal de surcouche est dit : {bloque:?}");

        // VALEUR 0 : rien n'est refusé, rien n'est dit hors de la politique.
        assert_eq!(jouer("objets", &[("PLUME_SSRF_BLOCK_PRIVATE", "0")]).1, vec![LIGNE_POLITIQUE_ADMISE.to_string()]);

        // LECTURES NON FAITES : une table absente, une ligne et une configuration illisibles sont dites ; ce qui a été
        // lu derrière est jugé quand même.
        let (_, aveux) = jouer("aveux", &[]);
        assert_eq!(
            aveux,
            vec![
                LIGNE_POLITIQUE_PAR_DEFAUT.to_string(),
                "[ssrf] inventaire des cibles privées incomplet : 1 ligne(s) de notifier illisible(s), non jugée(s)".to_string(),
                "[ssrf] inventaire des cibles privées incomplet : la table destination n'a pas pu être lue en entier (no such table: destination) — aucun de ses objets n'est jugé".to_string(),
                "[ssrf] inventaire des cibles privées incomplet : 1 ligne(s) de connector illisible(s), non jugée(s)".to_string(),
                ligne_d_inventaire("canal", 71, "url", "10.0.0.31"),
                ligne_d_inventaire("connecteur", 81, "url", "10.0.0.32"),
            ],
            "aveux de lecture, lignes entières"
        );
    }

    // ------------------------------------------------------------------ sites tenus par leur source

    fn sans_blancs(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Le démarrage inscrit le canal semé APRÈS les surcouches et le semis, et dit l'égress APRÈS l'inscription (sinon le
    /// canal semé serait dit refusé) : la fin d'`open_and_migrate_db`, comparée EN ENTIER, depuis `load_overlays`.
    #[test]
    fn p720a_ordre_du_demarrage() {
        let serveur = include_str!("../server/mod.rs");
        let debut = serveur.find("fn open_and_migrate_db(").expect("instrument : open_and_migrate_db");
        let corps = &serveur[debut..];
        let fin = corps.find("\n}\n").expect("instrument : fin de open_and_migrate_db");
        let queue = sans_blancs(&corps[corps.find("load_overlays(&conn, &conf);").expect("instrument : load_overlays")..fin]);
        assert!(queue.starts_with("load_overlays(&conn, &conf);"), "contrôle : {queue}");
        assert!(
            queue.ends_with("seed_env_notifier(&conn, &conf); // `P7.20-a` — le canal semé, inscrit sous son identifiant ; puis, APRÈS les surcouches (cibles inscrites) et lui : la // politique de la garde d'égress, et les objets stockés dont la cible privée sera refusée (fil à part, non attendu). crate::overlays_oac::inscrire_le_canal_de_l_environnement(&conn, &conf); let _inventaire_d_egress = crate::overlays_oac::dire_l_egress_au_demarrage(&conn); conn"),
            "la fin du démarrage, en entier : {queue}"
        );
        assert_eq!(serveur.matches("dire_l_egress_au_demarrage(").count(), 1, "un seul appel");
        assert_eq!(serveur.matches("inscrire_le_canal_de_l_environnement(").count(), 1, "un seul appel");
    }

    /// Les fichiers de test que `sec.rs` cite existent.
    #[test]
    fn p720a_sec_cite_des_fichiers_qui_existent() {
        let sec = fichier_du_depot("daemon/src/tests/sec.rs");
        let cites: Vec<&str> = sec.split('`').filter(|t| t.ends_with(".rs") && !t.contains(char::is_whitespace)).collect();
        assert!(!cites.is_empty(), "instrument : sec.rs cite au moins un fichier");
        for cite in cites {
            let nom = cite.rsplit('/').next().unwrap_or(cite);
            assert!(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tests").join(nom).is_file(), "sec.rs cite `{cite}`, absent de daemon/src/tests");
        }
    }

    // ------------------------------------------------------------------ (3) allowlist d'hôte, cœur pur

    #[test]
    fn p720a_decision_de_l_hote_strict() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // cfg lit l'environnement avant la carte
        premisse_sans_environnement(&["PLUME_HOST", "PLUME_HOST_STRICT"]);
        assert_eq!(hote_strict_au_demarrage(&carte(&[]), "plume.localhost"), (false, LIGNE_HOTE_INACTIVE_DEFAUT.to_string()));
        assert_eq!(
            hote_strict_au_demarrage(&carte(&[("PLUME_HOST", HOTE_DECLARE)]), HOTE_DECLARE),
            (false, LIGNE_HOTE_INACTIVE_DECLARE.to_string()),
            "PLUME_HOST déclaré, réglage absent : NON stricte (la boucle locale des clients documentés reste servie)"
        );
        assert_eq!(
            hote_strict_au_demarrage(&carte(&[("PLUME_HOST", HOTE_DECLARE), ("PLUME_HOST_STRICT", "0")]), HOTE_DECLARE),
            (false, LIGNE_HOTE_INACTIVE_DECLARE.to_string())
        );
        assert_eq!(
            hote_strict_au_demarrage(&carte(&[("PLUME_HOST", HOTE_DECLARE), ("PLUME_HOST_STRICT", "  ")]), HOTE_DECLARE),
            (false, LIGNE_HOTE_INACTIVE_DECLARE.to_string()),
            "PLUME_HOST_STRICT blanc : absent"
        );
        assert_eq!(
            hote_strict_au_demarrage(&carte(&[("PLUME_HOST", HOTE_DECLARE), ("PLUME_HOST_STRICT", "true")]), HOTE_DECLARE),
            (false, LIGNE_HOTE_AUTRE_VALEUR.to_string()),
            "« 1 » seul active ; une autre valeur posée est DITE comme telle"
        );
        assert_eq!(
            hote_strict_au_demarrage(&carte(&[("PLUME_HOST", HOTE_DECLARE), ("PLUME_HOST_STRICT", "1")]), HOTE_DECLARE),
            (true, LIGNE_HOTE_EXPLICITE.to_string())
        );
    }

    // ------------------------------------------------------------------ (3) allowlist d'hôte, bout en bout

    async fn sonder(addr: std::net::SocketAddr, chemin: &str, autorite: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let requete = format!("GET {chemin} HTTP/1.1\r\nHost: {autorite}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        let fut = async {
            let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
            s.write_all(requete.as_bytes()).await.ok()?;
            let mut brut = Vec::new();
            s.read_to_end(&mut brut).await.ok()?;
            let texte = String::from_utf8_lossy(&brut).into_owned();
            let code = texte.split_whitespace().nth(1)?.parse::<u16>().ok()?;
            let (entete, brut_du_corps) = texte.split_once("\r\n\r\n")?;
            let corps = if entete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
                // Corps découpé : taille hexadécimale, CRLF, morceau, CRLF … jusqu'au morceau nul.
                let mut reste = brut_du_corps;
                let mut assemble = String::new();
                loop {
                    let (taille, suite) = reste.split_once("\r\n")?;
                    let n = usize::from_str_radix(taille.trim(), 16).ok()?;
                    if n == 0 {
                        break;
                    }
                    assemble.push_str(suite.get(..n)?);
                    reste = suite.get(n + 2..)?;
                }
                assemble
            } else {
                brut_du_corps.to_string()
            };
            Some((code, corps))
        };
        tokio::time::timeout(Duration::from_secs(20), fut).await.ok().flatten().unwrap_or((0, String::new()))
    }

    /// Le démarrage RÉEL (`boot_config`) décide ; le routeur réel l'applique. Chaque cas juge la ligne `[host]` du
    /// journal (ligne entière), l'autorité de boucle locale, l'autorité déclarée et les deux sondes sous une autorité
    /// de boucle locale ET sous une adresse de pod.
    #[test]
    fn p720a_l_hote_strict_selon_le_demarrage_reel() {
        const ENFANT: &str = "P720A_ENFANT_HOTE";
        const FIN: &str = "P720A-HOTE-A-JOUE";
        if std::env::var(ENFANT).is_ok() {
            println!(); // la première ligne de l'enfant suit l'en-tête de libtest
            let (strict, hote) = crate::server::temoin_de_l_hote_strict::hote_retenu_par_le_demarrage();
            println!("P720A-STRICT:{strict}");
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime de l'enfant");
            rt.block_on(async {
                let (mut st, _db) = router_test_state("p720a-hote");
                st.host = Arc::new(hote);
                st.host_strict = strict;
                let addr = router_serve(st).await;
                for (nom, chemin, autorite) in [
                    ("BOUCLE", "/api/me", "127.0.0.1:7000"),
                    ("LOCALHOST", "/api/me", "localhost"),
                    ("DECLARE", "/api/me", HOTE_DECLARE),
                    ("DEFAUT", "/api/me", "plume.localhost"),
                    ("INGEST-BOUCLE", "/api/ingest", "127.0.0.1:7000"),
                    ("HEALTHZ-BOUCLE", "/healthz", "127.0.0.1:7000"),
                    ("READYZ-BOUCLE", "/readyz", "127.0.0.1:7000"),
                    ("HEALTHZ-POD", "/healthz", "10.42.0.17:7000"),
                    ("READYZ-POD", "/readyz", "10.42.0.17:7000"),
                ] {
                    let (code, corps) = sonder(addr, chemin, autorite).await;
                    println!("P720A-SONDE-{nom}:{code}");
                    if code == 421 {
                        println!("P720A-CORPS-{nom}:{}", serde_json::to_string(&corps).expect("corps en une ligne"));
                    }
                }
            });
            println!("{FIN}");
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // le parent lit l'environnement pour le vider chez l'enfant
        let dossier = crate::tmp_possede::TmpPossede::neuf("p720a-configuration-hote");
        let fichier_natif = dossier.join("plume.conf");
        std::fs::write(&fichier_natif, format!("PLUME_HOST={HOTE_DECLARE}\n")).expect("configuration native du témoin");
        let fichier_natif_strict = dossier.join("plume-strict.conf");
        std::fs::write(&fichier_natif_strict, format!("PLUME_HOST={HOTE_DECLARE}\nPLUME_HOST_STRICT=1\n")).expect("configuration native stricte");
        let fichier_vide = dossier.join("vide.conf");
        std::fs::write(&fichier_vide, "# rien\n").expect("configuration vide du témoin");
        let jouer = |configuration: &std::path::Path, reglages: &[(&str, &str)]| -> (String, String) {
            let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}p720a_l_hote_strict_selon_le_demarrage_reel"));
            for (nom, _) in std::env::vars_os() {
                if nom.to_string_lossy().starts_with("PLUME_") {
                    commande.env_remove(&nom);
                }
            }
            commande.env(ENFANT, "1").env("PLUME_CONFIG", configuration).env("PLUME_SESSION_SECRET", SIGNATURE_DE_SESSION);
            for (k, v) in reglages {
                commande.env(k, v);
            }
            let sortie = commande.output().expect("ré-exécution du binaire de test");
            let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
            assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout ({reglages:?}) : {stdout}\n{stderr}");
            assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 ({reglages:?}) : {stdout}\n{stderr}");
            (stdout, stderr)
        };
        let lu = |stdout: &str, cle: &str| -> String {
            let prefixe = format!("{cle}:");
            let trouves: Vec<&str> = stdout.lines().filter_map(|l| l.strip_prefix(prefixe.as_str())).collect();
            assert_eq!(trouves.len(), 1, "une seule ligne {cle} : {stdout}");
            trouves[0].to_string()
        };
        let lignes_host = |stderr: &str| -> Vec<String> { stderr.lines().filter(|l| l.starts_with("[host]")).map(str::to_string).collect() };
        let sondes_servies = |stdout: &str| {
            for nom in ["HEALTHZ-BOUCLE", "READYZ-BOUCLE", "HEALTHZ-POD", "READYZ-POD"] {
                let code = lu(stdout, &format!("P720A-SONDE-{nom}"));
                assert!(code == "200" || code == "503", "la sonde {nom} est servie par son gestionnaire, jamais 421 : {code}");
            }
        };

        let boucle_servie = |out: &str, cas: &str| {
            for nom in ["BOUCLE", "LOCALHOST", "INGEST-BOUCLE"] {
                assert_ne!(lu(out, &format!("P720A-SONDE-{nom}")), "421", "{cas} : la boucle locale ({nom}) est servie");
            }
        };

        // (a) PLUME_HOST déclaré par l'environnement (les deux installateurs le font), réglage absent : NON stricte —
        // la preuve d'installation et les agents qui poussent vers 127.0.0.1:7000 restent servis.
        let (a, a_err) = jouer(&fichier_vide, &[("PLUME_HOST", HOTE_DECLARE)]);
        assert_eq!(lu(&a, "P720A-STRICT"), "false");
        assert_eq!(lignes_host(&a_err), vec![LIGNE_HOTE_INACTIVE_DECLARE.to_string()], "la ligne du démarrage, entière");
        boucle_servie(&a, "PLUME_HOST déclaré");
        assert_ne!(lu(&a, "P720A-SONDE-DECLARE"), "421", "l'autorité déclarée passe");
        sondes_servies(&a);

        // (b) PLUME_HOST déclaré par le FICHIER (mode natif) : non stricte aussi.
        let (b, b_err) = jouer(&fichier_natif, &[]);
        assert_eq!(lu(&b, "P720A-STRICT"), "false");
        assert_eq!(lignes_host(&b_err), vec![LIGNE_HOTE_INACTIVE_DECLARE.to_string()]);
        boucle_servie(&b, "mode natif");
        sondes_servies(&b);

        // (c) Sans PLUME_HOST : inchangé, et dit.
        let (c, c_err) = jouer(&fichier_vide, &[]);
        assert_eq!(lu(&c, "P720A-STRICT"), "false");
        assert_eq!(lignes_host(&c_err), vec![LIGNE_HOTE_INACTIVE_DEFAUT.to_string()]);
        boucle_servie(&c, "sans PLUME_HOST");
        assert_ne!(lu(&c, "P720A-SONDE-DEFAUT"), "421", "l'hôte par défaut passe");
        sondes_servies(&c);

        // (d) Valeur explicite 1 par l'environnement : stricte, la boucle locale est refusée et le refus dit sa cause.
        let (d, d_err) = jouer(&fichier_vide, &[("PLUME_HOST", HOTE_DECLARE), ("PLUME_HOST_STRICT", "1")]);
        assert_eq!(lu(&d, "P720A-STRICT"), "true");
        assert_eq!(lignes_host(&d_err), vec![LIGNE_HOTE_EXPLICITE.to_string()]);
        assert_eq!(lu(&d, "P720A-SONDE-BOUCLE"), "421", "stricte : la boucle locale est refusée");
        assert_eq!(lu(&d, "P720A-CORPS-BOUCLE"), serde_json::to_string(PHRASE_HOTE_REFUSE).unwrap(), "le refus dit sa cause, corps entier");
        assert_eq!(lu(&d, "P720A-SONDE-LOCALHOST"), "421");
        assert_eq!(lu(&d, "P720A-SONDE-INGEST-BOUCLE"), "421", "stricte : l'ingestion par la boucle locale aussi");
        assert_ne!(lu(&d, "P720A-SONDE-DECLARE"), "421", "l'autorité déclarée passe");
        sondes_servies(&d);

        // (e) Valeur explicite 1 écrite dans le FICHIER (levier du mode natif).
        let (e, e_err) = jouer(&fichier_natif_strict, &[]);
        assert_eq!(lu(&e, "P720A-STRICT"), "true");
        assert_eq!(lignes_host(&e_err), vec![LIGNE_HOTE_EXPLICITE.to_string()]);
        assert_eq!(lu(&e, "P720A-SONDE-BOUCLE"), "421");
        sondes_servies(&e);

        // (f) Autre valeur posée : inactive, et dit comme tel.
        let (f, f_err) = jouer(&fichier_vide, &[("PLUME_HOST", HOTE_DECLARE), ("PLUME_HOST_STRICT", "true")]);
        assert_eq!(lu(&f, "P720A-STRICT"), "false");
        assert_eq!(lignes_host(&f_err), vec![LIGNE_HOTE_AUTRE_VALEUR.to_string()]);
        boucle_servie(&f, "valeur autre que 1");
    }
}
