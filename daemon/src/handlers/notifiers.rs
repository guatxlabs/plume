//! Notifications multi-canal (P-IR) : neutralisation d'en-têtes `oneline`, garde d'URL `safe_url`,
//! envoi `notify_send`, dispatch de fond `dispatch_notifications`, et CRUD/test des notifiers.
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;
use crate::handlers::transaction_validee::{ouvrir_la_transaction_du_geste, rendre_apres_validation};

// ---------- notifications multi-canal (P-IR) ----------
/// Neutralise l'injection d'en-têtes (CR/LF) dans les valeurs passées à curl (Title/Subject/From/To).
pub(crate) fn oneline(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}
/// DURCISSEMENT — exécute `curl` en passant les options SENSIBLES (auth) via un fichier de
/// CONFIG lu sur STDIN (`-K -`), JAMAIS en argv : `/proc/<pid>/cmdline` est lisible par tout ce qui partage le
/// PID-ns (sidecar, `kubectl debug`, descendants). `secret_cfg` = lignes de config curl (`header = "…"` /
/// `user = "…"`) déjà échappées. Vide -> aucune ligne de config, stdin fermé (aucun secret à cacher).
///
/// `P10.33-n` (confidentialité) — LA RÉPONSE DU SERVICE NE VA PLUS DANS LE JOURNAL DU DÉMON. curl héritait de
/// la sortie standard du démon, et `-s` ne retire que la barre de progression : le CORPS DE RÉPONSE y était
/// imprimé. ntfy répond à une publication par le message publié — le détail de l'alerte et le nom d'hôte
/// atterrissaient donc dans le journal du démon (journald, `kubectl logs`), lisible bien au-delà des
/// administrateurs du canal. La sortie standard part désormais vers le néant. La sortie d'erreur (`-S` : une
/// ligne de cause, jamais de corps — `-f` n'imprime pas le corps d'une réponse en erreur) est lue au plus
/// `STDERR_CURL_LU_MAX` octets, le reste drainé sans être gardé, et réémise sur UNE ligne bornée à
/// `STDERR_CURL_EMIS_MAX` caractères. Le succès reste le seul code de sortie de curl.
fn curl_send(args: &[String], secret_cfg: &str) -> bool {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    let mut cmd = Command::new("curl");
    if !secret_cfg.is_empty() {
        cmd.arg("-K").arg("-"); // options sensibles lues depuis stdin, hors argv
    }
    cmd.args(args);
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());
    cmd.stdin(if secret_cfg.is_empty() { Stdio::null() } else { Stdio::piped() });
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(_) => return false,
    };
    if let Some(si) = child.stdin.as_mut() {
        let _ = si.write_all(secret_cfg.as_bytes());
    }
    let _ = child.stdin.take(); // ferme stdin -> curl lit EOF
    let mut erreur = Vec::new();
    if let Some(mut se) = child.stderr.take() {
        let _ = (&mut se).take(STDERR_CURL_LU_MAX).read_to_end(&mut erreur);
        let _ = std::io::copy(&mut se, &mut std::io::sink()); // drainé, jamais gardé : curl n'est pas bloqué
    }
    let statut = child.wait();
    if let Some(ligne) = ligne_bornee_de_la_sortie_d_erreur_de_curl(&erreur) {
        let code = match &statut {
            Ok(s) => s.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
            Err(_) => "attente impossible".into(),
        };
        eprintln!("[plume] notification : curl (code {code}) a écrit sur sa sortie d'erreur : {ligne}");
    }
    statut.map(|s| s.success()).unwrap_or(false)
}
/// `P10.33-n` — octets de la sortie d'erreur de curl gardés en mémoire (le reste est drainé).
const STDERR_CURL_LU_MAX: u64 = 4096;
/// `P10.33-n` — caractères de la sortie d'erreur de curl réémis dans le journal du démon.
pub(crate) const STDERR_CURL_EMIS_MAX: usize = 240;
/// `P10.33-n` — la sortie d'erreur de curl sur UNE ligne (blancs et sauts repliés), bornée à
/// `STDERR_CURL_EMIS_MAX` caractères ; `None` si curl n'a rien écrit.
fn ligne_bornee_de_la_sortie_d_erreur_de_curl(erreur: &[u8]) -> Option<String> {
    let texte = String::from_utf8_lossy(erreur);
    let une_ligne = texte.split_whitespace().collect::<Vec<_>>().join(" ");
    if une_ligne.is_empty() {
        return None;
    }
    if une_ligne.chars().count() <= STDERR_CURL_EMIS_MAX {
        return Some(une_ligne);
    }
    Some(une_ligne.chars().take(STDERR_CURL_EMIS_MAX).collect::<String>() + " [tronqué]")
}
/// Échappe une valeur pour une chaîne `"…"` d'un fichier de config curl (backslash + guillemet). Combiné à
/// `oneline` (retire CR/LF) -> aucune évasion de la ligne de config (anti config-injection).
/// `P10.33-s` (sécurité) — un en-tête d'auth n'est admis que sous la forme `Nom: valeur`, le nom fait de lettres,
/// chiffres, `-` et `_`. Dans la config curl, `header = "@chemin"` fait LIRE le fichier local `chemin` et en
/// envoie chaque ligne `Nom: valeur` comme en-tête vers l'URL du canal : un admin lisait ainsi des fichiers du
/// démon. Rend la ligne admise (CR/LF neutralisés), ou `None` : l'envoi est alors annulé, jamais tenté sans.
pub(crate) fn en_tete_d_auth_admis(auth: &str) -> Option<String> {
    let ligne = oneline(auth.trim());
    let (nom, _) = ligne.split_once(':')?;
    if nom.is_empty() || !nom.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return None;
    }
    Some(ligne)
}
fn curl_cfg_quote(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"")
}
/// Schéma d'URL autorisé (anti argv flag-smuggling : empêche aussi une URL commençant par '-').
pub(crate) fn safe_url(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    ["http://", "https://", "smtp://", "smtps://"].iter().any(|p| u.starts_with(p))
}
/// URL d'ÉGRESS notifier VALIDE : schéma autorisé (`safe_url`) ET garde SSRF (`ssrf_guard` :
/// rejette loopback/link-local/RFC1918 + re-vérifie l'IP résolue, anti-rebind). Utilisée à la CRÉATION/MAJ
/// (retour d'erreur admin) ET au point d'ÉGRESS réel `notify_send` (choke-point non contournable, y compris
/// une `webhook_url` slack posée directement en config). `safe_url` NU reste pour la validation de GABARIT
/// (workflow_actions) où l'URL porte des placeholders `$field$` non encore résolus.
pub(crate) fn egress_url_ok(url: &str) -> bool {
    safe_url(url) && ssrf_guard(url).is_ok()
}

/// Envoie une notification via `curl` (https/SMTP sans dépendance Rust). Args directs + `--` = pas d'injection.
pub(crate) fn notify_send(kind: &str, url: &str, config: &Value, sev: i64, title: &str, detail: &str, host: &str, ts: i64) -> bool {
    match kind {
        "ntfy" => {
            if !egress_url_ok(url) { return false; } // garde SSRF au point d'égress (couvre aussi le bypass config direct)
            let prio = match sev { 4 => "5", 3 => "4", 2 => "3", 1 => "2", _ => "1" };
            let g = |k: &str| config.str_field(k);
            // `P10.33-s` (sécurité) — `--data-raw`, jamais `-d` : `-d @chemin` fait LIRE à curl un fichier local
            // et en envoie le contenu au service. Le début du détail vient de la requête de la règle ; un détail
            // « @/var/lib/… » exfiltrait donc un fichier du démon vers le canal. `--data-raw` envoie le littéral.
            let mut args: Vec<String> = vec![
                "-fsS".into(), "--max-time".into(), "10".into(),
                "-H".into(), format!("Title: {}", oneline(title)),
                "-H".into(), format!("Priority: {prio}"),
                "-H".into(), "Tags: rotating_light".into(),
                "--data-raw".into(), format!("{detail}{}", if host.is_empty() { String::new() } else { format!("\n[{host}]") }),
            ];
            // Auth ntfy (serveurs en deny-all/protégés) : token Bearer (préféré) OU user/pass (basic). S2 : les
            // creds passent par la CONFIG STDIN (`curl_send`), plus jamais en argv (fuite /proc/<pid>/cmdline).
            let (token, user, pass) = (g("token"), g("user"), g("pass"));
            let mut secret_cfg = String::new();
            if !token.is_empty() {
                secret_cfg.push_str(&format!("header = \"Authorization: Bearer {}\"\n", curl_cfg_quote(&oneline(token))));
            } else if !user.is_empty() {
                secret_cfg.push_str(&format!("user = \"{}:{}\"\n", curl_cfg_quote(&oneline(user)), curl_cfg_quote(pass)));
            }
            args.push("--".into());
            args.push(url.to_string());
            curl_send(&args, &secret_cfg)
        }
        "webhook" => {
            if !egress_url_ok(url) { return false; } // garde SSRF au point d'égress
            let body = json!({ "ts": ts, "severity": sev, "title": title, "detail": detail, "host": host }).to_string();
            // `P10.33-n` : par `curl_send` comme les autres genres — la réponse du service ne va pas au journal.
            let args: Vec<String> = [
                "-fsS", "--max-time", "10", "-X", "POST",
                "-H", "Content-Type: application/json", "-d", &body, "--", url,
            ].iter().map(|a| a.to_string()).collect();
            curl_send(&args, "")
        }
        "email" => {
            let g = |k: &str| config.str_field(k);
            let (from, to, user, pass) = (g("from"), g("to"), g("user"), g("pass"));
            if url.is_empty() || from.is_empty() || to.is_empty() {
                return false;
            }
            let seq = INGEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Le corps du mail (titre + détail de l'alerte) transite par un fichier temporaire que
            // curl téléverse. Il était effacé sur le SEUL chemin nominal : un `return false` après
            // une écriture PARTIELLE, ou une panique, laissait le contenu de l'alerte en clair dans
            // $TMPDIR. Le garde RAII l'efface sur TOUTE sortie de portée — et ses sidecars avec.
            let garde = crate::backup::PlaintextTempGuard(
                crate::tmp_possede::racine_systeme().join(format!("plume-mail-{ts}-{seq}.eml")),
            );
            let p = garde.path().to_path_buf();
            if !egress_url_ok(url) { // garde SSRF (smtp) au point d'égress
                return false;
            }
            let body = format!("From: {}\r\nTo: {}\r\nSubject: [Plume] {}\r\n\r\n{detail}\r\n[{host}]\r\n", oneline(from), oneline(to), oneline(title));
            if std::fs::write(&p, body).is_err() {
                return false;
            }
            let mut args: Vec<String> = vec![
                "-fsS".into(), "--max-time".into(), "15".into(), "--url".into(), url.into(),
                "--mail-from".into(), oneline(from), "--mail-rcpt".into(), oneline(to),
                "--upload-file".into(), p.to_string_lossy().into_owned(),
            ];
            // S2 : creds SMTP via config STDIN (`curl_send`), plus en argv (fuite /proc/<pid>/cmdline).
            let mut secret_cfg = String::new();
            if !user.is_empty() {
                secret_cfg.push_str(&format!("user = \"{}:{}\"\n", curl_cfg_quote(&oneline(user)), curl_cfg_quote(pass)));
            }
            let r = curl_send(&args, &secret_cfg);
            // Plus de `remove_file` ici : le garde efface en sortie de portée, et il ÉCRASE le
            // contenu avant de délier (`secure_delete`) — un simple unlink laissait les pages du
            // corps d'alerte récupérables sur le volume.
            r
        }
        // #48 SLACK (incoming webhook). L'URL du webhook EST un secret -> elle vit dans `config.webhook_url`
        // (jamais projetée), PAS dans `url` (affiché). Payload « blocks » + fallback texte.
        "slack" => {
            let wh = config.str_field("webhook_url");
            if !egress_url_ok(wh) { // la webhook_url slack est un égress -> garde SSRF
                return false;
            }
            let body = slack_payload(sev, title, detail, host, ts).to_string();
            // S2 : la `webhook_url` (SECRET) passe par la config STDIN (`url = …`), plus en argv (fuite /proc).
            let args: Vec<String> = vec![
                "-fsS".into(), "--max-time".into(), "10".into(), "-X".into(), "POST".into(),
                "-H".into(), "Content-Type: application/json".into(), "-d".into(), body,
            ];
            curl_send(&args, &format!("url = \"{}\"\n", curl_cfg_quote(wh)))
        }
        // #48 PAGERDUTY (Events API v2, action trigger). La `routing_key` EST un secret -> `config.routing_key`.
        // Endpoint FIXE (pas de SSRF : la cible n'est pas pilotable par l'appelant). dedup_key = titre neutralisé.
        "pagerduty" => {
            let rk = config.str_field("routing_key");
            if rk.is_empty() {
                return false;
            }
            let endpoint = "https://events.pagerduty.com/v2/enqueue";
            let body = pagerduty_payload(rk, &oneline(title), sev, title, detail, host, ts).to_string();
            // S2 : le body embarque la `routing_key` (SECRET) -> config STDIN (`data = …`), plus en argv (fuite /proc).
            let args: Vec<String> = vec![
                "-fsS".into(), "--max-time".into(), "10".into(), "-X".into(), "POST".into(),
                "-H".into(), "Content-Type: application/json".into(), "--".into(), endpoint.into(),
            ];
            curl_send(&args, &format!("data = \"{}\"\n", curl_cfg_quote(&body)))
        }
        // #48 GÉNÉRIQUE HTTP avec gabarit SÛR. `url` = cible (non secrète). `config.template` = corps rendu par
        // substitution de placeholders CONNUS uniquement (pas de commande, pas de SSRF hors `url`). En-tête
        // d'auth optionnel `config.auth_header` (secret, ex `Authorization: Bearer x`), neutralisé CR/LF.
        "generic" => {
            if !egress_url_ok(url) { // garde SSRF au point d'égress
                return false;
            }
            let tmpl = config.str_field("template");
            let body = if tmpl.is_empty() {
                json!({ "ts": ts, "severity": sev, "title": title, "detail": detail, "host": host }).to_string()
            } else {
                render_template(tmpl, sev, title, detail, host, ts)
            };
            let ctype = config.str_field("content_type");
            let ctype = if ctype.is_empty() { "application/json" } else { ctype };
            let mut args: Vec<String> = vec![
                "-fsS".into(), "--max-time".into(), "10".into(), "-X".into(), "POST".into(),
                "-H".into(), format!("Content-Type: {}", oneline(ctype)),
            ];
            // S2 : l'`auth_header` (SECRET, ex. `Authorization: Bearer …`) passe par la config STDIN (`header = …`),
            // plus en argv (fuite /proc/<pid>/cmdline). CR/LF déjà neutralisés (`oneline`) + échappement config.
            let auth = config.str_field("auth_header");
            let secret_cfg = if auth.is_empty() {
                String::new()
            } else {
                match en_tete_d_auth_admis(auth) {
                    Some(ligne) => format!("header = \"{}\"\n", curl_cfg_quote(&ligne)),
                    None => {
                        // La valeur est un SECRET : jamais au journal, seule la forme attendue l'est.
                        eprintln!("[plume] notification generic : auth_header refusé, forme « Nom: valeur » exigée — envoi annulé");
                        return false;
                    }
                }
            };
            // `P10.33-s` (sécurité) — `--data-raw` : un gabarit qui commence par {{title}}, {{host}} ou {{detail}}
            // rend un corps qui peut commencer par « @ », que `-d` lirait comme un chemin de fichier local.
            // (webhook et slack gardent `-d` : leur corps est un objet JSON sérialisé, il commence par « { ».)
            args.push("--data-raw".into());
            args.push(body);
            args.push("--".into());
            args.push(url.to_string());
            curl_send(&args, &secret_cfg)
        }
        // #48 output-to-lookup : PAS de réseau. Écrit dans une table lookup (#36) -> géré dans
        // dispatch_notifications (a besoin d'un `Connection`). Ici : no-op de garde (jamais appelé pour ce kind).
        "lookup" => false,
        _ => false,
    }
}

/// `P10.33-n` — CE QU'UN ENVOI RÉUSSI ÉTABLIT, PAR GENRE DE CANAL. `notify_send` rend `true` quand curl sort en
/// zéro, c'est-à-dire quand le SERVICE a accepté l'envoi (ntfy a pris la publication, le relais SMTP a pris le
/// message, l'URL a répondu 2xx). Aucun de ces services ne renvoie un accusé de LECTURE, et un sujet ntfy sans
/// abonné accepte une publication comme un autre : un succès ne dit donc jamais que quelqu'un a vu l'alerte. Le
/// démon dit ce qu'il sait — « remis au service, aucun accusé de lecture connu » — et ne fabrique pas d'échec là
/// où le service ne sait pas répondre. Fonction PURE : aucun réseau, le genre seul décide (aucun réglage d'un
/// canal ne lui fait renvoyer un accusé).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccuseDuCanal {
    /// ntfy, webhook, email, slack, pagerduty, generic : le succès est la remise au service, rien au-delà.
    RemisAuServiceSansAccuseDeLecture,
    /// lookup : écriture dans une table locale, vérifiable sur place — aucun destinataire en jeu.
    Local,
    /// Genre que `notify_send` ne connaît pas : rien ne part, il n'y a rien à accuser.
    GenreInconnu,
}

impl AccuseDuCanal {
    /// La valeur servie sous `accuse_de_lecture` (liste des canaux, essai d'un canal).
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::RemisAuServiceSansAccuseDeLecture => "inconnu",
            Self::Local => "local",
            Self::GenreInconnu => "sans_objet",
        }
    }
}

/// `P10.33-n` — le genre d'un canal -> ce que son succès établit. Voir `AccuseDuCanal`.
pub(crate) fn accuse_du_canal(kind: &str) -> AccuseDuCanal {
    match kind {
        "ntfy" | "webhook" | "email" | "slack" | "pagerduty" | "generic" => AccuseDuCanal::RemisAuServiceSansAccuseDeLecture,
        "lookup" => AccuseDuCanal::Local,
        _ => AccuseDuCanal::GenreInconnu,
    }
}

/// `P10.33-n` — la phrase servie par l'essai d'un canal quand le service a ACCEPTÉ l'envoi (jamais sur un échec).
pub(crate) const PHRASE_REMIS_AU_SERVICE_SANS_ACCUSE_DE_LECTURE: &str = "Remis au service : il a accepté l'envoi. \
     Aucun accusé de lecture n'existe pour ce canal — Plume ne sait pas si quelqu'un reçoit ou consulte ce message \
     (un sujet sans abonné accepte une publication comme un autre).";

/// Kinds de canaux dont la CIBLE (endpoint) est dans `url` (donc `url` requis & validé à la création).
/// Slack/PagerDuty/lookup portent leur cible/clé dans `config` (secret) -> `url` peut rester vide.
pub(crate) fn notifier_kind_needs_url(kind: &str) -> bool {
    matches!(kind, "ntfy" | "webhook" | "email" | "generic")
}

/// `P10.33-h` — la clé de compte d'un genre de canal refusé : `GENRE_DE_CANAL_INCONNU` pour un genre que `notify_send` ne
/// connaît pas (texte libre de la création : il ne fait pas monter la cardinalité du compte).
pub(crate) const GENRE_DE_CANAL_INCONNU: &str = "(genre inconnu)";
fn genre_de_canal_compte(kind: &str) -> &'static str {
    match kind {
        "ntfy" => "ntfy",
        "webhook" => "webhook",
        "email" => "email",
        "slack" => "slack",
        "pagerduty" => "pagerduty",
        "generic" => "generic",
        "lookup" => "lookup",
        _ => GENRE_DE_CANAL_INCONNU,
    }
}
/// `P10.33-h` — la cause d'un `notify_send` qui rend faux : il ne rend qu'un booléen, la phrase dit donc les causes
/// possibles sans en choisir une (la ligne curl qui précède, s'il y en a une, la nomme), et jamais l'URL.
fn cause_d_un_envoi_non_pris(genre: &str) -> &'static str {
    if genre == GENRE_DE_CANAL_INCONNU {
        "genre de canal inconnu du démon, rien n'est parti"
    } else {
        "envoi refusé : garde d'URL, configuration du canal incomplète ou curl en échec"
    }
}

/// Dispatche les alertes non notifiées, puis marque notified=1.
///
/// #48/#53 : le routage passe désormais par `plan_dispatch`. MODE 0 (aucune politique, aucun silence) :
///  - `plan_dispatch` renvoie `silenced=false` et `target_ids` = TOUS les canaux enabled -> la boucle d'envoi
///    (filtre `sev>=min_severity` PAR CANAL, inchangé) reproduit EXACTEMENT le fan-out plat historique ;
///  - un silence actif matche l'alerte -> elle est marquée notified=1 SANS envoi (mute gouverné) ;
///  - une politique présente -> l'alerte n'est envoyée qu'aux points de contact routés (most-specific-wins) ;
///  - un canal `lookup` (#36) n'émet pas de réseau : l'alerte est écrite dans la table lookup (enrichissement).
pub(crate) fn dispatch_notifications(db: &Arc<Mutex<Connection>>) {
    // NotifierRef complet (id inclus) pour le filtrage par politique.
    struct NotifierRef { id: i64, kind: String, url: String, min_severity: i64, config: String }
    #[allow(clippy::type_complexity)]
    let (alerts, notifiers, policies, silences): (
        Vec<(i64, i64, i64, String, String, String, String, String)>,
        Vec<NotifierRef>,
        Vec<Policy>,
        Vec<Vec<(String, String)>>,
    ) = {
        let conn = db.lock();
        // labels de routage : mitre / host / source(=rule) / env_id, en plus de ts/severity/title/detail.
        // `P10.7-f` (lot 109) — la file des alertes à notifier est lue EN BLOC : une lecture ratée (ou une ligne
        // en erreur) ne raccourcit plus la file en silence, le tour est refusé et COMPTÉ, le suivant relit.
        let alerts: Vec<(i64, i64, i64, String, String, String, String, String)> = match conn
            .prepare(
                "SELECT id,ts,severity,title,detail,COALESCE(host,''),COALESCE(mitre,''),COALESCE(rule,'') \
                 FROM alert WHERE notified=0 ORDER BY ts LIMIT 20",
            )
            .and_then(|mut s| s.query_map([], |r| Ok((
                r.get(0)?, r.get(1)?, r.get(2)?,
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                r.get(5)?, r.get(6)?, r.get(7)?,
            )))?.collect::<rusqlite::Result<Vec<_>>>())
        {
            Ok(v) => v,
            Err(e) => { crate::metrics::compter_un_tick_aveugle("dispatch_alerts", &e.to_string()); return; }
        };
        if alerts.is_empty() {
            return;
        }
        // `P10.7-f` (lot 109) — CRUCIAL : des canaux NON LUS ne rendent plus une liste VIDE. Avec une liste vide,
        // la boucle ne dispatche rien MAIS l'alerte était quand même marquée `notified=1` en fin de tour — marquée
        // envoyée, jamais dispatchée : une PERTE SILENCIEUSE. Sur lecture ratée, on saute le tour et on le compte ;
        // aucune alerte n'est marquée, le tour suivant relit.
        let notifiers: Vec<NotifierRef> = match conn
            .prepare("SELECT id,kind,url,min_severity,config FROM notifier WHERE enabled=1 ORDER BY id")
            .and_then(|mut s| s.query_map([], |r| Ok(NotifierRef { id: r.get(0)?, kind: r.get(1)?, url: r.get(2)?, min_severity: r.get(3)?, config: r.get(4)? }))?.collect::<rusqlite::Result<Vec<_>>>())
        {
            Ok(v) => v,
            Err(e) => { crate::metrics::compter_un_tick_aveugle("dispatch_notifiers", &e.to_string()); return; }
        };
        // `P10.7-f` (rang 2) — LE ROUTAGE ET LES SILENCES SONT LUS, OU LE TOUR EST SAUTÉ EN LE COMPTANT.
        // Avant, `load_policies` et `load_active_silences` rendaient un `Vec` et une lecture ratée y valait
        // un vecteur VIDE — c'est-à-dire, mot pour mot, le MODE 0 documenté vingt lignes plus haut :
        //   * politiques non lues -> `plan_dispatch` retombe en FAN-OUT PLAT : l'alerte que l'exploitant
        //     avait routée vers une seule astreinte part sur TOUS les canaux activés (et `notify_send` est
        //     irréversible : on ne rappelle pas un SMS PagerDuty) ;
        //   * silences non lus -> `plan.silenced` est faux pour tout le monde : l'alerte qu'un humain avait
        //     explicitement muselée part quand même.
        // Dans les deux cas l'alerte était ENSUITE marquée `notified=1` — donc le mauvais routage était
        // définitif, et le tour suivant ne pouvait pas le rattraper. Le geste est celui du lot 109 sur cette
        // même fonction : on compte un tour aveugle (`compter_un_tick_aveugle`, qui journalise aussi la
        // cause sur la sortie d'erreur) et on SORT AVANT la boucle d'envoi. Rien n'est envoyé, et surtout
        // rien n'est marqué : l'`UPDATE alert SET notified=1` vit dans la boucle qu'on n'atteint pas, donc
        // les alertes de ce tour restent `notified=0` et redeviennent dispatchables au tour suivant.
        let policies = match load_policies(&conn) {
            Ok(v) => v,
            Err(e) => { crate::metrics::compter_un_tick_aveugle("dispatch_policies", &e.to_string()); return; }
        };
        let silences = match load_active_silences(&conn, now()) {
            Ok(v) => v,
            Err(e) => { crate::metrics::compter_un_tick_aveugle("dispatch_silences", &e.to_string()); return; }
        };
        (alerts, notifiers, policies, silences)
    };
    let enabled_ids: Vec<i64> = notifiers.iter().map(|n| n.id).collect();
    for (id, ts, sev, title, detail, host, mitre, source) in &alerts {
        // env_id non porté par le SELECT (colonne rare en label) : reste vide -> matcher `env` inopérant en mode 0.
        let labels = alert_labels(*sev, mitre, host, source, "");
        let plan = plan_dispatch(&labels, &policies, &silences, &enabled_ids);
        // `P10.33-h` (reste) — LE VERDICT DE CHAQUE CANAL EST LU. Avant : `let _ =` sur l'écriture du lookup comme sur
        // `notify_send`, puis le marqueur `notified=1` plus bas : une alerte dont TOUS les canaux avaient refusé était
        // marquée envoyée sans un mot. Décision par défaut (politique de renvoi non décidée, envoi irréversible côté
        // PagerDuty/SMS) : chaque refus est compté par genre et journalisé (alerte, canal, genre, cause ; jamais l'URL,
        // la configuration ni le contenu), l'alerte qu'aucun canal visé n'a prise est comptée UNE fois ; le marqueur
        // garde son sens, rien n'est renvoyé.
        let mut canaux_vises = 0usize;
        let mut envois_pris = 0usize;
        if !plan.silenced {
            for n in &notifiers {
                if !plan.target_ids.contains(&n.id) || sev < &n.min_severity {
                    continue;
                }
                canaux_vises += 1;
                let genre = genre_de_canal_compte(&n.kind);
                let config: Value = serde_json::from_str(&n.config).unwrap_or_else(|_| json!({}));
                if n.kind == "lookup" {
                    // écrit l'alerte dans le lookup configuré (défaut `alerts`, clé = host).
                    let name = { let s = config.str_field("lookup"); if s.is_empty() { "alerts".to_string() } else { s.to_string() } };
                    let key_field = { let s = config.str_field("key_field"); if s.is_empty() { "host".to_string() } else { s.to_string() } };
                    let key = match key_field.as_str() { "host" => host.clone(), "source" => source.clone(), "mitre" => mitre.clone(), _ => host.clone() };
                    let fields = json!({ "host": host, "source": source, "mitre": mitre, "severity": sev, "title": title, "ts": ts });
                    let conn = db.lock();
                    match write_alert_to_lookup(&conn, &name, &key_field, &key, &fields) {
                        Ok(()) => envois_pris += 1,
                        Err(e) => crate::metrics::compter_un_envoi_d_alerte_refuse(*id, n.id, genre, &e.to_string()),
                    }
                } else if notify_send(&n.kind, &n.url, &config, *sev, title, detail, host, *ts) {
                    envois_pris += 1;
                } else {
                    crate::metrics::compter_un_envoi_d_alerte_refuse(*id, n.id, genre, cause_d_un_envoi_non_pris(genre));
                }
            }
        }
        if canaux_vises > 0 && envois_pris == 0 {
            crate::metrics::compter_une_alerte_sans_aucun_envoi_pris(*id, canaux_vises);
        }
        // `P10.20-w` — LE MARQUEUR EST COMPTÉ. Avant, `let _ =` : un marqueur refusé laissait l'alerte `notified=0`
        // et les vingt alertes du lot repartaient à chaque tour, y compris par des canaux irréversibles. Au PREMIER
        // refus (ou écriture sans effet), le tour s'ARRÊTE : les alertes suivantes attendent le tour suivant au lieu
        // de repartir en boucle derrière une marque perdue, et le tour est compté sous `dispatch_marqueur` avec la
        // cause du moteur. L'alerte en cours (envoyée, ou silencée) y repassera si elle existe encore.
        let conn = db.lock();
        let marque = conn.execute("UPDATE alert SET notified=1, notified_value=current_value WHERE id=?1", params![id]); // `P4.12-h` : la barre de re-notification est reposée ici
        match marque {
            Ok(1) => {}
            autre => {
                let cause = match autre { Err(e) => e.to_string(), Ok(n) => format!("{n} ligne(s) écrite(s) au lieu d'une") };
                eprintln!("[plume] dispatch : alerte {id} traitée (envoyée ou silencée) mais marqueur `notified` NON ÉCRIT, tour arrêté avant les alertes suivantes, renvoyées au tour suivant (celle-ci aussi, si elle existe encore)");
                crate::metrics::compter_un_tick_aveugle("dispatch_marqueur", &cause);
                return;
            }
        }
    }
}

/// DURCISSEMENT : la colonne `config` porte le token ntfy / user:pass SMTP. Elle N'EST PLUS
/// JAMAIS projetée -> on renvoie `has_auth` (booléen, miroir de connectors_list `has_secret`). Un viewer/editor
/// est DÉJÀ bloqué par rbac_gate (admin-only, GET compris) ; ce re-check DOUBLE la garde (défense en profondeur).
pub(crate) async fn notifiers_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    crate::req_conn!(st, au, conn);
    // `P10.7-f` (rang 4, vague b) — LA LISTE DES CANAUX EST ENTIÈRE OU AVOUÉE. Avant : DEUX `unwrap()`
    // (une table `notifier` retirée sous les pieds du gestionnaire PANIQUAIT — une panique n'est pas un
    // aveu) puis `rows.flatten().collect::<Vec<_>>()`, qui jetait la ligne dont le mappeur échoue (`url`
    // ou `config` corrompus, colonne de migration que la connexion qui sert ne voit pas encore) et servait
    // le reste sous un corps rigoureusement identique à celui d'une liste complète. Un canal absent se lit
    // « aucune notification n'est configurée là » : l'administrateur en crée un second vers la MÊME
    // destination et l'astreinte reçoit tout en double — pendant que le canal invisible, lui, continue
    // d'émettre, parce que le dispatch lit la table et non cette vue. L'aveu est celui du dépôt
    // (`liste_bornee::corps_de_liste_illisible` : `notifiers` présente et VIDE, `error` nomme la cause) ;
    // `web/detection_admin.js:533` teste déjà `Array.isArray(d.notifiers)`, donc la forme tient.
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare("SELECT id,name,kind,enabled,url,min_severity,config FROM notifier ORDER BY id")
        .and_then(|mut stmt| {
            stmt.query_map([], |r| {
                // has_auth = le canal porte un credential (token ntfy OU user/pass SMTP) non vide. Le blob `config`
                // (secret) N'EST PAS renvoyé -> aucune fuite de token/mot de passe, même pour un admin (édition = re-saisie).
                let cfg: String = r.get(6)?;
                // #48 : la liste des clés-secrets s'étend aux nouveaux canaux (webhook Slack, routing key PagerDuty,
                // en-tête d'auth du canal générique). AUCUNE n'est projetée -> `has_auth` booléen seul (défense en
                // profondeur ; rbac_gate bloque déjà tout non-admin, GET compris).
                let has_auth = serde_json::from_str::<Value>(&cfg)
                    .ok()
                    .map(|v| ["token", "user", "pass", "webhook_url", "routing_key", "auth_header"].iter().any(|k| v.get(*k).and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)))
                    .unwrap_or(false);
                // `P10.33-n` : ce que le succès de ce canal établit (« inconnu » pour un canal réseau : aucun accusé
                // de lecture n'existe). Un inconnu CONSTANT n'est pas un signal : aucun état de santé n'en dérive.
                let kind: String = r.get(2)?;
                let accuse = accuse_du_canal(&kind).code();
                Ok(json!({
                    "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "kind": kind,
                    "enabled": r.get::<_, i64>(3)? != 0, "url": r.get::<_, String>(4)?,
                    "min_severity": r.get::<_, i64>(5)?, "has_auth": has_auth, "accuse_de_lecture": accuse
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(rows) => Json(json!({ "notifiers": rows })).into_response(),
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({}), "notifiers")).into_response(),
    }
}
// `P10.28-c`, `P10.28-q` — LES CANAUX DE NOTIFICATION REFUSENT PAR LA FORME PARTAGÉE : 503 nommé quand la base ne
// prend pas ou ne valide pas la transaction, 400 nommé quand la demande est mal formée, le refus du rôle dans la phrase
// de `rbac_gate`.
//
// LA FORME D'AVANT, MESURÉE LE 2026-09-25 (témoins `bdrn_`) — SIX formes de refus pour trois routes, dont aucune que la
// console pouvait lire autrement que « refusé sans cause » ou « passerelle » :
//  * création : TOUS ses refus en deux cents `{error}` — rôle, URL refusée, `BEGIN` refusé (« verrou base
//    indisponible »), écriture refusée, `COMMIT` refusé (la cause nommée, mais sous un 200) ;
//  * modification et suppression : `BEGIN` refusé et écriture refusée en 500 SANS corps, `COMMIT` refusé en 503 SANS
//    corps (la cause n'était qu'au journal), URL refusée en 400 sans corps, rôle en 403 sans corps.
// L'énoncé (`P10.28-c` : « 200 `{error}`, 503 sans corps » ; `P10.28-q` : « 503 sans corps et 200 `{error}` ») sous-comptait
// les 500 et 400 sans corps et le 403 nu. Les succès sont INCHANGÉS (`{id}`, 204, 204). CE QUI CHANGE, POUR LA CONSOLE :
// la création rend désormais un statut d'erreur (403, 400, 500, 503) là où elle rendait 200 `{error}`.

/// `P10.28-d` — le `BEGIN` de la création d'un canal de notification refusé.
pub(crate) const CAUSE_CANAL_DE_NOTIFICATION_NON_CREE_TRANSACTION_NON_OUVERTE: &str = "CANAL DE NOTIFICATION NON CRÉÉ : \
     la base n'a pas pris la transaction de la création (BEGIN refusé : verrou tenu, ou transaction d'un autre geste \
     pendante sur l'écrivain) — RIEN n'est écrit : aucun canal n'existe, aucune alerte ne partira vers lui, et aucune \
     trace n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";

/// `P10.28-q` — le `COMMIT` de la modification d'un canal de notification refusé.
pub(crate) const CAUSE_CANAL_DE_NOTIFICATION_INCHANGE: &str = "CANAL DE NOTIFICATION INCHANGÉ : la base n'a pas validé \
     la transaction (COMMIT refusé) et l'a annulée — le canal garde sa cible, son secret, son seuil et son activation \
     d'avant, et aucune trace n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou \
     verrouillée.";

/// `P10.28-d` — le `BEGIN` de la modification d'un canal de notification refusé.
pub(crate) const CAUSE_CANAL_DE_NOTIFICATION_INCHANGE_TRANSACTION_NON_OUVERTE: &str = "CANAL DE NOTIFICATION INCHANGÉ : \
     la base n'a pas pris la transaction de la modification (BEGIN refusé : verrou tenu, ou transaction d'un autre geste \
     pendante sur l'écrivain) — RIEN n'est écrit : le canal garde sa cible, son secret, son seuil et son activation \
     d'avant, et aucune trace n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";

/// `P10.28-q` — le `COMMIT` de la suppression d'un canal de notification refusé.
pub(crate) const CAUSE_CANAL_DE_NOTIFICATION_NON_SUPPRIME: &str = "CANAL DE NOTIFICATION NON SUPPRIMÉ : la base n'a pas \
     validé la transaction (COMMIT refusé) et l'a annulée — le canal est toujours là et reçoit toujours les alertes, et \
     aucune trace n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";

/// `P10.28-d` — le `BEGIN` de la suppression d'un canal de notification refusé.
pub(crate) const CAUSE_CANAL_DE_NOTIFICATION_NON_SUPPRIME_TRANSACTION_NON_OUVERTE: &str = "CANAL DE NOTIFICATION NON \
     SUPPRIMÉ : la base n'a pas pris la transaction du retrait (BEGIN refusé : verrou tenu, ou transaction d'un autre \
     geste pendante sur l'écrivain) — RIEN n'est écrit : le canal est toujours là et reçoit toujours les alertes, et \
     aucune trace n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";

/// `P10.28-q` — LE REFUS DU RÔLE D'UN CANAL : la phrase même de `rbac_gate` (daemon/src/rbac.rs), en quatre cent trois
/// TEXTE, parce que c'est la seule forme que la console lit comme le refus du rôle (`leRefusEstCeluiDuRole`,
/// web/core.js). Ce re-contrôle double le garde d'authentification, qui refuse le premier.
fn refus_du_role_sur_un_canal() -> Response {
    (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response()
}

pub(crate) async fn notifier_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return refus_du_role_sur_un_canal();
    }
    let url = b.str_field("url");
    let kind = b.get("kind").and_then(|v| v.as_str()).unwrap_or("ntfy").to_string();
    // #48 : slack/pagerduty/lookup portent leur cible/clé dans `config` (secret) -> `url` peut être vide ;
    // les autres canaux exigent une `url` valide. SEC-FIX : on valide DÈS LA CRÉATION avec `egress_url_ok`
    // (= schéma autorisé ET garde SSRF) — pas seulement `safe_url` — sinon un notifier ciblant une adresse
    // interne (loopback/metadata) était accepté puis ÉCHOUAIT SILENCIEUSEMENT à chaque envoi (aucun last_error).
    // L'admin obtient un refus IMMÉDIAT explicite. NB (fix on-prem) : un relais SMTP interne en RFC1918 PASSE
    // par défaut (RFC1918 opt-in via PLUME_SSRF_BLOCK_PRIVATE) — seul le never-egress est refusé d'office.
    if notifier_kind_needs_url(&kind) && !egress_url_ok(url) {
        return bad_req("URL invalide : http(s):// (ntfy/webhook/generic) ou smtp(s):// (email) requis, et cible non-interne (SSRF)");
    }
    if !url.is_empty() && !egress_url_ok(url) {
        return bad_req("URL invalide : schéma non autorisé ou cible interne refusée (SSRF)");
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Canal").to_string();
    let enabled = b.bool_field("enabled", true) as i64;
    let min_sev = b.i64_field("min_severity", 2);
    let config = b.get("config").and_then(|v| v.as_str()).unwrap_or("{}").to_string();
    crate::req_conn!(st, au, conn);
    // M3 : mutation + audit (ledger + event plume-config) DANS UNE transaction fail-closed (patron
    // source_settings_put) -> plus d'angle mort effaçable sans trace. Le `config` (token ntfy / user:pass SMTP)
    // n'est JAMAIS logué : l'audit ne porte que name/kind/enabled.
    if let Err(refus) = ouvrir_la_transaction_du_geste(
        &conn,
        "notifiers",
        &format!("création du canal '{name}'"),
        CAUSE_CANAL_DE_NOTIFICATION_NON_CREE_TRANSACTION_NON_OUVERTE,
    ) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES(?1,?2,?3,?4,?5,?6)",
            params![name, kind, enabled, url, min_sev, config],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn,
            "config.notifier.create",
            &format!("notifier '{name}' ({kind}) créé par {}", au.name),
            3,
            &format!("canal de notification '{name}' ({kind}, enabled={}) créé par {}", enabled != 0, au.name),
            &json!({ "id": id, "kind": kind, "enabled": enabled != 0, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => rendre_apres_validation(&conn, "notifiers", &format!("création du canal '{name}'"), CAUSE_CANAL_DE_NOTIFICATION_NON_CREE, || {
            Json(json!({ "id": id })).into_response()
        }),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}
// `P10.25-g` — LES `COMMIT` DES CANAUX DE NOTIFICATION SONT JUGÉS. MESURÉ sur la forme d'avant (témoins `cjds_`) :
// `{ id }`, 204 et 204 sur une transaction que la base n'avait pas prise, laissée ouverte sur l'écrivain. `P10.28-q` —
// les trois routes rendent désormais le 503 nommé de leur geste (la création ne passe plus par un deux cents `{error}`,
// la modification et la suppression ne rendent plus un 503 sans corps).
/// `P10.25-g` — canal de notification non créé : le `COMMIT` de ce geste refusé.
pub(crate) const CAUSE_CANAL_DE_NOTIFICATION_NON_CREE: &str = "CANAL DE NOTIFICATION NON CRÉÉ : la base n'a pas \
     validé la transaction (COMMIT refusé) et l'a annulée — aucun canal n'est écrit, aucune alerte ne partira vers \
     lui, et aucune trace n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou \
     verrouillée.";

pub(crate) async fn notifier_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return refus_du_role_sur_un_canal();
    }
    if let Some(v) = b.get("url").and_then(|x| x.as_str()) {
        // SEC-FIX : validation d'ÉGRESS complète (schéma + SSRF) à la MAJ, pas seulement le schéma -> pas de
        // notifier ré-pointé vers une cible interne qui échouerait ensuite en silence.
        if !egress_url_ok(v) {
            return bad_req("URL invalide : schéma non autorisé ou cible interne refusée (SSRF)");
        }
    }
    crate::req_conn!(st, au, conn);
    // M3 : mutation + audit fail-closed. Le champ `config`/`url` peut porter un secret -> l'audit note QUELS
    // champs ont changé (NOMS), jamais leurs valeurs.
    if let Err(refus) = ouvrir_la_transaction_du_geste(
        &conn,
        "notifiers",
        &format!("modification du canal #{id}"),
        CAUSE_CANAL_DE_NOTIFICATION_INCHANGE_TRANSACTION_NON_OUVERTE,
    ) {
        return refus;
    }
    let outcome: rusqlite::Result<()> = (|| {
        for (k, col) in [("name", "name"), ("kind", "kind"), ("url", "url"), ("config", "config")] {
            if let Some(v) = b.get(k).and_then(|x| x.as_str()) {
                conn.execute(&format!("UPDATE notifier SET {col}=?1 WHERE id=?2"), params![v, id])?;
            }
        }
        if let Some(v) = b.get("min_severity").and_then(|x| x.as_i64()) { conn.execute("UPDATE notifier SET min_severity=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) { conn.execute("UPDATE notifier SET enabled=?1 WHERE id=?2", params![v as i64, id])?; }
        let changed: Vec<&str> = ["name", "kind", "url", "config", "min_severity", "enabled"].iter().copied().filter(|k| b.get(*k).is_some()).collect();
        audit_config_change(
            &conn,
            "config.notifier.update",
            &format!("notifier #{id} modifié ({}) par {}", changed.join(","), au.name),
            3,
            &format!("canal #{id} modifié (champs: {}) par {}", changed.join(","), au.name),
            &json!({ "id": id, "changed": changed, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => rendre_apres_validation(&conn, "notifiers", &format!("modification du canal #{id}"), CAUSE_CANAL_DE_NOTIFICATION_INCHANGE, || {
            StatusCode::NO_CONTENT.into_response()
        }),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}
pub(crate) async fn notifier_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return refus_du_role_sur_un_canal();
    }
    crate::req_conn!(st, au, conn);
    // M3 : suppression + audit fail-closed (une désactivation de canal ne doit pas être effaçable sans trace).
    if let Err(refus) = ouvrir_la_transaction_du_geste(
        &conn,
        "notifiers",
        &format!("suppression du canal #{id}"),
        CAUSE_CANAL_DE_NOTIFICATION_NON_SUPPRIME_TRANSACTION_NON_OUVERTE,
    ) {
        return refus;
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM notifier WHERE id=?1", params![id])?;
        audit_config_change(
            &conn,
            "config.notifier.delete",
            &format!("notifier #{id} supprimé par {}", au.name),
            3,
            &format!("canal de notification #{id} supprimé par {}", au.name),
            &json!({ "id": id, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => rendre_apres_validation(&conn, "notifiers", &format!("suppression du canal #{id}"), CAUSE_CANAL_DE_NOTIFICATION_NON_SUPPRIME, || {
            StatusCode::NO_CONTENT.into_response()
        }),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}
/// `P10.20-b` (rang quatre) — l'essai d'un canal dont la ligne n'a pas pu être lue : ce n'est pas « canal introuvable ».
pub(crate) const CAUSE_CANAL_NON_ESSAYE_NON_LU: &str = "CANAL NON ESSAYÉ : la base n'a pas rendu ce canal de \
     notification — ce n'est PAS « canal introuvable », c'est une lecture qui n'a pas eu lieu ; aucun envoi n'est fait. \
     Réessayez ; si le refus persiste, la table des canaux est illisible.";

/// `P10.20-j` — ses refus portent leur statut (ils étaient servis en deux cents `{error}`) : le rôle par la phrase TEXTE
/// de `rbac_gate` en 403, comme la création d'un canal (`refus_du_role_sur_un_canal`), et un canal absent en 404.
/// `P10.20-b` (rang quatre) — la ligne du canal se lit en TROIS issues (`.optional()` au lieu de `.ok()`) : présente, essayée ;
/// absente, le 404 d'avant ; lecture ratée, 503 `CAUSE_CANAL_NON_ESSAYE_NON_LU`, cause du moteur au journal seul, aucun envoi.
pub(crate) async fn notifier_test(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return refus_du_role_sur_un_canal();
    }
    let row = {
        use rusqlite::OptionalExtension;
        crate::req_conn!(st, au, conn);
        conn.query_row("SELECT kind,url,config FROM notifier WHERE id=?1", params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))).optional()
    };
    let (kind, url, cfg) = match row {
        Ok(Some(x)) => x,
        Ok(None) => return not_found("canal introuvable"),
        Err(e) => {
            eprintln!("[notifiers] WARN canal #{id} NON lu pour l'essai, aucun envoi : {e}");
            return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_CANAL_NON_ESSAYE_NON_LU);
        }
    };
    let config: Value = serde_json::from_str(&cfg).unwrap_or_else(|_| json!({}));
    let ts = now();
    let accuse = accuse_du_canal(&kind);
    let ok = tokio::task::spawn_blocking(move || notify_send(&kind, &url, &config, 3, "Test Plume", "Notification de test depuis Plume.", "", ts))
        .await.unwrap_or(false);
    // `P10.33-n` — `ok` reste tel quel (la console le lit) ; s'y ajoute ce qu'il établit. Un succès d'un canal
    // réseau est une REMISE AU SERVICE, sans accusé de lecture : la phrase le dit, et elle n'est servie que sur un
    // succès — un échec reste un échec, sans phrase d'accusé.
    let remis = ok && accuse == AccuseDuCanal::RemisAuServiceSansAccuseDeLecture;
    let mut corps = json!({ "ok": ok, "remis_au_service": remis, "accuse_de_lecture": accuse.code() });
    if remis {
        corps["remise"] = json!(PHRASE_REMIS_AU_SERVICE_SANS_ACCUSE_DE_LECTURE);
    }
    Json(corps).into_response()
}
