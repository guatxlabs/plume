//! Collecteur SOC mail (host-natif) — cf. GuatX-Infra ADR-0008.
//! Lit le maildir, applique des patterns IOC/phishing, emet des events MINIMAUX vers le spool
//! (compte, dossier, sujet/exp., message-id, sample IOC/URL). JAMAIS de body en clair.
//! Le body complet reste un pull gate+audite (capacite agent-side distincte, hors de ce binaire).
/// `S36` — la garde dérivée de cette surface (suite seulement) : une boîte qu'on ne sait pas
/// examiner ne se conclut pas par « 0 alerte ».
mod garde_lisibilite;
mod lisibilite;
mod maildir;
mod patterns;
mod url_extract;

use anyhow::{anyhow, Result};
use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| d.to_string())
}
fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
/// L'IDENTITE DE CET HOTE, LUE OU AVOUEE — jamais inventee (`S36`, forme de `S33`). Le repli
/// `unknown` etait un nom d'hote PLAUSIBLE : indiscernable d'une lecture reussie, commun a toutes les
/// machines en echec, et attribuable a une machine reellement nommee ainsi.
fn identite_hote() -> lisibilite::Lecture<String> {
    lisibilite::identite_hote_depuis(
        std::path::Path::new("/proc/sys/kernel/hostname"),
        std::env::var("HOSTNAME").ok().as_deref(),
    )
}

/// L'identite DECLAREE par l'exploitant (`PLUME_HOST`) n'a rien a prouver ; sinon on lit, et si la
/// lecture echoue on rend le VERDICT a la place du nom. L'appelant AVOUE alors.
fn identite() -> lisibilite::Lecture<String> {
    match std::env::var("PLUME_HOST").ok().filter(|v| !v.is_empty()) {
        Some(h) => lisibilite::Lecture::Lue(h),
        None => identite_hote(),
    }
}
fn mtime_epoch(p: &std::path::Path) -> u64 {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or_else(now)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Sous-commandes : `scan` (defaut, detection -> events) | `body` (lecture complete gate+auditee)
    let res = match args.get(1).map(|s| s.as_str()) {
        Some("body") => run_body(&args),
        Some("scan") | None => run(),
        Some(other) => Err(anyhow!("sous-commande inconnue '{other}' (attendu: scan | body)")),
    };
    if let Err(e) = res {
        eprintln!("collector-mail: {e}");
        std::process::exit(1);
    }
}

/// Ecriture atomique d'une enveloppe dans le spool (0640), reutilisee par scan ET audit body.
fn write_spool(spool: &str, name: &str, env: &serde_json::Value) -> Result<String> {
    std::fs::create_dir_all(spool).ok();
    let tmp = format!("{spool}/.{name}.tmp");
    let dst = format!("{spool}/{name}.json");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(serde_json::to_string(env)?.as_bytes())?;
        f.flush()?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640)).ok();
    std::fs::rename(&tmp, &dst)?;
    Ok(dst)
}

/// body-fetch GATE + AUDITE (cf. ADR-0006/0008) : lecture complete d'UN message a la demande.
/// Gate = l'invocation est reservee au central admin (acces agent/SSH) ; chaque lecture est tracee
/// par un event `source=mail-audit` -> SOC (cherchable). Le central rend le html en iframe sandbox+CSP.
/// Usage : plume-collector-mail body <account> <id> [folder]
fn run_body(args: &[String]) -> Result<()> {
    let account = args.get(2).ok_or_else(|| anyhow!("usage: body <account> <id> [folder]"))?;
    let id = args.get(3).ok_or_else(|| anyhow!("usage: body <account> <id> [folder]"))?;
    let folder = args.get(4).map(|s| s.as_str()).unwrap_or("*");
    let root = std::env::var("PLUME_MAIL_ROOT").map_err(|_| anyhow!("PLUME_MAIL_ROOT requis"))?;
    let spool = env_or("PLUME_SPOOL", "/var/lib/plume/spool");
    let host = identite().valeur().cloned().unwrap_or_else(|| lisibilite::HOTE_NON_LU.to_string());
    let actor = env_or("PLUME_ACTOR", "unknown"); // le central renseigne QUI declenche la lecture

    let (fname, path) = maildir::find_message(&root, account, folder, id)?;
    let raw = maildir::read_capped(&path)?;
    let parsed = maildir::parse_msg(&raw);

    // AUDIT : trace la lecture AVANT de rendre le body (best-effort -> spool -> SOC + ledger central)
    let ts = now();
    let audit = serde_json::json!({ "ts": ts, "host": host, "kind": "events", "events": [{
        "ts": ts, "source": "mail-audit", "category": "mail", "severity": 1,
        "message": format!("body read: {}/{}/{} by {}", account, fname, id, actor)
    }]});
    if let Err(e) = write_spool(&spool, &format!("mail-audit-{ts}-{}", std::process::id()), &audit) {
        eprintln!("collector-mail: audit non ecrit ({e})"); // on n'avorte pas la lecture pour autant
    }

    // BODY complet -> stdout (le central capte et rend en iframe sandbox + CSP, cf. ADR-0006)
    let headers: serde_json::Map<String, serde_json::Value> = parsed
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    let out = serde_json::json!({
        "account": account, "folder": fname, "id": id,
        "subject": parsed.subject, "from": parsed.from, "to": parsed.to,
        "date": parsed.date, "message_id": parsed.message_id,
        "headers": headers,
        "text": parsed.text_body.unwrap_or_default(),
        "html": parsed.html_body.unwrap_or_default(),
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

fn run() -> Result<()> {
    let root = std::env::var("PLUME_MAIL_ROOT")
        .map_err(|_| anyhow!("PLUME_MAIL_ROOT requis (racine maildir, ex: /opt/local-path-provisioner/<pvc>_mail_mail-data-mailserver-0)"))?;
    let domain = env_or("PLUME_MAIL_DOMAIN", "localhost");
    let spool = env_or("PLUME_SPOOL", "/var/lib/plume/spool");
    let identite = identite();
    let host = identite.valeur().cloned().unwrap_or_else(|| lisibilite::HOTE_NON_LU.to_string());
    let folder = env_or("PLUME_MAIL_FOLDER", "*");
    let limit: usize = env_or("PLUME_MAIL_LIMIT", "2000").parse().unwrap_or(2000);
    let max_events: usize = env_or("PLUME_MAIL_MAX_EVENTS", "1000").parse().unwrap_or(1000);
    let state_path = env_or("PLUME_MAIL_STATE", &format!("{spool}/.mail-seen"));
    let pat_file = std::env::var("PLUME_MAIL_PATTERNS").ok().filter(|v| !v.is_empty());

    std::fs::create_dir_all(&spool).ok();
    let patterns = patterns::load(pat_file.as_deref())?;

    // ETAT : messages deja traites (account|folder|fileid) -> scan INCREMENTAL.
    // UN ETAT ABSENT EST LE CAS NOMINAL (premier passage) ; un etat PRESENT et illisible ne l'est pas
    // — le collecteur re-examine alors tout, ce que la dedup du central absorbe, mais l'exploitant
    // doit savoir que son etat incrementiel a disparu. `S36` : le fait est AVOUE, pas devine.
    let (mut seen, etat_illisible): (HashSet<String>, Option<(&'static str, String)>) =
        match std::fs::read_to_string(&state_path) {
            Ok(t) => (t.lines().map(|l| l.to_string()).collect(), None),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (HashSet::new(), None),
            Err(e) => (
                HashSet::new(),
                Some((lisibilite::cause_io(&e), format!("{state_path} : {e}"))),
            ),
        };

    let accounts = maildir::list_account_emails(&root, &domain)?;
    let ts = now();
    let mut events: Vec<serde_json::Value> = Vec::new();
    let mut scanned = 0usize;
    let mut newly_seen: Vec<String> = Vec::new();
    let mut capped = false;
    // `S36` — CE QUE LE PASSAGE N'A PAS PU EXAMINER. Sans ces compteurs, un passage qui n'a rien pu
    // ouvrir se conclut par « 0 alerte », mot pour mot comme un passage ou tout etait sain.
    let mut aveux: Vec<serde_json::Value> = Vec::new();
    let mut comptes_sautes: Vec<String> = Vec::new();
    let mut messages_non_lus = 0usize;
    let mut messages_non_decodes = 0usize;
    let mut points_illisibles = 0usize;

    'outer: for account in &accounts {
        let (mut paths, illisibles) = match maildir::message_paths(&root, account, &folder) {
            Ok(p) => p,
            // UN COMPTE SAUTE EN SILENCE EST UNE BOITE ENTIERE HORS SURVEILLANCE. Le rapport le
            // comptait pourtant parmi les comptes balayes : « 8 comptes, 0 alerte » pouvait vouloir
            // dire « 3 boites jamais ouvertes ». Le saut est conserve (une boite absente ne doit pas
            // emporter les autres), mais il est NOMME.
            Err(e) => {
                comptes_sautes.push(format!("{account} ({e})"));
                continue;
            }
        };
        points_illisibles += illisibles;
        // plus recent d'abord + plafond par compte (borne le cout du 1er run)
        paths.sort_by_cached_key(|(_, p)| std::fs::metadata(p).and_then(|m| m.modified()).ok());
        paths.reverse();
        paths.truncate(limit);

        for (fname, path) in paths {
            let fileid = path.file_name().and_then(|s| s.to_str()).unwrap_or("?").to_string();
            let key = format!("{account}|{fname}|{fileid}");
            if seen.contains(&key) {
                continue; // deja traite
            }
            if events.len() >= max_events {
                capped = true;
                break 'outer; // on laisse le reste NON-vu -> prochain run (pas de flood)
            }

            // `S36` — LE MARQUEUR SUIT L'EXAMEN, IL NE LE PRECEDE PLUS.
            //
            // LE DEFAUT FERME ICI. Le message etait marque « vu » AVANT d'etre lu ; si la lecture
            // echouait, un `continue` muet passait au suivant. Le message n'avait donc jamais ete
            // examine, ne le serait plus JAMAIS (il est « vu »), et le passage se concluait par
            // « 0 alerte ». Un message rendu illisible — droits, disque, fichier retire sous les
            // pieds du scanner — sortait ainsi du perimetre de detection sans un mot.
            let raw = match maildir::read_capped(&path) {
                Ok(r) => r,
                Err(e) => {
                    // NON marque vu : le prochain passage reessaiera. La dedup du central absorbe
                    // une eventuelle double alerte ; l'inverse — un message jamais examine — ne se
                    // rattrape pas.
                    messages_non_lus += 1;
                    // La cause SYSTEME est recuperee quand elle est encore la ; sinon on reste sur
                    // `source_illisible`, qui est le mot honnete pour « la lecture a echoue et on ne
                    // sait pas mieux ». On n'invente pas une precision qu'on n'a pas.
                    let cause = e
                        .downcast_ref::<std::io::Error>()
                        .map(lisibilite::cause_io)
                        .unwrap_or(lisibilite::CAUSE_SOURCE_ILLISIBLE);
                    eprintln!(
                        "collector-mail: message NON LU ({cause}) : {account}/{fname}/{fileid} — {e}"
                    );
                    continue;
                }
            };
            let parsed = maildir::parse_msg(&raw);
            // A partir d'ici le message a ete OUVERT : il est marque vu, examinable ou non.
            newly_seen.push(key.clone());
            seen.insert(key);
            scanned += 1;

            // UN MESSAGE QUE LE DECODEUR REFUSE N'EST PAS UN MESSAGE SAIN. Ses champs sont tous
            // vides, donc aucun motif ne peut s'y appliquer : « aucune alerte » serait la reponse a
            // un message qu'on n'a pas su ouvrir — et un expediteur peut PROVOQUER cette reponse.
            // Il produit donc un evenement a lui, qui pointe le message pour un analyste.
            if !parsed.decode {
                messages_non_decodes += 1;
                events.push(serde_json::json!({
                    "ts": mtime_epoch(&path),
                    "source": "mail",
                    "category": "mail",
                    "severity": 2,
                    "message": format!(
                        "mail NON EXAMINE : {account}/{fname} — le decodeur a refuse le message \
                         ({} octets) ; AUCUN motif de detection n'a pu s'y appliquer",
                        raw.len()
                    ),
                    "dedup": format!("mail:non-decode:{account}:{fname}:{fileid}"),
                    "fields": {
                        "account": account, "folder": fname, "fileid": fileid,
                        "scan_status": "non-examine",
                        "cause": lisibilite::CAUSE_FORME_INCONNUE,
                        "verdict": lisibilite::VERDICT_ILLISIBLE,
                    },
                }));
                continue;
            }
            let urls = url_extract::extract_urls(parsed.html_body.as_deref(), parsed.text_body.as_deref());
            let hits = patterns::scan_message(&parsed, &raw, &urls, &patterns);
            if hits.is_empty() {
                continue;
            }
            // 1 event MINIMAL par message flagge (severite = max ; pas de body)
            let top = hits.iter().max_by_key(|h| h.severity).unwrap();
            let ids: Vec<&str> = hits.iter().map(|h| h.pattern_id.as_str()).collect();
            let msgid = if parsed.message_id.is_empty() { fileid.clone() } else { parsed.message_id.clone() };
            let subj: String = parsed.subject.chars().take(160).collect();
            let from: String = parsed.from.chars().take(160).collect();
            let message = format!(
                "mail {}: {} -> {}/{} | subj: {} | msgid: {} | patterns: {} | sample: {}",
                top.category, from, account, fname, subj, msgid, ids.join(","), top.sample
            );
            events.push(serde_json::json!({
                "ts": mtime_epoch(&path),
                "source": "mail",
                "category": top.category,
                "severity": top.severity,
                "message": message,
                "dedup": format!("mail:{account}:{fname}:{fileid}"),
                // champs structures -> le central peut cibler le message (body-fetch) sans parser le texte
                "fields": {
                    "account": account, "folder": fname, "fileid": fileid,
                    "msgid": msgid, "patterns": ids.join(","), "sample": top.sample
                },
            }));
        }
    }

    // persiste l'etat (incremental) meme s'il n'y a pas d'event
    if !newly_seen.is_empty() {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&state_path) {
            let _ = f.write_all(newly_seen.join("\n").as_bytes());
            let _ = f.write_all(b"\n");
            let _ = std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o640));
        }
    }

    // `S36` — LES AVEUX DU PASSAGE, AVANT TOUTE CONCLUSION. Chacun emprunte le canal
    // d'indisponibilite deja livre (`category=config`, `collect_status=unavailable`), sur lequel la
    // regle livree ALERTE deja : aucune regle, aucune categorie, aucune metrique nouvelle. Un aveu
    // par CAUSE, pas un par message — le detail par message vit dans les evenements ci-dessus.
    if let Some((cause, detail)) = &etat_illisible {
        aveux.push(lisibilite::event_indisponibilite(
            "mail",
            lisibilite::RAISON_SOURCE_ABSENTE,
            cause,
            &format!("etat incrementiel present mais illisible : {detail} — tout est re-examine"),
            ts as i64,
        ));
    }
    if !comptes_sautes.is_empty() {
        aveux.push(lisibilite::event_indisponibilite(
            "mail",
            lisibilite::RAISON_SOURCE_ABSENTE,
            lisibilite::CAUSE_SOURCE_ABSENTE,
            &format!(
                "{} compte(s) sur {} n'ont PAS pu etre ouverts : {} — leurs messages ne sont pas \
                 analyses, et le compte de comptes balayes ne le disait pas",
                comptes_sautes.len(),
                accounts.len(),
                comptes_sautes.join(" ; ")
            ),
            ts as i64,
        ));
    }
    if messages_non_lus > 0 || points_illisibles > 0 {
        aveux.push(lisibilite::event_indisponibilite(
            "mail",
            lisibilite::RAISON_SOURCE_ABSENTE,
            lisibilite::CAUSE_SOURCE_REFUSEE,
            &format!(
                "{messages_non_lus} message(s) non lu(s) et {points_illisibles} point(s)                  d'enumeration illisible(s) : ces messages n'ont PAS ete analyses (ils ne sont pas                  marques vus, le prochain passage reessaiera)"
            ),
            ts as i64,
        ));
    }
    if messages_non_decodes > 0 {
        aveux.push(lisibilite::event_indisponibilite(
            "mail",
            lisibilite::RAISON_SOURCE_ABSENTE,
            lisibilite::CAUSE_FORME_INCONNUE,
            &format!(
                "{messages_non_decodes} message(s) refuse(s) par le decodeur : AUCUN motif n'a pu                  s'y appliquer (un par evenement `scan_status=non-examine`)"
            ),
            ts as i64,
        ));
    }
    if let lisibilite::Lecture::Illisible { cause, detail } = &identite {
        aveux.push(lisibilite::event_indisponibilite(
            lisibilite::HOTE_NON_LU,
            lisibilite::RAISON_CONFIG_ABSENTE,
            cause,
            &format!(
                "identite de l'hote non lue : {detail}. Les evenements de ce collecteur partent sous \
                 un VERDICT et non sous un nom ; pose PLUME_HOST=<nom>."
            ),
            ts as i64,
        ));
    }
    if !aveux.is_empty() {
        let n = aveux.len();
        let env = serde_json::json!({ "ts": ts, "host": host, "kind": "events", "events": aveux });
        match write_spool(&spool, &format!("mail-availability-{ts}-{}", std::process::id()), &env) {
            Ok(_) => eprintln!("collector-mail: {n} aveu(x) d'indisponibilite publie(s)"),
            Err(e) => eprintln!("collector-mail: aveux NON ecrits ({e}) — les trous restent invisibles"),
        }
    }

    if events.is_empty() {
        eprintln!(
            "collector-mail: {} compte(s) dont {} ouvert(s), {scanned} message(s) examine(s), 0 alerte{}",
            accounts.len(),
            accounts.len() - comptes_sautes.len(),
            if capped { " (cap atteint)" } else { "" }
        );
        return Ok(());
    }

    // enveloppe spool (meme format que les autres collecteurs) -> ship.sh la poste
    let n_ev = events.len();
    let env = serde_json::json!({ "ts": ts, "host": host, "kind": "events", "events": events });
    let dst = write_spool(&spool, &format!("mail-{ts}"), &env)?;
    eprintln!(
        "collector-mail: {} compte(s) dont {} ouvert(s), {scanned} message(s) examine(s), {n_ev} alerte(s) -> {dst}{}",
        accounts.len(),
        accounts.len() - comptes_sautes.len(),
        if capped { " (cap atteint)" } else { "" }
    );
    Ok(())
}
