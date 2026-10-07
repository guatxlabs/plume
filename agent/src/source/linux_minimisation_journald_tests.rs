//! Témoins `P10.31-a` : l'agent restreint `journalctl -o json` aux champs lus (même liste que
//! `collectors/journal.sh`), avoue le repli systemd < 236, et `to_event` n'a besoin d'aucun champ
//! retiré.

use super::*;
use crate::config::JournaldCfg;

fn lecteur() -> JournaldReader {
    JournaldReader::new(
        JournaldCfg { id: "auth".into(), comm: vec!["sudo".into()], units: vec![], since: "15min".into() },
        "h".into(),
    )
}

/// Champs que journald émet TOUJOURS, même sous `--output-fields` (champs d'adresse).
const CHAMPS_ADRESSE: &[&str] =
    &["__CURSOR", "__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP", "_BOOT_ID", "__SEQNUM", "__SEQNUM_ID"];

#[test]
fn args_restreignent_journalctl_aux_champs_lus() {
    let a = lecteur().args();
    let attendu = format!("--output-fields={JRNL_FIELDS}");
    assert!(a.contains(&attendu), "journalctl sans --output-fields : _CMDLINE expédié ({a:?})");
    assert!(!JRNL_FIELDS.split(',').any(|f| f == "_CMDLINE"), "_CMDLINE ne doit jamais être demandé");
}

#[test]
fn liste_identique_a_celle_du_capteur_shell() {
    let sh = include_str!("../../../collectors/journal.sh");
    let ligne = sh
        .lines()
        .find(|l| l.starts_with("JRNL_FIELDS='"))
        .expect("JRNL_FIELDS absent de collectors/journal.sh");
    assert_eq!(ligne, format!("JRNL_FIELDS='{JRNL_FIELDS}'"), "agent et capteur shell divergent");
}

/// La ligne de commande seule. L'ÉMISSION de l'aveu est prouvée par la sonde exercée
/// (`linux_sonde_output_fields_tests.rs`), pas par le texte d'une constante.
#[test]
fn repli_sans_option_rend_la_forme_complete() {
    let mut r = lecteur();
    r.output_fields = Some(false);
    let a = r.args();
    assert!(!a.iter().any(|x| x.starts_with("--output-fields")), "option refusée -> forme complète");
    // Supportée explicitement -> restreinte.
    r.output_fields = Some(true);
    assert!(r.args().iter().any(|x| x.starts_with("--output-fields=")));
}

#[test]
fn to_event_n_a_besoin_d_aucun_champ_retire() {
    let complet = r#"{"__CURSOR":"s=abc;i=7;b=2","__REALTIME_TIMESTAMP":"1700000000000000","__MONOTONIC_TIMESTAMP":"99","_BOOT_ID":"b","__SEQNUM":"7","__SEQNUM_ID":"q","_COMM":"sudo","_PID":"4242","_UID":"1000","PRIORITY":"5","_SYSTEMD_UNIT":"session-1.scope","_HOSTNAME":"web01","MESSAGE":"guat : TTY=pts/0 ; COMMAND=/usr/bin/env PLUME_TOKEN=leurre","_CMDLINE":"sudo env PLUME_TOKEN=leurre","_EXE":"/usr/bin/sudo","_GID":"1000","_CAP_EFFECTIVE":"1ff","_AUDIT_SESSION":"3","_TRANSPORT":"syslog","SYSLOG_IDENTIFIER":"sudo","_SOURCE_REALTIME_TIMESTAMP":"1"}"#;
    let j: Value = serde_json::from_str(complet).unwrap();
    let garde: Vec<&str> = JRNL_FIELDS.split(',').chain(CHAMPS_ADRESSE.iter().copied()).collect();
    let reduit: serde_json::Map<String, Value> =
        j.as_object().unwrap().iter().filter(|(k, _)| garde.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
    assert!(!reduit.contains_key("_CMDLINE"));
    let reduit = Value::Object(reduit).to_string();
    let e_complet = journald_to_event(complet, "h").expect("event");
    let e_reduit = journald_to_event(&reduit, "h").expect("event");
    assert_eq!(e_reduit, e_complet, "to_event lit un champ que --output-fields retire");
    assert_eq!(json_cursor(&reduit), json_cursor(complet));
}

/// Le VRAI consommateur : `ingest_journal_lines` du démon (et non le miroir `journald_to_event`,
/// qui ne lit ni `_SYSTEMD_UNIT` ni `_HOSTNAME`). Les champs qu'il lit doivent être EXACTEMENT ceux
/// que l'agent demande, plus les deux champs d'adresse que journald émet toujours : un champ lu mais
/// non demandé arriverait vide, un champ demandé mais non lu partirait pour rien.
#[test]
fn champs_lus_par_le_demon_egalent_les_champs_demandes() {
    let lus = champs_lus_par_ingest_journal_lines(include_str!("../../../daemon/src/ingest/mod.rs"));
    let envoyee = lecteur().args().into_iter().find_map(|a| a.strip_prefix("--output-fields=").map(str::to_string));
    let envoyee = envoyee.expect("journalctl sans --output-fields");
    let mut attendus: std::collections::BTreeSet<String> = envoyee.split(',').map(str::to_string).collect();
    attendus.insert("__CURSOR".into());
    attendus.insert("__REALTIME_TIMESTAMP".into());
    assert_eq!(lus, attendus, "champs lus par le démon != champs demandés par l'agent");
}

/// La jambe Windows d'agent-ci extrait en CRLF (`core.autocrlf=true` sur les runners, aucun
/// `.gitattributes eol`) : `include_str!` y rend `\r\n`. L'analyse doit trouver les mêmes champs.
#[test]
fn champs_lus_par_le_demon_identiques_sur_une_extraction_crlf() {
    let lf = include_str!("../../../daemon/src/ingest/mod.rs").replace("\r\n", "\n");
    let crlf = lf.replace('\n', "\r\n");
    assert_eq!(champs_lus_par_ingest_journal_lines(&crlf), champs_lus_par_ingest_journal_lines(&lf));
}

/// Champs que lit `ingest_journal_lines` (`j.get("…")`, `j["…"]`), fins de ligne normalisées.
fn champs_lus_par_ingest_journal_lines(src: &str) -> std::collections::BTreeSet<String> {
    let src = src.replace("\r\n", "\n");
    let debut = src.find("fn ingest_journal_lines(").expect("ingest_journal_lines introuvable");
    let corps = &src[debut..];
    let corps = &corps[..corps.find("\n}\n").expect("fin de ingest_journal_lines introuvable")];
    // Sans blancs : `j\n    .get("…")` (chaîne d'appels sur plusieurs lignes) compte aussi.
    let corps: String = corps.chars().filter(|c| !c.is_whitespace()).collect();
    let mut lus = std::collections::BTreeSet::new();
    for motif in ["j.get(\"", "j[\""] {
        for (i, _) in corps.match_indices(motif) {
            let reste = &corps[i + motif.len()..];
            lus.insert(reste[..reste.find('"').unwrap()].to_string());
        }
    }
    lus
}
