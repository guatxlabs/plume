//! Témoins `P10.31-a` de la SONDE `--output-fields` : c'est la porte qui peut couper la
//! minimisation, elle est donc EXERCÉE (et pas seulement la ligne de commande qu'elle conditionne).
//!
//! Le programme lancé est un exécutable fabriqué qui joue `journalctl` : il rend, sonde après sonde,
//! les codes qu'on lui écrit (0 = option supportée, 1 = option inconnue, avec le message d'erreur
//! d'un vieux systemd), consigne la ligne de commande de chaque lot et écrit une ligne journald. Le
//! verdict ne dépend donc pas du systemd de la machine qui joue les témoins. Comme un vrai systemd
//! < 236, il ne refuse QUE si `--output-fields=` figure dans les arguments : une sonde qui
//! oublierait l'option serait acceptée, et les témoins le verraient. L'aveu passe par un
//! enregistreur (on prouve qu'il est ÉMIS, et combien de fois) ; un témoin dédié rejoue le chemin de
//! service (`new()` puis stderr) dans un processus enfant.

use super::*;
use crate::config::JournaldCfg;
use crate::lisibilite::RAISON_DEPENDANCE_ABSENTE;
use std::cell::RefCell;
use std::path::PathBuf;

thread_local! {
    static AVEUX: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn enregistrer(aveu: &str) {
    AVEUX.with(|a| a.borrow_mut().push(aveu.to_string()));
}

fn aveux() -> Vec<String> {
    AVEUX.with(|a| a.borrow().clone())
}

/// Répertoire propre au témoin (pid + nom : deux témoins concurrents ne se partagent rien).
fn atelier(nom: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("plume-agent-sonde-{}-{nom}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Fabrique le faux `journalctl` : `codes` = un code de sortie par sonde successive (le dernier se
/// répète). Un code non nul ne s'applique qu'en présence de `--output-fields=` (c'est l'option que
/// le vieux systemd ne connaît pas) ; sans elle, la sonde réussit. Rend le chemin du programme.
fn faux_journalctl(d: &PathBuf, codes: &[i32]) -> String {
    let codes_txt: String = codes.iter().map(|c| format!("{c}\n")).collect();
    std::fs::write(d.join("codes"), codes_txt).unwrap();
    let dir = d.display();
    let script = format!(
        r#"#!/bin/sh
option=0
for a in "$@"; do
  case "$a" in --output-fields=*) option=1 ;; esac
done
for a in "$@"; do
  if [ "$a" = "-n0" ]; then
    n=$(cat '{dir}/sondes' 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > '{dir}/sondes'
    code=$(sed -n "${{n}}p" '{dir}/codes'); [ -n "$code" ] || code=$(tail -n1 '{dir}/codes')
    [ "$option" = 1 ] || exit 0
    [ "$code" = 0 ] || echo "journalctl: unrecognized option '--output-fields=MESSAGE'" >&2
    exit "$code"
  fi
done
printf '%s\n' "$*" >> '{dir}/lots'
echo '{{"__CURSOR":"s=x;i=1","__REALTIME_TIMESTAMP":"1700000000000000","_COMM":"sudo","MESSAGE":"m"}}'
"#
    );
    let prog = d.join("journalctl");
    std::fs::write(&prog, script).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();
    prog.display().to_string()
}

fn cfg_auth() -> JournaldCfg {
    JournaldCfg { id: "auth".into(), comm: vec!["sudo".into()], units: vec![], since: "15min".into() }
}

/// Lecteur branché sur le faux `journalctl`, avec l'enregistreur d'aveux.
fn lecteur_sur_faux_journalctl(d: &PathBuf, codes: &[i32]) -> JournaldReader {
    let mut r = JournaldReader::new(cfg_auth(), "h".into());
    r.programme = faux_journalctl(d, codes);
    r.avouer = enregistrer;
    r
}

fn lots(d: &PathBuf) -> Vec<String> {
    std::fs::read_to_string(d.join("lots")).unwrap_or_default().lines().map(str::to_string).collect()
}

fn sondes(d: &PathBuf) -> u32 {
    std::fs::read_to_string(d.join("sondes")).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

fn option() -> String {
    format!("--output-fields={JRNL_FIELDS}")
}

#[test]
fn sonde_acceptee_restreint_le_lot_sans_aveu() {
    let d = atelier("acceptee");
    let mut r = lecteur_sur_faux_journalctl(&d, &[0]);
    let rel = r.next_batch(10);
    assert!(rel.lisibilite.est_lue(), "lot lu attendu");
    assert_eq!(rel.records.len(), 1);
    assert_eq!(sondes(&d), 1, "la sonde doit avoir été LANCÉE avant le lot");
    assert_eq!(r.output_fields, Some(true), "sonde rendue 0 -> support acquis");
    let l = lots(&d);
    assert!(l.len() == 1 && l[0].contains(&option()), "lot non restreint malgré le support : {l:?}");
    assert!(aveux().is_empty(), "aucun aveu quand l'option est supportée : {:?}", aveux());
    // Le support est acquis : pas de nouvelle sonde au lot suivant.
    let _ = r.next_batch(10);
    assert_eq!(sondes(&d), 1, "support acquis -> sonde non rejouée");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn sonde_refusee_replie_et_avoue_une_seule_fois() {
    let d = atelier("refusee");
    let mut r = lecteur_sur_faux_journalctl(&d, &[1]);
    let rel = r.next_batch(10);
    assert!(rel.lisibilite.est_lue(), "le repli lit quand même le journal");
    assert_eq!(r.output_fields, Some(false));
    let _ = r.next_batch(10);
    let l = lots(&d);
    assert_eq!(l.len(), 2);
    assert!(l.iter().all(|x| !x.contains("--output-fields")), "repli -> forme complète : {l:?}");
    assert_eq!(sondes(&d), 2, "un refus est re-sondé à chaque lot");
    let a = aveux();
    assert_eq!(a.len(), 1, "l'aveu est émis une fois, à l'entrée dans le repli : {a:?}");
    assert!(a[0].contains(AVEU_SANS_OUTPUT_FIELDS), "aveu sans le texte attendu : {a:?}");
    assert!(a[0].contains("[journald:auth]"), "aveu sans la source : {a:?}");
    assert!(a[0].contains("unrecognized option"), "aveu sans l'erreur de la sonde : {a:?}");
    assert!(a[0].contains("exit status: 1"), "aveu sans le statut de la sonde : {a:?}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn refus_passager_ne_coupe_pas_la_minimisation() {
    let d = atelier("passager");
    let mut r = lecteur_sur_faux_journalctl(&d, &[1, 0]);
    let _ = r.next_batch(10);
    assert_eq!(r.output_fields, Some(false));
    let _ = r.next_batch(10);
    assert_eq!(r.output_fields, Some(true), "la sonde suivante a réussi -> minimisation rétablie");
    let l = lots(&d);
    assert_eq!(l.len(), 2);
    assert!(!l[0].contains("--output-fields") && l[1].contains(&option()), "lots : {l:?}");
    assert_eq!(aveux().len(), 1);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn journalctl_introuvable_n_est_pas_un_systemd_ancien() {
    let d = atelier("introuvable");
    let mut r = lecteur_sur_faux_journalctl(&d, &[0]);
    r.programme = d.join("absent").display().to_string();
    let rel = r.next_batch(10);
    assert!(!rel.lisibilite.est_lue(), "programme absent -> illisible, pas un lot vide");
    assert_eq!(rel.raison, RAISON_DEPENDANCE_ABSENTE);
    assert_eq!(r.output_fields, None, "un programme introuvable ne tranche rien sur le support");
    assert!(aveux().is_empty(), "pas de faux aveu « systemd < 236 » : {:?}", aveux());
    let _ = std::fs::remove_dir_all(&d);
}

/// Variable qui fait jouer à ce même binaire de test le rôle de l'agent EN SERVICE.
const ENFANT_EN_SERVICE: &str = "PLUME_AGENT_TEMOIN_AVEU_EN_SERVICE";

/// L'aveu du repli doit sortir sur le stderr de l'agent EN SERVICE : lecteur construit par `new()`
/// (rien de remplacé, hors le programme lancé), stderr réel. Les autres témoins branchent un
/// enregistreur, ils ne voient donc ni le branchement de `new()` ni `eprintln!`. Ce témoin se
/// relance lui-même comme processus enfant, sans capture de sortie, et lit le stderr de l'enfant.
#[test]
fn aveu_en_service_part_sur_le_stderr_de_l_agent() {
    if std::env::var_os(ENFANT_EN_SERVICE).is_some() {
        let d = atelier("service");
        let mut r = JournaldReader::new(cfg_auth(), "h".into());
        r.programme = faux_journalctl(&d, &[1]);
        let rel = r.next_batch(10);
        let _ = std::fs::remove_dir_all(&d);
        assert!(rel.lisibilite.est_lue(), "le repli lit quand même le journal");
        return;
    }
    let nom = format!("{}::aveu_en_service_part_sur_le_stderr_de_l_agent", module_path!());
    let nom = nom.split_once("::").map(|(_, n)| n).unwrap_or(&nom).to_string();
    let sortie = std::process::Command::new(std::env::current_exe().unwrap())
        .args([nom.as_str(), "--exact", "--nocapture", "--test-threads=1"])
        .env(ENFANT_EN_SERVICE, "1")
        .output()
        .expect("relance du binaire de test impossible");
    let stdout = String::from_utf8_lossy(&sortie.stdout);
    let stderr = String::from_utf8_lossy(&sortie.stderr);
    assert!(sortie.status.success(), "enfant en échec ({}) : {stdout}\n{stderr}", sortie.status);
    assert!(stdout.contains("1 passed"), "l'enfant n'a pas joué le témoin {nom} : {stdout}");
    let aveux: Vec<&str> = stderr.lines().filter(|l| l.contains(AVEU_SANS_OUTPUT_FIELDS)).collect();
    assert_eq!(aveux.len(), 1, "aveu absent du stderr de l'agent en service : {stderr}");
    assert!(aveux[0].contains("[journald:auth]") && aveux[0].contains("unrecognized option"), "{aveux:?}");
}
