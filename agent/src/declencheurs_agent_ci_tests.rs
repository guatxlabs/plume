//! Garde `P10.31-e` : tout fichier HORS de `agent/` que les sources de l'agent lisent (par
//! `include_str!` ou par une chaîne `env!("CARGO_MANIFEST_DIR")…join(…)`) doit figurer dans les
//! `paths` des déclencheurs `push` ET `pull_request` de `.github/workflows/agent-ci.yml`. Sans cela,
//! une divergence venue de ce fichier n'est rejugée qu'au prochain changement de l'agent.
//!
//! GARDE DÉRIVÉE, PAS UNE LISTE : elle découvre les cibles en balayant `agent/src`, donc le prochain
//! `include_str!` hors de la caisse est jugé sans qu'on touche à ce fichier. Un PLANCHER ferme le
//! mode de panne d'un balayage : un parcours cassé qui ne trouve rien et rend vert.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

fn collecter_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collecter_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Normalisation LEXICALE (sans toucher au disque) en chemin relatif à la racine du dépôt, à `/`.
fn relatif_au_depot(racine_depot: &Path, p: &Path) -> Option<String> {
    let mut pile: Vec<String> = Vec::new();
    let rel = p.strip_prefix(racine_depot).ok()?;
    for c in rel.components() {
        match c {
            Component::ParentDir => {
                pile.pop()?;
            }
            Component::Normal(n) => pile.push(n.to_string_lossy().into_owned()),
            _ => {}
        }
    }
    Some(pile.join("/"))
}

/// Les littéraux de chaîne qui suivent `motif` jusqu'au premier `)` fermant (forme `motif"x")`).
fn litteraux_apres<'a>(texte: &'a str, motif: &str) -> Vec<&'a str> {
    let mut v = Vec::new();
    let mut reste = texte;
    while let Some(i) = reste.find(motif) {
        reste = &reste[i + motif.len()..];
        if let Some(fin) = reste.find('"') {
            v.push(&reste[..fin]);
        }
    }
    v
}

/// Texte sans les lignes de commentaire (un bandeau qui CITE un `include_str!` n'en est pas un).
fn sans_commentaires(src: &str) -> String {
    src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n")
}

/// Cibles hors de `agent/` lues par les sources de l'agent, en chemins relatifs au dépôt.
fn cibles_hors_caisse(caisse: &Path, fichiers: &[PathBuf]) -> BTreeSet<String> {
    let depot = caisse.parent().expect("agent/ a un parent");
    let moi = Path::new(file!()).file_name().unwrap().to_owned();
    let mut cibles = BTreeSet::new();
    for f in fichiers {
        if f.file_name() == Some(moi.as_os_str()) {
            continue; // ce fichier porte les motifs comme données
        }
        let src = sans_commentaires(&std::fs::read_to_string(f).unwrap_or_default());
        let dir = f.parent().unwrap();
        let mut lus: Vec<PathBuf> =
            litteraux_apres(&src, "include_str!(\"").into_iter().map(|l| dir.join(l)).collect();
        let mut reste = src.as_str();
        while let Some(i) = reste.find("env!(\"CARGO_MANIFEST_DIR\")") {
            reste = &reste[i + 1..];
            let enonce = &reste[..reste.find(';').unwrap_or(reste.len())];
            let mut p = caisse.to_path_buf();
            for j in litteraux_apres(enonce, ".join(\"") {
                p = p.join(j);
            }
            lus.push(p);
        }
        for p in lus {
            if let Some(r) = relatif_au_depot(depot, &p) {
                if !r.starts_with("agent/") {
                    cibles.insert(r);
                }
            }
        }
    }
    cibles
}

/// Les entrées `paths:` du déclencheur `evenement` (`push` ou `pull_request`) sous `on:`.
fn chemins_du_declencheur(flux: &str, evenement: &str) -> Vec<String> {
    let mut dans_on = false;
    let mut dans_evt = false;
    let mut dans_paths = false;
    let mut v = Vec::new();
    for brute in flux.lines() {
        let l = brute.trim_end_matches('\r');
        let nu = l.trim_start();
        if nu.is_empty() || nu.starts_with('#') {
            continue;
        }
        let indent = l.len() - nu.len();
        if indent == 0 {
            dans_on = nu == "on:";
            dans_evt = false;
            dans_paths = false;
            continue;
        }
        if !dans_on {
            continue;
        }
        if indent == 2 {
            dans_evt = nu == format!("{evenement}:");
            dans_paths = false;
        } else if dans_evt && indent == 4 {
            dans_paths = nu == "paths:";
        } else if dans_evt && dans_paths && nu.starts_with("- ") {
            v.push(nu[2..].trim().trim_matches('"').to_string());
        }
    }
    v
}

fn couvert(chemin: &str, motifs: &[String]) -> bool {
    motifs.iter().any(|m| match m.strip_suffix("/**") {
        Some(pref) => chemin.starts_with(&format!("{pref}/")),
        None => m == chemin,
    })
}

#[test]
fn chaque_fichier_lu_hors_de_la_caisse_declenche_agent_ci() {
    let caisse = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut fichiers = Vec::new();
    collecter_rs(&caisse.join("src"), &mut fichiers);
    assert!(fichiers.len() >= 15, "plancher : {} fichier(s) .rs balayé(s) — parcours cassé", fichiers.len());
    let cibles = cibles_hors_caisse(caisse, &fichiers);
    // 4 cibles MESURÉES le 2026-10-07 ; le plancher est plus bas (retirer une lecture est de la routine).
    assert!(
        cibles.len() >= 2 && cibles.contains("collectors/journal.sh"),
        "plancher : cibles trouvées {cibles:?} — le balayage ne voit plus les include_str! hors de la caisse"
    );
    // Lu à l'exécution (pas include_str!) : le flux est jugé tel qu'il est sur le disque au moment du test.
    let chemin_flux = caisse.join("..").join(".github").join("workflows").join("agent-ci.yml");
    let flux = std::fs::read_to_string(&chemin_flux)
        .unwrap_or_else(|e| panic!("flux {} illisible ({e}) : la garde ne peut pas conclure", chemin_flux.display()));
    for evt in ["push", "pull_request"] {
        let motifs = chemins_du_declencheur(&flux, evt);
        assert!(couvert("agent/src/main.rs", &motifs), "lecture du flux cassée : {evt}.paths = {motifs:?}");
        let manquants: Vec<&String> = cibles.iter().filter(|c| !couvert(c, &motifs)).collect();
        assert!(
            manquants.is_empty(),
            "agent-ci.yml on.{evt}.paths ne couvre pas {manquants:?}, lu(s) par agent/src : un changement \
             de ce(s) fichier(s) ne rejouerait pas les tests de l'agent"
        );
    }
}
