//! LA LIMITE DE GROUPE DE CONTRÔLE QUI TUE LE PROCESSUS, LUE SUR LE SYSTÈME — jamais supposée.
//!
//! Module FEUILLE extrait de `sqlite_plafond` par déplacement pur (`P7.18-a`) : il ne dépend que de la
//! bibliothèque standard et ne sait rien du plafond qu'on lui confronte. Il rend trois verdicts
//! exclusifs (`LimiteCgroup`) ; la CONFRONTATION au budget de SQLite (`Couverture`) reste dans
//! `sqlite_plafond`, qui est son seul consommateur. Les chemins réels (`/sys/fs/cgroup`,
//! `/proc/self/cgroup`) ne sont nommés qu'ici, dans `limite_cgroup()` ; tout le reste travaille sur une
//! racine passée en paramètre, et les tests qui l'exercent vivent dans `sqlite_plafond::plafond_tests`.

/// CE QUE L'INTERFACE DE GROUPES DE CONTRÔLE A DIT — trois verdicts EXCLUSIFS, et c'est LA correction que
/// ce bloc porte. « il n'y a PAS de limite » et « la lecture N'A PAS ABOUTI » étaient tous deux rendus `None`,
/// donc rendus par la même phrase « NON LISIBLE ». La confusion coûte des DEUX côtés : sur un hôte sans
/// limite — le cas ordinaire d'un service système natif sans `MemoryMax=` — la bannière accusait
/// l'instrument alors que l'instrument allait bien ; et sur un hôte où le chemin a changé de forme, elle
/// laissait croire à une propriété du déploiement alors que rien n'avait été mesuré. Un `match` exhaustif
/// (aucun bras `_`) interdit qu'un quatrième cas se glisse silencieusement dans l'un des trois.
#[derive(Debug, PartialEq)]
pub(crate) enum LimiteCgroup {
    /// Une limite EXISTE et vaut N octets : c'est ce nombre-là qui déclenche l'OOM-kill.
    Octets(i64),
    /// L'interface a été LUE et COMPRISE, et elle dit qu'il n'y a AUCUNE limite (v2 : le mot `max` ;
    /// v1 : la sentinelle « illimitée »). L'instrument va bien — c'est le déploiement qui ne borne rien.
    Aucune,
    /// L'interface n'a pas pu être lue, ou sa forme n'a pas été reconnue. Porte CE QUI A ÉTÉ TENTÉ : un
    /// aveu qui ne nomme pas le chemin essayé n'est pas actionnable.
    Illisible(String),
}

/// Au-delà de ce seuil, un nombre n'est plus un budget : c'est la façon dont cgroup v1 écrit « pas de
/// limite » (`i64::MAX` arrondi au multiple de page, et `u64::MAX` sur d'autres configurations — cette
/// seconde forme ne rentrait même pas dans un `i64`, donc elle était comptée comme illisible). 1 Pio est
/// des ordres de grandeur au-dessus de toute limite qu'un exploitant pose réellement ; publier « plafond
/// de 8 Eio » serait pire que se taire.
const SEUIL_SANS_LIMITE: u128 = 1 << 50;

/// LA FORME DU CONTENU D'UN FICHIER DE LIMITE — PURE, donc exerçable sur chaque variante connue sans
/// aucun groupe de contrôle sous la main. Les deux versions de l'interface écrivent « pas de limite »
/// différemment (v2 : le mot `max` ; v1 : un entier énorme) et c'est le SEUL endroit qui le sait.
/// Une forme qui n'est ni l'une ni l'autre rend `Illisible` — jamais `Aucune` : confondre les deux est
/// précisément le défaut fermé ici.
pub(crate) fn valeur_limite(txt: &str) -> LimiteCgroup {
    let t = txt.trim();
    if t.eq_ignore_ascii_case("max") {
        return LimiteCgroup::Aucune;
    }
    match t.parse::<u128>() {
        Ok(n) if n >= SEUIL_SANS_LIMITE => LimiteCgroup::Aucune,
        // `n < SEUIL_SANS_LIMITE` (2^50) : la conversion ne peut pas déborder un i64.
        Ok(n) => LimiteCgroup::Octets(n as i64),
        Err(_) => LimiteCgroup::Illisible(format!(
            "forme non reconnue ({:?})",
            t.chars().take(24).collect::<String>()
        )),
    }
}

/// LA LIGNÉE cgroup v2, isolée. Rend `None` quand AUCUN fichier de limite n'a pu être lu — c'est-à-dire
/// exactement le cas où le repli v1 a encore quelque chose à dire ; tout autre cas est déjà un verdict.
///
/// UN `memory.max` ABSENT À UN NIVEAU N'EST PAS UNE PANNE : le noyau n'expose pas le contrôleur mémoire
/// sur le cgroup RACINE, donc la dernière itération de la remontée ne trouve normalement rien. Un
/// `memory.max` PRÉSENT dont la forme n'est pas reconnue, lui, EN EST une, et il remonte au lieu d'être
/// avalé par le `if let Ok(...)` qui l'ignorait.
///
/// FAIL-CLOSED SUR UNE LIGNÉE PARTIELLEMENT LISIBLE : si un niveau est incompris, on ne conclut PAS sur le
/// minimum des autres. Un niveau qu'on n'a pas su lire peut porter une limite PLUS SERRÉE, et annoncer
/// « protégé » sur la foi des niveaux lisibles serait revendiquer une couverture qu'on n'a pas établie.
fn lignee_v2(racine: &std::path::Path, chemin: &str) -> Option<LimiteCgroup> {
    let mut ici = racine.join(chemin.trim_start_matches('/'));
    let (mut mini, mut lus, mut incomprises) = (None::<i64>, 0usize, Vec::new());
    loop {
        let f = ici.join("memory.max");
        if let Ok(v) = std::fs::read_to_string(&f) {
            match valeur_limite(&v) {
                LimiteCgroup::Octets(n) => {
                    lus += 1;
                    mini = Some(mini.map_or(n, |m: i64| m.min(n)));
                }
                LimiteCgroup::Aucune => lus += 1,
                LimiteCgroup::Illisible(quoi) => incomprises.push(format!("{} : {quoi}", f.display())),
            }
        }
        if ici == racine {
            break;
        }
        match ici.parent() {
            Some(p) if p.starts_with(racine) => ici = p.to_path_buf(),
            _ => break,
        }
    }
    if !incomprises.is_empty() {
        return Some(LimiteCgroup::Illisible(format!(
            "{}{}",
            incomprises.join(" ; "),
            mini.map_or(String::new(), |n| format!(
                " (un niveau lisible annonce {n} o, mais un niveau ILLISIBLE peut être plus serré)"
            ))
        )));
    }
    if let Some(n) = mini {
        return Some(LimiteCgroup::Octets(n));
    }
    if lus > 0 {
        return Some(LimiteCgroup::Aucune);
    }
    None
}

/// LA LIMITE QUI NOUS TUE, LUE SUR LE SYSTÈME — jamais supposée. PARAMÉTRÉE sur ses deux chemins, et
/// c'est ce qui la rend EXERÇABLE : les tests lui présentent une arborescence fabriquée dans un
/// temporaire possédé, donc chaque forme connue de l'interface se joue sans dépendre de l'hôte qui
/// exécute la suite. Un test qui n'aurait passé que sous conteneur aurait rougi en intégration continue,
/// et un test qui n'aurait passé que sur un hôte sans limite n'aurait rien prouvé du cas conteneurisé.
///
/// LES FORMES RECENSÉES, et pourquoi chacune existe :
///   1. cgroup v2 (hiérarchie unifiée) — `/proc/self/cgroup` porte une ligne `0::<chemin>`. La limite
///      EFFECTIVE est la PLUS PETITE de la lignée : un parent plus serré tue avant la feuille, d'où la
///      remontée jusqu'à la racine du montage.
///   2. cgroup v2, valeur `max` — la limite est ABSENTE, et le fichier le DIT en toutes lettres. C'est le
///      cas ordinaire d'un hôte systemd sans `MemoryMax=`, et c'est celui qui était pris pour une panne.
///   3. cgroup v2, RACINE du montage — la racine n'expose PAS `memory.max` (le noyau ne pose pas le
///      contrôleur mémoire sur le cgroup racine). Un fichier manquant à ce niveau est donc NORMAL, et ne
///      doit pas à lui seul faire conclure à l'illisibilité.
///   4. conteneur AVEC espace de noms de cgroup (défaut des moteurs récents) — `/proc/self/cgroup` rend
///      `0::/` et le montage EST le cgroup du conteneur : `memory.max` à la racine VISIBLE porte alors la
///      limite. C'est l'exception à (3), et c'est pourquoi la racine est lue elle aussi.
///   5. conteneur SANS espace de noms (moteurs anciens, `--cgroupns=host`) — `/proc/self/cgroup` rend le
///      chemin de l'HÔTE alors que le montage est la feuille : le chemin joint n'existe pas, aucun fichier
///      n'est lu. C'est une vraie ABSENCE DE MESURE, et elle doit se dire AVEC le chemin tenté.
///   6. cgroup v1 — aucune ligne `0::` porteuse, et le fichier historique
///      `<racine>/memory/memory.limit_in_bytes`. « Pas de limite » y est un entier énorme, pas un mot.
///   7. hybride v1+v2 — la ligne `0::` existe mais la hiérarchie unifiée ne porte pas le contrôleur
///      mémoire ; aucun `memory.max` n'est trouvé sous la racine v2, et le repli v1 tranche.
///   8. ni l'un ni l'autre (`/proc` masqué, système non Linux) — rien n'est lisible, et on le dit.
pub(crate) fn limite_cgroup_depuis(racine: &std::path::Path, proc_self_cgroup: &std::path::Path) -> LimiteCgroup {
    let mut tentes: Vec<String> = Vec::new();
    match std::fs::read_to_string(proc_self_cgroup) {
        Ok(txt) => match txt.lines().find_map(|l| l.strip_prefix("0::")) {
            Some(chemin) => match lignee_v2(racine, chemin.trim()) {
                Some(verdict) => return verdict,
                None => tentes.push(format!(
                    "aucun memory.max lisible sous {}",
                    racine.join(chemin.trim().trim_start_matches('/')).display()
                )),
            },
            None => tentes.push(format!(
                "{} ne porte aucune ligne `0::` (hiérarchie v1 ou hybride)",
                proc_self_cgroup.display()
            )),
        },
        Err(e) => tentes.push(format!("{} : {e}", proc_self_cgroup.display())),
    }
    let v1 = racine.join("memory").join("memory.limit_in_bytes");
    match std::fs::read_to_string(&v1) {
        Ok(txt) => match valeur_limite(&txt) {
            LimiteCgroup::Illisible(quoi) => tentes.push(format!("{} : {quoi}", v1.display())),
            verdict => return verdict,
        },
        Err(e) => tentes.push(format!("{} : {e}", v1.display())),
    }
    LimiteCgroup::Illisible(tentes.join(" ; "))
}

/// Les chemins RÉELS. Le seul endroit du module qui les nomme — tout le reste travaille sur une racine
/// passée en paramètre, donc s'exerce.
pub(crate) fn limite_cgroup() -> LimiteCgroup {
    limite_cgroup_depuis(
        std::path::Path::new("/sys/fs/cgroup"),
        std::path::Path::new("/proc/self/cgroup"),
    )
}
