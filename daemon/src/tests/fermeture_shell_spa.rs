// =================================================================================================
// P4.13-a — SANS MANDATAIRE, L'ÉCRAN DE LOGIN NE POUVAIT JAMAIS S'AFFICHER.
//
// LE DÉFAUT, MESURÉ SUR UN DÉMON LANCÉ (2026-08-29), PAS LU DANS UN ARBRE. Le statique est servi par
// le `fallback_service` (`ServeDir`), lequel est ENVELOPPÉ par les couches globales dont `auth_guard`.
// Avec un mot de passe configuré et AUCUN mandataire devant, `GET /` rendait `401 auth requise` —
// douze octets de texte brut — et `GET /app.js` la même chose. Le module qui PEINT l'écran de login
// (`login.js`, déclenché par le 401 de `/api/me`) n'était donc jamais chargé. Les modes `host` et
// `docker` atteignent le démon EN DIRECT ; seul `k3s` passe par un mandataire qui laisse déjà passer
// `/`. Le correctif sert DEUX modes sur trois, et le troisième était le seul éprouvé.
//
// CE QUE CE FICHIER TIENT, ET DANS CET ORDRE
// ------------------------------------------
//  (1) LA DÉRIVATION, RECALCULÉE ET COMPARÉE DANS LES DEUX SENS. `SHELL_JS_CLOSURE` doit être
//      EXACTEMENT la fermeture des imports ES statiques atteignable depuis `web/app.js` : un module
//      atteignable mais absent casse le login ; un module présent mais devenu inatteignable laisse
//      une surface publique MORTE. Idem pour `INDEX_DIRECT_ASSETS` contre ce que `index.html` et
//      `style.css` référencent réellement.
//  (2) L'INSTRUMENT EST VALIDÉ AVANT DE RENDRE UN VERDICT. Un extracteur d'imports rend vert de deux
//      façons : tout va bien, ou son motif ne reconnaît plus rien. Le piège est MESURÉ dans ce dépôt :
//      « post-import (injecté par app.js… » — de la PROSE FRANÇAISE dans un commentaire de
//      `sigmaimport.js` — est lu comme un import DYNAMIQUE par un motif naïf, et une fermeture qui ne
//      l'écarterait pas exempterait le mauvais ensemble. Le témoin joue donc les DEUX sens : la prose
//      réelle du dépôt doit être écartée, ET un vrai `import(` fabriqué doit être VU.
//  (3) LA PREUVE PAR SERVICE, PAS PAR LECTURE D'ARBRE. Le routeur RÉEL (ses six couches, son
//      `fallback_service`) est monté sur le `web/` LIVRÉ et interrogé en HTTP par une prise TCP, sans
//      identité : la racine et le script d'entrée doivent rendre le SHELL et non une phrase, et les
//      octets servis doivent être IDENTIQUES à ceux du dépôt (un « 200 » sur un corps altéré ne
//      prouverait rien).
//  (4) LES DEUX TÉMOINS NÉGATIFS, QUI VALENT AUTANT. Les routes `/api/*` restent 401 pour un anonyme
//      (population DÉRIVÉE de la table de routage, jamais trois noms choisis) ; et un chemin de `web/`
//      qui n'est PAS dans l'ensemble dérivé ne devient PAS public — non plus qu'un voisin de nom
//      (`/app.js.map`, `/App.js`), ce qu'un élargissement en préfixe ou en suffixe ferait rougir.
//
// CE QUE CE FICHIER NE TIENT PAS, ET IL FAUT LE DIRE
// -------------------------------------------------
//  * Il n'exécute AUCUN JavaScript : il prouve que tous les octets du graphe de modules sont servis à
//    un anonyme et qu'ils sont ceux du dépôt, pas que le navigateur peint l'overlay. Que ces mêmes
//    octets se LIENT et peignent est tenu ailleurs, par `.github/scripts/web_esm_harnais.mjs`.
//  * Il monte le routeur dans le processus de test : c'est le produit SERVI (couches + ServeDir +
//    protocole HTTP réel), ce n'est pas le binaire lancé par une unité systemd. `P8.27-i` reste
//    OUVERTE — rien ici n'éprouve un déploiement, seulement le produit servi.
//  * La dérivation ne lit QUE les `import` ; une réexportation (`export … from`) la ferait REFUSER
//    (aucune n'existe aujourd'hui — mesuré : 183 mots-clés `import`, tous statiques avec `from`).
// =================================================================================================

/// Racine du dépôt : le crate `daemon` en est un enfant direct.
fn shell_racine_du_depot() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("INSTRUMENT : le crate n'a pas de répertoire parent")
        .to_path_buf()
}

fn shell_web() -> std::path::PathBuf {
    shell_racine_du_depot().join("web")
}

/// Lit un fichier de `web/`. Une lecture impossible REFUSE au lieu de rendre une fermeture amputée
/// (qui, elle, passerait pour une exemption « propre » en fermant l'écran de login).
fn shell_lire_du_web(rel: &str) -> String {
    let p = shell_web().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!("INSTRUMENT MUET : `{}` illisible ({e}) — la dérivation ne conclut RIEN", p.display())
    })
}

/// Retire les COMMENTAIRES et le CONTENU des chaînes d'une source JavaScript en CONSERVANT les
/// positions (un caractère masqué reste un caractère), et rend la table `index du guillemet ouvrant
/// -> valeur de la chaîne`. C'est ce masquage, et lui seul, qui écarte la prose française lue comme
/// un import dynamique.
fn shell_masquer_js(src: &str) -> (Vec<char>, std::collections::BTreeMap<usize, String>) {
    let c: Vec<char> = src.chars().collect();
    let n = c.len();
    let mut out = c.clone();
    let mut chaines: std::collections::BTreeMap<usize, String> = std::collections::BTreeMap::new();
    let mut i = 0usize;
    while i < n {
        let ch = c[i];
        if ch == '/' && i + 1 < n && c[i + 1] == '/' {
            let mut j = i;
            while j < n && c[j] != '\n' {
                out[j] = ' ';
                j += 1;
            }
            i = j;
        } else if ch == '/' && i + 1 < n && c[i + 1] == '*' {
            let mut j = i + 2;
            while j + 1 < n && !(c[j] == '*' && c[j + 1] == '/') {
                if c[j] != '\n' {
                    out[j] = ' ';
                }
                j += 1;
            }
            out[i] = ' ';
            out[i + 1] = ' ';
            if j + 1 < n {
                out[j] = ' ';
                out[j + 1] = ' ';
                j += 2;
            } else {
                j = n;
            }
            i = j;
        } else if ch == '\'' || ch == '"' || ch == '`' {
            let q = ch;
            let mut j = i + 1;
            let mut buf = String::new();
            let mut ferme = false;
            while j < n {
                if c[j] == '\\' {
                    if j + 1 < n {
                        buf.push(c[j + 1]);
                    }
                    j += 2;
                    continue;
                }
                if c[j] == q {
                    ferme = true;
                    break;
                }
                // Une chaîne simple ne franchit pas une fin de ligne : un guillemet ORPHELIN (une
                // apostrophe française dans du texte) ne doit pas avaler le reste du fichier.
                if q != '`' && c[j] == '\n' {
                    break;
                }
                buf.push(c[j]);
                j += 1;
            }
            if ferme {
                for k in (i + 1)..j {
                    if out[k] != '\n' {
                        out[k] = '\u{1}';
                    }
                }
                chaines.insert(i, buf);
                i = j + 1;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    (out, chaines)
}

/// Le mot `mot` commence-t-il en `i`, à un BORD d'identifiant ? Le point compte comme un caractère
/// d'identifiant EN AMONT (`foo.import` n'est pas le mot-clé), jamais en aval (`import.meta` l'est).
fn shell_mot_a(m: &[char], i: usize, mot: &str) -> bool {
    let w: Vec<char> = mot.chars().collect();
    if i + w.len() > m.len() || m[i..i + w.len()] != w[..] {
        return false;
    }
    if i > 0 {
        let p = m[i - 1];
        if p.is_ascii_alphanumeric() || p == '_' || p == '$' || p == '.' {
            return false;
        }
    }
    match m.get(i + w.len()) {
        None => true,
        Some(&c) => !(c.is_ascii_alphanumeric() || c == '_' || c == '$'),
    }
}

#[derive(Default, Debug)]
struct LectureDesImports {
    specificateurs: Vec<String>,
    dynamiques: usize,
    metas: usize,
    nus: usize,
}

/// Classe TOUT mot-clé `import` d'une source : statique (avec `from`), nu (`import './x.js'`),
/// dynamique (`import(`), ou `import.meta`. Un mot-clé qu'elle ne sait pas classer, ou une
/// réexportation `export … from`, rend une ERREUR — jamais un silence : une fermeture amputée
/// exempterait le mauvais ensemble et refermerait l'écran de login sans que rien ne le dise.
fn shell_lire_les_imports(src: &str, origine: &str) -> Result<LectureDesImports, String> {
    let (m, chaines) = shell_masquer_js(src);
    let n = m.len();
    let mut out = LectureDesImports::default();
    let mut i = 0usize;
    while i < n {
        if shell_mot_a(&m, i, "export") {
            let mut j = i + 6;
            while j < n && m[j].is_whitespace() {
                j += 1;
            }
            if m.get(j) == Some(&'*') {
                j += 1;
            } else if m.get(j) == Some(&'{') {
                while j < n && m[j] != '}' {
                    j += 1;
                }
                j = (j + 1).min(n);
            } else {
                i += 6;
                continue;
            }
            while j < n && m[j].is_whitespace() {
                j += 1;
            }
            if shell_mot_a(&m, j, "from") {
                return Err(format!(
                    "{origine} : une RÉEXPORTATION `export … from` (offset {i}). La dérivation de \
                     P4.13-a ne lit que les `import` : elle rendrait une fermeture AMPUTÉE, donc un \
                     écran de login cassé sans un mot. Étendre `shell_lire_les_imports`, pas le test."
                ));
            }
            i += 6;
            continue;
        }
        if !shell_mot_a(&m, i, "import") {
            i += 1;
            continue;
        }
        let mut j = i + 6;
        while j < n && m[j].is_whitespace() {
            j += 1;
        }
        match m.get(j).copied() {
            Some('(') => {
                out.dynamiques += 1;
                i = j + 1;
                continue;
            }
            Some('.') => {
                out.metas += 1;
                i = j + 1;
                continue;
            }
            Some(c) if c == '\'' || c == '"' || c == '`' => {
                let v = chaines.get(&j).ok_or_else(|| {
                    format!("{origine} : `import '…'` (offset {j}) dont la chaîne n'a pas été isolée")
                })?;
                out.nus += 1;
                out.specificateurs.push(v.clone());
                i = j + 1;
                continue;
            }
            _ => {}
        }
        let mut k = j;
        let mut apres_from = None;
        while k < n && m[k] != ';' {
            if shell_mot_a(&m, k, "from") {
                apres_from = Some(k + 4);
                break;
            }
            k += 1;
        }
        let Some(mut q) = apres_from else {
            return Err(format!(
                "{origine} : mot-clé `import` (offset {i}) sans `from` avant le `;` et sans forme \
                 connue — l'extracteur REFUSE plutôt que de rendre une fermeture qu'il n'a pas lue."
            ));
        };
        while q < n && m[q].is_whitespace() {
            q += 1;
        }
        let v = chaines.get(&q).ok_or_else(|| {
            format!("{origine} : `import … from` (offset {i}) non suivi d'une chaîne LITTÉRALE")
        })?;
        out.specificateurs.push(v.clone());
        i = q + 1;
    }
    Ok(out)
}

/// Résout un spécificateur RELATIF contre le module qui l'importe. Un `./` littéral laissé dans le
/// chemin donnerait un nom de fichier qui n'existe pas — et une exemption qui ne couvre rien.
fn shell_resoudre(depuis: &str, spec: &str) -> Result<String, String> {
    if !(spec.starts_with("./") || spec.starts_with("../")) {
        return Err(format!(
            "`{depuis}` importe `{spec}` : spécificateur NON RELATIF. La dérivation ne sait pas où \
             ce module est SERVI, donc elle ne peut pas l'exempter — elle refuse."
        ));
    }
    let mut segs: Vec<String> = match std::path::Path::new(depuis).parent() {
        Some(p) => p
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
            .collect(),
        None => Vec::new(),
    };
    for s in spec.split('/') {
        match s {
            "." | "" => {}
            ".." => {
                if segs.pop().is_none() {
                    return Err(format!("`{depuis}` importe `{spec}` : sort de `web/`"));
                }
            }
            autre => segs.push(autre.to_string()),
        }
    }
    Ok(segs.join("/"))
}

/// La fermeture des imports ES STATIQUES atteignable depuis `entree`, en chemins SERVIS (`/x.js`).
fn shell_fermeture_servie_depuis(entree: &str) -> std::collections::BTreeSet<String> {
    let mut vus: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut pile = vec![entree.to_string()];
    while let Some(rel) = pile.pop() {
        if !vus.insert(rel.clone()) {
            continue;
        }
        let src = shell_lire_du_web(&rel);
        let lecture = shell_lire_les_imports(&src, &rel).unwrap_or_else(|e| panic!("INSTRUMENT : {e}"));
        assert_eq!(
            lecture.dynamiques, 0,
            "`{rel}` porte un import DYNAMIQUE : la fermeture STATIQUE ne peut plus prétendre couvrir \
             ce que le navigateur ira chercher. Le module chargé à l'exécution doit être exempté \
             explicitement, ou l'import rendu statique."
        );
        for spec in lecture.specificateurs {
            pile.push(shell_resoudre(&rel, &spec).unwrap_or_else(|e| panic!("INSTRUMENT : {e}")));
        }
    }
    vus.into_iter().map(|r| format!("/{r}")).collect()
}

/// Valeurs d'un attribut HTML (`href`, `src`) — le caractère qui PRÉCÈDE doit être un blanc, sinon
/// `data-href="…"` serait compté comme un `href`.
///
/// P4.13-a (reprise) — ELLE REFUSE CE QU'ELLE NE SAIT PAS LIRE, elle ne l'ignore plus. Le défaut, vu par
/// la critique adverse : cette lecture cherchait LITTÉRALEMENT `href="` / `src="`, donc un `src='/x.svg'`
/// (guillemets simples) ou un `src=/x.svg` (non quoté) n'était ni lu NI REFUSÉ — la référence disparaissait
/// en silence, l'asset restait 401 et le témoin restait VERT pendant que la carte de login s'affichait avec
/// une image cassée. C'est l'exact inverse de la dérivation des imports ES, qui, elle, ROUGIT en nommant la
/// forme non couverte. Une valeur d'attribut est donc lue seulement si elle est entre guillemets DOUBLES ;
/// toute autre forme rend une ERREUR qui NOMME la forme et sa position.
fn shell_valeurs_d_attribut(txt: &str, attribut: &str) -> Result<Vec<String>, String> {
    let motif = format!("{attribut}=");
    let octets = txt.as_bytes();
    let mut out = Vec::new();
    let mut depart = 0usize;
    while let Some(p) = txt[depart..].find(&motif) {
        let abs = depart + p;
        let bord = abs == 0 || (octets[abs - 1] as char).is_whitespace();
        let debut = abs + motif.len();
        if !bord {
            depart = debut;
            continue;
        }
        let suivant = txt[debut..].chars().next();
        if suivant != Some('"') {
            let extrait: String = txt[abs..].chars().take(48).collect();
            return Err(format!(
                "FORME DE RÉFÉRENCE NON COUVERTE — `{attribut}=` sans guillemets DOUBLES à « {extrait} ». \
                 Cette dérivation ne lit que `{attribut}=\"…\"` : sous une autre forme, l'asset serait \
                 référencé par le navigateur, absent de `INDEX_DIRECT_ASSETS`, servi 401, et AUCUN témoin ne \
                 le verrait. Remettre des guillemets doubles, ou étendre cette lecture."
            ));
        }
        let debut = debut + 1;
        match txt[debut..].find('"') {
            Some(q) => {
                out.push(txt[debut..debut + q].to_string());
                depart = debut + q;
            }
            None => {
                return Err(format!("`{attribut}=\"` sans guillemet fermant : le document est malformé"));
            }
        }
    }
    Ok(out)
}

/// P4.13-a (reprise) — LES `url(…)` RACINÉS D'UNE SOURCE, et le REFUS d'un `@import`.
/// Le balayage porte sur le TEXTE ENTIER qu'on lui donne : pour `index.html` cela couvre du même geste le
/// bloc `<style>` EN LIGNE et un éventuel attribut `style="…"`, que la version d'origine ne lisait ni ne
/// refusait — elle ne cherchait `url(` que dans `style.css`. Un `background-image:url(/marque.svg)` posé
/// demain dans le style en ligne était donc invisible à la dérivation, et l'image serait servie 401.
fn shell_urls_racinees(source: &str, ou: &str) -> Result<Vec<String>, String> {
    if source.contains("@import") {
        return Err(format!(
            "`{ou}` porte un `@import` : la feuille en tire une AUTRE, que cette dérivation ne suit pas. \
             L'écran de login serait servi sans elle."
        ));
    }
    let mut out = Vec::new();
    let mut reste = source;
    while let Some(p) = reste.find("url(") {
        let apres = &reste[p + 4..];
        match apres.find(')') {
            Some(q) => {
                let v = apres[..q].trim().trim_matches(['\'', '"']).trim();
                if v.starts_with('/') {
                    out.push(v.to_string());
                }
                reste = &apres[q..];
            }
            None => break,
        }
    }
    Ok(out)
}

/// P4.13-a (reprise) — LES ATTRIBUTS PORTEURS DE SOUS-RESSOURCE QUE CETTE DÉRIVATION NE LIT PAS.
/// Aucun n'existe dans le document d'aujourd'hui (mesuré) ; le jour où l'un apparaît, il doit faire ROUGIR
/// et non disparaître. `xlink:href` est le piège le plus proche : le contrôle de bord de
/// `shell_valeurs_d_attribut` exige un BLANC avant `href=`, et c'est un `:` qui précède — la référence
/// serait donc sautée sans un mot.
const SHELL_ATTRIBUTS_NON_LUS: &[&str] = &["srcset", "poster", "xlink:href", "formaction"];

fn shell_refuser_les_attributs_non_lus(html: &str) -> Result<(), String> {
    let octets = html.as_bytes();
    for a in SHELL_ATTRIBUTS_NON_LUS {
        let motif = format!("{a}=");
        let mut depart = 0usize;
        while let Some(p) = html[depart..].find(&motif) {
            let abs = depart + p;
            // `xlink:href=` porte un `:` avant `href` : on cherche le nom COMPLET, donc le bord est le
            // blanc qui précède l'attribut entier.
            if abs == 0 || (octets[abs - 1] as char).is_whitespace() {
                let extrait: String = html[abs..].chars().take(56).collect();
                return Err(format!(
                    "ATTRIBUT PORTEUR DE SOUS-RESSOURCE NON LU — `{a}=` à « {extrait} ». Le navigateur ira \
                     chercher cette ressource ; la dérivation ne la voit pas, elle serait servie 401 et \
                     aucun témoin ne le dirait. L'étendre, ou retirer l'attribut."
                ));
            }
            depart = abs + motif.len();
        }
    }
    Ok(())
}

/// Ce que le document d'entrée et sa feuille de style référencent DIRECTEMENT, en chemins servis.
/// `/` et `/index.html` désignent le MÊME fichier (`ServeDir` sert l'index d'un répertoire) : les
/// deux noms existent pour un visiteur, les deux sont donc EXIGÉS.
///
/// P4.13-a (reprise) — CETTE DÉRIVATION REFUSE, elle ne se tait plus. Elle rendait un ensemble AMPUTÉ sans
/// un mot dès qu'une référence prenait une forme qu'elle ne lit pas ; le cœur du calcul (`shell_…`) porte
/// désormais le refus, et il est joué dans les DEUX SENS par
/// `p4_13_a_la_derivation_des_assets_refuse_les_formes_qu_elle_ne_lit_pas`.
fn shell_references_directes() -> std::collections::BTreeSet<String> {
    shell_references_directes_de(&shell_lire_du_web("index.html"), &shell_lire_du_web("style.css"))
        .unwrap_or_else(|e| panic!("DÉRIVATION DES ASSETS DIRECTS : {e}"))
}

/// Le CŒUR de la dérivation, sur des sources données : c'est lui que les fixtures jouent, dans les deux sens.
fn shell_references_directes_de(html: &str, css: &str) -> Result<std::collections::BTreeSet<String>, String> {
    shell_refuser_les_attributs_non_lus(html)?;
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    out.insert("/".to_string());
    out.insert("/index.html".to_string());
    for a in ["href", "src"] {
        for v in shell_valeurs_d_attribut(html, a)? {
            if v.starts_with('/') {
                out.insert(v);
            }
        }
    }
    // Le document ENTIER, pas seulement la feuille : un `url(…)` posé dans le `<style>` en ligne ou dans un
    // attribut `style="…"` est une référence que le navigateur suivra, et elle échappait à ce calcul.
    for v in shell_urls_racinees(html, "index.html")? {
        out.insert(v);
    }
    for v in shell_urls_racinees(css, "style.css")? {
        out.insert(v);
    }
    Ok(out)
}

/// L'ensemble PUBLIC total : les QUATRE listes du module de surface, réunies. Il est construit ICI par la
/// même énumération que `est_publique` lit — et le témoin (1ter) exige que les deux répondent PAREIL sur
/// toute la population, faute de quoi la porte et son budget parleraient de deux ensembles différents.
fn shell_ensemble_public() -> std::collections::BTreeSet<String> {
    crate::surface_publique_du_shell::PWA_PUBLIC_ASSETS
        .iter()
        .chain(crate::surface_publique_du_shell::INDEX_DIRECT_ASSETS.iter())
        .chain(crate::surface_publique_du_shell::LICENCES_DES_FONTES.iter())
        .chain(crate::surface_publique_du_shell::SHELL_JS_CLOSURE.iter())
        .map(|s| s.to_string())
        .collect()
}

/// Le fichier de `web/` que sert un chemin exempté (`/` -> `index.html`).
fn shell_fichier_du_chemin(chemin: &str) -> std::path::PathBuf {
    shell_web().join(if chemin == "/" { "index.html" } else { chemin.trim_start_matches('/') })
}

/// (1) LA FERMETURE PORTÉE PAR LA GARDE EST CELLE QUE LE DOCUMENT D'ENTRÉE ATTEINT — dans les DEUX
/// SENS. Atteignable mais absent : le login casse. Présent mais inatteignable : surface publique
/// morte. Un fichier posé demain sous `web/` n'est donc PAS exempté par accident ; il fait rougir ici.
#[test]
fn p4_13_a_la_fermeture_du_shell_est_celle_que_la_garde_porte_dans_les_deux_sens() {
    let calculee = shell_fermeture_servie_depuis("app.js");
    let portee: std::collections::BTreeSet<String> =
        crate::surface_publique_du_shell::SHELL_JS_CLOSURE.iter().map(|s| s.to_string()).collect();
    assert!(
        calculee.len() >= 40,
        "PLANCHER DE NON-DÉGÉNÉRESCENCE : la fermeture ne rend que {} module(s). Un extracteur qui ne \
         reconnaît plus rien rendrait vert en ne mesurant rien.",
        calculee.len()
    );
    let manquants: Vec<&String> = calculee.difference(&portee).collect();
    assert!(
        manquants.is_empty(),
        "ATTEIGNABLE MAIS NON EXEMPTÉ — un visiteur non authentifié recevra 401 sur {manquants:?}, le \
         graphe de modules ne se fermera pas, et l'écran de login NE S'AFFICHERA PAS. Ajouter ces \
         chemins à `SHELL_JS_CLOSURE` (liste EXACTE et TRIÉE), jamais un préfixe."
    );
    let morts: Vec<&String> = portee.difference(&calculee).collect();
    assert!(
        morts.is_empty(),
        "EXEMPTÉ MAIS PLUS ATTEIGNABLE — {morts:?} sont servis PUBLIQUEMENT sans que le shell en ait \
         besoin. C'est de la surface publique morte : les retirer de `SHELL_JS_CLOSURE`."
    );
}

/// (1bis) CE QUE LE DOCUMENT D'ENTRÉE RÉFÉRENCE EST EXEMPTÉ, ET RIEN DE PLUS. `INDEX_DIRECT_ASSETS`
/// est exactement « ce dont le shell a besoin, moins ce qui est déjà exempté ailleurs » : les trois
/// listes ne se recouvrent pas, et chacune désigne un fichier qui EXISTE.
#[test]
fn p4_13_a_les_assets_directs_du_document_sont_exempte_et_rien_de_plus() {
    let exiges = shell_references_directes();
    let public = shell_ensemble_public();
    let non_servis: Vec<&String> = exiges.difference(&public).collect();
    // P4.13-a (reprise) — LE PREMIER MESSAGE QUE LIT LE DÉVELOPPEUR NE DOIT PAS LUI DIRE D'EXPOSER.
    // Défaut vu par la critique adverse : ce rouge disait « la garde ne laisse pas passer X », ce qui se
    // lit comme une consigne d'INSCRIRE X. Or `shell_references_directes` ramasse tout `href="/…"` du
    // document SANS regarder la balise : un `<a href="/metrics">` posé demain arriverait ici, et
    // `/metrics` est justement la route dont `auth_guard` dit qu'elle « n'est JAMAIS anonyme au monde ».
    // La collision avec la table de routage l'arrêtait — mais APRÈS, et par un autre témoin. Le verdict
    // est donc rendu ICI, et il DIT lequel des deux gestes est le bon.
    let routes: std::collections::BTreeSet<String> =
        declared_route_table().into_iter().map(|(p, _)| p).collect();
    let mais_ce_sont_des_routes: Vec<&&String> =
        non_servis.iter().filter(|c| routes.contains(**c)).collect();
    assert!(
        mais_ce_sont_des_routes.is_empty(),
        "LE DOCUMENT D'ENTRÉE RÉFÉRENCE {mais_ce_sont_des_routes:?}, QUI SONT DES ROUTES DÉCLARÉES DU \
         DÉMON — surtout PAS de les inscrire dans une liste publique : ce sont des surfaces d'interface \
         que `auth_guard` gate (`/metrics` n'est JAMAIS anonyme au monde). Le geste est de RETIRER la \
         référence du document, ou de la rendre inatteignable sans identité."
    );
    assert!(
        non_servis.is_empty(),
        "LE SHELL RÉFÉRENCE {non_servis:?} QUE LA GARDE NE LAISSE PAS PASSER : la carte de login \
         s'affichera amputée (image cassée, police de repli) ou pas du tout. Ce sont bien des FICHIERS \
         STATIQUES (aucun n'est une route déclarée — vérifié juste au-dessus) : les inscrire dans \
         `INDEX_DIRECT_ASSETS`, liste EXACTE et TRIÉE, jamais un préfixe."
    );
    let directs: std::collections::BTreeSet<String> =
        crate::surface_publique_du_shell::INDEX_DIRECT_ASSETS.iter().map(|s| s.to_string()).collect();
    let orphelins: Vec<&String> = directs.difference(&exiges).collect();
    assert!(
        orphelins.is_empty(),
        "SURFACE PUBLIQUE MORTE : {orphelins:?} sont exemptés alors que ni `index.html` ni \
         `style.css` ne les référencent."
    );
    let closure: std::collections::BTreeSet<String> =
        crate::surface_publique_du_shell::SHELL_JS_CLOSURE.iter().map(|s| s.to_string()).collect();
    let pwa: std::collections::BTreeSet<String> =
        crate::surface_publique_du_shell::PWA_PUBLIC_ASSETS.iter().map(|s| s.to_string()).collect();
    let licences: std::collections::BTreeSet<String> =
        crate::surface_publique_du_shell::LICENCES_DES_FONTES.iter().map(|s| s.to_string()).collect();
    for (a, na, b, nb) in [
        (&directs, "INDEX_DIRECT_ASSETS", &closure, "SHELL_JS_CLOSURE"),
        (&directs, "INDEX_DIRECT_ASSETS", &pwa, "PWA_PUBLIC_ASSETS"),
        (&directs, "INDEX_DIRECT_ASSETS", &licences, "LICENCES_DES_FONTES"),
        (&closure, "SHELL_JS_CLOSURE", &pwa, "PWA_PUBLIC_ASSETS"),
        (&closure, "SHELL_JS_CLOSURE", &licences, "LICENCES_DES_FONTES"),
        (&pwa, "PWA_PUBLIC_ASSETS", &licences, "LICENCES_DES_FONTES"),
    ] {
        let commun: Vec<&String> = a.intersection(b).collect();
        assert!(commun.is_empty(), "{na} et {nb} se recouvrent sur {commun:?} : un seul auteur par chemin.");
    }
    for c in &public {
        let f = shell_fichier_du_chemin(c);
        assert!(f.is_file(), "`{c}` est exempté mais ne désigne aucun fichier de `web/` ({})", f.display());
    }
}

/// (1ter) L'ORDRE EST CE QUE LA DICHOTOMIE EXIGE. `auth_guard` traverse ce bloc à CHAQUE requête, y
/// compris les `/api/*` : la recherche y est dichotomique, donc les listes doivent être STRICTEMENT
/// croissantes — ce qui interdit du même geste les doublons. Et aucune ne peut toucher une route.
#[test]
fn p4_13_a_l_ordre_strict_est_ce_que_la_dichotomie_exige() {
    for (nom, liste) in [
        ("SHELL_JS_CLOSURE", crate::surface_publique_du_shell::SHELL_JS_CLOSURE),
        ("INDEX_DIRECT_ASSETS", crate::surface_publique_du_shell::INDEX_DIRECT_ASSETS),
        ("PWA_PUBLIC_ASSETS", crate::surface_publique_du_shell::PWA_PUBLIC_ASSETS),
        ("LICENCES_DES_FONTES", crate::surface_publique_du_shell::LICENCES_DES_FONTES),
    ] {
        for f in liste.windows(2) {
            assert!(
                f[0] < f[1],
                "{nom} n'est pas STRICTEMENT croissante en `{}` / `{}` : la recherche dichotomique de \
                 `auth_guard` peut MANQUER une entrée — un chemin exempté serait servi 401 au hasard \
                 de sa place dans la liste.",
                f[0], f[1]
            );
        }
        for c in liste {
            assert!(c.starts_with('/'), "{nom} : `{c}` n'est pas un chemin servi");
        }
    }
    let public = shell_ensemble_public();
    // P4.13-a (reprise) — LA GARDE N'EST PLUS ÉNUMÉRÉE. Elle refusait `/api/`, `/scim/`, `/services/` et
    // RIEN D'AUTRE : ni `/metrics`, ni `/healthz`, ni `/readyz`, ni `/v1/traces`, ni `/loki/`. La propriété
    // tenait quand même, mais par UN seul témoin — la collision ci-dessous — et l'énumération donnait
    // l'illusion d'un second. La question n'est pas « ce chemin commence-t-il par un préfixe interdit »,
    // c'est « ce chemin est-il une surface d'INTERFACE » : la table de routage le dit, exhaustivement, et
    // elle le dit sous les DEUX formes qu'un chemin y prend — le gabarit littéral (`/api/users/{id}`) et sa
    // forme concrète (`/api/users/1`), qui est celle qu'un client envoie vraiment.
    let routes = declared_route_table();
    assert!(routes.len() > 200, "table de routage lue depuis le module `server` : {} routes", routes.len());
    let mut collisions: Vec<String> = Vec::new();
    for (gabarit, _) in &routes {
        if public.contains(gabarit) {
            collisions.push(format!("{gabarit} (gabarit)"));
        }
        let concret = concrete_path(gabarit);
        if &concret != gabarit && public.contains(&concret) {
            collisions.push(format!("{concret} (forme concrète de {gabarit})"));
        }
    }
    assert!(
        collisions.is_empty(),
        "UN CHEMIN EXEMPTÉ EST AUSSI UNE ROUTE DÉCLARÉE : {collisions:?}. L'exemption court-circuiterait \
         l'authentification de cette route — c'est la SEULE chose que ces listes ne doivent jamais faire."
    );
    // ... et le prédicat que le PRODUIT consulte répond comme cette énumération, sur toute la population :
    // `auth_guard` et `budget_du_shell_public` lisent `est_publique`, pas ces quatre constantes. Si les deux
    // divergeaient (une liste oubliée dans le prédicat), la porte et son budget porteraient sur des
    // ensembles différents — et ce fichier mesurerait un ensemble que personne ne sert.
    for c in &public {
        assert!(
            crate::surface_publique_du_shell::est_publique(c),
            "`{c}` est dans une des quatre listes mais `est_publique` répond NON : le prédicat que le \
             produit consulte ne lit pas tout ce que ce fichier vérifie."
        );
    }
    for (gabarit, _) in &routes {
        assert!(
            !crate::surface_publique_du_shell::est_publique(gabarit)
                && !crate::surface_publique_du_shell::est_publique(&concrete_path(gabarit)),
            "`est_publique` laisse passer la route déclarée `{gabarit}`."
        );
    }
}

/// (2) L'INSTRUMENT EST VALIDÉ, DANS LES DEUX SENS, AVANT DE SERVIR À QUOI QUE CE SOIT.
/// Le faux positif est CELUI DU DÉPÔT, pas une invention : `sigmaimport.js` porte « post-import
/// (injecté par app.js… » en prose française. Un motif naïf y voit un import dynamique et la
/// fermeture qu'il calcule n'est plus celle du produit. Le témoin INVERSE interdit un masquage qui
/// écarterait TOUT : un vrai `import(` doit être VU, et un vrai `import … from` doit être LU.
#[test]
fn p4_13_a_l_instrument_ecarte_la_prose_et_voit_un_vrai_import_dynamique() {
    // (a) LE FAUX POSITIF RÉEL DU DÉPÔT — présent dans la source, écarté par le masquage.
    let sigma = shell_lire_du_web("sigmaimport.js");
    assert!(
        sigma.contains("post-import ("),
        "CONTRÔLE POSITIF PERDU : la prose « post-import ( » a disparu de `sigmaimport.js`. Le témoin \
         ci-dessous ne prouverait plus rien — retrouver un faux positif réel, ou retirer ce témoin."
    );
    let lu = shell_lire_les_imports(&sigma, "sigmaimport.js").expect("sigmaimport.js se lit");
    assert_eq!(
        lu.dynamiques, 0,
        "LA PROSE EST COMPTÉE COMME UN IMPORT DYNAMIQUE : la fermeture refuserait de conclure sur un \
         module qui n'importe rien dynamiquement."
    );

    // (b) TÉMOIN INVERSE — un VRAI import dynamique, dans du code, doit être VU.
    let vrai = "import { a } from './core.js';\nasync function f(){ const m = await import('./tard.js'); return m; }\n";
    let lu = shell_lire_les_imports(vrai, "fixture-dynamique").expect("la fixture se lit");
    assert_eq!(lu.dynamiques, 1, "un VRAI `import(` n'est pas vu : le masquage écarte tout, donc ne prouve rien");
    assert_eq!(lu.specificateurs, vec!["./core.js".to_string()]);

    // (c) LES AUTRES FORMES QUE LA PROSE ET LES CHAÎNES PRENNENT.
    let corpus = concat!(
        "// import { faux } from './commentaire.js';\n",
        "/* import('./bloc.js') */\n",
        "const s = \"import('./chaine.js')\";\n",
        "const t = `import { x } from './gabarit.js'`;\n",
        "import defaut, { a as b } from './vrai.js';\n",
        "import * as ns from './espace.js';\n",
        "import {\n  c,\n  d\n} from './multiligne.js';\n",
        "import './effet-de-bord.js';\n",
        "const u = import.meta.url;\n",
        "const v = obj.import;\n"
    );
    let lu = shell_lire_les_imports(corpus, "fixture-corpus").expect("le corpus se lit");
    assert_eq!(lu.dynamiques, 0, "un `import(` en COMMENTAIRE ou en CHAÎNE a été compté");
    assert_eq!(lu.metas, 1, "`import.meta` doit être classé, jamais confondu avec un module");
    assert_eq!(lu.nus, 1, "un `import './x.js'` sans clause est un module du graphe");
    assert_eq!(
        lu.specificateurs,
        vec![
            "./vrai.js".to_string(),
            "./espace.js".to_string(),
            "./multiligne.js".to_string(),
            "./effet-de-bord.js".to_string(),
        ],
        "les quatre formes STATIQUES doivent être lues, et elles seules"
    );

    // (d) LA RÉEXPORTATION REFUSE, elle ne se tait pas.
    let e = shell_lire_les_imports("export { a } from './ailleurs.js';\n", "fixture-reexport")
        .expect_err("`export … from` doit être REFUSÉ");
    assert!(e.contains("RÉEXPORTATION"), "le refus doit NOMMER la forme non couverte : {e}");

    // (e) LA RÉSOLUTION DE CHEMIN — le `./` littéral, et le parent.
    assert_eq!(shell_resoudre("app.js", "./core.js").unwrap(), "core.js");
    assert_eq!(shell_resoudre("sous/x.js", "../core.js").unwrap(), "core.js");
    assert!(shell_resoudre("app.js", "lodash").is_err(), "un spécificateur NU doit être refusé");
}

/// Sert le routeur RÉEL sur le `web/` LIVRÉ (et non un répertoire inexistant comme `router_serve`) :
/// c'est le `fallback_service` réel, derrière les six couches réelles.
async fn shell_servir_le_web_livre(st: AppState) -> std::net::SocketAddr {
    let app = build_router(st, shell_web().to_string_lossy().into_owned());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await;
    });
    addr
}

/// Recolle un corps `Transfer-Encoding: chunked`. Rend `None` sur une trame malformée : une sonde qui
/// devinerait un corps à partir d'octets qu'elle n'a pas su lire ne mesurerait plus rien.
fn shell_decouper(brut: &[u8]) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(brut.len());
    let mut i = 0usize;
    loop {
        let fin = brut[i..].windows(2).position(|w| w == b"\r\n")? + i;
        let taille = usize::from_str_radix(
            std::str::from_utf8(&brut[i..fin]).ok()?.split(';').next()?.trim(),
            16,
        )
        .ok()?;
        i = fin + 2;
        if taille == 0 {
            return Some(out);
        }
        if i + taille > brut.len() {
            return None;
        }
        out.extend_from_slice(&brut[i..i + taille]);
        i += taille + 2;
    }
}

/// Une requête HTTP/1.1 SANS identité, dont on lit le corps ENTIER (borné) : « 200 » sur un corps
/// tronqué ou altéré ne prouverait pas que le shell est servi.
async fn shell_sonde(addr: std::net::SocketAddr, chemin: &str) -> (u16, Vec<u8>) {
    let (code, _, corps) = shell_sonde_complete(addr, chemin, "127.0.0.1").await;
    (code, corps)
}

/// La même sonde, mais elle rend AUSSI les en-têtes et laisse choisir l'AUTORITÉ demandée.
/// P4.13-a (reprise) — les deux manques que la critique adverse a nommés : la preuve n'avait jamais fait
/// varier le `Host` (les trois valeurs sondées étaient exactement celles que `host_guard` auto-accepte,
/// donc elle était STRUCTURELLEMENT aveugle au second mur), et elle ne lisait aucun en-tête, donc ni la
/// politique de contenu ni la longueur déclarée — deux propriétés dont ce lot dépend désormais.
async fn shell_sonde_complete(
    addr: std::net::SocketAddr,
    chemin: &str,
    hote: &str,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let req = format!("GET {chemin} HTTP/1.1\r\nHost: {hote}\r\nConnection: close\r\n\r\n");
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
        s.write_all(req.as_bytes()).await.ok()?;
        let mut brut: Vec<u8> = Vec::with_capacity(8192);
        let mut buf = [0u8; 8192];
        while brut.len() < 4 * 1024 * 1024 {
            match s.read(&mut buf).await.ok()? {
                0 => break,
                n => brut.extend_from_slice(&buf[..n]),
            }
        }
        let sep = brut.windows(4).position(|w| w == b"\r\n\r\n")?;
        let entete = String::from_utf8_lossy(&brut[..sep]).into_owned();
        let code = entete.split_whitespace().nth(1)?.parse::<u16>().ok()?;
        let entetes: Vec<(String, String)> = entete
            .lines()
            .skip(1)
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        let corps = brut[sep + 4..].to_vec();
        // LE CORPS EST DÉCODÉ QUAND IL EST DÉCOUPÉ EN MORCEAUX. Mesuré : les 401 de `auth_guard` sont
        // servis en `Transfer-Encoding: chunked` (« C\r\nauth requise\r\n0\r\n\r\n ») là où
        // `ServeDir` annonce une longueur. Une sonde qui rendrait les octets BRUTS comparerait des
        // enveloppes au lieu de contenus — et un corps altéré passerait pour identique.
        let corps = if entete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            shell_decouper(&corps)?
        } else {
            corps
        };
        Some((code, entetes, corps))
    };
    tokio::time::timeout(Duration::from_secs(20), fut)
        .await
        .ok()
        .flatten()
        .unwrap_or((0, Vec::new(), Vec::new()))
}

/// Un en-tête de la réponse, par son nom en minuscules.
fn shell_entete<'a>(entetes: &'a [(String, String)], nom: &str) -> Option<&'a str> {
    entetes.iter().find(|(k, _)| k == nom).map(|(_, v)| v.as_str())
}

/// La même sonde, en DEMANDANT la compression. P4.13-a (reprise) — ce n'est pas un détail : la couche de
/// compression est la PLUS EXTERNE des deux, donc elle RETIRE le `content-length` de la réponse que le
/// client voit (corps découpé en morceaux). Une lecture du budget qui n'aurait mesuré que l'en-tête vu du
/// CLIENT aurait donc conclu « rien n'est facturable » alors que `rate_limit`, qui vit SOUS cette couche,
/// voit la réponse NON compressée et sa longueur. Mesuré au banc sur le démon lancé : `Accept-Encoding:
/// gzip` posé, le refus tombe au même rang exactement — la facturation porte bien sur les octets BRUTS.
async fn shell_sonde_gzip(addr: std::net::SocketAddr, chemin: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let req = format!(
        "GET {chemin} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
    );
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
        s.write_all(req.as_bytes()).await.ok()?;
        let mut brut: Vec<u8> = Vec::with_capacity(8192);
        let mut buf = [0u8; 8192];
        while brut.len() < 4 * 1024 * 1024 {
            match s.read(&mut buf).await.ok()? {
                0 => break,
                n => brut.extend_from_slice(&buf[..n]),
            }
        }
        let sep = brut.windows(4).position(|w| w == b"\r\n\r\n")?;
        let entete = String::from_utf8_lossy(&brut[..sep]).into_owned();
        let code = entete.split_whitespace().nth(1)?.parse::<u16>().ok()?;
        let entetes: Vec<(String, String)> = entete
            .lines()
            .skip(1)
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        Some((code, entetes, brut[sep + 4..].to_vec()))
    };
    tokio::time::timeout(Duration::from_secs(20), fut)
        .await
        .ok()
        .flatten()
        .unwrap_or((0, Vec::new(), Vec::new()))
}

/// (3) LA PREUVE PAR SERVICE — LE PRODUIT SERVI, PAS UN ARBRE LU. Sans identité, la RACINE rend le
/// SHELL et le script d'entrée est servi ; et tout l'ensemble public est rendu BYTE À BYTE tel que le
/// dépôt le porte. C'est la mutation exacte du défaut : avant le correctif, la racine rendait douze
/// octets de texte (« auth requise »).
#[tokio::test]
async fn p4_13_a_sans_mandataire_un_anonyme_recoit_le_shell_et_jamais_une_phrase() {
    let (st, dbp) = router_test_state("shell-anon");
    let addr = shell_servir_le_web_livre(st).await;

    let (code, corps) = shell_sonde(addr, "/").await;
    assert_eq!(
        code, 200,
        "LA RACINE REND {code} À UN ANONYME : un visiteur sans mandataire devant le démon ne voit pas \
         un formulaire, il voit « {} ».",
        String::from_utf8_lossy(&corps)
    );
    let html = String::from_utf8_lossy(&corps).into_owned();
    assert!(html.starts_with("<!doctype html>"), "la racine ne rend pas le document d'entrée : {:.80}", html);
    assert!(
        html.contains("<script type=\"module\" src=\"/app.js\">"),
        "le document servi ne charge pas le script d'entrée : l'écran de login ne peut pas se peindre"
    );
    assert!(
        html.contains("login-brand"),
        "le document servi ne porte pas le balisage de la carte de login"
    );

    let (code, corps) = shell_sonde(addr, "/app.js").await;
    assert_eq!(code, 200, "LE SCRIPT D'ENTRÉE REND {code} : aucun module de la console ne se charge");
    assert!(
        String::from_utf8_lossy(&corps).contains("from './login.js'"),
        "le script d'entrée servi n'importe pas le module qui PEINT l'écran de login"
    );

    // LA POPULATION SONDÉE EST CE QUE LE SHELL EXIGE, RECALCULÉ — PAS LA LISTE QU'ON VÉRIFIE.
    // Mesuré : en sondant les CONSTANTES, retirer `/login.js` de `SHELL_JS_CLOSURE` laissait ce témoin
    // VERT (il sondait un chemin de moins). Une garde qui dérive son échantillon de la chose qu'elle
    // garde ne mesure plus rien ; l'attente vient donc de l'ARBRE, la réponse du PRODUIT SERVI.
    let mut exiges = shell_fermeture_servie_depuis("app.js");
    exiges.extend(shell_references_directes());
    assert!(exiges.len() >= 50, "plancher : {} chemins exigés par le shell seulement", exiges.len());
    let mut ecarts: Vec<String> = Vec::new();
    for c in &exiges {
        let (code, corps) = shell_sonde(addr, c).await;
        let attendu = std::fs::read(shell_fichier_du_chemin(c)).expect("le fichier exempté se lit");
        if code != 200 {
            ecarts.push(format!("{c} -> {code}"));
        } else if corps != attendu {
            ecarts.push(format!("{c} -> 200 mais {} octets servis pour {} attendus", corps.len(), attendu.len()));
        }
    }
    assert!(
        ecarts.is_empty(),
        "DES OCTETS DU SHELL NE SONT PAS SERVIS TELS QUELS À UN ANONYME : {ecarts:?}. Le graphe de \
         modules ne se ferme pas dans le navigateur d'un visiteur : l'écran de login ne se peint pas."
    );
    ff_rm(&dbp);
}

/// (4) LES DEUX TÉMOINS NÉGATIFS. L'exemption est une liste de NOMS EXACTS : elle ne peut pas élargir
/// une route d'interface (population DÉRIVÉE de la table de routage, pas trois noms choisis), et elle
/// ne peut pas s'étendre par préfixe ni par suffixe à un fichier de `web/` qui n'en fait pas partie —
/// ni à un VOISIN DE NOM qui n'existe même pas.
#[tokio::test]
async fn p4_13_a_ni_une_route_ni_un_fichier_hors_fermeture_ne_devient_public() {
    let (st, dbp) = router_test_state("shell-negatif");
    let addr = shell_servir_le_web_livre(st).await;

    // (a) LES ROUTES D'INTERFACE RESTENT 401 — sur toute la table déclarée, moins les bypass justifiés.
    let mut fautives: Vec<String> = Vec::new();
    let mut sondees = 0usize;
    for (path, methodes) in declared_route_table() {
        if router_bypassed(&path) || !methodes.iter().any(|m| m == "GET") {
            continue;
        }
        let (code, _) = shell_sonde(addr, &concrete_path(&path)).await;
        sondees += 1;
        if code != 401 {
            fautives.push(format!("GET {path} -> {code}"));
        }
    }
    assert!(sondees > 80, "sonde effective sur les lectures de la table ({sondees} requêtes)");
    assert!(
        fautives.is_empty(),
        "UNE ROUTE D'INTERFACE NE RÉPOND PLUS 401 À UN ANONYME : {fautives:?}. L'exemption du shell \
         aurait élargi une surface d'API."
    );

    // (b) LES FICHIERS DE `web/` HORS ENSEMBLE PUBLIC — population DÉRIVÉE de l'arbre.
    let public = shell_ensemble_public();
    let mut hors: Vec<String> = Vec::new();
    let mut a_visiter = vec![shell_web()];
    while let Some(d) = a_visiter.pop() {
        for e in std::fs::read_dir(&d).expect("web/ se lit") {
            let p = e.expect("entrée de web/").path();
            if p.is_dir() {
                a_visiter.push(p);
                continue;
            }
            let rel = p.strip_prefix(shell_web()).expect("sous web/").to_string_lossy().into_owned();
            let servi = format!("/{rel}");
            if !public.contains(&servi) {
                hors.push(servi);
            }
        }
    }
    // P4.13-a (reprise) — CE PLANCHER A ÉTÉ MESURÉ FAUX, ET LA MESURE DIT QUELQUE CHOSE. Il exigeait
    // qu'AU MOINS deux fichiers de `web/` restent hors de l'ensemble public, « sinon ce témoin ne
    // distinguerait plus une exemption exacte d'une exemption totale ». Depuis que les deux textes de
    // licence OFL sont publics (la SIL OFL 1.1 l'exige des fontes qu'on distribue), cette population est
    // VIDE : **la totalité de `web/` est publique aujourd'hui**, 62 fichiers sur 62. Il faut l'écrire au
    // lieu de le contourner. Ce que l'exactitude des listes achète n'est donc PAS « moins que tout l'arbre
    // aujourd'hui » — c'est qu'un fichier DÉPOSÉ DEMAIN sous `web/` ne devienne pas public sans décision
    // (témoin (1), qui rougit), et qu'aucun élargissement en préfixe ou en suffixe ne passe. Ce second
    // point est ce que mesurent les VOISINS DE NOM ci-dessous, et c'est sur EUX que porte le plancher.
    println!(
        "[surface] {} fichier(s) de `web/` hors de l'ensemble public — la totalité de l'arbre web est \
         publique quand ce nombre vaut 0 ; l'exactitude des listes vaut alors pour ce qui sera AJOUTÉ.",
        hors.len()
    );
    // ... et les VOISINS DE NOM, qui n'existent pas : un `starts_with`/`ends_with` les servirait. Ce sont
    // eux le discriminant : chacun est la forme exacte d'un élargissement possible (suffixe, casse,
    // préfixe de répertoire, segment de chemin, encodage pourcent, barre double, segment `.`).
    let voisins = [
        "/app.js.map", "/App.js", "/login.js.bak", "/style.css.map", "/fonts/",
        "/index.html/", "/%61pp.js", "//app.js", "/./app.js", "/app.js;x", "/web/app.js",
    ];
    assert!(
        voisins.len() >= 8,
        "PLANCHER : {} voisin(s) de nom sondés — c'est la SEULE population qui distingue encore une \
         exemption exacte d'un élargissement en préfixe ou en suffixe.",
        voisins.len()
    );
    let mut ouverts: Vec<String> = Vec::new();
    for c in hors.iter().map(String::as_str).chain(voisins.iter().copied()) {
        let (code, corps) = shell_sonde(addr, c).await;
        let vu = String::from_utf8_lossy(&corps).into_owned();
        if code != 401 || vu != "auth requise" {
            // L'extrait est BORNÉ : un corps servi par erreur peut faire des dizaines de kilo-octets
            // (mesuré sur un élargissement en préfixe), et un rouge illisible ne se lit pas.
            let extrait: String = vu.chars().take(60).collect();
            ouverts.push(format!("{c} -> {code} « {extrait} »"));
        }
    }
    assert!(
        ouverts.is_empty(),
        "UN CHEMIN HORS FERMETURE EST DEVENU PUBLIC : {ouverts:?}. L'allowlist doit rester une liste \
         de noms EXACTS ; un élargissement en préfixe ou en suffixe rougit ici."
    );
    ff_rm(&dbp);
}

// =================================================================================================
// REPRISE — CE QUE LA CRITIQUE ADVERSE A VU, ET QUI N'ÉTAIT TENU PAR AUCUN TÉMOIN
// =================================================================================================

/// (5) LA DÉRIVATION DES ASSETS REFUSE LES FORMES QU'ELLE NE LIT PAS — dans les DEUX sens.
///
/// LE DÉFAUT. Elle cherchait LITTÉRALEMENT `href="` / `src="` et ne balayait `url(` que dans
/// `style.css`. Un `src='/logo.svg'`, un `src=/logo.svg`, un `<use xlink:href="…">`, un `srcset=`, ou un
/// `background-image:url(/marque.svg)` posé dans le `<style>` EN LIGNE du document : jamais lus, jamais
/// REFUSÉS. Le fichier serait atteignable par le navigateur, absent de `INDEX_DIRECT_ASSETS`, servi 401 —
/// et le témoin (1bis) serait resté VERT parce qu'il ne l'aurait jamais vu. Inoffensif le jour de la
/// mesure (les 15 attributs du document sont tous en guillemets doubles, le style en ligne ne porte aucun
/// `url(`) : c'était un PIÈGE POSÉ, pas un défaut vivant. C'est le pire cas d'un instrument — il rend vert
/// des deux façons, et rien ne les distingue.
#[test]
fn p4_13_a_la_derivation_des_assets_refuse_les_formes_qu_elle_ne_lit_pas() {
    // (a) LE DOCUMENT RÉEL PASSE — sinon les refus ci-dessous ne prouveraient rien d'autre qu'un instrument
    //     qui refuse tout. C'est le contrôle positif.
    let html = shell_lire_du_web("index.html");
    let css = shell_lire_du_web("style.css");
    let vu = shell_references_directes_de(&html, &css).expect("le document livré se lit");
    assert!(
        vu.len() >= 8,
        "PLANCHER : la dérivation ne rend que {} référence(s) sur le document livré — elle ne mesure plus rien.",
        vu.len()
    );

    // (b) LES FORMES NON COUVERTES SONT REFUSÉES, ET LE REFUS LES NOMME.
    for (source, attendu, quoi) in [
        ("<img src='/logo.svg'>", "guillemets DOUBLES", "guillemets simples"),
        ("<img src=/logo.svg>", "guillemets DOUBLES", "valeur non quotée"),
        ("<svg><use xlink:href=\"/sprite.svg#q\"></use></svg>", "xlink:href", "attribut non lu"),
        ("<img srcset=\"/logo@2x.svg 2x\">", "srcset", "attribut non lu"),
        ("<video poster=\"/vignette.png\"></video>", "poster", "attribut non lu"),
        ("<button formaction=\"/api/x\"></button>", "formaction", "attribut non lu"),
    ] {
        let e = shell_references_directes_de(source, "").expect_err(&format!("{quoi} doit être REFUSÉ"));
        assert!(e.contains(attendu), "le refus de « {quoi} » doit NOMMER la forme ({attendu}) : {e}");
    }

    // (c) LE `url(` DU STYLE EN LIGNE EST DÉSORMAIS LU (il ne l'était PAS : seule `style.css` l'était).
    let avec_style_en_ligne = "<style>.login-brand{background-image:url(/marque.svg)}</style>";
    let vu = shell_references_directes_de(avec_style_en_ligne, "").expect("le style en ligne se lit");
    assert!(
        vu.contains("/marque.svg"),
        "un `url(…)` du `<style>` EN LIGNE n'est pas vu : l'image serait servie 401 sans qu'aucun témoin \
         ne le dise. Vu : {vu:?}"
    );

    // (d) LE `@import` REFUSE DES DEUX CÔTÉS — il ne l'était que dans `style.css`.
    for (h, c, ou) in [("<style>@import url(/autre.css);</style>", "", "index.html"), ("", "@import url(/autre.css);", "style.css")] {
        let e = shell_references_directes_de(h, c).expect_err("un `@import` doit être REFUSÉ");
        assert!(e.contains(ou), "le refus doit nommer la source ({ou}) : {e}");
    }

    // (e) LE BORD D'IDENTIFIANT TIENT ENCORE : `data-href="…"` n'est pas un `href`.
    let vu = shell_references_directes_de("<div data-href=\"/pas-un-asset\"></div>", "").expect("se lit");
    assert!(!vu.contains("/pas-un-asset"), "`data-href` a été compté comme un `href` : {vu:?}");
}

/// (6) LA LICENCE ACCOMPAGNE LA FONTE DISTRIBUÉE — règle DÉRIVÉE, jouée dans les deux sens.
///
/// LE DÉFAUT. `INDEX_DIRECT_ASSETS` a rendu publics les quatre `.woff2` (c'est la voie NOMINALE : le
/// navigateur d'un ANONYME les charge depuis les `@font-face` de `style.css`), et les deux textes de
/// licence du MÊME répertoire restaient gatés — ils figuraient nommément parmi les chemins que le lot
/// vérifiait rester en 401. La SIL Open Font License 1.1 exige que l'avis de copyright et le texte de la
/// licence accompagnent TOUTE distribution du logiciel de fonte ; servir la fonte par HTTP EN EST UNE.
///
/// LA RÈGLE N'EST PAS UNE ÉNUMÉRATION : *pour tout répertoire de `web/` dont un fichier de fonte est
/// PUBLIC, tout texte de licence de ce répertoire est PUBLIC*. Une fonte ajoutée demain sans sa licence
/// rougit ; une licence exemptée sans fonte publique rougit aussi (surface publique morte).
#[test]
fn p4_13_a_la_licence_accompagne_la_fonte_distribuee_dans_les_deux_sens() {
    fn est_une_licence(nom: &str) -> bool {
        let n = nom.to_ascii_uppercase();
        n.starts_with("OFL") || n.starts_with("LICENSE") || n.starts_with("LICENCE") || n.starts_with("COPYING")
    }
    let public = shell_ensemble_public();
    let mut fontes_publiques = 0usize;
    let mut exigees: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut a_visiter = vec![shell_web()];
    let mut repertoires_de_fontes: std::collections::BTreeSet<std::path::PathBuf> =
        std::collections::BTreeSet::new();
    while let Some(d) = a_visiter.pop() {
        for e in std::fs::read_dir(&d).expect("web/ se lit") {
            let p = e.expect("entrée de web/").path();
            if p.is_dir() {
                a_visiter.push(p);
                continue;
            }
            let rel = p.strip_prefix(shell_web()).expect("sous web/").to_string_lossy().into_owned();
            let servi = format!("/{rel}");
            let nom = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if (nom.ends_with(".woff2") || nom.ends_with(".woff") || nom.ends_with(".ttf") || nom.ends_with(".otf"))
                && public.contains(&servi)
            {
                fontes_publiques += 1;
                repertoires_de_fontes.insert(p.parent().expect("un fichier a un parent").to_path_buf());
            }
        }
    }
    assert!(
        fontes_publiques >= 4,
        "PLANCHER : {fontes_publiques} fonte(s) publique(s) — sans fonte distribuée, cette règle ne dirait rien."
    );
    for d in &repertoires_de_fontes {
        for e in std::fs::read_dir(d).expect("le répertoire de fontes se lit") {
            let p = e.expect("entrée").path();
            let nom = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if p.is_file() && est_une_licence(&nom) {
                let rel = p.strip_prefix(shell_web()).expect("sous web/").to_string_lossy().into_owned();
                exigees.insert(format!("/{rel}"));
            }
        }
    }
    assert!(
        !exigees.is_empty(),
        "CONTRÔLE POSITIF PERDU : aucun texte de licence trouvé à côté des fontes distribuées. Soit les \
         licences ont disparu du dépôt (et la distribution devient irrégulière), soit ce témoin ne sait \
         plus les reconnaître — dans les deux cas il ne prouve plus rien."
    );
    let retenues: Vec<&String> = exigees.difference(&public).collect();
    assert!(
        retenues.is_empty(),
        "FONTE DISTRIBUÉE, LICENCE RETENUE : {retenues:?} sont servis 401 alors que les fontes de leur \
         répertoire sont publiques. La SIL OFL 1.1 exige que l'avis de copyright et le texte de la licence \
         accompagnent la distribution du logiciel de fonte — les inscrire dans `LICENCES_DES_FONTES`."
    );
    let portees: std::collections::BTreeSet<String> =
        crate::surface_publique_du_shell::LICENCES_DES_FONTES.iter().map(|s| s.to_string()).collect();
    let mortes: Vec<&String> = portees.difference(&exigees).collect();
    assert!(
        mortes.is_empty(),
        "SURFACE PUBLIQUE MORTE : {mortes:?} sont exemptés alors qu'aucune fonte publique ne vit dans leur \
         répertoire. Une licence n'est publique que parce qu'une fonte l'est."
    );
}

/// (7) LE FILET DE SÉCURITÉ DU DOCUMENT EST AUTORISÉ PAR LA POLITIQUE QUE LE SERVEUR ÉMET.
///
/// LE DÉFAUT, MESURÉ SUR LE DÉMON LANCÉ PUIS ICI. `index.html` porte un unique `<script>` EN LIGNE, celui
/// qui « révèle après 6 s si l'init JS échoue » — c'est écrit dans le document, à la ligne au-dessus. La
/// politique servie posait `script-src 'self'` SANS `'unsafe-inline'` ni nonce : ce script n'a JAMAIS
/// tourné dans un navigateur. Le mode de panne qu'il couvre est EXACTEMENT celui que `P4.13-a` rend
/// atteignable — le graphe ES ne se lie pas — et le résultat était un écran DÉFINITIVEMENT MUET :
/// `<main>` masqué par la règle d'état, l'overlay de connexion `hidden` (c'est `showLogin(true)` qui le
/// lève, et il n'est jamais appelé), aucun message.
///
/// L'EMPREINTE EST RECALCULÉE DEPUIS LE DOCUMENT, PAS RELUE DANS LA CONSTANTE : une empreinte écrite au
/// démon et un script écrit dans `web/` divergent en silence, et la panne serait la même qu'avant.
#[tokio::test]
async fn p4_13_a_le_filet_de_securite_du_document_est_autorise_par_la_politique_servie() {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let html = shell_lire_du_web("index.html");
    // Les blocs `<script>` SANS `src` : ce sont ceux qu'une empreinte doit couvrir.
    let mut en_ligne: Vec<String> = Vec::new();
    let mut reste = html.as_str();
    while let Some(p) = reste.find("<script") {
        let apres = &reste[p..];
        let fin_balise = match apres.find('>') {
            Some(x) => x,
            None => break,
        };
        let ouvrante = &apres[..fin_balise];
        let corps_debut = p + fin_balise + 1;
        let fin = match reste[corps_debut..].find("</script>") {
            Some(x) => corps_debut + x,
            None => break,
        };
        if !ouvrante.contains("src=") {
            en_ligne.push(reste[corps_debut..fin].to_string());
        }
        reste = &reste[fin + 9..];
    }
    assert_eq!(
        en_ligne.len(),
        1,
        "CONTRÔLE POSITIF : le document doit porter EXACTEMENT un script en ligne (le filet des 6 s). \
         Il en porte {} — si le filet a disparu, ce témoin ne prouve plus rien ; s'il y en a deux, le \
         second n'est couvert par aucune empreinte et ne s'exécutera pas.",
        en_ligne.len()
    );
    assert!(
        en_ligne[0].contains("app-ready") && en_ligne[0].contains("6000"),
        "le script en ligne n'est plus le filet de sécurité des 6 s : {}",
        &en_ligne[0][..en_ligne[0].len().min(120)]
    );

    let (st, dbp) = router_test_state("shell-csp");
    let addr = shell_servir_le_web_livre(st).await;
    let (code, entetes, _) = shell_sonde_complete(addr, "/", "127.0.0.1").await;
    assert_eq!(code, 200, "la racine doit être servie pour qu'on puisse lire sa politique");
    let csp = shell_entete(&entetes, "content-security-policy")
        .expect("le serveur doit émettre une politique de contenu")
        .to_string();
    for bloc in &en_ligne {
        let empreinte = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(bloc.as_bytes()));
        let jeton = format!("'sha256-{empreinte}'");
        assert!(
            csp.contains(&jeton),
            "LE FILET DE SÉCURITÉ DU DOCUMENT EST INTERDIT PAR LA POLITIQUE SERVIE : `script-src` ne porte \
             ni `'unsafe-inline'`, ni nonce, ni l'empreinte {jeton} de ce script. Il ne s'exécutera dans \
             AUCUN navigateur, et le commentaire du document qui l'annonce sera faux — l'écran restera muet \
             quand le graphe de modules ne se lie pas. Politique servie : {csp}"
        );
    }
    assert!(
        !csp.contains("'unsafe-inline'") || !csp.split("script-src").nth(1).unwrap_or("").split(';').next().unwrap_or("").contains("'unsafe-inline'"),
        "`script-src` a gagné `'unsafe-inline'` : l'empreinte ne prouverait plus rien et l'injection de \
         script redeviendrait possible dans TOUT le document. Politique servie : {csp}"
    );
    ff_rm(&dbp);
}

/// (8) UNE AUTORITÉ NON DÉCLARÉE REÇOIT UNE PHRASE, PLUS HUIT OCTETS — ET LA PREUVE FAIT VARIER LE `Host`.
///
/// LE DÉFAUT DE LA PREUVE, PUIS CELUI DU PRODUIT. La preuve par service n'avait sondé que
/// `127.0.0.1`, `localhost` et `plume.localhost` : exactement les trois valeurs que la branche non stricte
/// de `host_guard` AUTO-ACCEPTE quelle que soit la configuration. Elle était donc structurellement aveugle
/// au second mur. Et ce mur, franchi par une autorité qu'il refuse, rendait « bad host » — huit octets,
/// la MÊME forme que le défaut qu'on venait de fermer, sur le chemin le plus banal qui soit : l'exploitant
/// bascule `PLUME_ADDR` de `127.0.0.1` à `0.0.0.0` pour atteindre la console depuis son poste et vise l'IP
/// du serveur. `host_guard` s'exécutant AVANT `auth_guard`, le correctif du shell n'est même pas atteint.
#[tokio::test]
async fn p4_13_a_une_autorite_non_declaree_recoit_une_phrase_et_pas_huit_octets() {
    let (mut st, dbp) = router_test_state("shell-hote");
    // L'ÉTAT DE TEST DÉCLARE UN HÔTE, et c'est une mesure en soi : il n'en déclarait AUCUN (`st.host` vide),
    // et un `PLUME_HOST` vide fait passer un `Host:` vide (`"".split(',')` rend `[""]`, qui s'apparie).
    // Le produit, lui, part de `plume.localhost` — mais un témoin qui mesure le second mur doit le mesurer
    // dans la posture où ce mur EXISTE, sinon il ne mesure que le cas dégénéré. Le premier contrôle
    // ci-dessous garde l'instrument : avec un hôte vide, `contains("")` répondrait toujours oui.
    st.host = Arc::new("plume.exemple.test".to_string());
    let hote_declare = st.host.to_string();
    assert!(
        !hote_declare.is_empty(),
        "INSTRUMENT : l'hôte déclaré est VIDE — `contains(\"\")` répondrait TOUJOURS oui et le contrôle \
         « le refus n'énumère pas les autorités acceptées » ne mesurerait rien."
    );
    let addr = shell_servir_le_web_livre(st).await;

    // (a) LES AUTORITÉS ACCEPTÉES LE RESTENT — sans ce sens, le témoin ne distinguerait pas un mur d'un mur
    //     fermé sur tout le monde.
    for h in ["127.0.0.1", "localhost", hote_declare.as_str()] {
        let (code, _, _) = shell_sonde_complete(addr, "/", h).await;
        assert_eq!(code, 200, "l'autorité acceptée `{h}` ne reçoit plus le shell");
    }

    // (b) UNE AUTORITÉ REFUSÉE PREND 421 — et la preuve FAIT VARIER le `Host`, ce qu'elle n'avait jamais fait.
    for h in ["192.0.2.10", "192.0.2.10:7000", "plume.autre.invalid", ""] {
        let (code, _, corps) = shell_sonde_complete(addr, "/", h).await;
        assert_eq!(
            code, 421,
            "l'autorité `{h}` n'est pas refusée : l'allowlist d'hôte ne protège plus du DNS-rebinding"
        );
        let phrase = String::from_utf8_lossy(&corps).into_owned();
        assert!(
            phrase.len() > 60,
            "REFUS MUET : l'autorité `{h}` reçoit {} octet(s) (« {phrase} »). C'est la forme exacte du \
             défaut que ce lot ferme — une phrase, pas un formulaire, et ici même pas une cause.",
            phrase.len()
        );
        assert!(
            phrase.contains("PLUME_HOST"),
            "le refus ne NOMME pas le réglage à changer : l'exploitant n'a rien à lire. Reçu : « {phrase} »"
        );
        // Il ne RÉFLÉCHIT pas l'autorité présentée, et ne LISTE pas celles qui passent.
        assert!(
            !phrase.contains("192.0.2.10") && !phrase.contains(hote_declare.as_str()),
            "le refus réfléchit l'entrée du client ou énumère les autorités acceptées : « {phrase} »"
        );
    }
    ff_rm(&dbp);
}

/// (9) LE BUDGET D'OCTETS BORNE LA SURFACE PUBLIQUE — SANS TOUCHER L'API, ET SANS GÊNER UN CHARGEMENT.
///
/// LE DÉFAUT. Les deux plafonds de `rate_limit` comptent des REQUÊTES et ont été dimensionnés quand un
/// anonyme coûtait douze octets. Mesuré AU BANC (poste de développement, binaire du dépôt lancé à la main,
/// rafales fabriquées — aucune installation n'est décrite) : depuis `P4.13-a`, la même requête anonyme
/// rend jusqu'à 167 542 octets et coûte 13,28 ms d'UC en debug — dont 95 % de `gzip`, dont ~6,5 ms
/// restent dus en release par arithmétique (`zlib` C niveau 6 sur les mêmes octets, au même banc). Soit
/// 63 × un 401, à plafonds INCHANGÉS : 92,7 Mo/s au banc pour une seule IP. Le rapport du lot bornait
/// l'échange aux DONNÉES ; le versant RESSOURCES n'était ni nommé ni mesuré.
///
/// CE QUE CE TÉMOIN TIENT, DANS LES TROIS SENS QUI COMPTENT : le budget par défaut ne gêne PAS un
/// chargement complet de la console (sinon on aurait fermé le login autrement) ; abaissé, il REFUSE et
/// son refus DIT quoi faire ; et il ne touche JAMAIS une route d'interface, dont le 401 reste un 401.
#[tokio::test]
async fn p4_13_a_le_budget_d_octets_borne_la_surface_publique_sans_toucher_l_api() {
    // (a) AU DÉFAUT DU PRODUIT, UN CHARGEMENT COMPLET PASSE. La population est l'EXIGENCE recalculée.
    {
        let (st, dbp) = router_test_state("shell-budget-defaut");
        assert_eq!(
            st.shell_octets_ip_max,
            crate::budget_du_shell_public::OCTETS_IP_MAX_DEFAUT,
            "l'état de test doit porter le DÉFAUT DU PRODUIT : un budget neutralisé ne mesurerait rien"
        );
        let addr = shell_servir_le_web_livre(st).await;
        let mut exiges = shell_fermeture_servie_depuis("app.js");
        exiges.extend(shell_references_directes());
        let mut refuses: Vec<String> = Vec::new();
        for c in &exiges {
            let (code, _) = shell_sonde(addr, c).await;
            if code != 200 {
                refuses.push(format!("{c} -> {code}"));
            }
        }
        assert!(
            refuses.is_empty(),
            "LE BUDGET REFUSE UN CHARGEMENT LÉGITIME : {refuses:?}. Une borne qui casse le cas nominal \
             rouvre exactement le défaut que ce lot ferme."
        );
        ff_rm(&dbp);
    }

    // (b) ABAISSÉ SOUS LE COÛT D'UN SEUL FICHIER, IL REFUSE — ET SON REFUS EST LISIBLE.
    {
        let (mut st, dbp) = router_test_state("shell-budget-serre");
        st.shell_octets_ip_max = 1; // une dette d'un octet suffit à dépasser : le 2e appel est refusé
        let addr = shell_servir_le_web_livre(st).await;
        let (premier, _, _) = shell_sonde_complete(addr, "/app.js", "127.0.0.1").await;
        assert_eq!(premier, 200, "la PREMIÈRE requête passe : on refuse sur une dette CONTRACTÉE, pas prédite");
        let (code, entetes, corps) = shell_sonde_complete(addr, "/app.js", "127.0.0.1").await;
        assert_eq!(code, 429, "le budget abaissé ne refuse pas : la borne est inerte");
        assert_eq!(
            shell_entete(&entetes, "retry-after"),
            Some("10"),
            "un refus sans `Retry-After` ne dit pas quand réessayer"
        );
        let phrase = String::from_utf8_lossy(&corps).into_owned();
        assert!(
            phrase.contains("PLUME_SHELL_OCTETS") && phrase.contains("console"),
            "le refus ne nomme ni la cause ni le réglage : un 429 nu sur un fichier du shell rend, lui \
             aussi, un écran muet. Reçu : « {phrase} »"
        );
        // (c) LA COMPRESSION NE DÉFAIT PAS LA FACTURATION. La couche de compression est PLUS EXTERNE que
        //     `rate_limit` : le client ne reçoit plus de `content-length` (corps découpé), mais le budget,
        //     lui, voit la réponse NON compressée. Sans ce sens, une borne pourrait être neutralisée en
        //     demandant simplement `gzip` — la façon la plus coûteuse de demander la même chose.
        let (code, entetes, _) = shell_sonde_gzip(addr, "/style.css").await;
        assert_eq!(
            code, 429,
            "le budget ne refuse plus dès que le client demande la compression : la facturation lirait la \
             réponse COMPRESSÉE (sans `content-length`) au lieu des octets bruts"
        );
        // ET LE CLIENT NE VOIT PLUS DE LONGUEUR : c'est la couche de compression qui la retire. Mesuré ici
        // pour que la limite de `p4_13_a_chaque_reponse_publique_est_facturable` soit ÉCRITE et non
        // supposée — ce témoin-là sonde SANS compression, donc il lit la longueur d'avant la couche, qui
        // est bien celle que `octets_de` facture ; il ne lit pas ce que le client reçoit.
        assert!(
            shell_entete(&entetes, "content-length").is_none(),
            "la réponse compressée porte encore une longueur : la mesure ci-dessus ne dirait plus rien de \
             la couche qui la retire"
        );

        // (d) L'API N'EST PAS TOUCHÉE : même seau épuisé, une route reste un 401, jamais un 429.
        let (code, _) = shell_sonde(addr, "/api/me").await;
        assert_eq!(
            code, 401,
            "le budget du SHELL déborde sur l'API : il ne doit peser que sur les chemins que la porte ouvre"
        );
        ff_rm(&dbp);
    }
}

/// (10) CHAQUE RÉPONSE PUBLIQUE EST FACTURABLE. Le budget lit `content-length` ; une réponse qui n'en
/// porterait pas serait servie GRATUITEMENT, et le trou serait invisible. Il est donc MESURÉ, pas supposé
/// — et la longueur déclarée doit être celle du fichier du dépôt, sinon on facturerait autre chose que ce
/// qu'on sert.
#[tokio::test]
async fn p4_13_a_chaque_reponse_publique_est_facturable() {
    let (st, dbp) = router_test_state("shell-facturable");
    let addr = shell_servir_le_web_livre(st).await;
    let public = shell_ensemble_public();
    assert!(public.len() >= 60, "PLANCHER : {} chemins publics seulement", public.len());
    let mut muets: Vec<String> = Vec::new();
    for c in &public {
        let (code, entetes, _) = shell_sonde_complete(addr, c, "127.0.0.1").await;
        let attendu = std::fs::metadata(shell_fichier_du_chemin(c)).expect("le fichier exempté se lit").len();
        match shell_entete(&entetes, "content-length").and_then(|v| v.parse::<u64>().ok()) {
            None => muets.push(format!("{c} -> {code} sans content-length")),
            Some(n) if n != attendu => muets.push(format!("{c} -> content-length {n} pour {attendu} octets")),
            Some(_) => {}
        }
    }
    assert!(
        muets.is_empty(),
        "DES RÉPONSES PUBLIQUES NE SONT PAS FACTURABLES : {muets:?}. `budget_du_shell_public::octets_de` \
         facture zéro sur une réponse sans `content-length` : ces chemins échapperaient à la borne."
    );
    ff_rm(&dbp);
}
