// =================================================================================================
// `S31` (restes de la garde `spool_toute_ecriture_passe_par_publier`) — FORMES FORCÉES de l'issue et du
// détachement, jugées par le MÊME lecteur que la garde (`refus` et `NOMINAL`, rendus `pub(super)`).
//
// VU (sondes du vérificateur sur le blob 9c2e1cb5, rejouées ici) : ACCEPTÉES alors que l'issue de
// `spool::publier` est détachée ou abandonnée —
//   * une fermeture `async` sans accolades dont le corps est une affectation (`let f = async move || r =
//     …publier(…).await;` puis `tokio::spawn(f())`) : la doc de la garde la disait refusée ;
//   * une fermeture `async` dont la liste de paramètres contient `{…}` ou `;` (`|S { a, .. }: S|`,
//     `|_x: [u8; 2]|`) : la tête de l'accolade était coupée dans les paramètres, avant `async` ;
//   * `'\''` collé à `')'` dans un `spawn` : le blanchisseur partagé laisse un `'` orphelin qui libère le `)`
//     et dépile le cadre du `spawn` ;
//   * un abandon en `_` derrière `return`, `let r =` ou un `=` chaîné (`return _ =`, `let r = _ =`, `x = _ =`) :
//     le lieu n'était lu qu'après le dernier `let` ou `=>`.
// Et trois mutants de la garde restaient verts : E2 (`sans_cfg_test` sans `(`/`)`), G4 (`p == "return"` lu
// en `starts_with`), H2 (branche `#![` de `sans_attributs` retirée). Chacun a ici sa forme qui le distingue.
//
// MUTANTS JOUÉS (par variable de mutation, retirés avant le commit) : R4_ASYNC (refus du mot `async` retiré), R4_PARAMS
// (liste de paramètres non sautée), R4_PIPE_PV (l'ouvrant `|` cherché au-delà d'un `;`), R4_QUOTE (`'\''` non
// neutralisé), R4_RETURN (lieu non lu après `return`), R4_EGAL (lieu non lu après un `=` intermédiaire), et les
// trois mutants E2, G4, H2 réinjectés : chacun rougit au moins un des témoins ci-dessous.
// Seconde passe (mutants d'un vérificateur restés verts, retirés de même) : premier `=` intermédiaire au lieu
// du dernier (`x = y = _ =` accepté), mot `return` non borné à droite (`let return_code =` refusé), et dans
// `ouverture_des_parametres` le `|` fermant cherché au-delà d'un `;` (P2) ou d'un `{`/`}` (P3), l'ouvrant
// cherché au-delà d'un `{` non apparié (P6) : chacun rougit au moins un témoin. L'arrêt du `|` fermant sur un
// `(`/`[` ouvrant (P4) est ÉQUIVALENT : ce groupe encore ouvert pose déjà un cadre détachant dans
// `contexte_detache`, et le seul consommateur ne lit que `.is_some()`.
// Troisième passe : le saut des paramètres introduisait un faux refus RÉALISTE (sondes FP1 à FP7 d'un
// vérificateur) — le `|` d'un motif de bras ou d'un « ou » lu comme liste de paramètres, la tête couvrant un
// `async` d'un bras précédent. Correctif : arrêt du `|` fermant sur `=>` (mutant C3_FAT) et ouvrant retenu
// seulement derrière `move` / `async` (mutant C3_FL), épinglés par
// `les_bras_et_les_ou_qui_suivent_un_async_restent_acceptes` ; le comptage de `)` / `]` en remontant (mutant
// C_P1) par deux fermetures `async` à type de retour parenthésé ; P2 et P3 rejoués (P3 par un témoin sans
// `=>`, l'ancien étant neutralisé par l'arrêt sur `=>`). Sous l'exigence `move` / `async`, l'arrêt de
// l'ouvrant sur `;` (R4_PIPE_PV) et sur un `{` non apparié (P6, P6b) devient ÉQUIVALENT (voir la doc de la
// garde) : leurs anciens témoins restent comme voisines acceptées.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ceux de la garde (régime de base `durable:false`, détachement un niveau
// plus haut, ré-exports, sites `HORS_RECEPTION` non jugés sur leur conformité) ; voir sa doc. Deux restes du
// côté LÂCHE sont épinglés ACCEPTÉS, pas fermés (`les_restes_laches_declares_sont_encore_acceptes`) : la
// fermeture `async` dont le type de retour contient `{`/`}` (bloc constant), détachée ; le `=` dans
// l'annotation de type d'un lieu en `_` (`let _r: Box<dyn Iterator<Item = u8>> = …`), aucune forme connue qui
// compile pour l'issue de `publier` ; la fermeture `async` sans accolades à corps `if … else { …publier… }`
// (ou `else if`), détachée, antérieure au lot.
// =================================================================================================

mod spool_publier_formes_forcees {
    use super::spool_toute_ecriture_passe_par_publier::{refus, NOMINAL};

    const APPEL: &str = "    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {\n        Ok(p) => ok(p),\n        Err(_) => ko(),\n    }\n";
    const PB: &str = "crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync)";

    fn variante(nom: &str, forme: &str) -> String {
        let v = NOMINAL.replace(APPEL, forme);
        assert_ne!(v, NOMINAL, "INSTRUMENT : substitution sans effet ({nom})");
        v
    }

    /// Chaque forme forcée qui détache ou abandonne l'issue est refusée « issue non attendue » ; les acceptées
    /// sont TOUTES nommées.
    #[test]
    fn les_formes_forcees_d_abandon_ou_de_detachement_rougissent() {
        let pb = PB;
        let rouges = [
            ("fermeture async sans accolades, corps en affectation", format!("    let mut r = Ok(0);\n    let f = async move || r = {pb}.await;\n    tokio::spawn(f());\n    ok(())\n")),
            ("fermeture async sans accolades, corps nu (voisine)", format!("    let f = async move || {pb}.await;\n    tokio::spawn(f());\n    ok(())\n")),
            ("fermeture async à paramètre motif de structure", format!("    let f = async move |S {{ a, .. }}: S| {{\n        let r = {pb}.await;\n        trace(r, a);\n    }};\n    tokio::spawn(f(s));\n    ok(())\n")),
            ("fermeture async à paramètre tableau", format!("    let f = async move |_x: [u8; 2]| {{\n        let r = {pb}.await;\n        trace(r);\n    }};\n    tokio::spawn(f([0, 0]));\n    ok(())\n")),
            ("fermeture async à paramètre simple (voisine)", format!("    let f = async move |_x: u8| {{\n        let r = {pb}.await;\n        trace(r);\n    }};\n    tokio::spawn(f(0));\n    ok(())\n")),
            ("'\\'' collé dans un spawn", format!("    tokio::spawn(async move {{\n        let _c = ['\\'',')'];\n        let _d = ['\\'',')'];\n        let r = {pb}.await;\n        trace(r);\n    }});\n    ok(())\n")),
            ("'\\'' formaté dans un spawn (voisine)", format!("    tokio::spawn(async move {{\n        let _c = ['\\'', ')'];\n        let _d = ['\\'', ')'];\n        let r = {pb}.await;\n        trace(r);\n    }});\n    ok(())\n")),
            ("return _ =", format!("    return _ = {pb}.await;\n")),
            ("let r = _ =", format!("    let r = _ = {pb}.await;\n    rendre(r)\n")),
            ("x = _ =", format!("    let x;\n    x = _ = {pb}.await;\n    rendre(x)\n")),
            ("x = y = _ = (deux `=` intermédiaires : le dernier compte)", format!("    let y;\n    let x;\n    x = y = _ = {pb}.await;\n    rendre(x)\n")),
            ("fermeture async à type de retour sans accolades (voisine du reste lâche)", format!("    let f = async move |x: u8| -> Foo<1> {{\n        let r = {pb}.await;\n        trace(r, x);\n    }};\n    tokio::spawn(f(0));\n    ok(())\n")),
            ("return n == (comparaison derrière return)", format!("    let n = Ok(0);\n    return n == {pb}.await;\n")),
            ("fermeture async à paramètre tableau et type de retour parenthésé (`)`/`]` comptés en remontant)", format!("    let f = async move |_x: [u8; 2]| -> Result<(), E> {{\n        let r = {pb}.await;\n        trace(r);\n        Ok(())\n    }};\n    tokio::spawn(f([0, 0]));\n    ok(())\n")),
            ("fermeture async à paramètre motif de structure et retour en tuple", format!("    let f = async move |S {{ a, .. }}: S| -> (u8, u8) {{\n        let r = {pb}.await;\n        trace(r, a);\n        (0, 0)\n    }};\n    tokio::spawn(f(s));\n    ok(())\n")),
            ("fermeture async sans accolades, publier dans la branche if (voisine du reste lâche)", format!("    let f = async move || if c {{\n        match {pb}.await {{\n            Ok(p) => ok(p),\n            Err(_) => ko(),\n        }}\n    }} else {{ ko() }};\n    tokio::spawn(f());\n    ok(())\n")),
            ("#[cfg(test)] static à fermeture dans un spawn", format!("    tokio::spawn(async move {{\n        #[cfg(test)] static A: Lazy<u8> = Lazy::new(|| {{ 0 }});\n        #[cfg(test)] static B: Lazy<u8> = Lazy::new(|| {{ 0 }});\n        let r = {pb}.await;\n        trace(r);\n    }});\n    ok(())\n")),
        ];
        let mut acceptees = Vec::new();
        for (nom, forme) in &rouges {
            let r = refus(&variante(nom, forme));
            if !r.contains("[recu_post]") || !r.contains("issue non attendue") {
                acceptees.push(format!("{nom} : {r:?}"));
            }
        }
        assert!(acceptees.is_empty(), "forme(s) forcée(s) acceptée(s) : {acceptees:#?}");
    }

    /// Les voisines qui CONSOMMENT l'issue dans le gestionnaire restent acceptées : le refus du mot `async` est
    /// borné (`async_r` n'est pas `async`), le lieu lu est celui de la dernière affectation (`let _u = r = …` :
    /// l'issue est dans `r`), un attribut interne `#![…]` devant `match` est retiré, et l'ouvrant `|` d'une
    /// fermeture n'est pas cherché au-delà de l'instruction (un `if a | b {` qui suit une fermeture `async` ne
    /// devient pas `async`).
    #[test]
    fn les_voisines_qui_consomment_l_issue_restent_acceptees() {
        let pb = PB;
        let controles = [
            ("let async_r =", format!("    let async_r = {pb}.await;\n    rendre(async_r)\n")),
            ("let _u = r = (lieu de la dernière affectation)", format!("    let mut r = Ok(0);\n    let _u = r = {pb}.await;\n    rendre(r)\n")),
            ("#![allow(…)] puis match dans un bloc", format!("    {{\n        #![allow(unreachable_patterns)]\n        match {pb}.await {{\n            Ok(p) => ok(p),\n            Err(_) => ko(),\n        }}\n    }}\n")),
            ("let return_code = (mot `return` borné à droite)", format!("    let return_code = {pb}.await;\n    rendre(return_code)\n")),
            ("if c après une fermeture async à corps nu (`|` fermant jamais cherché au-delà d'un `;`)", format!("    let f = async move |x| trace(x);\n    if c {{\n        match {pb}.await {{\n            Ok(p) => ok(p),\n            Err(_) => ko(),\n        }}\n    }} else {{\n        ko()\n    }}\n")),
            ("else après un bras à fermeture async (`|` fermant jamais cherché au-delà d'un `{` ou `}`)", format!("    match k {{\n        0 => async move |a| a,\n        _ => if c {{ trace() }} else {{\n            match {pb}.await {{\n            Ok(p) => ok(p),\n            Err(_) => ko(),\n        }}\n        }},\n    }}\n")),
            ("else dans un champ de structure après une fermeture async (`|` fermant jamais cherché au-delà d'un `{` ou `}`, sans `=>`)", format!("    let s = S {{ f: async move |a| a, g: if c {{ trace() }} else {{\n        match {pb}.await {{\n            Ok(p) => ok(p),\n            Err(_) => ko(),\n        }}\n    }} }};\n    rendre(s)\n")),
            ("A | B => après un bloc à fermeture async (ouvrant jamais cherché au-delà d'un `{` non apparié)", format!("    if c {{ let g = async move |q| q | y }}\n    match x {{\n        A | B => {{\n            match {pb}.await {{\n            Ok(p) => ok(p),\n            Err(_) => ko(),\n        }}\n        }}\n    }}\n")),
            ("if a | b après une fermeture async", format!("    let f = async move || trace();\n    if a | b {{\n        match {pb}.await {{\n            Ok(p) => ok(p),\n            Err(_) => ko(),\n        }}\n    }} else {{\n        ko()\n    }}\n")),
        ];
        let mut refusees = Vec::new();
        for (nom, forme) in &controles {
            let r = refus(&variante(nom, forme));
            if !r.is_empty() {
                refusees.push(format!("{nom} : {r:?}"));
            }
        }
        assert!(refusees.is_empty(), "voisine(s) conforme(s) refusée(s) : {refusees:#?}");
    }

    /// Faux refus RÉALISTES que le saut de la liste de paramètres introduisait (sondes FP1 à FP7 d'un
    /// vérificateur) : le `|` d'un motif de bras (`K::C | K::D => {`) ou d'un « ou » (`if c | d {`) était pris
    /// pour le fermant d'une liste de paramètres, le `|` d'un bras ou d'une condition PRÉCÉDENTS pour
    /// l'ouvrant, et la tête couvrait alors un `async` déjà fermé : un `publier` conforme du bras courant
    /// était refusé « issue non attendue ». Le `|` fermant n'est plus cherché au-delà d'un `=>`, l'ouvrant
    /// n'est retenu que précédé de `move` ou `async`. FP3 et FP4 sont les contrôles (acceptés avant comme
    /// après) ; la dernière, forcée, distingue l'arrêt sur `=>` seul (un bras qui rend une fermeture `async` à
    /// paramètre motif de structure : son ouvrant suit bien `move`).
    #[test]
    fn les_bras_et_les_ou_qui_suivent_un_async_restent_acceptes() {
        let m = "match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {\n                Ok(p) => ok(p),\n                Err(_) => ko(),\n            }";
        let pb = PB;
        let controles = [
            ("FP1 bras A | B qui détache un async, puis C | D", format!("    match k {{\n        K::A | K::B => {{ tokio::spawn(async move {{ trace().await }}); ok(()) }}\n        K::C | K::D => {{\n            {m}\n        }}\n    }}\n")),
            ("FP2 bras A | B, bras C qui détache un async, puis D | E", format!("    match k {{\n        K::A | K::B => ok(()),\n        K::C => {{ tokio::spawn(async move {{ trace().await }}); ok(()) }}\n        K::D | K::E => {{\n            {m}\n        }}\n    }}\n")),
            ("FP3 contrôle : bras A sans `|` qui détache un async, puis C | D", format!("    match k {{\n        K::A => {{ tokio::spawn(async move {{ trace().await }}); ok(()) }}\n        K::C | K::D => {{\n            {m}\n        }}\n    }}\n")),
            ("FP4 contrôle : bras A | B sans async, puis C | D", format!("    match k {{\n        K::A | K::B => {{ trace(); ok(()) }}\n        K::C | K::D => {{\n            {m}\n        }}\n    }}\n")),
            ("FP5 bras A | B sans accolades qui détache un async, puis C | D à `let r =`", format!("    match k {{\n        K::A | K::B => tokio::spawn(async move {{ trace().await }}).map(|_| ok(())).unwrap(),\n        K::C | K::D => {{\n            let r = {pb}.await;\n            rendre(r)\n        }}\n    }}\n")),
            ("FP6 if a | b qui détache un async, puis if c | d", format!("    if a | b {{ tokio::spawn(async move {{ trace().await }}); }}\n    if c | d {{\n        {m}\n    }} else {{\n        ko()\n    }}\n")),
            ("FP7 bras A | B qui détache, bras X | Y, puis C sans `|`", format!("    match k {{\n        K::A | K::B => tokio::spawn(async move {{ trace().await }}).map(|_| ok(())).unwrap(),\n        K::X | K::Y => ok(()),\n        K::C => {{\n            {m}\n        }}\n    }}\n")),
            ("bras qui rend une fermeture async à paramètre motif de structure, puis C (arrêt sur `=>`)", format!("    match k {{\n        K::A => async move |S {{ a, .. }}: S| a,\n        K::C => {{\n            {m}\n        }}\n    }}\n")),
        ];
        let mut refusees = Vec::new();
        for (nom, forme) in &controles {
            let r = refus(&variante(nom, forme));
            if !r.is_empty() {
                refusees.push(format!("{nom} : {r:?}"));
            }
        }
        assert!(refusees.is_empty(), "publier conforme refusé derrière un bras ou un « ou » : {refusees:#?}");
    }

    /// Restes du côté LÂCHE, DÉCLARÉS dans la doc de la garde et épinglés tels qu'ils sont : ces formes
    /// détachent ou abandonnent l'issue et sont pourtant ACCEPTÉES. Si ce témoin rougit parce que le lecteur
    /// les refuse désormais, déplacer la forme dans `les_formes_forcees_d_abandon_ou_de_detachement_rougissent`
    /// et retirer le reste de la doc.
    ///   * fermeture `async` dont le type de retour contient `{`/`}` (bloc constant) : l'arrêt du `|` fermant
    ///     sur `{`/`}` coupe sa tête avant `async` (la voisine `-> Foo<1>` est refusée) ;
    ///   * `=` dans l'annotation de type d'un lieu en `_` : le lieu est lu après ce `=` (`u8>>`), pas sur `_r` ;
    ///   * fermeture `async` sans accolades à corps `if c { … } else { …publier… }` (ou `else if`) : l'instruction
    ///     commence au `{` du `else`, préfixe `match`, cadre `async` du `if c {` déjà dépilé (la voisine qui
    ///     publie dans la branche `if` est refusée).
    #[test]
    fn les_restes_laches_declares_sont_encore_acceptes() {
        let pb = PB;
        let laches = [
            ("fermeture async à type de retour entre accolades, détachée", format!("    let f = async move |x: u8| -> Foo<{{ 1 }}> {{\n        let r = {pb}.await;\n        trace(r, x);\n    }};\n    tokio::spawn(f(0));\n    ok(())\n")),
            ("`=` dans l'annotation de type d'un lieu en `_`", format!("    let _r: Box<dyn Iterator<Item = u8>> = {pb}.await;\n    ok(())\n")),
            ("fermeture async sans accolades, publier dans la branche else, détachée", format!("    let f = async move || if c {{ trace() }} else {{\n        match {pb}.await {{\n            Ok(p) => ok(p),\n            Err(_) => ko(),\n        }}\n    }};\n    tokio::spawn(f());\n    ok(())\n")),
            ("fermeture async sans accolades, publier dans la branche else if, détachée", format!("    let f = async move || if c {{ trace() }} else if d {{\n        match {pb}.await {{\n            Ok(p) => ok(p),\n            Err(_) => ko(),\n        }}\n    }} else {{ ko() }};\n    tokio::spawn(f());\n    ok(())\n")),
        ];
        let mut refusees = Vec::new();
        for (nom, forme) in &laches {
            let r = refus(&variante(nom, forme));
            if !r.is_empty() {
                refusees.push(format!("{nom} : {r:?}"));
            }
        }
        assert!(refusees.is_empty(), "reste lâche déclaré désormais refusé (mettre à jour la doc et le ranger parmi les rouges) : {refusees:#?}");
    }
}
