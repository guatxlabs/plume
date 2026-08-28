//! Réponse / actions (responder) : validation stricte (`action_valid`/`action_valid_ctx`/
//! `action_kind_valid`/`action_kind_destructive`), CRUD/approbation des actions, résolution de
//! commande (`which`/`action_command`), amorçage nft (`ensure_nft_blocklist`) et l'exécuteur root
//! `respond_run`. Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

/// UN SEUL NOM RÉPONDAIT À DEUX QUESTIONS, ET LA PROMESSE NE PORTE QUE SUR L'UNE (`P4.7-b`).
///
/// `P4.7-a` a extrait « ceci est une adresse » de `action_valid_ctx` et l'a donnée à
/// `allowlist_stop_service`, sous l'en-tête « UNE SEULE DÉFINITION, DEUX LECTEURS ». CET EN-TÊTE
/// ÉTAIT FAUX DE DEUX FAÇONS, mesurées le 2026-08-28 :
///   * il n'y avait pas UNE définition côté démon mais TROIS — `Slot::target_ok` recopiait les
///     quatre clauses de `ban_ip` mot pour mot, les trois de `stop_service` mot pour mot, et une
///     TROISIÈME version FAUSSE du plancher de PID (`p > 0` là où l'amont exige `p > 300`). Le
///     premier jet de ce lot n'en a supprimé qu'une et a ÉCRIT que les deux autres étaient « plus
///     étroites » : c'était l'inverse. Les trois APPELLENT désormais, il n'y a plus de miroir ;
///   * et surtout la fonction unique répondait à DEUX questions qui n'ont pas la même réponse :
///       (Q1) « ce produit sait-il BANNIR cette cible ? » — une borne de CAPACITÉ (v1 : IPv4, parce
///            que c'est ce que `nft`/`cscli`/`fail2ban` reçoivent par le chemin hôte) ;
///       (Q2) « cette LIGNE est-elle une adresse, c'est-à-dire du contenu de l'AUTRE politique ? »
///            — une CLASSIFICATION, et c'est ELLE SEULE que le lot promet commune avec
///            `collectors/respond.sh` (`is_ip`).
/// Les confondre coûtait exactement ce que `P4.7-a` prétendait fermer : une liste d'épargne écrite en
/// IPv6 hexadécimale pure (`2001:db8::1`, `::1`) ne portait pas de point, n'était donc pas reconnue
/// comme une adresse, et TOMBAIT dans `services.push(...)` — lue comme une liste de NOMS DE SERVICE,
/// sans un mot, pendant que le fichier affirmait à l'exploitant que « les deux lecteurs REFUSENT le
/// contenu de l'autre politique ». Les deux fonctions ci-dessous séparent les deux questions.
///
/// (Q1) LA BORNE D'ENFORCEMENT — CE QUE CE PRODUIT SAIT BANNIR. Corps INCHANGÉ, clause pour clause :
/// c'est un TÉMOIN, pas une intention. Élargir ici enverrait une IPv6 vers `nft add element inet
/// plume blocklist` et vers `collectors/respond.sh`, dont ni les gabarits ni les jeux d'ensembles
/// n'ont été lus ; ce lot ne touche donc PAS à ce qui part vers un pare-feu.
/// LA BORNE EST DITE : elle accepte des chaînes qui ne sont pas des adresses (`.`, `1.2.3.4.5`,
/// `999.999.999.999`, `cafe.beef`) et refuse toute IPv6 sans point. Le geste qui la fermerait existe
/// à 370 lignes d'ici — `netban_validate_ip`, `parse::<IpAddr>()` + canonicalisation — mais il
/// applique `ip_is_protected` et la garde d'engagement INCONDITIONNELLEMENT, là où `action_valid_ctx`
/// ne les applique qu'au BAN (l'unban reste permis) et reçoit `engagement_on` par injection : le
/// déplacer tel quel casserait la garde M2 sur l'unban. Ce n'est donc pas ce lot.
pub(crate) fn cible_de_ban_acceptee(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 45
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
        && s.contains('.')
}

/// (Q2) LE CLASSIFICATEUR — « CETTE LIGNE EST-ELLE UNE ADRESSE ? », LA SEULE QUESTION QUE LES DEUX
/// LECTEURS SE PROMETTENT EN COMMUN. Il ne décide de RIEN qui parte vers un pare-feu : il sert
/// uniquement à reconnaître qu'un fichier porte l'AUTRE politique, et son seul effet est un REFUS.
///
/// LA DISJONCTION `.` OU `:` N'EST PAS UNE INVENTION — C'EST UN DÉPLACEMENT, PROUVÉ PAR EMPREINTE.
/// Le même charset avec la BONNE disjonction est déjà écrit dans le produit, du côté qui OBSERVE :
/// `extract_src_ip` (`daemon/src/ingest/mod.rs`) emploie `all(hex|'.'|':')` puis `any('.' ou ':')`,
/// sous le commentaire « un IPv6 nu `2001:db8:...` doit rester entier ». Le démon INGÈRE donc des
/// `src_ip` IPv6 avec ce prédicat-ci, et sa moitié qui RÉPOND ne les reconnaissait pas : la
/// divergence n'était pas seulement entre le démon et l'hôte, elle était interne au démon.
///
/// LA BORNE DE LONGUEUR A ÉTÉ RETIRÉE, ET C'EST MESURÉ, PAS ESTHÉTIQUE. `45` est la longueur de
/// `0000:0000:0000:0000:0000:ffff:255.255.255.255` : c'est une borne d'ARGUMENT, elle appartient à
/// (Q1). La garder ici laissait un trou : `dead:beef:cafe:cafe:cafe:cafe:cafe:cafe:cafe:cafe`
/// (49 caractères) est ACCEPTÉ par `is_ip` de `collectors/respond.sh` (mesuré) et aurait été poussé
/// ici comme nom de service — la SEULE ligne du corpus partagé que les DEUX lecteurs auraient
/// acceptée en silence. Sans la borne, tout ce que l'agent lit comme adresse, le démon le refuse.
///
/// CE QU'IL NE PRÉTEND PAS ÊTRE : il n'est ni nécessaire ni suffisant pour « ceci est une adresse
/// valide ». Il est DÉLIBÉRÉMENT plus large que `is_ip` (il reconnaît en plus `::ffff:192.0.2.1`,
/// `cafe.beef`, `1.2.3.4.5`, `.`), et cette largeur va TOUJOURS dans la direction protectrice : elle
/// ne fait que REFUSER davantage de listes, donc autoriser MOINS de `stop_service`. La direction
/// inverse — une ligne d'adresse prise pour un nom de service — est celle qui était ouverte.
/// LIMITE ÉCRITE, INCHANGÉE DEPUIS `P4.7-a` : un nom d'unité systemd composé uniquement de chiffres,
/// de `a`-`f`, de points et de deux-points serait pris pour une adresse et ferait refuser la liste.
/// Aucun suffixe d'unité connu ne le permet (`.service`, `.socket`, `.timer`, `.mount`, `.device`,
/// `.target`, `.slice`, `.scope`, `.path`, `.swap` portent tous une lettre hors de l'alphabet
/// hexadécimal), et le refus va dans la direction protectrice — mais la borne est dite.
pub(crate) fn ressemble_a_une_adresse(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
        && s.chars().any(|c| c == '.' || c == ':')
}

/// (Q1 bis) LES DEUX AUTRES BORNES DE CAPACITÉ, EXTRAITES POUR LA MÊME RAISON QUE `cible_de_ban_acceptee`
/// — ET PARCE QUE LE COMMENTAIRE QUI LES DÉCRIVAIT ÉTAIT FAUX (`P4.7-b`, reprise du 2026-08-28).
/// Le premier jet de ce lot a supprimé UNE copie (`Slot::target_ok(Slot::Ip)`) et laissé les deux
/// autres debout, sous une phrase neuve qui affirmait : « `Slot::Pid`/`Slot::Service` restent des
/// miroirs de charset écrits ici — plus étroits que la validation amont (`p > 0` contre `p > 300`),
/// donc jamais plus permissifs qu'elle. » MESURÉ : c'est l'INVERSE. `p > 0` accepte 1..=300, que
/// `p > 300` REFUSE ; le miroir était donc STRICTEMENT PLUS PERMISSIF que ce qu'il prétendait
/// refléter, exactement sur la propriété qui justifie l'existence de `target_ok` (« re-vérifié ici
/// pour que le rendu soit sûr même appelé isolément »). Et `Slot::Service` n'était pas « plus
/// étroit » non plus : une COPIE VERBATIM des trois clauses de `action_valid_ctx`.
/// Les deux bornes vivent désormais ICI, en un seul exemplaire chacune, et les DEUX lecteurs les
/// APPELLENT. Un miroir ne peut plus dériver parce qu'il n'y a plus de miroir.
/// AUCUN CHEMIN LIVRÉ NE CHANGE DE VERDICT : `respond_run` appelle `action_valid` (l. ~919) AVANT
/// `platform_command` (l. ~944), donc un PID de 1..=300 était déjà refusé en amont. Ce qui change
/// est le rendu appelé ISOLÉMENT — c'est-à-dire précisément le cas que la phrase promettait sûr.
pub(crate) fn cible_de_kill_acceptee(s: &str) -> bool {
    matches!(s.parse::<i64>(), Ok(p) if p > 300)
}

/// (Q1 ter) La borne de `stop_service` : le charset d'un nom d'unité, en UN seul exemplaire.
/// Elle ne dit RIEN de l'allowlist (`allowlist_stop_service`), qui est un second verrou : celle-ci
/// borne la FORME de la cible, celle-là dit quels noms l'exploitant a autorisés.
pub(crate) fn cible_de_stop_service_acceptee(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
}

/// LA FORME QUE CE PRODUIT SAIT PORTER POUR CETTE ACTION — la dispatch par `kind` des trois bornes
/// ci-dessus, c'est-à-dire `Slot::target_ok` vue par le NOM de l'action plutôt que par son slot.
/// ELLE SÉPARE DEUX REFUS QUE `action_valid` REND SOUS UN MÊME `Err`, et cette séparation porte une
/// conséquence mesurable dans `run_playbooks` (`P4.7-d`) :
///   * FORME NON PORTABLE (`false` ici) — le produit ne sait pas exprimer cette cible : une `src_ip`
///     IPv6 que l'ingestion a gardée ENTIÈRE, un PID sous le plancher de sûreté. Une riposte
///     sélectionnée est alors jetée, et c'est une PERTE DE COUVERTURE : elle se compte.
///   * POLITIQUE (`true` ici, et `action_valid` refuse quand même) — IP protégée, engagement actif.
///     C'est délibéré, écrit, et la détection continue : rien n'est perdu, rien ne se compte, sans
///     quoi le bilan du tick deviendrait un compteur d'IP privées.
pub(crate) fn cible_de_forme_portable(kind: &str, target: &str) -> bool {
    match Slot::for_kind(kind) {
        Some(slot) => slot.target_ok(target),
        None => false,
    }
}

/// L'ALLOWLIST DE `stop_service` REJETTE CE QUI N'EST PAS DE SA POLITIQUE (`P4.7-a`).
///
/// LE DÉFAUT, MESURÉ SUR L'ARBRE le 2026-08-27. `/etc/plume/responder.allow` est écrit par les DEUX
/// installateurs et lu par DEUX composants, avec deux significations qui ne se recouvrent pas : ici,
/// des NOMS DE SERVICE autorisés pour `stop_service` ; côté agent (`collectors/respond.sh`), des
/// ADRESSES à NE JAMAIS bannir. Les deux installateurs ne créent le fichier que s'il est ABSENT, si
/// bien que sur une machine à la fois centrale et agent, le second hérite du contenu du premier.
/// De ce côté-ci, la conséquence n'est pas dangereuse — un nom de service ne figure pas dans une
/// liste d'adresses, donc tout `stop_service` était BLOQUÉ — mais elle était MAL DITE : le refus
/// annonçait « ce service n'est pas dans l'allowlist » alors que le fichier ne parlait pas de
/// services du tout. Un exploitant ajoutait alors son service à une liste que ce lecteur-ci n'aurait
/// de toute façon jamais dû lire.
///
/// CE QUE CETTE FONCTION REND :
///   `Ok(services)`  la liste a été lue et ne porte QUE des noms de service (commentaires et lignes
///                   vides écartés — une liste par défaut, telle que l'installateur la pose, est
///                   donc une liste VIDE et non un refus : aucun `stop_service` n'est autorisé, ce
///                   qui est le défaut voulu) ;
///   `Err(cause)`    la liste n'a pas pu être lue, OU elle porte l'autre politique. Les deux sont
///                   des NON-RÉPONSES, elles ne se rendent pas comme « ce service n'y est pas ».
///
/// LE CRITÈRE EST DÉRIVÉ, PAS ÉNUMÉRÉ : une ligne est « de l'autre politique » quand elle porte la
/// FORME d'une ADRESSE au sens de `ressemble_a_une_adresse` — le CLASSIFICATEUR partagé avec
/// `collectors/respond.sh` —, éventuellement habillée d'un préfixe CIDR (`/24`) ou d'un identifiant
/// de zone (`%eth0`), formes qu'un exploitant écrit spontanément dans une liste d'adresses. Aucun nom
/// d'unité systemd n'a cette forme : un suffixe (`.service`, `.socket`, `.timer`, `.mount`…) porte
/// des lettres hors de l'alphabet hexadécimal.
/// `P4.7-b` : le classificateur reconnaît DÉSORMAIS toute la famille IPv6 (`2001:db8::1`, `::1`,
/// `fe80::1`, et les formes zonée/CIDR par la tête). Avant, elles tombaient dans `services.push(...)`
/// SANS un mot — le défaut même que cette fonction existe pour fermer, sur la moitié de la famille
/// des adresses. La borne et les limites du classificateur sont écrites à sa définition.
pub(crate) fn allowlist_stop_service(lecture: std::io::Result<String>) -> Result<Vec<String>, String> {
    let contenu = match lecture {
        Ok(c) => c,
        Err(e) => return Err(format!("lecture impossible ({e}) — aucun arrêt de service n'est autorisé tant que la liste n'est pas lisible")),
    };
    let mut services = Vec::new();
    for ligne in contenu.lines() {
        let l = ligne.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        // La TÊTE de la ligne : ce qui précède un préfixe CIDR (`/24`, `/32`) OU un identifiant de
        // zone (`%eth0`). Les deux sont des habillages qu'un exploitant écrit spontanément AUTOUR
        // d'une adresse dans une liste d'adresses, et aucun nom d'unité systemd n'en porte. Le `%`
        // est ajouté par `P4.7-b` : `fe80::1%eth0` est REFUSÉ par le lecteur d'hôte (mesuré : `is_ip`
        // n'admet pas le `%`, donc `forme_inconnue` -> aucun ban n'est appliqué), et il tombait ici
        // dans `services.push(...)` — les deux lecteurs voyaient la même ligne, un seul se plaignait.
        let tete = l.split('/').next().unwrap_or(l);
        let tete = tete.split('%').next().unwrap_or(tete);
        if ressemble_a_une_adresse(tete) {
            return Err(format!(
                "la ligne « {l} » porte la FORME d'une ADRESSE, pas d'un nom de service : ce fichier porte \
                 la liste des adresses à ne jamais bannir (politique de `collectors/respond.sh`), pas celle \
                 des services autorisés pour `stop_service`. Séparez les deux — posez `PLUME_STOP_SERVICE_ALLOW` \
                 sur un autre chemin"
            ));
        }
        services.push(l.to_string());
    }
    Ok(services)
}

/// Validation stricte d'une action (utilisée à la création ET par le responder root — défense en profondeur).
/// Délègue à `action_valid_ctx` avec le drapeau engagement RÉEL (byte-identique quand off : le drapeau vaut
/// false -> la clause engagement n'est même pas évaluée -> comportement STRICTEMENT identique à aujourd'hui).
pub(crate) fn action_valid(kind: &str, target: &str, db_path: &str) -> Result<(), String> {
    action_valid_ctx(kind, target, engagement_enabled(), db_path)
}
/// Cœur testable de `action_valid` : `engagement_on` explicite (le drapeau global est injecté par l'appelant).
/// `db_path` = tenant acteur -> le guard Arm A ne consulte QUE le scope de CE tenant (isolation multi-tenant).
pub(crate) fn action_valid_ctx(kind: &str, target: &str, engagement_on: bool, db_path: &str) -> Result<(), String> {
    match kind {
        "ban_ip" | "unban_ip" => {
            // v1 : IPv4. `P4.7-b` — c'est la BORNE D'ENFORCEMENT (Q1), PAS le classificateur d'adresse
            // (Q2) : ce chemin décide de ce qui PART vers `nft`/`cscli`/`fail2ban`, et son verdict est
            // INCHANGÉ, clause pour clause. Élargir ici est un autre lot, qui devra d'abord lire les
            // gabarits d'exécution (`platform_template`, `action_command`) et le versant hôte.
            let ok = cible_de_ban_acceptee(target);
            if !ok { return Err("IPv4 invalide".into()); }
            // M2 : refuse le BAN d'une IP protégée (loopback/privée/opérateur/passerelle). L'unban reste permis
            // (inoffensif : ces IP ne sont jamais bannies -> no-op), on ne bride donc QUE le ban destructif.
            if kind == "ban_ip" && ip_is_protected(target) {
                return Err("IP protégée (loopback/privée/opérateur) — ban refusé".into());
            }
            // ARM A (v75, MODE ENGAGEMENT) : le BAN d'une IP dans le scope d'un engagement ACTIF est REFUSÉ —
            // le daemon suspend SON PROPRE auto-ban (run_playbooks skippe sur action_valid Err), EXACTEMENT comme
            // la protection opérateur. INVARIANT SACRÉ : ceci ne touche QUE l'enforcement (ban) ; run_due_rules
            // continue d'ALERTER et coverage_detections continue de COMPTER (l'attaquant scopé reste DÉTECTÉ,
            // juste pas auto-bloqué -> une exemption compromise est VISIBLE, jamais un angle mort). unban/kill/
            // stop inchangés. Byte-identique quand off : `engagement_on=false` -> clause court-circuitée.
            if kind == "ban_ip" && engagement_on && ip_in_active_engagement(target, db_path) {
                return Err("IP sous engagement autorisé actif — auto-ban suspendu (détection/alerte inchangées)".into());
            }
            Ok(())
        }
        // `P4.7-b` — LA BORNE EST APPELÉE, PAS RECOPIÉE (comme `ban_ip` ci-dessus). Les deux messages
        // distincts survivent : « trop bas » et « invalide » ne disent pas la même chose à l'analyste.
        "kill_pid" => match target.parse::<i64>() {
            Ok(_) if cible_de_kill_acceptee(target) => Ok(()),
            Ok(_) => Err("PID trop bas (refusé par sécurité)".into()),
            Err(_) => Err("PID invalide".into()),
        },
        "stop_service" => {
            if cible_de_stop_service_acceptee(target) { Ok(()) } else { Err("nom de service invalide".into()) }
        }
        _ => Err(format!("action inconnue : {kind}")),
    }
}

/// #1c — valide UNIQUEMENT le `kind` d'une action (ENUM FERMÉ), SANS cible, pour la sauvegarde d'un
/// playbook (garde-fou #3). `action_valid(kind,target)` valide kind+cible à l'EXÉCUTION ; à l'écriture
/// la cible n'existe pas encore (elle sort de la requête au runtime), on ne contrôle donc que le kind.
/// Miroir volontaire de l'enum d'`action_valid` : ban_ip | unban_ip | kill_pid | stop_service. Toute
/// autre valeur -> Err (aucune action custom/script : pas de nouvelle surface d'exécution).
pub(crate) fn action_kind_valid(kind: &str) -> Result<(), String> {
    match kind {
        "ban_ip" | "unban_ip" | "kill_pid" | "stop_service" => Ok(()),
        _ => Err(format!("action inconnue : {kind} (attendu ban_ip/unban_ip/kill_pid/stop_service)")),
    }
}

/// Une action de réponse est DESTRUCTIVE (effet réel sur un hôte : ban réseau, kill de process,
/// stop de service). L'ENUM FERMÉ actuel est INTÉGRALEMENT destructif -> poser un playbook qui en porte une
/// = armement d'une réponse automatique (réservé admin, cf validate_detection_content). Isolé pour évoluer si
/// un jour une action non-destructive (ex : `notify`) rejoint l'ENUM (elle resterait alors ouverte à l'editor).
pub(crate) fn action_kind_destructive(kind: &str) -> bool {
    matches!(kind, "ban_ip" | "unban_ip" | "kill_pid" | "stop_service")
}

pub(crate) async fn action_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Json<Value> {
    let kind = b.str_field("kind").to_string();
    let target = b.trimmed("target");
    // db_path du tenant acteur -> le guard Arm A ne consulte que le scope d'engagement de CE tenant.
    if let Err(e) = action_valid(&kind, &target, &req_db_path(&st, &au)) {
        return Json(json!({ "error": e }));
    }
    let dry = b.bool_field("dry_run", true) as i64;
    let alert_id = b.get("alert_id").and_then(|v| v.as_i64());
    let reason = b.str_field("reason");
    // host optionnel : cible explicite (ex : depuis un event de ban qui porte son hôte). Absent/vide ->
    // action NON assignée, réclamée par l'agent du 1er hôte qui poll (cf actions_pending).
    let host = b.get("host").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty());
    crate::req_conn!(st, au, conn);
    let _ = conn.execute(
        "INSERT INTO action(ts,kind,target,status,dry_run,alert_id,reason,host) VALUES(?1,?2,?3,'pending',?4,?5,?6,?7)",
        params![now(), kind, target, dry, alert_id, reason, host],
    );
    let id = conn.last_insert_rowid();
    ledger_append(&conn, "action.queued", &format!("{kind} {target} dry={dry}"));
    Json(json!({ "id": id }))
}
// =================================================================================================
// `P11.17-e` — LA FILE DE RIPOSTE DIT CE QU'ELLE SERT, ET CE QU'ELLE NE SERT PAS.
//
// LE DÉFAUT. `GET /api/actions` bornait sa lecture à cent lignes et ne rendait QUE ces lignes : ni
// total, ni indicateur de troncature. La console n'avait donc, pour tout chiffre, que le nombre de
// lignes SERVIES — qu'un lecteur prend pour un total alors qu'il est une fenêtre. C'est la famille
// de défaut que ce dépôt poursuit — un composant qui SAIT son résultat incomplet et le présente
// comme complet — et elle portait ici sur la file des gestes de RIPOSTE, là où une ligne manquante
// se paie. Elle grandit avec le temps : rien ne purge `action` (aucun `DELETE` de production, aucune
// rétention), donc la table ne fait que croître et la fenêtre en couvre une part toujours plus
// petite.
//
// LE REMÈDE, REPRIS DE `/api/query` : un COMPTAGE BORNÉ. `SELECT COUNT(*) FROM (SELECT 1 FROM action
// LIMIT CAP+1)` s'arrête au plafond partagé `PAGINATION_COUNT_CAP` — au-dessous le total est EXACT,
// au-dessus il est plafonné ET `total_capped:true` le DIT, de sorte que la vue écrit « sur tant et
// plus » au lieu d'un chiffre faux présenté comme exact. Même motif, même raison et même plafond que
// le `total` de `handlers/query.rs` et que celui du journal d'intégrité (`handlers/admin_ui.rs`).
//
// CE QUE LA CLÉ DE **CETTE** TABLE PERMET — vérifié plutôt que supposé, parce que la FORME se reprend
// et le SQL, non :
//   * `action.id` est `INTEGER PRIMARY KEY` (migration v4), donc l'alias du `rowid` : la fenêtre
//     `ORDER BY id DESC LIMIT N` est un parcours ARRIÈRE de l'arbre de la clé primaire, O(N), sans
//     tri ni index annexe. `action` ne porte AUCUN autre index.
//   * Aucune ligne n'est SUPPRIMÉE en production (seuls `INSERT` et `UPDATE` touchent cette table) :
//     un `id` n'est donc jamais réutilisé, et l'ordre des `id` est celui des créations.
//   * LE KEYSET `(ts,id)` DE `/api/query` NE SE RECOPIE PAS ICI, et c'est la raison qui compte :
//     `action.ts` n'est pas indexé, et le moteur de réponse insère plusieurs actions dans la MÊME
//     seconde (`run_playbooks`) — un curseur `(ts,id)` ordonnerait donc autrement que la fenêtre
//     servie, en balayant sans index. La clé qui convient ici est `id`, seule et nue.
//   * CE QUI RESTE OUVERT, ÉCRIT PLUTÔT QUE TU : la route ne rend toujours PAS de curseur. Rien ne
//     l'en empêche — `action` ne porte aucune chaîne d'intégrité, contrairement au journal d'audit
//     dont l'ordre EST celui de sa chaîne de hash — mais aucun parcours au-delà de la fenêtre n'est
//     construit à ce jour. Le total est ce qui rend cette limite VISIBLE au lieu de la taire.
// =================================================================================================

/// TAILLE DE LA FENÊTRE servie par `GET /api/actions` — les `ACTIONS_WINDOW` actions les plus récentes.
/// Nommée plutôt qu'écrite dans l'énoncé : la vue la RECOIT, et le test la lit ici au lieu de la recopier.
pub(crate) const ACTIONS_WINDOW: i64 = 100;

/// LE SEUL fabricant du COMPTAGE de la file — écrit une fois pour que le test mesure CE QUI EST ÉMIS et
/// non une copie. `SELECT 1` ne demande aucune colonne, `LIMIT CAP+1` ARRÊTE le balayage au plafond :
/// sous le plafond le total est EXACT, au-dessus il est plafonné ET annoncé.
pub(crate) fn actions_total_sql() -> String {
    format!("SELECT COUNT(*) FROM (SELECT 1 FROM action LIMIT {})", PAGINATION_COUNT_CAP + 1)
}

/// LE SEUL fabricant de la FENÊTRE servie. Projection et ordre INCHANGÉS par rapport à la version
/// d'origine (`id,ts,kind,target,status,dry_run,reason,result,done_ts,host`, `ORDER BY id DESC`) : ce
/// correctif ajoute un chiffre à côté de la liste, il ne touche pas à la liste.
pub(crate) fn actions_window_sql() -> String {
    format!(
        "SELECT id,ts,kind,target,status,dry_run,reason,result,done_ts,host FROM action ORDER BY id DESC LIMIT {ACTIONS_WINDOW}"
    )
}

/// Fenêtre + total borné de la file de riposte. Fonction PURE sur `&Connection` -> testable sans AppState.
///
/// Rend `{actions, served, window, total, total_capped}`. `served` est le nombre de lignes RENDUES et
/// `window` la borne de la route : leur égalité est précisément ce qui dit à la vue que la borne MORD.
/// `total`/`total_capped` valent `null` — jamais `0` — quand le comptage n'a pas pu être lu : « non
/// compté » et « aucune action » sont deux faits différents, et sur cette file l'écart va dans le sens
/// dangereux.
pub(crate) fn actions_page(conn: &Connection) -> Value {
    let rows: Vec<Value> = match conn.prepare(&actions_window_sql()) {
        Ok(mut stmt) => stmt
            .query_map([], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?, "ts": r.get::<_, i64>(1)?, "kind": r.get::<_, String>(2)?, "target": r.get::<_, String>(3)?,
                    "status": r.get::<_, String>(4)?, "dry_run": r.get::<_, i64>(5)? != 0, "reason": r.get::<_, Option<String>>(6)?,
                    "result": r.get::<_, Option<String>>(7)?, "done_ts": r.get::<_, Option<i64>>(8)?, "host": r.get::<_, Option<String>>(9)?
                }))
            })
            .map(|m| m.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    // COMPTAGE BORNÉ : `raw` = min(vrai_total, CAP+1). > CAP -> plafonné (CAP + `total_capped`) ; sinon exact.
    // Un comptage qui ÉCHOUE ne rend pas un zéro rassurant : il rend `null`, et la vue dit qu'elle ne sait pas.
    let (total, total_capped) = match conn.query_row(&actions_total_sql(), [], |r| r.get::<_, i64>(0)) {
        Ok(raw) => {
            let capped = raw > PAGINATION_COUNT_CAP;
            (json!(if capped { PAGINATION_COUNT_CAP } else { raw }), json!(capped))
        }
        Err(_) => (Value::Null, Value::Null),
    };
    json!({
        "actions": rows,
        "served": rows.len(),
        "window": ACTIONS_WINDOW,
        "total": total,
        "total_capped": total_capped,
    })
}

pub(crate) async fn actions_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    Json(actions_page(&conn))
}

/// Agent (token) : réclame les actions APPROUVÉES à appliquer sur SON hôte (ban/unban uniquement).
/// Réponse = TSV `id<TAB>kind<TAB>target<TAB>dry_run` (1 par ligne) -> parse trivial en shell, sans jq.
/// Marque chaque action `claimed_ts` (anti double-exécution) ; re-remise auto si pas de résultat sous 5 min.
/// SÉCURITÉ : l'hôte est dérivé du TOKEN (lié à un hôte), pas d'un paramètre -> un agent ne voit/claim
/// QUE les actions de son hôte (anti-IDOR cross-agent). Un token non lié à un hôte est refusé ici.
pub(crate) async fn actions_pending(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if au.role != "agent" || au.name.is_empty() {
        return (StatusCode::FORBIDDEN, "token agent lié à un hôte requis").into_response();
    }
    let host = au.name.clone();
    let now_ts = now();
    const STALE: i64 = 300; // re-remise si réclamée sans résultat depuis > 5 min (agent planté)
    crate::req_conn!(st, au, conn);
    // host=?1 : actions ciblant CET hôte. host NULL/'' : actions non assignées (créées depuis l'UI sans
    // cible explicite) -> réclamables par n'importe quel agent ; à la réclamation on les ASSIGNE à l'hôte
    // réclamant (cf plus bas) pour que action_result (AND host=?) puisse les clôturer + anti double-claim.
    // Anti-IDOR préservé : un agent ne voit JAMAIS une action ciblant un AUTRE hôte (host=<autre> exclu).
    let rows: Vec<(i64, String, String, bool)> = match conn.prepare(
        "SELECT id,kind,target,dry_run FROM action WHERE (host=?1 OR host IS NULL OR host='') AND status='approved' \
         AND kind IN ('ban_ip','unban_ip') AND (claimed_ts IS NULL OR ?2-claimed_ts>?3) ORDER BY id LIMIT 100",
    ) {
        Ok(mut s) => s
            .query_map(params![host, now_ts, STALE], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)? != 0)))
            .map(|m| m.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let mut body = String::new();
    for (id, kind, target, dry) in &rows {
        // assigne l'action à l'hôte réclamant (no-op si déjà ciblée sur lui) -> action_result peut clôturer
        let _ = conn.execute("UPDATE action SET claimed_ts=?2, host=?3 WHERE id=?1", params![id, now_ts, host]);
        body.push_str(&format!("{id}\t{kind}\t{target}\t{}\n", if *dry { 1 } else { 0 }));
    }
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}

/// Agent (token) : remonte le résultat d'une action appliquée chez lui -> clôt l'action + journalise.
/// Idempotent (n'agit que sur une action encore 'approved'). status: done | failed | dryrun.
/// SÉCURITÉ : ne clôt QUE les actions de l'hôte LIÉ au token (`AND host=?`) -> un agent ne peut pas
/// clôturer/injecter le résultat d'une action d'un autre hôte. `result` borné + nettoyé (anti-injection log).
pub(crate) async fn action_result(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Json<Value> {
    if au.role != "agent" || au.name.is_empty() {
        return Json(json!({ "ok": false, "error": "token agent lié à un hôte requis" }));
    }
    let host = au.name.clone();
    let id = b.i64_field("id", 0);
    let status = match b.str_field("status") {
        "done" => "done",
        "dryrun" => "dryrun",
        _ => "failed",
    };
    // borne + retire les caractères de contrôle (le résultat finit dans le ledger -> anti log-injection)
    let result: String = b
        .get("result")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(500)
        .collect();
    if id == 0 {
        return Json(json!({ "ok": false, "error": "id requis" }));
    }
    crate::req_conn!(st, au, conn);
    let n = conn
        .execute(
            "UPDATE action SET status=?2, result=?3, done_ts=?4 WHERE id=?1 AND status='approved' AND host=?5",
            params![id, status, result, now(), host],
        )
        .unwrap_or(0);
    if n > 0 {
        ledger_append(&conn, "action.remote", &format!("#{id}@{host} -> {status} : {result}"));
    }
    Json(json!({ "ok": n > 0 }))
}
pub(crate) async fn action_approve(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    let _ = conn.execute("UPDATE action SET status='approved' WHERE id=?1 AND status='pending'", params![id]);
    ledger_append(&conn, "action.approved", &format!("id={id}"));
    // BAN NATIF PLUME (chantier ② Phase 1) : l'approbation d'un `ban_ip` NON dry-run ARME AUSSI le blocage HTTP
    // in-process (`net_ban`) -> plume s'auto-enforce pour l'IP réelle, EN PLUS de la décision CrowdSec/nft de
    // l'hôte (exécutée ensuite par le responder/agent). `unban_ip` retire le blocage. Additif : n'altère NI le
    // pipeline responder/agent existant NI le mode 0 (aucune action ban_ip -> aucun net_ban). TTL = mirror 4h
    // CrowdSec ; réversible via unban / DELETE /api/netban. Garde protected-IP redondante (déjà refusée à la
    // création par action_valid) mais défensive.
    if netban_from_actions_enabled() {
        if let Ok((kind, target, dry)) = conn.query_row(
            "SELECT kind, target, dry_run FROM action WHERE id=?1 AND status='approved'",
            params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? != 0)),
        ) {
            // Canonicalise (mirror `real_client_ip`) ; les gardes protected/engagement ont déjà tourné à la création.
            let canon = target.trim().parse::<std::net::IpAddr>().map(|i| i.to_string()).unwrap_or_else(|_| target.trim().to_string());
            if kind == "ban_ip" && !dry && !ip_is_protected(&canon) {
                // REFUS SUR STORE PLEIN (`NETBAN_CACHE_CAP`) : tracé au ledger. L'action reste approuvée —
                // l'enforcement réseau délégué (CrowdSec/fail2ban/nft) n'est pas concerné par ce plafond,
                // qui ne borne que la banlist HTTP in-process.
                if !netban_upsert(&conn, &canon, Some(now() + NETBAN_ACTION_TTL_S), "auto: action ban_ip", &au.name, "prod") {
                    ledger_append(&conn, "netban.plafond", &format!("{canon} refusé : store live plein (action {id})"));
                }
            } else if kind == "unban_ip" {
                netban_remove(&conn, &canon);
            }
        }
    }
    StatusCode::NO_CONTENT
}

/// AUTO-INTÉGRATION action->net_ban OPT-IN (anti blast-radius). DÉFAUT **OFF** :
/// une action `ban_ip` (surtout un auto-approve de playbook) ne bloque PAS d'office l'opérateur au niveau HTTP
/// plume — le canal PRIMAIRE reste l'API admin `/api/netban` (pilotée par admin-console). Activable
/// `PLUME_NETBAN_FROM_ACTIONS=1` quand l'opérateur veut que ses actions ban_ip s'auto-enforcent aussi au HTTP.
pub(crate) fn netban_from_actions_enabled() -> bool {
    matches!(
        std::env::var("PLUME_NETBAN_FROM_ACTIONS").unwrap_or_default().trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Valide + CANONICALISE une IP pour un ban HTTP `net_ban`. Accepte IPv4 **ET
/// IPv6** (le gate HTTP voit l'IP réelle CF qui peut être v6 ; `action_valid` restait IPv4 pour le chemin nft hôte).
/// CANONICALISE (`IpAddr::to_string()`) -> l'entrée stockée matche EXACTEMENT l'IP calculée par `real_client_ip`
/// (fin du faux no-op `01.02.03.04`). Réutilise les gardes : jamais loopback/privé/opérateur/passerelle
/// (`ip_is_protected`), suspend sous engagement autorisé actif.
pub(crate) fn netban_validate_ip(ip: &str, db_path: &str) -> Result<String, String> {
    let parsed: std::net::IpAddr = ip.trim().parse().map_err(|_| "IP invalide".to_string())?;
    let canon = parsed.to_string();
    if ip_is_protected(&canon) {
        return Err("IP protégée (loopback/privée/opérateur/passerelle) — ban refusé".into());
    }
    if engagement_enabled() && ip_in_active_engagement(&canon, db_path) {
        return Err("IP sous engagement autorisé actif — ban suspendu (détection/alerte inchangées)".into());
    }
    Ok(canon)
}

// ---------- BAN NATIF PLUME — API admin `/api/netban` (chantier ② Phase 1) ----------
// admin-only (route_min_role -> Admin, GET compris) : c'est le canal qu'admin-console (plan de contrôle) appelle
// pour pousser/retirer un blocage HTTP. Par-tenant (req_db). Garde-fous : jamais bannir loopback/privé/opérateur/
// passerelle + engagement (netban_validate_ip). ACCEPTE IPv4+IPv6, canonicalise.

/// GET /api/netban — liste les bans LIVE (net_ban) + le compte des bans ACTIFS (permanent OU expiry futur).
pub(crate) async fn netban_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let now_ts = now();
    let mut stmt = match conn.prepare(
        "SELECT ip,reason,created_ts,expires_ts,created_by,env_id FROM net_ban ORDER BY created_ts DESC",
    ) {
        Ok(s) => s,
        Err(_) => return Json(json!({ "bans": [], "active": 0 })),
    };
    let bans: Vec<Value> = stmt
        .query_map([], |r| {
            let expires: Option<i64> = r.get(3)?;
            Ok(json!({
                "ip": r.get::<_, String>(0)?,
                "reason": r.get::<_, Option<String>>(1)?,
                "created_ts": r.get::<_, Option<i64>>(2)?,
                "expires_ts": expires,
                "created_by": r.get::<_, Option<String>>(4)?,
                "env_id": r.get::<_, String>(5)?,
                "active": expires.map(|e| e > now_ts).unwrap_or(true),
            }))
        })
        .map(|m| m.flatten().collect())
        .unwrap_or_default();
    let active = bans.iter().filter(|b| b["active"].as_bool().unwrap_or(false)).count();
    // CE QUE LA BORNE MÉMOIRE FAIT, DIT ICI. `charges` = entrées réellement portées par le store live
    // (ce qui bloque), `cap` = son plafond, `tronque` = la base porte plus de bans que le cache n'en
    // charge, donc certains ne bloquent PAS. Sans ces trois valeurs, un opérateur ne peut pas
    // distinguer « mon ban est actif » de « mon ban est enregistré ».
    Json(json!({
        "bans": bans,
        "active": active,
        "charges": netban_cache().read().len(),
        "cap": NETBAN_CACHE_CAP,
        "tronque": netban_store_tronque(),
    }))
}

/// POST /api/netban `{ip, ttl_s?, reason?}` — pose/rafraîchit un ban HTTP. `ttl_s` absent/≤0 = PERMANENT.
pub(crate) async fn netban_add(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) { return r; } // défense en profondeur (route déjà admin-only)
    // Valide + CANONICALISE (IPv4/IPv6) : format + IP protégée refusée + engagement -> 400 explicite (anti
    // self-lockout). `ip` DEVIENT la forme canonique stockée (matche `real_client_ip` au gate).
    let ip = match netban_validate_ip(&b.trimmed("ip"), &req_db_path(&st, &au)) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, e),
    };
    let ttl = b.get("ttl_s").and_then(|v| v.as_i64()).filter(|t| *t > 0);
    let expires = ttl.map(|t| now() + t);
    let reason = b.str_field("reason");
    crate::req_conn!(st, au, conn);
    // STORE PLEIN -> REFUS EXPLICITE, jamais un 200 sur un ban qui ne bloquera rien. 507 (Insufficient
    // Storage) nomme la ressource épuisée : c'est le plafond du store live, pas la requête qui est fautive.
    if !netban_upsert(&conn, &ip, expires, reason, &au.name, "prod") {
        ledger_append(&conn, "netban.plafond", &format!("{ip} refusé : store live plein by={}", au.name));
        return err_json(
            StatusCode::INSUFFICIENT_STORAGE,
            format!("store de bans plein ({NETBAN_CACHE_CAP} IP) — libérer par DELETE /api/netban/{{ip}}, ou bloquer en amont (pare-feu/CDN)"),
        );
    }
    ledger_append(&conn, "netban.add", &format!("{ip} ttl={} by={}", ttl.map(|t| t.to_string()).unwrap_or_else(|| "permanent".into()), au.name));
    Json(json!({ "ok": true, "ip": ip, "expires_ts": expires })).into_response()
}

/// DELETE /api/netban/{ip} — retire un ban HTTP (réversibilité). Idempotent (retirer une IP absente = ok).
pub(crate) async fn netban_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(ip): Path<String>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    let ip = ip.trim().to_string();
    crate::req_conn!(st, au, conn);
    netban_remove(&conn, &ip);
    ledger_append(&conn, "netban.remove", &format!("{ip} by={}", au.name));
    Json(json!({ "ok": true, "ip": ip })).into_response()
}
pub(crate) async fn action_cancel(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    let _ = conn.execute("UPDATE action SET status='cancelled' WHERE id=?1 AND status IN ('pending','approved')", params![id]);
    StatusCode::NO_CONTENT
}

/// Un exécutable est-il dans le PATH ? (pour déléguer aux enforcers existants).
pub(crate) fn which(cmd: &str) -> bool {
    std::env::var("PATH")
        .map(|p| p.split(':').any(|d| std::path::Path::new(d).join(cmd).is_file()))
        .unwrap_or(false)
}

/// Commande système pour une action validée -> (programme, args). Args directs (pas de shell).
/// Principe : DÉLÉGUER le ban d'IP aux enforcers réseau existants (CrowdSec/fail2ban) ; nft = fallback.
pub(crate) fn action_command(kind: &str, target: &str, backend: &str, jail: &str) -> (String, Vec<String>) {
    let s = |v: &str| v.to_string();
    match kind {
        "ban_ip" => match backend {
            "crowdsec" => (s("cscli"), vec![s("decisions"), s("add"), s("--ip"), s(target), s("--duration"), s("4h"), s("--reason"), s("plume")]),
            "fail2ban" => (s("fail2ban-client"), vec![s("set"), s(jail), s("banip"), s(target)]),
            _ => (s("nft"), vec![s("add"), s("element"), s("inet"), s("plume"), s("blocklist"), format!("{{ {target} }}")]),
        },
        "unban_ip" => match backend {
            "crowdsec" => (s("cscli"), vec![s("decisions"), s("delete"), s("--ip"), s(target)]),
            "fail2ban" => (s("fail2ban-client"), vec![s("set"), s(jail), s("unbanip"), s(target)]),
            _ => (s("nft"), vec![s("delete"), s("element"), s("inet"), s("plume"), s("blocklist"), format!("{{ {target} }}")]),
        },
        "kill_pid" => (s("kill"), vec![s("-TERM"), s(target)]),
        "stop_service" => (s("systemctl"), vec![s("stop"), s(target)]),
        _ => (s("true"), vec![]),
    }
}

// ===================================================================================================
// EXÉCUTEUR PAR-PLATEFORME (#20/#21) — DESCRIPTEUR pour le VOCAB FERMÉ (ban_ip/unban_ip/kill_pid/stop_service).
// -----------------------------------------------------------------------------------------------------
// Objectif : rendre pluggable UNIQUEMENT le « COMMENT » (la commande native) d'une action DÉJÀ validée sur
// une plateforme donnée — JAMAIS le « QUOI ». Le vocab reste FERMÉ (`action_kind_valid` intouché) : une
// action hors vocab est toujours rejetée en amont ; le descripteur ne fait que CHOISIR la commande native.
//
// GARDE-FOUS (non-négociables) :
//   * un gabarit = argv FIXE (programme + arguments littéraux), JAMAIS `sh -c`, JAMAIS de chaînage.
//   * le SEUL point variable = un slot TYPÉ ({ip}/{pid}/{service}), 1 par action, rempli par l'arg du vocab
//     DÉJÀ type-validé (action_valid) -> injection impossible (pas de shell + charset typé).
//   * tout métacaractère shell dans le gabarit, tout placeholder inconnu/non résolu -> gabarit REJETÉ.
//   * plateforme "linux" (DÉFAUT) = chemin nft/fail2ban historique `action_command` : BYTE-IDENTIQUE.
// ===================================================================================================

/// Slot TYPÉ autorisé dans un gabarit — ENSEMBLE FERMÉ, miroir des args du vocab fermé (1 slot par action).
/// Tout autre `{...}` dans un gabarit est un placeholder INCONNU -> le gabarit est rejeté au rendu.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Slot {
    Ip,
    Pid,
    Service,
}
impl Slot {
    /// Le jeton textuel exact reconnu dans un gabarit (le SEUL substituable pour cette action).
    fn token(self) -> &'static str {
        match self {
            Slot::Ip => "{ip}",
            Slot::Pid => "{pid}",
            Slot::Service => "{service}",
        }
    }
    /// Slot attendu par un `action_kind` du vocab fermé (None = hors vocab -> aucun rendu possible).
    fn for_kind(kind: &str) -> Option<Slot> {
        match kind {
            "ban_ip" | "unban_ip" => Some(Slot::Ip),
            "kill_pid" => Some(Slot::Pid),
            "stop_service" => Some(Slot::Service),
            _ => None,
        }
    }
    /// Défense en profondeur : la cible respecte-t-elle la BORNE TYPÉE du slot ? (déjà garanti par
    /// `action_valid` en amont ; re-vérifié ici pour que le rendu soit sûr même appelé ISOLÉMENT.)
    /// LES TROIS ARMS APPELLENT LA BORNE D'`action_valid_ctx` — il n'y a plus AUCUN miroir ici, donc
    /// plus rien qui puisse dériver, et « jamais plus permissif que la validation amont » est vrai
    /// PAR CONSTRUCTION au lieu d'être une phrase. Le premier jet de `P4.7-b` n'avait déplacé que
    /// `Slot::Ip` et avait ÉCRIT que les deux autres étaient « plus étroits (`p > 0` contre
    /// `p > 300`) » : c'était l'inverse, et le témoin
    /// `le_rendu_type_n_est_jamais_plus_permissif_que_la_validation_amont` l'épingle désormais.
    fn target_ok(self, target: &str) -> bool {
        match self {
            // `P4.7-b` — CES TROIS LIGNES ÉTAIENT DES COPIES VERBATIM des clauses d'`action_valid_ctx`
            // (Ip : quatre clauses ; Service : trois), sous un commentaire qui disait « miroir STRICT »,
            // et Pid était une copie FAUSSE (`p > 0`). Ce sont des APPELS désormais.
            Slot::Ip => cible_de_ban_acceptee(target),
            Slot::Pid => cible_de_kill_acceptee(target),
            Slot::Service => cible_de_stop_service_acceptee(target),
        }
    }
}

/// Métacaractères shell INTERDITS dans TOUT jeton de gabarit (programme ou argument). Les accolades `{}`
/// sont traitées À PART (délimiteurs de slot) : un `{`/`}` résiduel APRÈS substitution = placeholder inconnu.
/// L'espace est inclus : un jeton argv ne contient jamais d'espace (le gabarit brut est splité dessus).
const SHELL_META: &[char] = &[
    ';', '|', '&', '$', '`', '(', ')', '<', '>', '"', '\'', '*', '?', '~', '!', '#', '\\', '=', '\n', '\r', '\t', ' ',
];

/// Rend UN jeton d'argument : rejette les métacaractères, substitue le slot typé attendu, rejette tout
/// placeholder résiduel/inconnu. `=` est un métacaractère interdit ICI -> les gabarits `k=v` passent le
/// couple comme un seul jeton pré-formé côté `CmdTemplate` (voir windows) sans traverser cette fonction
/// via un split ; pour un gabarit brut admin on impose la forme `--flag valeur` (pas de `k=v`).
fn render_arg(tok: &str, slot: Slot, target: &str) -> Result<String, String> {
    if let Some(bad) = tok.chars().find(|c| SHELL_META.contains(c)) {
        return Err(format!("métacaractère shell interdit dans le gabarit ({bad:?}) : {tok:?}"));
    }
    let out = tok.replace(slot.token(), target);
    if out.contains('{') || out.contains('}') {
        return Err(format!("placeholder inconnu/non résolu dans le gabarit : {tok:?} (seul {} est permis)", slot.token()));
    }
    Ok(out)
}

/// Gabarit VETTÉ interne (windows/pfsense) : programme + arguments littéraux à trou typé. PAS un script.
struct CmdTemplate {
    prog: &'static str,
    args: &'static [&'static str],
}

/// Rend un gabarit VETTÉ (programme + args) en (prog, argv) sûr, pour l'action `kind`/`target`.
/// Ré-applique TOUS les garde-fous (défense en profondeur) : slot du vocab, charset cible, no-shell,
/// no-placeholder-inconnu. Les jetons `k=v` des gabarits internes (ex netsh `remoteip={ip}`) contiennent
/// `=` : ils sont substitués AVANT le contrôle métacaractère (le `=` littéral est ALORS toléré car il
/// provient d'un gabarit VETTÉ à la compilation, non d'une entrée). On distingue donc rendu interne vs brut.
fn render_vetted(tmpl: &CmdTemplate, kind: &str, target: &str) -> Result<(String, Vec<String>), String> {
    let slot = Slot::for_kind(kind).ok_or_else(|| format!("action hors vocab fermé : {kind}"))?;
    if !slot.target_ok(target) {
        return Err(format!("cible invalide pour le slot {} : {target:?}", slot.token()));
    }
    // le programme ne porte JAMAIS de slot ni de métacaractère.
    if tmpl.prog.is_empty() || tmpl.prog.chars().any(|c| SHELL_META.contains(&c) || c == '{' || c == '}') {
        return Err(format!("programme de gabarit invalide : {:?}", tmpl.prog));
    }
    let mut argv = Vec::with_capacity(tmpl.args.len());
    for raw in tmpl.args {
        // gabarit interne VETTÉ : on substitue d'abord le slot, puis on rejette tout {}/métacaractère
        // résiduel HORS `=` (toléré car il vient d'un littéral compilé `k=v`, jamais d'une entrée).
        let sub = raw.replace(slot.token(), target);
        if let Some(bad) = sub.chars().find(|c| SHELL_META.contains(c) && *c != '=') {
            return Err(format!("métacaractère shell interdit dans le gabarit interne ({bad:?}) : {raw:?}"));
        }
        if sub.contains('{') || sub.contains('}') {
            return Err(format!("placeholder inconnu/non résolu dans le gabarit interne : {raw:?}"));
        }
        argv.push(sub);
    }
    Ok((tmpl.prog.to_string(), argv))
}

/// Gabarit VETTÉ à la compilation pour (plateforme non-linux, action). None = paire non supportée.
/// Ces commandes NE lancent AUCUN shell : argv fixe, un seul slot typé. Elles reflètent le vocab fermé :
///   windows : netsh advfirewall (ban/unban) / taskkill (kill) / sc (stop).
///   pfsense : pfctl table plume_blocklist (ban/unban) / kill (kill) / service (stop) — base FreeBSD.
fn platform_template(platform: &str, kind: &str) -> Option<CmdTemplate> {
    match (platform, kind) {
        // --- WINDOWS ---------------------------------------------------------------------------------
        ("windows", "ban_ip") => Some(CmdTemplate {
            prog: "netsh",
            args: &["advfirewall", "firewall", "add", "rule", "name=plume-ban-{ip}", "dir=in", "action=block", "remoteip={ip}"],
        }),
        ("windows", "unban_ip") => Some(CmdTemplate {
            prog: "netsh",
            args: &["advfirewall", "firewall", "delete", "rule", "name=plume-ban-{ip}"],
        }),
        ("windows", "kill_pid") => Some(CmdTemplate { prog: "taskkill", args: &["/PID", "{pid}", "/F"] }),
        ("windows", "stop_service") => Some(CmdTemplate { prog: "sc", args: &["stop", "{service}"] }),
        // --- PFSENSE / FreeBSD ----------------------------------------------------------------------
        ("pfsense", "ban_ip") => Some(CmdTemplate { prog: "pfctl", args: &["-t", "plume_blocklist", "-T", "add", "{ip}"] }),
        ("pfsense", "unban_ip") => Some(CmdTemplate { prog: "pfctl", args: &["-t", "plume_blocklist", "-T", "delete", "{ip}"] }),
        ("pfsense", "kill_pid") => Some(CmdTemplate { prog: "kill", args: &["-TERM", "{pid}"] }),
        ("pfsense", "stop_service") => Some(CmdTemplate { prog: "service", args: &["{service}", "stop"] }),
        _ => None,
    }
}

/// Rend un gabarit BRUT admin-configuré (generic-appliance) : split sur les espaces (PAS de shell ->
/// pas d'expansion, pas de guillemets), 1er jeton = programme, jetons suivants = args à trou typé.
/// GARDE-FOUS DURS via `render_arg` : métacaractère (dont `=`) interdit -> forme `--flag valeur` imposée ;
/// placeholder inconnu interdit ; le programme ne porte ni slot ni métacaractère. Vide -> Err.
fn render_generic(raw: &str, kind: &str, target: &str) -> Result<(String, Vec<String>), String> {
    let slot = Slot::for_kind(kind).ok_or_else(|| format!("action hors vocab fermé : {kind}"))?;
    if !slot.target_ok(target) {
        return Err(format!("cible invalide pour le slot {} : {target:?}", slot.token()));
    }
    let mut toks = raw.split_whitespace();
    let prog = toks.next().ok_or_else(|| "gabarit generic vide".to_string())?;
    if prog.chars().any(|c| SHELL_META.contains(&c) || c == '{' || c == '}') {
        return Err(format!("programme de gabarit generic invalide : {prog:?}"));
    }
    let mut argv = Vec::new();
    for t in toks {
        argv.push(render_arg(t, slot, target)?);
    }
    Ok((prog.to_string(), argv))
}

/// POINT D'ENTRÉE : commande native FINALE pour (plateforme, action) du vocab fermé.
///   * "linux" (DÉFAUT) -> `action_command` intact (nft/fail2ban/crowdsec) : BYTE-IDENTIQUE.
///   * "windows"/"pfsense" -> gabarit VETTÉ compilé + substitution du slot typé.
///   * "generic-appliance" -> gabarit BRUT admin-configuré (`generic`) + substitution ; None -> Err.
/// `kind`/`target` sont supposés DÉJÀ validés par `action_valid` ; les garde-fous sont RÉ-appliqués (def-in-depth).
pub(crate) fn platform_command(
    platform: &str,
    kind: &str,
    target: &str,
    backend: &str,
    jail: &str,
    generic: Option<&str>,
) -> Result<(String, Vec<String>), String> {
    // le vocab reste FERMÉ : une action hors enum n'a AUCUN gabarit (verrou redondant avec action_kind_valid).
    if Slot::for_kind(kind).is_none() {
        return Err(format!("action hors vocab fermé : {kind}"));
    }
    match platform {
        "linux" => Ok(action_command(kind, target, backend, jail)), // chemin historique : intouché
        "generic-appliance" => match generic {
            Some(raw) => render_generic(raw, kind, target),
            None => Err(format!("generic-appliance : gabarit admin manquant pour {kind} (PLUME_EXEC_GENERIC_{})", kind.to_uppercase())),
        },
        _ => match platform_template(platform, kind) {
            Some(t) => render_vetted(&t, kind, target),
            None => Err(format!("plateforme inconnue ou action non supportée : {platform}/{kind}")),
        },
    }
}

/// Résout le gabarit BRUT generic-appliance pour un `kind` depuis la config (`PLUME_EXEC_GENERIC_<KIND>`).
/// Retour None si non configuré (le rendu échouera proprement -> action `blocked`, jamais d'exécution floue).
pub(crate) fn generic_template_for(conf: &std::collections::HashMap<String, String>, kind: &str) -> Option<String> {
    let key = format!("PLUME_EXEC_GENERIC_{}", kind.to_uppercase());
    let v = cfg(conf, &key, ""); // env PLUME_EXEC_GENERIC_* > conf > "" (non configuré)
    let v = v.trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

/// Crée (idempotent) l'infra nft dédiée à Plume pour les bans — table `inet plume` SÉPARÉE du ruleset existant.
pub(crate) fn ensure_nft_blocklist() {
    use std::process::Command;
    let runs: [&[&str]; 4] = [
        &["add", "table", "inet", "plume"],
        &["add", "set", "inet", "plume", "blocklist", "{ type ipv4_addr; }"],
        &["add", "chain", "inet", "plume", "input", "{ type filter hook input priority -150; policy accept; }"],
        &["add", "rule", "inet", "plume", "input", "ip", "saddr", "@blocklist", "drop"],
    ];
    for r in runs {
        let _ = Command::new("nft").args(r).status(); // idempotent : « File exists » ignoré
    }
}
/// LES ACTIONS QUE CE RESPONDER RÉCLAME — UN SEUL AUTEUR POUR CET ÉNONCÉ (`S33`).
///
/// `?1` = l'identité de cet hôte, `?2` = 1 si elle a été LUE. Les actions NON CIBLÉES (`host` NULL ou
/// vide) disent « n'importe quel hôte », et cette phrase reste vraie même quand on ne sait pas son
/// propre nom : elles sont réclamées dans les deux cas. Les actions CIBLÉES exigent une identité
/// LUE — sans quoi elles seraient appariées à un nom inventé, et exécutées sur la mauvaise machine.
///
/// La constante existe pour que le test exerce l'énoncé du PRODUIT et non une recopie : une paraphrase
/// resterait verte le jour où celui-ci changerait.
pub(crate) const ACTIONS_A_RECLAMER_ICI: &str = "SELECT id,kind,target,dry_run FROM action \
     WHERE status='approved' AND (host IS NULL OR host='' OR (?2 = 1 AND host = ?1))";

/// QUELLE IDENTITÉ CE RESPONDER OPPOSE AUX ACTIONS CIBLÉES, ET S'IL EN A UNE — pur, donc exerçable.
///
/// L'étiquette posée par l'exploitant (`PLUME_HOST_LABEL`) prime : c'est une décision explicite, elle
/// n'a pas à être mesurée. À défaut, l'identité vient de la mesure — et si celle-ci n'a rien pu
/// établir, il n'y a PAS de troisième valeur. L'ancienne forme repliait sur `localhost` : un nom
/// d'hôte plausible ment mieux qu'un zéro, car il est indiscernable d'une lecture réussie. Deux
/// conséquences, opposées et toutes deux muettes : les actions visant le VRAI nom de cette machine
/// dormaient indéfiniment en `approved` — une réponse décidée par un analyste ne s'exécutait jamais —
/// pendant que celles visant une AUTRE machine réellement nommée `localhost` s'exécutaient ici. Une
/// action appliquée au mauvais hôte est un incident, pas un manque de signal.
///
/// L'aveu part sur la sortie d'erreur ET dans `/metrics`, où `plume_host_identity_lisible` porte la
/// cause : une garde éteinte doit se voir, sans quoi elle est indiscernable d'une garde satisfaite.
pub(crate) fn identite_pour_reclamation(
    etiquette: &str,
    mesure: crate::mesure_environnement::Mesure<String>,
) -> (String, bool) {
    if !etiquette.is_empty() {
        return (etiquette.to_string(), true);
    }
    match mesure {
        crate::mesure_environnement::Mesure::Lue(h) => (h, true),
        crate::mesure_environnement::Mesure::Illisible { cause, detail } => {
            eprintln!(
                "[responder] identité de l'hôte ILLISIBLE ({cause}) : {detail} — les actions CIBLÉES ne \
                 sont pas réclamées ici (les apparier sans identité les appliquerait peut-être au mauvais \
                 hôte) ; les actions non ciblées restent traitées"
            );
            (String::new(), false)
        }
    }
}


/// Sous-commande `plume-daemon respond` (exécutée en ROOT par plume-respond) : n'exécute QUE les actions
/// approuvées + allowlistées + validées ; dry-run -> aucune modif ; tout est journalisé dans `action`.
pub(crate) fn respond_run() {
    let conf = load_config();
    let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
    // CE RESPONDER TOURNE EN ROOT (systemd/plume-respond.service, timer 20 s) ET IL ÉCRIT : il change
    // le statut des actions et pose `done_ts`. Il passe donc par LA PORTE, comme le daemon. Mesuré
    // avant ce correctif, avec le vrai binaire : sur une base estampillée 111 amputée de `net_ban` —
    // celle où `plume-daemon token` sortait en 1 sans rien écrire — `respond` sortait en 0 et écrivait
    // (action 1 `approved` -> `failed`, `done_ts` posé) ; et sur une base en retard de 5 migrations, il
    // écrivait aussi sans migrer ni refuser. C'est l'asymétrie exacte que ce chantier voulait retirer :
    // le daemon refusait bruyamment de SERVIR pendant que le responder root continuait d'EXÉCUTER.
    let conn = match PreparedDb::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[schema] respond : {e} — AUCUNE action exécutée. Arrêt propre.");
            std::process::exit(1);
        }
    };
    // LA LISTE DE `stop_service` — SON CHEMIN SE POSE, ET SON CONTENU EST DE SA POLITIQUE (`P4.7-a`).
    // Le chemin était écrit EN DUR ici, donc ni exerçable ni séparable de la liste de l'agent ; il
    // se pose désormais par `PLUME_STOP_SERVICE_ALLOW`, dont le DÉFAUT est le chemin historique (le
    // comportement d'une installation qui ne pose rien est inchangé). Ce levier porte un nom PROPRE
    // et non `PLUME_RESPONDER_ALLOW`, qui désigne déjà la liste des adresses à ne jamais bannir de
    // l'agent : deux politiques sous un même nom sont exactement le défaut que cette clé ferme.
    let chemin_allow = cfg(&conf, "PLUME_STOP_SERVICE_ALLOW", "/etc/plume/responder.allow");
    let allow = allowlist_stop_service(std::fs::read_to_string(&chemin_allow));
    // `P4.7-c` — CE RESPONDER-CI NE LIT AUCUNE LISTE D'ÉPARGNE, ET C'EST UNE DIRECTION OUVERTE.
    // Re-mesuré le 2026-08-28 : `grep -rn PLUME_RESPONDER_ALLOW daemon/` ne rend que des
    // COMMENTAIRES. La liste chargée ci-dessus est celle de `stop_service`, et elle n'est consultée
    // que sous `if kind == "stop_service"` (plus bas) : le chemin `ban_ip` ne la voit jamais — c'est
    // ce qui rend l'élargissement du classificateur de `P4.7-b` incapable de changer un verdict de
    // ban, et c'est aussi ce qui laisse le trou ci-dessous.
    // CE QUE ÇA COÛTE, SUR LA MACHINE MÊME QUE `P4.7-a`/`P4.7-b` DÉCRIVENT (centrale ET agent) :
    // l'exploitant sépare proprement les deux politiques, garde `/etc/plume/responder.allow` comme
    // liste d'IP à NE JAMAIS bannir, y écrit son rebond d'administration — et une action `ban_ip`
    // non ciblée est réclamée ICI (timer 20 s) AVANT que `collectors/respond.sh` ne la voie. Le ban
    // PART : la liste d'épargne n'a jamais été ouverte. Seuls `ip_is_protected` (plages réservées,
    // opérateur, passerelle) et la garde d'engagement filtrent de ce côté.
    // POURQUOI CE LOT NE LA FERME PAS, ET C'EST MESURÉ, PAS PRUDENT : le DÉFAUT de
    // `PLUME_STOP_SERVICE_ALLOW` et celui de `PLUME_RESPONDER_ALLOW` sont LE MÊME chemin. Un lecteur
    // d'épargne calqué sur celui de l'agent (fail-closed : une ligne non-adresse désarme tout ban)
    // refuserait donc TOUT bannissement sur toute installation centrale existante, dont le fichier
    // porte des NOMS DE SERVICE — c'est-à-dire qu'il transformerait un trou de protection en panne
    // d'enforcement généralisée. Fermer `P4.7-c` demande un chemin d'épargne PROPRE au démon et un
    // arbitrage écrit sur ce que vaut une liste illisible ; c'est un lot d'enforcement, pas celui-ci.
    let jail = cfg(&conf, "PLUME_FAIL2BAN_JAIL", "sshd");
    // déléguer le ban à l'IPS existant ; nft = fallback seulement
    let backend = match cfg(&conf, "PLUME_BAN_BACKEND", "auto").as_str() {
        "auto" => {
            if which("cscli") { "crowdsec".to_string() }
            else if which("fail2ban-client") { "fail2ban".to_string() }
            else { "nft".to_string() }
        }
        other => other.to_string(),
    };
    // Le central n'applique QUE ses actions locales (host NULL/vide/hostname local) ; les actions
    // ciblant un autre hôte sont laissées 'approved' -> réclamées par l'agent de cet hôte (/api/actions/pending).
    // Plateforme d'EXÉCUTION de ce responder (#20/#21). DÉFAUT "linux" = chemin nft/fail2ban historique ->
    // BYTE-IDENTIQUE. Un responder tournant sur/pour un endpoint non-linux pose PLUME_EXEC_PLATFORM ;
    // le vocab reste FERMÉ, seule la commande native change (cf platform_command).
    let platform = cfg(&conf, "PLUME_EXEC_PLATFORM", "linux");
    // S33 — QUI SUIS-JE ? C'EST CETTE RÉPONSE QUI DÉCIDE CE QUI S'EXÉCUTE ICI, et elle ne s'invente pas.
    // L'ancienne forme repliait sur `localhost` quand `/etc/hostname` n'était pas lisible et que
    // `$HOSTNAME` n'était pas posé. Un nom d'hôte plausible ment mieux qu'un zéro : les actions
    // ciblant le VRAI nom de cette machine dormaient indéfiniment en `approved` — une réponse décidée
    // par un analyste ne s'exécutait jamais, et rien ne le comptait — pendant que celles visant une
    // AUTRE machine réellement nommée `localhost` s'exécutaient ici. Une action appliquée au mauvais
    // hôte est un incident, pas un manque de signal.
    // CE QU'ON FAIT À LA PLACE, et l'arbitrage est écrit : les actions NON CIBLÉES (`host` NULL ou
    // vide) restent exécutées — elles disent « n'importe quel hôte », et cette phrase reste vraie
    // quand on ne sait pas son propre nom. Les actions CIBLÉES sont laissées intactes : elles ne
    // peuvent pas être appariées sans identité, et les apparier au hasard serait précisément le
    // défaut. Elles restent `approved`, donc réclamables plus tard, y compris par l'agent de l'hôte
    // visé via /api/actions/pending. L'aveu part sur la sortie d'erreur ET dans /metrics, où la jauge
    // `plume_host_identity_lisible` porte la cause.
    let (me, identite_lue) =
        identite_pour_reclamation(&cfg(&conf, "PLUME_HOST_LABEL", ""), crate::maintenance::identite_hote());
    let pending: Vec<(i64, String, String, bool)> = match conn.prepare(ACTIONS_A_RECLAMER_ICI) {
        Ok(mut s) => s
            .query_map(params![me, i64::from(identite_lue)], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)? != 0)))
            .map(|x| x.flatten().collect())
            .unwrap_or_default(),
        Err(_) => return,
    };
    if pending.is_empty() {
        return;
    }
    // nft = infra LINUX seulement : amorcée uniquement sur la plateforme linux (défaut) -> byte-identique
    // pour le chemin historique (platform=="linux" && backend=="nft" == backend=="nft" quand défaut).
    if platform == "linux" && backend == "nft" && pending.iter().any(|(_, k, _, d)| (k == "ban_ip" || k == "unban_ip") && !d) {
        ensure_nft_blocklist();
    }
    for (id, kind, target, dry) in pending {
        if let Err(e) = action_valid(&kind, &target, &db_path) {
            let _ = conn.execute("UPDATE action SET status='blocked', result=?2, done_ts=?3 WHERE id=?1", params![id, format!("invalide : {e}"), now()]);
            continue;
        }
        if kind == "stop_service" {
            match &allow {
                // La liste n'a PAS été lue, ou elle porte l'autre politique : le refus NOMME
                // laquelle des deux, au lieu de se déguiser en « ce service n'y est pas ».
                Err(pourquoi) => {
                    let _ = conn.execute("UPDATE action SET status='blocked', result=?2, done_ts=?3 WHERE id=?1",
                        params![id, format!("allowlist stop_service INEXPLOITABLE ({chemin_allow}) : {pourquoi}"), now()]);
                    continue;
                }
                Ok(services) if !services.contains(&target) => {
                    let _ = conn.execute("UPDATE action SET status='blocked', result=?2, done_ts=?3 WHERE id=?1",
                        params![id, format!("service hors allowlist ({chemin_allow})"), now()]);
                    continue;
                }
                Ok(_) => {}
            }
        }
        // Résolution de la commande native via le descripteur par-plateforme (#20/#21). platform=="linux"
        // (défaut) -> action_command intact (BYTE-IDENTIQUE). Un gabarit invalide/plateforme inconnue ->
        // action `blocked` (jamais d'exécution floue). generic-appliance : gabarit admin PLUME_EXEC_GENERIC_*.
        let generic = generic_template_for(&conf, &kind);
        let (prog, args) = match platform_command(&platform, &kind, &target, &backend, &jail, generic.as_deref()) {
            Ok(pa) => pa,
            Err(e) => {
                let _ = conn.execute("UPDATE action SET status='blocked', result=?2, done_ts=?3 WHERE id=?1", params![id, format!("gabarit plateforme refusé : {e}"), now()]);
                continue;
            }
        };
        if dry {
            let _ = conn.execute("UPDATE action SET status='dryrun', result=?2, done_ts=?3 WHERE id=?1", params![id, format!("[dry-run] {prog} {}", args.join(" ")), now()]);
            continue;
        }
        let (status, result) = match std::process::Command::new(&prog).args(&args).output() {
            Ok(o) => {
                let s = if o.status.success() { "done" } else { "failed" };
                let mut txt = String::from_utf8_lossy(&o.stdout).into_owned();
                txt.push_str(&String::from_utf8_lossy(&o.stderr));
                if txt.trim().is_empty() {
                    txt = format!("{prog} {} -> {}", args.join(" "), o.status);
                }
                (s, txt.chars().take(500).collect::<String>())
            }
            Err(e) => ("failed", format!("exec: {e}")),
        };
        let _ = conn.execute("UPDATE action SET status=?2, result=?3, done_ts=?4 WHERE id=?1", params![id, status, result, now()]);
        ledger_append(&conn, "action.exec", &format!("{kind} {target} -> {status}"));
        // BAN NATIF PLUME (chantier ② Phase 1) : quand le RESPONDER local exécute réellement un ban_ip/unban_ip,
        // synchronise AUSSI le store `net_ban` (blocage HTTP). Sur ce chemin (processus responder SÉPARÉ), le
        // reload ne rafraîchit que le cache de CE processus ; le daemon LIVE, lui, re-lit la table au tick de
        // maintenance (spawn_netban_maintenance) -> convergence. `action_approve`/`run_playbooks` couvrent déjà
        // le blocage IMMÉDIAT in-process ; ceci est le filet pour un chemin qui atteindrait 'approved' hors d'eux.
        if netban_from_actions_enabled() && status == "done" && !dry {
            let canon = target.trim().parse::<std::net::IpAddr>().map(|i| i.to_string()).unwrap_or_else(|_| target.trim().to_string());
            if kind == "ban_ip" && !ip_is_protected(&canon) {
                // REFUS SUR STORE PLEIN : tracé au ledger. L'enforcement RÉSEAU vient d'aboutir (`done`) —
                // seul le miroir HTTP manque, et c'est précisément ce que l'exploitant doit pouvoir lire.
                if !netban_upsert(&conn, &canon, Some(now() + NETBAN_ACTION_TTL_S), "auto: responder ban_ip", "responder", "prod") {
                    ledger_append(&conn, "netban.plafond", &format!("{canon} refusé : store live plein (responder, action {id})"));
                }
            } else if kind == "unban_ip" {
                netban_remove(&conn, &canon);
            }
        }
    }
}
