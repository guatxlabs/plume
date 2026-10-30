//! Cycle de vie des tenants (onboarding/destruction) & handlers HTTP de gestion : génération de clé
//! (`tenant_generate_key`), provisionnement/destruction (`tenant_provision`/`tenant_destroy`/
//! `seed_tenant_content`) et les routes `my_tenants`/`tenants_list`/`tenant_create`/`tenant_suspend`/
//! `tenant_unsuspend`/`tenant_set_suspended`/`tenant_delete` + grants (`grants_list`/`grant_set`/
//! `grant_delete`). Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

/// Nombre d'octets d'une clé SQLCipher de tenant (-> 2x en hex). 256 bits, la taille attendue par
/// `PRAGMA key` sous forme hexadécimale.
pub(crate) const TENANT_KEY_BYTES: usize = 32;

/// Clé SQLCipher d'un tenant : 256 bits tirés du CSPRNG de l'OS via le PRODUCTEUR UNIQUE `os_entropy`
/// (`/dev/urandom`, puis `getrandom(2)` sans descripteur de fichier) -> hex 64 chars. `None` si l'hôte
/// n'offre AUCUNE source d'entropie : l'appelant REFUSE de créer le tenant.
///
/// MÊME DOCTRINE QUE LE SECRET D'INSTALLATION, et pour la même raison. Le « filet anti-panique » qui
/// vivait ici hachait `now() | pid | adresse de pile | SystemTime::now()` : qui connaît la minute de
/// création d'un tenant énumère l'espace restant, et cette clé chiffre TOUTE la base du tenant, pour
/// toute la durée de rétention de la donnée. Un avertissement au journal ne referme pas cela — il se
/// lit une fois, la clé reste faible aussi longtemps que la donnée vit.
///
/// CE QUE LE REPLI COUVRAIT est SERVI, pas perdu : le cas réel visé (`/dev` non monté — chroot,
/// conteneur minimal) est exactement celui que la SECONDE source d'`os_entropy` traite, `getrandom(2)`
/// n'ayant besoin d'aucun descripteur. Les trois modes de déploiement revendiqués (systemd hôte-natif,
/// Docker, k3s) sont Linux, où cet appel existe depuis 3.17. Reste le noyau SANS CSPRNG : il n'y a pas
/// de bonne réponse à ce cas, et surtout pas une clé fabriquée à partir d'une horloge.
#[allow(dead_code)]
pub(crate) fn tenant_generate_key() -> Option<String> {
    tenant_key_from_entropy(os_entropy::<TENANT_KEY_BYTES>())
}

/// Formate la clé de tenant À PARTIR DE la matière aléatoire fournie — la clé EST cette matière, rien
/// d'autre. `None` en entrée -> `None` en sortie : il n'existe AUCUNE troisième voie, donc aucun repli
/// dérivé d'une horloge, d'un pid ou d'un compteur. Cœur PUR : c'est lui qui rend la mutation
/// « entropie indisponible » mesurable sans démonter l'hôte.
pub(crate) fn tenant_key_from_entropy(raw: Option<[u8; TENANT_KEY_BYTES]>) -> Option<String> {
    raw.map(|b| hex_encode(&b))
}

/// `P10.34-h` — POURQUOI `tenant_provision` N'A RIEN CRÉÉ. Le jeter serait taire un refus.
#[must_use]
#[derive(Debug)]
pub(crate) enum ProvisionNonFaite {
    /// Mode 0, slug invalide, clé non résoluble, tenant existant, base non créée : la phrase d'avant, servie comme avant
    /// (`409` pour « existe déjà », `400` sinon).
    Refusee(String),
    /// La base du plan de contrôle n'a pas pris la transaction de la création (`BEGIN`, un effacement de ce qui restait
    /// sous l'identifiant, l'inscription de la ligne du tenant, ou le `COMMIT`) : l'étape refusée, servie par sa phrase
    /// fixe (`refuser_la_creation_non_prise`) ; le texte du moteur est dit au journal, jamais servi.
    NonPrise(EtapeDeLaCreationNonPrise),
}

/// Les refus d'avant (`&str`, `String`) restent des `Refusee`, à la même phrase.
impl From<&str> for ProvisionNonFaite {
    fn from(phrase: &str) -> Self {
        ProvisionNonFaite::Refusee(phrase.to_string())
    }
}
impl From<String> for ProvisionNonFaite {
    fn from(phrase: String) -> Self {
        ProvisionNonFaite::Refusee(phrase)
    }
}

/// `P10.34-h` — l'étape de la transaction de la création que la base n'a pas prise ; chacune a sa phrase
/// `CAUSE_TENANT_NON_CREE_*`, servie par sa constante.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EtapeDeLaCreationNonPrise {
    TransactionNonOuverte,
    RestesNonEffaces,
    LigneNonInscrite,
    NonValidee,
}

/// `P10.34-h` — le 503 d'une création non prise : la phrase fixe de l'étape, par sa constante.
fn refuser_la_creation_non_prise(etape: EtapeDeLaCreationNonPrise) -> Response {
    match etape {
        EtapeDeLaCreationNonPrise::TransactionNonOuverte => err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TENANT_NON_CREE_TRANSACTION_NON_OUVERTE),
        EtapeDeLaCreationNonPrise::RestesNonEffaces => err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TENANT_NON_CREE_EFFACEMENT_NON_PRIS),
        EtapeDeLaCreationNonPrise::LigneNonInscrite => err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TENANT_NON_CREE_LIGNE_NON_INSCRITE),
        EtapeDeLaCreationNonPrise::NonValidee => err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TENANT_NON_CREE_NON_VALIDE),
    }
}

/// `P10.34-h` — le `BEGIN` de la création refusé (forme `OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`, web/core.js).
pub(crate) const CAUSE_TENANT_NON_CREE_TRANSACTION_NON_OUVERTE: &str = "TENANT NON CRÉÉ : la base n'a pas pris la \
     transaction de la création (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur l'écrivain) — \
     RIEN n'est créé : ni ligne au catalogue, ni base chiffrée. Réessayez ; s'il est refusé encore, l'écrivain est occupé \
     ou bloqué.";

/// `P10.34-h` — un effacement de ce qui restait sous l'identifiant refusé : la transaction est annulée (forme
/// `OUVERTURE_DE_L_ECRITURE_NON_PRISE`, web/core.js).
pub(crate) const CAUSE_TENANT_NON_CREE_EFFACEMENT_NON_PRIS: &str = "TENANT NON CRÉÉ : la base n'a pas pris \
     l'effacement de ce qui restait sous cet identifiant, et la transaction est annulée — RIEN n'est créé : ni ligne au \
     catalogue, ni base chiffrée. Réessayez ; si le refus persiste, la base du plan de contrôle est en lecture seule, \
     pleine ou verrouillée.";

/// `P10.34-h` — l'inscription de la ligne du tenant refusée : la transaction est annulée (forme
/// `OUVERTURE_DE_L_ECRITURE_NON_PRISE`, web/core.js). Avant, ce refus servait en `400` « insert tenant : » suivi du texte
/// du moteur.
pub(crate) const CAUSE_TENANT_NON_CREE_LIGNE_NON_INSCRITE: &str = "TENANT NON CRÉÉ : la base n'a pas pris l'écriture de \
     la ligne du tenant au catalogue, et la transaction est annulée — RIEN n'est créé : ni ligne au catalogue, ni base \
     chiffrée. Réessayez ; si le refus persiste, la base du plan de contrôle est en lecture seule, pleine ou verrouillée.";

/// `P10.34-h` — le `COMMIT` de la création refusé (forme `OUVERTURE_DE_L_ECRITURE_NON_VALIDEE`, web/core.js).
pub(crate) const CAUSE_TENANT_NON_CREE_NON_VALIDE: &str = "TENANT NON CRÉÉ : la base n'a pas validé la transaction \
     (COMMIT refusé) et l'a annulée — RIEN n'est créé : ni ligne au catalogue, ni base chiffrée. Réessayez une fois le \
     plan de contrôle de nouveau écrivable.";

/// ONBOARDING : crée l'entrée control-plane `tenant` (id, name, key_ref, db_path) PUIS la base tenant vide
/// CHIFFRÉE avec SA clé (schéma + migrations + seed minimal). FAIL-CLOSED : si `key_ref` ne résout pas
/// (ex. vault: injoignable), RIEN n'est créé. Enregistre la clé (registre read-pool) -> frontière crypto
/// immédiatement effective. La clé n'apparaît JAMAIS dans un message d'erreur/log.
///
/// `P10.34-h` — UN TENANT NAÎT SANS JETON, SANS DROIT ET SANS PROVENANCE SCIM. Dans la transaction qui inscrit sa
/// ligne, la création retire ce qui restait sous son identifiant (`RESTES_SOUS_UN_IDENTIFIANT_DE_TENANT` : jetons SCIM et
/// d'agent effacés, droits effacés, provenance scellée) : un jeton d'un tenant recréé est refusé, et ni un droit ni une
/// identité laissés sous cet identifiant ne passent au tenant recréé. Un refus (`BEGIN`, un effacement, l'inscription de
/// la ligne, `COMMIT`) rend `NonPrise` et rien n'est créé — ni ligne, ni base.
#[allow(dead_code)]
pub(crate) fn tenant_provision(mgr: &TenantDbManager, id: &str, name: &str, db_path: &str, key_ref: &str) -> Result<(), ProvisionNonFaite> {
    use crate::handlers::transaction_validee::{jouer_le_geste_garde, IssueDuGesteGarde as Issue};
    let cp = mgr.control.as_ref().ok_or("multi-tenant désactivé (mode 0) : provisioning indisponible")?;
    if !tenant_slug_ok(id) {
        return Err("slug tenant invalide (alphanumérique + '_'/'-', ≤ 64)".into());
    }
    // 1) Résout la clé AVANT toute création (fail-closed : jamais de tenant à moitié provisionné).
    let key = resolve_tenant_key(key_ref).map_err(|e| format!("key_ref non résoluble : {e}"))?;
    // 2) Entrée catalogue — refuse d'écraser un tenant existant (pas de perte silencieuse). `P10.34-h` : dans UNE
    //    transaction avec l'effacement de ce qui restait sous l'identifiant ; « existe déjà » annule avant tout effacement.
    {
        let conn = cp.conn.lock();
        let issue = jouer_le_geste_garde(&conn, "tenants", "création du tenant", |conn| -> Result<(), ProvisionNonFaite> {
            let exists = conn.query_row("SELECT 1 FROM tenant WHERE id=?1", params![id], |_| Ok(())).is_ok();
            if exists {
                return Err(ProvisionNonFaite::Refusee(format!("tenant '{id}' existe déjà")));
            }
            for (quoi, sql) in RESTES_SOUS_UN_IDENTIFIANT_DE_TENANT {
                if let Err(e) = conn.execute(sql, params![id]) {
                    eprintln!("[tenants] WARN création du tenant NON faite, rien n'est créé (effacement refusé : {quoi}) : {e}");
                    return Err(ProvisionNonFaite::NonPrise(EtapeDeLaCreationNonPrise::RestesNonEffaces));
                }
            }
            if let Err(e) = conn.execute(
                "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,?2,?3,?4,?5,0)",
                params![id, name, key_ref, db_path, now()],
            ) {
                eprintln!("[tenants] WARN création du tenant NON faite, rien n'est créé (ligne du tenant non inscrite) : {e}");
                return Err(ProvisionNonFaite::NonPrise(EtapeDeLaCreationNonPrise::LigneNonInscrite));
            }
            Ok(())
        });
        match issue {
            Issue::Valide(()) => {}
            Issue::Refuse(refus) => return Err(refus),
            // Le `BEGIN` refusé est déjà dit au journal par `ouvrir_sa_transaction`.
            Issue::NonOuvert(_) => return Err(ProvisionNonFaite::NonPrise(EtapeDeLaCreationNonPrise::TransactionNonOuverte)),
            Issue::NonValide(e) => {
                eprintln!("[tenants] WARN création du tenant NON faite, rien n'est créé (COMMIT refusé) : {e}");
                return Err(ProvisionNonFaite::NonPrise(EtapeDeLaCreationNonPrise::NonValidee));
            }
        }
    }
    // 3) Base tenant vide CHIFFRÉE avec SA clé (le FICHIER est le tenant). Parent créé au besoin.
    if let Some(parent) = std::path::Path::new(db_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // FAIL-CLOSED (même doctrine que la résolution de clé en 1) : la PORTE applique la garde
    // anti-downgrade puis `prepare_schema` (schéma, migrations, présence des objets ET des colonnes).
    // On REFUSE de déclarer le tenant prêt plutôt que de le seeder sur un schéma qui n'est pas celui
    // attendu. Les PRAGMA de la base tenant sont posés dans le prélude, donc AVANT le contrat (ordre
    // historique préservé : ils précédaient déjà `prepare_schema`).
    let conn = PreparedDb::open_keyed_with_prelude(db_path, key.as_deref(), |c| {
        let _ = c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;");
    })
    .map_err(|e| match e {
        DbOpenError::Ouverture(e) => format!("création base tenant : {e}"),
        autre => format!("base tenant : {autre} — tenant NON provisionné"),
    })?;
    // D7 (#2c) : contenu de détection COMPLET par tenant (dashboards + règles + playbooks builtin) — une
    // base tenant neuve démarre exactement comme une install fraîche (cf. run()). Les seeds conf/déploiement
    // (overlays config.d, notifier d'env, données de démo) sont DÉLIBÉRÉMENT exclus (spécifiques au site).
    seed_tenant_content(&conn);
    // 4) Enregistre la clé du tenant pour le read-pool (frontière crypto effective sans attendre un resolve).
    register_db_key(db_path, key);
    Ok(())
}

/// `P10.34-h` — POURQUOI `tenant_destroy` N'A RIEN DÉTRUIT. Le jeter serait taire un refus.
#[must_use]
#[derive(Debug)]
pub(crate) enum DestructionNonFaite {
    /// Mode 0, tenant `default` ou tenant inconnu : la phrase d'avant, servie comme avant.
    Refusee(String),
    /// La base du plan de contrôle n'a pas pris la transaction de la destruction (`BEGIN`, lecture de la ligne du
    /// tenant, un effacement ou le `COMMIT`) : l'étape refusée, servie par sa phrase fixe
    /// (`refuser_la_destruction_non_prise`). Le texte du moteur est dit au journal par la voie qui l'a rencontré, jamais
    /// servi.
    NonPrise(EtapeDeLaDestructionNonPrise),
}

/// `P10.34-h` — l'étape de la transaction de la destruction que la base n'a pas prise ; chacune a sa phrase
/// `CAUSE_TENANT_NON_DETRUIT_*`, servie par sa constante (la garde `check_web_reads_every_verdict` la dérive ainsi et
/// exige que la console en reconnaisse l'ouverture).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EtapeDeLaDestructionNonPrise {
    TransactionNonOuverte,
    LigneNonLue,
    EffacementNonPris,
    NonValidee,
}

/// `P10.34-h` — le 503 d'une destruction non prise : la phrase fixe de l'étape, par sa constante.
fn refuser_la_destruction_non_prise(etape: EtapeDeLaDestructionNonPrise) -> Response {
    match etape {
        EtapeDeLaDestructionNonPrise::TransactionNonOuverte => err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TENANT_NON_DETRUIT_TRANSACTION_NON_OUVERTE),
        EtapeDeLaDestructionNonPrise::LigneNonLue => err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TENANT_NON_DETRUIT_NON_LU),
        EtapeDeLaDestructionNonPrise::EffacementNonPris => err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TENANT_NON_DETRUIT_EFFACEMENT_NON_PRIS),
        EtapeDeLaDestructionNonPrise::NonValidee => err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TENANT_NON_DETRUIT_NON_VALIDE),
    }
}

/// `P10.34-h` — le `BEGIN` de la destruction refusé (`OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`, web/core.js).
pub(crate) const CAUSE_TENANT_NON_DETRUIT_TRANSACTION_NON_OUVERTE: &str = "TENANT NON DÉTRUIT : la base n'a pas pris la \
     transaction de la destruction (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur l'écrivain) \
     — RIEN n'est détruit : le tenant, sa base, sa clé, ses droits et ses jetons, SCIM compris, sont intacts ; la ligne du \
     journal de contrôle qui annonce cette destruction est déjà écrite. Réessayez ; s'il est refusé encore, l'écrivain est \
     occupé ou bloqué.";

/// `P10.34-h` — un effacement de la destruction refusé : la transaction est annulée (`OUVERTURE_DE_L_ECRITURE_NON_PRISE`,
/// web/core.js).
pub(crate) const CAUSE_TENANT_NON_DETRUIT_EFFACEMENT_NON_PRIS: &str = "TENANT NON DÉTRUIT : la base n'a pas pris \
     l'effacement de ce qui le rattache au plan de contrôle, et la transaction est annulée — RIEN n'est détruit : le \
     tenant, sa base, sa clé, ses droits et ses jetons, SCIM compris, sont intacts ; la ligne du journal de contrôle qui \
     annonce cette destruction est déjà écrite. Réessayez ; si le refus persiste, la base du plan de contrôle est en \
     lecture seule, pleine ou verrouillée.";

/// `P10.34-h` — le `COMMIT` de la destruction refusé (`OUVERTURE_DE_L_ECRITURE_NON_VALIDEE`, web/core.js).
pub(crate) const CAUSE_TENANT_NON_DETRUIT_NON_VALIDE: &str = "TENANT NON DÉTRUIT : la base n'a pas validé la transaction \
     (COMMIT refusé) et l'a annulée — RIEN n'est détruit : le tenant, sa base, sa clé, ses droits et ses jetons, SCIM \
     compris, sont intacts ; la ligne du journal de contrôle qui annonce cette destruction est déjà écrite. Réessayez une \
     fois le plan de contrôle de nouveau écrivable.";

/// `P10.34-h` — la ligne du tenant non relue au début de la destruction : ce n'est pas « tenant inconnu ».
pub(crate) const CAUSE_TENANT_NON_DETRUIT_NON_LU: &str = "TENANT NON DÉTRUIT : la base du plan de contrôle n'a pas pu \
     relire la ligne du tenant au début de la destruction — ce n'est PAS « tenant inconnu », son existence n'est ni \
     affirmée ni niée. RIEN n'est détruit : le tenant, sa base, sa clé, ses droits et ses jetons, SCIM compris, sont \
     intacts ; la ligne du journal de contrôle qui annonce cette destruction est déjà écrite. Réessayez une fois le plan \
     de contrôle de nouveau lisible.";

/// `P10.34-h` — ce qu'un identifiant de tenant porte dans le plan de contrôle hors de sa ligne : ses jetons SCIM, la
/// provenance des identités que son SCIM a créées (SCELLÉE, voir `EFFACEMENTS_DE_LA_DESTRUCTION`), ses jetons d'agent et
/// ses droits — les quatre tables à colonne `tenant_id` (`state::migrate_control`, `rbac::migrate_control_provenance_scim`).
/// La destruction les retire ; la création aussi, avant d'inscrire la ligne du tenant (`tenant_provision`), pour ce qui
/// serait resté sous l'identifiant : une destruction d'une version antérieure, un jeton posé sur un identifiant non
/// catalogué par une version antérieure de `scim-token` (qui le refuse désormais), une écriture tombée sous l'identifiant
/// après la destruction (une écriture SCIM relit son jeton dans sa transaction, `scim::scim_exiger_le_jeton_sur`). Le
/// premier élément nomme l'effacement au journal.
pub(crate) const RESTES_SOUS_UN_IDENTIFIANT_DE_TENANT: [(&str, &str); 4] = [
    ("jetons SCIM", "DELETE FROM scim_token WHERE tenant_id=?1"),
    ("provenance SCIM", "UPDATE scim_provenance SET tenant_id='(tenant détruit)' WHERE tenant_id=?1"),
    ("jetons d'agent", "DELETE FROM token WHERE tenant_id=?1"),
    ("droits", "DELETE FROM \"grant\" WHERE tenant_id=?1"),
];

/// `P10.34-h` — ce que la destruction efface dans le plan de contrôle, dans cet ordre et dans UNE transaction : les
/// jetons SCIM du tenant, la provenance de ses identités SCIM (SCELLÉE, voir plus bas), ses jetons d'agent, ses
/// droits, puis sa ligne (le `key_ref` disparaît : plus aucune référence à la clé). Le premier élément nomme
/// l'effacement au journal (constante, jamais le texte d'une demande).
///
/// LA PROVENANCE N'EST PAS EFFACÉE, ELLE EST SCELLÉE sur le tenant `(tenant détruit)`, qu'aucun tenant ne peut porter
/// (`tenant_slug_ok` refuse l'espace et les parenthèses). Effacée, une identité créée par le SCIM du tenant détruit et
/// sans droit ailleurs devenait « sans droit ni provenance », donc RATTACHABLE PAR TOUT TENANT SCIM
/// (`rbac::lire_le_rattachement_scim`) : `POST /Users` de son nom servait son id, `PATCH add` lui posait un droit.
/// Laissée telle quelle, un tenant recréé sous le même identifiant en héritait. Scellée, elle est étrangère à tous —
/// au tenant recréé compris — tant qu'aucun droit ne lui est posé hors SCIM.
///
/// LIMITE NOMMÉE (décision voisine de l'exploitant, `P10.34-h`) : une identité scellée garde sa ligne `platform_user` et
/// son nom ; aucun tenant ne peut plus la rattacher, si bien que `POST /Users` de ce nom rend `409`, au tenant recréé
/// compris : le nom est pris tant que l'identité n'est pas retirée hors SCIM.
pub(crate) const EFFACEMENTS_DE_LA_DESTRUCTION: [(&str, &str); 5] = [
    RESTES_SOUS_UN_IDENTIFIANT_DE_TENANT[0],
    RESTES_SOUS_UN_IDENTIFIANT_DE_TENANT[1],
    RESTES_SOUS_UN_IDENTIFIANT_DE_TENANT[2],
    RESTES_SOUS_UN_IDENTIFIANT_DE_TENANT[3],
    ("ligne du tenant", "DELETE FROM tenant WHERE id=?1"),
];

/// DESTRUCTION CRYPTO (RGPD) : OUBLIE la clé (supprime l'entrée control-plane `tenant` + ses grants/tokens, ses jetons
/// SCIM, scelle la provenance de ses identités SCIM + purge les caches de clé) et SUPPRIME le fichier chiffré (+ WAL/SHM).
/// Après cela, la donnée est cryptographiquement irrécupérable. Évince aussi le writer mémoïsé. Le tenant `default`
/// est protégé.
///
/// `P10.34-h` — TOUT OU RIEN DANS LE PLAN DE CONTRÔLE, PUIS LE FICHIER. Les effacements étaient jetés un par un
/// (`let _ =`) : un refus laissait le tenant à moitié oublié, et le fichier chiffré était supprimé quand même. La ligne
/// du tenant est relue et les cinq effacements faits dans UNE transaction (`jouer_le_geste_garde`) ; un refus (`BEGIN`,
/// lecture, effacement, `COMMIT`) rend `NonPrise` et RIEN n'est détruit — ni ligne, ni cache (écrivain mémoïsé, registre
/// des clés, cache Vault), ni fichier. Les caches et le fichier ne sont touchés qu'après le `COMMIT`.
#[allow(dead_code)]
pub(crate) fn tenant_destroy(mgr: &TenantDbManager, id: &str) -> Result<(), DestructionNonFaite> {
    use crate::handlers::transaction_validee::{jouer_le_geste_garde, IssueDuGesteGarde as Issue};
    use rusqlite::OptionalExtension as _;
    let cp = mgr
        .control
        .as_ref()
        .ok_or_else(|| DestructionNonFaite::Refusee("multi-tenant désactivé (mode 0) : destruction indisponible".into()))?;
    if id == "default" {
        return Err(DestructionNonFaite::Refusee("refus : le tenant 'default' ne peut pas être détruit".into()));
    }
    let issue = {
        let conn = cp.conn.lock();
        jouer_le_geste_garde(&conn, "tenants", "destruction du tenant", |conn| -> Result<(String, String), DestructionNonFaite> {
            let row = conn
                .query_row("SELECT db_path, key_ref FROM tenant WHERE id=?1", params![id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .optional();
            let (p, kr) = match row {
                Ok(Some(lu)) => lu,
                Ok(None) => return Err(DestructionNonFaite::Refusee(format!("tenant '{id}' inconnu"))),
                Err(e) => {
                    eprintln!("[tenants] WARN destruction du tenant NON faite, rien n'est détruit (ligne du tenant non relue) : {e}");
                    return Err(DestructionNonFaite::NonPrise(EtapeDeLaDestructionNonPrise::LigneNonLue));
                }
            };
            for (quoi, sql) in EFFACEMENTS_DE_LA_DESTRUCTION {
                if let Err(e) = conn.execute(sql, params![id]) {
                    eprintln!("[tenants] WARN destruction du tenant NON faite, rien n'est détruit (effacement refusé : {quoi}) : {e}");
                    return Err(DestructionNonFaite::NonPrise(EtapeDeLaDestructionNonPrise::EffacementNonPris));
                }
            }
            Ok((p, kr))
        })
    };
    let (db_path, key_ref) = match issue {
        Issue::Valide(lu) => lu,
        Issue::Refuse(refus) => return Err(refus),
        // Le `BEGIN` refusé est déjà dit au journal par `ouvrir_sa_transaction`.
        Issue::NonOuvert(_) => return Err(DestructionNonFaite::NonPrise(EtapeDeLaDestructionNonPrise::TransactionNonOuverte)),
        Issue::NonValide(e) => {
            eprintln!("[tenants] WARN destruction du tenant NON faite, rien n'est détruit (COMMIT refusé) : {e}");
            return Err(DestructionNonFaite::NonPrise(EtapeDeLaDestructionNonPrise::NonValidee));
        }
    };
    // Évince le writer chaud + purge les caches de clé (registre read-pool + cache Vault).
    mgr.writers.lock().remove(id);
    unregister_db_key(&db_path);
    // `P10.34-h` — le cache Vault est rangé sous `chemin#champ` (`resolve_vault_key_field`, champ `key` par défaut) : la
    // clé d'oubli est relue par la même grammaire que la résolution (`resolve_tenant_key`), sinon une référence
    // `vault:chemin` sans champ laissait la clé du tenant détruit en mémoire.
    let reference = guatx_core::secret::SecretRef::parse(key_ref.trim());
    if reference.scheme() == "vault" {
        let (chemin, champ) = reference.vault_path_field();
        vault_key_cache_forget(&format!("{chemin}#{champ}"));
    }
    // Supprime le fichier chiffré + journaux (destruction crypto : sans la clé, le contenu est illisible).
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(format!("{db_path}-wal"));
    let _ = std::fs::remove_file(format!("{db_path}-shm"));
    Ok(())
}

/// D7 (#2c) — SEED COMPLET du contenu de détection d'une base tenant NEUVE : dashboards + règles + playbooks
/// builtin, DANS LE MÊME ORDRE que run() sur une install fraîche. N'inclut PAS les seeds spécifiques au
/// déploiement/site (overlays config.d, notifier d'environnement, données de démo `seed_demo`) : ceux-ci
/// dépendent de la conf de l'hôte et n'ont pas de sens « par défaut » pour un tenant client. Idempotent
/// (chaque seed est gardé par son flag `meta.seeded_*`), donc sûr à ré-exécuter.
pub(crate) fn seed_tenant_content(conn: &Connection) {
    seed_default_dashboard(conn);
    seed_example_rules(conn);
    seed_purple_rules(conn);
    seed_detection_rules(conn);
    seed_runbooks(conn);   // #3 incidents Phase 1 : runbooks managés keyés MITRE (un drapeau `seeded_runbook_<clé>` par gabarit, managé amputé réparé : P10.28-k)
    seed_ti_alert_rules(conn);   // #23 activation : alerte match IOC (managé, inerte sans IOC)
    seed_risk_rules(conn);       // #24 activation : règles RBA mode risque (managé)
    seed_example_playbooks(conn);
    seed_ssh_cve_playbook(conn);
    seed_k8s_rules(conn);
    seed_obs_dashboard(conn);
    seed_obs_rules(conn);
    seed_sts_rules(conn);
    seed_velero_rule(conn);
    seed_malware_rule(conn);
    seed_slab_rule(conn);
    seed_security_dashboard(conn);
    seed_egress_dashboard(conn);
    seed_web_dashboard(conn);
    seed_mail_dashboard(conn);
    seed_dataaccess_dashboard(conn);
    seed_dataacl_dashboard(conn);
    seed_sca_dashboard(conn);    // #57 : posture SCA/CIS (BYO-agent endpoint)
    seed_vuln_dashboard(conn);   // #57 : vulnérabilités CVE endpoint
    seed_kube_rbac_dashboard(conn);
    seed_minio_dashboard(conn);
    seed_vault_dashboard(conn);
    seed_rollup_dashboard(conn);
    ensure_rollup_srcip_host_panels(conn);
    seed_banpass_dashboard_et_compter_son_refus(conn);
    seed_egress_rules(conn);
}

/// GET /api/my-tenants — liste les tenants accessibles à l'utilisateur (pour le switcher UI). Tout user
/// authentifié (mode 1). Mode 0 : `[{id:"default", role:<rôle courant>}]` (inerte, aucun control-plane).
/// Super-admin : TOUS les tenants (rôle = son grant s'il en a un, sinon "operator" = accès cross-tenant) ;
/// sinon : ses grants matérialisés (table `grant`). Le tenant COURANT (au.tenant) est toujours présent.
pub(crate) async fn my_tenants(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    if !st.multi_tenant {
        return Json(json!([{ "id": "default", "role": au.role }]));
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return Json(json!([{ "id": "default", "role": au.role }]));
    };
    let mut out: Vec<Value> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    {
        let conn = cp.conn.lock();
        if au.is_superadmin {
            // Super-admin : tous les tenants (non-supprimés). Rôle = son grant si membre, sinon "operator".
            if let Ok(mut stmt) = conn.prepare(
                "SELECT t.id, t.name, t.suspended, COALESCE(g.role,'operator') \
                 FROM tenant t LEFT JOIN \"grant\" g ON g.tenant_id=t.id \
                   AND g.user_id=(SELECT id FROM platform_user WHERE name=?1) ORDER BY t.id",
            ) {
                if let Ok(rows) = stmt.query_map(params![au.name], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?))
                }) {
                    for (id, name, susp, role) in rows.flatten() {
                        seen.insert(id.clone());
                        out.push(json!({ "id": id, "name": name, "role": role, "suspended": susp != 0 }));
                    }
                }
            }
        } else if let Ok(mut stmt) = conn.prepare(
            "SELECT t.id, t.name, t.suspended, g.role FROM \"grant\" g JOIN tenant t ON t.id=g.tenant_id \
             WHERE g.user_id=(SELECT id FROM platform_user WHERE name=?1) ORDER BY t.id",
        ) {
            if let Ok(rows) = stmt.query_map(params![au.name], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?))
            }) {
                for (id, name, susp, role) in rows.flatten() {
                    seen.insert(id.clone());
                    out.push(json!({ "id": id, "name": name, "role": role, "suspended": susp != 0 }));
                }
            }
        }
    }
    // Le tenant COURANT est toujours listé (couvre les grants SSO-live non matérialisés dans `grant`).
    if !au.tenant.is_empty() && !seen.contains(&au.tenant) {
        out.push(json!({ "id": au.tenant, "role": au.role }));
    }
    Json(json!(out))
}

/// GET /api/tenants — liste TOUS les tenants (SUPER-ADMIN only, re-check serveur). Mode 0 : `{tenants:[]}`.
pub(crate) async fn tenants_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !st.multi_tenant {
        return Json(json!({ "tenants": [] })).into_response();
    }
    if !au.is_superadmin {
        return (StatusCode::FORBIDDEN, "réservé au super-admin plateforme").into_response();
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return Json(json!({ "tenants": [] })).into_response();
    };
    let conn = cp.conn.lock();
    let mut stmt = match conn.prepare(
        "SELECT t.id, t.name, t.suspended, t.created, t.db_path, \
                (SELECT COUNT(*) FROM \"grant\" g WHERE g.tenant_id=t.id) \
         FROM tenant t ORDER BY t.id",
    ) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("control-plane indisponible: {e}")).into_response(),
    };
    let tenants: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "name": r.get::<_, String>(1)?,
                "suspended": r.get::<_, i64>(2)? != 0,
                "created": r.get::<_, Option<i64>>(3)?,
                "db_path": r.get::<_, String>(4)?,
                "nb_users": r.get::<_, i64>(5)?,
            }))
        })
        .map(|it| it.flatten().collect())
        .unwrap_or_default();
    Json(json!({ "tenants": tenants })).into_response()
}

/// POST /api/tenants — ONBOARDING d'un tenant (SUPER-ADMIN only). Body : {id, name, key_ref?, admin?}.
/// Génère une clé fraîche (`tenant_generate_key`, stockée `literal:` dans le control-plane chiffré) si aucun
/// `key_ref` explicite (ex. `vault:chemin` pré-approvisionné) n'est fourni. `tenant_provision` crée l'entrée
/// control-plane + la base chiffrée + seed COMPLET (D7). Refuse un slug invalide / `default` / existant.
/// Optionnellement pose le 1er grant admin. Audit : control_ledger `tenant.create` + event tenant.
pub(crate) async fn tenant_create(
    State(st): State<AppState>,
    secret_des_gestes: crate::secret_des_gestes::SecretDesGestesPresente,
    Extension(au): Extension<AuthUser>,
    Json(b): Json<Value>,
) -> Response {
    if !st.multi_tenant {
        return (StatusCode::NOT_FOUND, "multi-tenant désactivé (mode 0)").into_response();
    }
    if !au.is_superadmin {
        return (StatusCode::FORBIDDEN, "réservé au super-admin plateforme").into_response();
    }
    if st.tenants.control.is_none() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "control-plane indisponible").into_response();
    }
    let id = b.trimmed("id");
    let name = b.trimmed("name");
    if !tenant_slug_ok(&id) {
        return (StatusCode::BAD_REQUEST, "slug invalide (alphanumérique + '_'/'-', ≤ 64)").into_response();
    }
    if id == "default" {
        return (StatusCode::BAD_REQUEST, "le tenant 'default' est réservé").into_response();
    }
    let name = if name.is_empty() { id.clone() } else { name };
    // `P10.24-m` — UN TENANT CRÉÉ AVEC SON PREMIER ADMINISTRATEUR POSE UN DROIT ADMINISTRATEUR PERSISTANT : le secret des
    // gestes, avant tout provisionnement. Sans `admin` demandé, la création ne pose aucun accès (le catalogue et une
    // base vide) et reste ouverte au seul droit.
    if let Some(premier) = b.get("admin").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
        if let Err(refus) = crate::secret_des_gestes::exiger_le_secret_des_gestes(&st, &secret_des_gestes, &au.name, &format!("création du tenant '{id}' avec son premier administrateur '{premier}'")) {
            return refus;
        }
    }
    // key_ref explicite (ex. vault:...) sinon clé fraîche générée, stockée en literal: dans le control-plane
    // (lui-même chiffré at-rest par PLUME_CONTROL_KEY). tenant_provision est FAIL-CLOSED si key_ref ne résout pas.
    // Et la GÉNÉRATION l'est aussi : sans entropie de l'OS, AUCUN tenant n'est créé — plutôt aucun tenant
    // qu'un tenant dont la base entière est chiffrée par une clé énumérable. L'exploitant garde la voie
    // explicite (`key_ref` pré-approvisionné : `env:`, `literal:`, `vault:`), qui ne dépend pas de l'entropie locale.
    let key_ref = match b.get("key_ref").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(explicite) => explicite,
        None => match tenant_generate_key() {
            Some(k) => format!("literal:{k}"),
            None => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "aucune source d'entropie (ni /dev/urandom ni getrandom) : tenant NON créé. Aucune clé \
                     dérivée d'une horloge ou d'un pid n'est émise. Répare l'entropie de l'hôte, ou fournis \
                     un `key_ref` pré-approvisionné.",
                )
                    .into_response()
            }
        },
    };
    let db_path = tenant_db_path(&st, &id);
    // Provisioning HORS de l'exécuteur async (schéma + seeds = plusieurs ms). TenantDbManager est Clone (Arc).
    let mgr = st.tenants.clone();
    let (pid, pname, pdb, pkey) = (id.clone(), name.clone(), db_path.clone(), key_ref.clone());
    let provision = tokio::task::spawn_blocking(move || tenant_provision(&mgr, &pid, &pname, &pdb, &pkey))
        .await
        .unwrap_or_else(|e| Err(ProvisionNonFaite::Refusee(format!("tâche de provisioning interrompue: {e}"))));
    match provision {
        Ok(()) => {}
        // `P10.34-h` — la transaction de la création non prise : 503 à phrase fixe, rien n'est créé, rejouable.
        Err(ProvisionNonFaite::NonPrise(etape)) => return refuser_la_creation_non_prise(etape),
        Err(ProvisionNonFaite::Refusee(e)) => {
            // "existe déjà" -> 409 ; sinon échec de provisioning (clé/FS) -> 400 (fail-closed, rien créé).
            let code = if e.contains("existe déjà") { StatusCode::CONFLICT } else { StatusCode::BAD_REQUEST };
            return (code, e).into_response();
        }
    }
    // 1er grant admin OPTIONNEL : matérialise le platform_user + grant admin sur le nouveau tenant.
    // `P10.21-g` — le grant est COMPTÉ avant que le journal de contrôle ou la réponse ne le nomment.
    let premier_administrateur = poser_le_premier_administrateur(&st, &id, b.get("admin").and_then(|v| v.as_str()));
    let first_admin = premier_administrateur.pose().map(str::to_string);
    let premier_administrateur_non_pose = premier_administrateur.cause_de_non_pose();
    // `P10.20-z` — LE TENANT EST PROVISIONNÉ ; SI SA LIGNE MANQUE AU JOURNAL DE CONTRÔLE, LA RÉPONSE LE
    // DIT à côté du succès. Refuser serait faux : la base existe, et un rejeu rendrait « existe déjà ».
    // La ligne de contrôle dit aussi qu'un administrateur DEMANDÉ manque ; rien n'est ajouté au détail
    // sur le chemin nominal (le maillon y est haché sur le même texte qu'avant).
    let mut detail = json!({ "name": name, "db_path": db_path, "first_admin": first_admin });
    if premier_administrateur_non_pose.is_some() {
        detail["first_admin_non_pose"] = json!(true);
    }
    let maillon = control_ledger_append(&st, "tenant.create", &au.name, &id, &detail.to_string());
    // `P10.21-m` — l'événement du tenant rend son issue ; perdu, il est avoué à côté du deux cent un.
    // `P10.30-d` — une base NON SERVIE (`SansBaseServie`) aussi, par le même appel (`avouer_l_evenement_du_tenant_non_ecrit`,
    // rbac.rs) : la base vient d'être provisionnée, elle ne manque que si le tenant est suspendu, ou son ouverture
    // refusée, entre le provisionnement et cet événement. La forme du corps ci-dessous est relue telle quelle par le
    // harnais de la console (`web_esm_harnais.mjs`, provisionnement (b)) : l'aveu passe par l'appel existant.
    let evenement = audit_tenant_event(
        &st,
        &id,
        "tenant.create",
        2,
        &format!("tenant '{id}' provisionné par l'opérateur plateforme '{}'", au.name),
        json!({ "operator": au.name, "name": name, "first_admin": first_admin }),
    );
    let mut corps = json!({ "ok": true, "id": id, "name": name, "first_admin": first_admin });
    avouer_le_maillon_de_controle_manquant(&mut corps, &maillon);
    avouer_l_evenement_du_tenant_non_ecrit(&mut corps, &evenement);
    if let Some(cause) = premier_administrateur_non_pose {
        corps[CLE_PREMIER_ADMINISTRATEUR_NON_POSE] = json!(format!("{CAUSE_PREMIER_ADMINISTRATEUR_NON_POSE} ({cause})"));
    }
    (StatusCode::CREATED, Json(corps)).into_response()
}

/// `P10.21-g` — LA CLÉ SOUS LAQUELLE LA CRÉATION D'UN TENANT AVOUE QUE LE PREMIER ADMINISTRATEUR DEMANDÉ
/// N'A PAS ÉTÉ POSÉ. Absente sur le chemin nominal et quand aucun administrateur n'est demandé : le corps
/// y ressort byte-identique.
pub(crate) const CLE_PREMIER_ADMINISTRATEUR_NON_POSE: &str = "premier_administrateur_non_pose";

/// `P10.21-g` — CE QUE DIT UNE CRÉATION DE TENANT DONT LE PREMIER ADMINISTRATEUR N'EST PAS POSÉ. Le tenant
/// EST créé (201) : refuser mentirait, la base existe et un rejeu rendrait « existe déjà ». La phrase dit
/// donc ce qui manque et le geste qui le comble.
pub(crate) const CAUSE_PREMIER_ADMINISTRATEUR_NON_POSE: &str =
    "PREMIER ADMINISTRATEUR NON POSÉ : le tenant est créé, mais le droit d'administration demandé n'a pas \
     été écrit — personne n'administre encore ce tenant. Posez-le par la gestion des droits du tenant.";

/// `P10.21-g` — L'ISSUE DU PREMIER ADMINISTRATEUR D'UN TENANT NEUF. `NonPose` porte la cause : l'appelant
/// ne peut pas nommer un administrateur sans avoir écrit l'autre branche.
pub(crate) enum PremierAdministrateur {
    NonDemande,
    Pose(String),
    NonPose(String),
}

impl PremierAdministrateur {
    pub(crate) fn pose(&self) -> Option<&str> {
        match self {
            Self::Pose(nom) => Some(nom),
            Self::NonDemande | Self::NonPose(_) => None,
        }
    }

    pub(crate) fn cause_de_non_pose(&self) -> Option<String> {
        match self {
            Self::NonPose(cause) => Some(cause.clone()),
            Self::NonDemande | Self::Pose(_) => None,
        }
    }
}

/// `P10.21-g` — POSE LE PREMIER ADMINISTRATEUR DEMANDÉ, ET NE LE NOMME QUE SI LE DROIT EST ÉCRIT. Les
/// trois voies d'échec étaient muettes : un nom invalide et un compte plateforme non matérialisé
/// rendaient `first_admin: null` sans cause, et un `INSERT` avalé rendait le nom comme s'il était posé
/// — la réponse ET le journal de contrôle attestaient un administrateur qui n'existait pas.
pub(crate) fn poser_le_premier_administrateur(st: &AppState, tenant: &str, demande: Option<&str>) -> PremierAdministrateur {
    let Some(admin) = demande.map(str::trim).filter(|s| !s.is_empty()) else {
        return PremierAdministrateur::NonDemande;
    };
    if !platform_user_name_ok(admin) {
        return PremierAdministrateur::NonPose("nom de compte invalide (alphanumérique, . _ - uniquement)".into());
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return PremierAdministrateur::NonPose("plan de contrôle indisponible".into());
    };
    let Some(uid) = ensure_platform_user(cp, admin) else {
        return PremierAdministrateur::NonPose("le compte plateforme n'a pas pu être matérialisé".into());
    };
    let conn = cp.conn.lock();
    match EcritureDuPlanDeControle::from(conn.execute(
        "INSERT OR REPLACE INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'admin')",
        params![uid, tenant],
    )) {
        EcritureDuPlanDeControle::Ecrite => PremierAdministrateur::Pose(admin.to_string()),
        EcritureDuPlanDeControle::AucuneLigne => PremierAdministrateur::NonPose("aucune ligne écrite".into()),
        EcritureDuPlanDeControle::Refusee(cause) => PremierAdministrateur::NonPose(cause),
    }
}

/// POST /api/tenants/{id}/suspend | /unsuspend — bascule le flag `suspended` (SUPER-ADMIN only). Un tenant
/// suspendu = plus d'accès (guard fail-closed) + jobs de fond SKIP. `default` protégé. Audit.
pub(crate) async fn tenant_suspend(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<String>) -> Response {
    tenant_set_suspended(&st, &au, &id, true).await
}

pub(crate) async fn tenant_unsuspend(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<String>) -> Response {
    tenant_set_suspended(&st, &au, &id, false).await
}

pub(crate) async fn tenant_set_suspended(st: &AppState, au: &AuthUser, id: &str, suspend: bool) -> Response {
    if !st.multi_tenant {
        return (StatusCode::NOT_FOUND, "multi-tenant désactivé (mode 0)").into_response();
    }
    if !au.is_superadmin {
        return (StatusCode::FORBIDDEN, "réservé au super-admin plateforme").into_response();
    }
    if id == "default" {
        return (StatusCode::BAD_REQUEST, "le tenant 'default' ne peut pas être suspendu").into_response();
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "control-plane indisponible").into_response();
    };
    // Existence + audit AVANT de basculer (à la suspension, la base doit encore être résoluble pour l'event).
    // `P10.21-m` — TROIS ISSUES : présent, ABSENT (404), ILLISIBLE (503 nommé, comme `grant_set`). `.is_ok()`
    // servait une lecture ratée comme « tenant inconnu » : une lecture non faite rendue comme un fait.
    let existence = {
        let conn = cp.conn.lock();
        conn.query_row("SELECT 1 FROM tenant WHERE id=?1", params![id], |_| Ok(()))
    };
    match existence {
        Ok(()) => {}
        Err(rusqlite::Error::QueryReturnedNoRows) => return (StatusCode::NOT_FOUND, "tenant inconnu").into_response(),
        Err(e) => {
            eprintln!("[tenants] WARN tenant '{id}' NON lu à la bascule de suspension : {e}");
            return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TENANT_NON_LU_BASCULE_NON_FAITE);
        }
    }
    let (kind, sev, verb) = if suspend {
        ("tenant.suspend", 3, "suspendu")
    } else {
        ("tenant.unsuspend", 2, "réactivé")
    };
    // `P10.21-g` — LA POIGNÉE AVANT, L'ÉVÉNEMENT APRÈS. À la suspension, la base du tenant doit être
    // résolue tant qu'elle est active (après la bascule elle ne se résout plus) ; mais l'événement ne
    // s'écrit qu'une fois la bascule ÉCRITE : posé avant, il disait « suspendu » au tenant sur une
    // bascule que la base pouvait refuser.
    let poignee_avant_suspension = if suspend { st.tenants.handle_for(id) } else { None };
    let bascule = {
        let conn = cp.conn.lock();
        EcritureDuPlanDeControle::from(conn.execute("UPDATE tenant SET suspended=?1 WHERE id=?2", params![i64::from(suspend), id]))
    };
    match bascule {
        EcritureDuPlanDeControle::Ecrite => {}
        // Le tenant existait à la lecture ci-dessus et n'existe plus : détruit entre-temps.
        EcritureDuPlanDeControle::AucuneLigne => return (StatusCode::NOT_FOUND, "tenant inconnu").into_response(),
        EcritureDuPlanDeControle::Refusee(cause) => return refuser_le_geste_non_ecrit(CAUSE_BASCULE_DE_SUSPENSION_NON_ECRITE, &cause),
    }
    let message = format!("tenant '{id}' {verb} par '{}'", au.name);
    // `P10.21-m` — la bascule est ÉCRITE : un événement perdu ne l'annule pas, il est avoué à côté du succès.
    let evenement = match poignee_avant_suspension {
        Some(poignee) => audit_tenant_event_sur(&poignee, kind, sev, &message, json!({ "operator": au.name })),
        // Réactivation : la base redevient résoluble APRÈS la bascule. Suspension d'un tenant dont la
        // base ne se résolvait déjà pas : l'appel ne trouve rien, comme avant.
        None => audit_tenant_event(st, id, kind, sev, &message, json!({ "operator": au.name })),
    };
    // `P10.20-z` — la bascule est faite ; une ligne manquante au journal de contrôle est dite à côté.
    let maillon = control_ledger_append(st, kind, &au.name, id, &json!({ "operator": au.name }).to_string());
    let mut corps = json!({ "ok": true, "id": id, "suspended": suspend });
    avouer_le_maillon_de_controle_manquant(&mut corps, &maillon);
    avouer_l_evenement_du_tenant_non_ecrit(&mut corps, &evenement);
    Json(corps).into_response()
}

/// `P10.21-m` — la lecture du tenant visé par une bascule de suspension a échoué : ni présent ni absent n'est affirmé.
pub(crate) const CAUSE_TENANT_NON_LU_BASCULE_NON_FAITE: &str = "TENANT NON LU, BASCULE NON FAITE : le plan de contrôle \
     n'a pas pu lire le tenant visé — ce n'est PAS « tenant inconnu », son existence n'est ni affirmée ni niée. Le tenant \
     garde l'état qu'il avait (suspendu ou actif), rien n'est tracé. Réessayez une fois le plan de contrôle de nouveau lisible.";

/// `P10.21-g` — LA BASCULE DE SUSPENSION QUE LA BASE N'A PAS PRISE EST REFUSÉE : 503, et rien n'est posé
/// — ni au journal de contrôle, ni dans la base du tenant. L'état du tenant est celui d'avant la demande.
pub(crate) const CAUSE_BASCULE_DE_SUSPENSION_NON_ECRITE: &str =
    "BASCULE NON ENREGISTRÉE, RIEN N'A CHANGÉ : le plan de contrôle n'a pas pris l'écriture de la \
     suspension (ou de la réactivation) ; le tenant garde l'état qu'il avait, et aucune trace ne dit le \
     contraire. Réessayez une fois le plan de contrôle de nouveau écrivable.";

/// `P10.20-z` — LA DESTRUCTION D'UN TENANT EST REFUSÉE QUAND SA LIGNE N'ENTRE PAS AU JOURNAL DE CONTRÔLE :
/// 503, et rien n'est détruit. Le geste est rejouable tel quel.
pub(crate) const CAUSE_DESTRUCTION_SANS_TRACE: &str =
    "DESTRUCTION REFUSÉE, RIEN N'EST DÉTRUIT : le journal du plan de contrôle n'a pas pris la ligne qui \
     atteste cette destruction, et après elle ce journal serait la seule preuve qu'elle a eu lieu. Le \
     tenant et sa base sont intacts ; réessayez une fois le journal de contrôle de nouveau écrivable.";

/// DELETE /api/tenants/{id} — DESTRUCTION CRYPTO (SUPER-ADMIN only, DESTRUCTIF). Exige une confirmation forte
/// (body {confirm:<name>} == nom du tenant). `default` INTERDIT (protégé aussi par tenant_destroy). Audit
/// control_ledger `tenant.destroy` (niveau break-glass). La base tenant disparaissant, pas d'event tenant.
pub(crate) async fn tenant_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    if !st.multi_tenant {
        return (StatusCode::NOT_FOUND, "multi-tenant désactivé (mode 0)").into_response();
    }
    if !au.is_superadmin {
        return (StatusCode::FORBIDDEN, "réservé au super-admin plateforme").into_response();
    }
    if id == "default" {
        return (StatusCode::BAD_REQUEST, "le tenant 'default' ne peut pas être détruit").into_response();
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "control-plane indisponible").into_response();
    };
    let name: Option<String> = {
        let conn = cp.conn.lock();
        conn.query_row("SELECT name FROM tenant WHERE id=?1", params![id], |r| r.get::<_, String>(0)).ok()
    };
    let Some(name) = name else {
        return (StatusCode::NOT_FOUND, "tenant inconnu").into_response();
    };
    // CONFIRMATION FORTE : body {confirm} DOIT égaler EXACTEMENT le nom du tenant (anti-suppression accidentelle).
    let confirm = b.str_field("confirm");
    if confirm != name {
        return (StatusCode::BAD_REQUEST, "confirmation invalide : `confirm` doit égaler EXACTEMENT le nom du tenant").into_response();
    }
    // Audit AVANT destruction (la base + son ledger disparaissent) — niveau break-glass (opération destructive).
    //
    // `P10.20-z` — LA TRACE PRÉCÈDE LA DESTRUCTION, OU LA DESTRUCTION N'A PAS LIEU. La destruction est
    // IRRÉVERSIBLE et emporte le journal du tenant : après elle, la ligne de contrôle est la SEULE preuve
    // qu'elle a eu lieu et de qui l'a faite. Rien n'est encore détruit à ce point, donc le refus ne perd
    // rien et le geste est rejouable — c'est le contrat de l'approbation d'une riposte (`P10.20-v`).
    if let Some(cause) = control_ledger_append(
        &st,
        "tenant.destroy",
        &au.name,
        &id,
        &json!({ "operator": au.name, "name": name, "level": "break-glass", "destructive": true }).to_string(),
    )
    .cause_de_non_inscription()
    {
        return err_json(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE_DESTRUCTION_SANS_TRACE} ({cause})"));
    }
    let mgr = st.tenants.clone();
    let tid = id.clone();
    let destroy = tokio::task::spawn_blocking(move || tenant_destroy(&mgr, &tid))
        .await
        .unwrap_or_else(|e| Err(DestructionNonFaite::Refusee(format!("tâche de destruction interrompue: {e}"))));
    // `P10.34-h` — la transaction de la destruction non prise : 503 à phrase fixe, rien n'est détruit, rejouable.
    match destroy {
        Ok(()) => Json(json!({ "ok": true, "id": id, "destroyed": true })).into_response(),
        Err(DestructionNonFaite::NonPrise(etape)) => refuser_la_destruction_non_prise(etape),
        Err(DestructionNonFaite::Refusee(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

/// GET /api/tenants/{id}/grants — liste (user -> role) du tenant. SUPER-ADMIN (tout tenant) OU admin de CE
/// tenant (re-check serveur `can_manage_grants`).
pub(crate) async fn grants_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<String>) -> Response {
    if !st.multi_tenant {
        return Json(json!({ "grants": [] })).into_response();
    }
    if !can_manage_grants(&au, &id) {
        return (StatusCode::FORBIDDEN, "gestion des grants réservée au super-admin ou à l'admin du tenant").into_response();
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return Json(json!({ "grants": [] })).into_response();
    };
    let conn = cp.conn.lock();
    let mut stmt = match conn.prepare(
        "SELECT p.name, g.role FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id \
         WHERE g.tenant_id=?1 ORDER BY p.name",
    ) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("control-plane indisponible: {e}")).into_response(),
    };
    let grants: Vec<Value> = stmt
        .query_map(params![id], |r| Ok(json!({ "user": r.get::<_, String>(0)?, "role": r.get::<_, String>(1)? })))
        .map(|it| it.flatten().collect())
        .unwrap_or_default();
    Json(json!({ "tenant": id, "grants": grants })).into_response()
}

/// POST /api/tenants/{id}/grants — pose/màj un grant {user, role}. SUPER-ADMIN (tout tenant) OU admin de CE
/// tenant. `role` ∈ {admin, editor, viewer} (enum FERMÉ -> aucune escalade superadmin). Anti-lockout : un
/// non-superadmin ne peut pas retirer/rétrograder le DERNIER admin du tenant. Audit control_ledger + event.
pub(crate) async fn grant_set(
    State(st): State<AppState>,
    secret_des_gestes: crate::secret_des_gestes::SecretDesGestesPresente,
    Extension(au): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(b): Json<Value>,
) -> Response {
    if !st.multi_tenant {
        return (StatusCode::NOT_FOUND, "multi-tenant désactivé (mode 0)").into_response();
    }
    if !can_manage_grants(&au, &id) {
        return (StatusCode::FORBIDDEN, "gestion des grants réservée au super-admin ou à l'admin du tenant").into_response();
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "control-plane indisponible").into_response();
    };
    let user = b.trimmed("user");
    let role = b.trimmed("role");
    if !platform_user_name_ok(&user) {
        return (StatusCode::BAD_REQUEST, "nom d'utilisateur invalide (alphanumérique, . _ - uniquement)").into_response();
    }
    if !valid_grant_role(&role) {
        return (StatusCode::BAD_REQUEST, "rôle invalide (admin | editor | viewer)").into_response();
    }
    // `P10.24-m` — UN DROIT DE TENANT EST UN ACCÈS QUI SURVIT À LA SESSION (tout rôle : un droit `viewer` lit toute la
    // télémétrie du tenant) : le secret des gestes, après la validation du corps et avant toute lecture et écriture.
    if let Err(refus) = crate::secret_des_gestes::exiger_le_secret_des_gestes(&st, &secret_des_gestes, &au.name, &format!("pose du droit {role} de '{user}' sur le tenant '{id}'")) {
        return refus;
    }
    // Le tenant doit exister (jamais un grant sur un tenant fantôme).
    // `P10.21-u` — TROIS ISSUES : présent, ABSENT (404), ILLISIBLE (503 nommé). Mesuré le 2026-09-28 sur la forme
    // d'avant (`.is_err()`, lecture de `tenant` refusée) : `404 « tenant inconnu »` sur un tenant qui existe — un refus,
    // mais une fausse cause, qu'une console ou un script lit comme « ce tenant n'existe pas ».
    {
        let conn = cp.conn.lock();
        match conn.query_row("SELECT 1 FROM tenant WHERE id=?1", params![id], |_| Ok(())) {
            Ok(()) => {}
            Err(rusqlite::Error::QueryReturnedNoRows) => return (StatusCode::NOT_FOUND, "tenant inconnu").into_response(),
            Err(e) => {
                eprintln!("[tenants] WARN tenant '{id}' NON lu à la pose d'un droit : {e}");
                return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TENANT_NON_LU_DROIT_NON_POSE);
            }
        }
    }
    // ANTI-LOCKOUT (non-superadmin, #64 effective-base-aware) : rétrograder le dernier admin EFFECTIF vers un
    // rôle SANS autorité admin laisserait 0 admin. Le NOUVEAU rôle garde-t-il l'autorité admin ? -> pas une
    // rétrogradation (ré-assigner un rôle composable base=admin reste admin). L'ANCIEN grant est-il effective-admin
    // (littéral OU custom base=admin) ? Sinon rien à protéger.
    // `P10.21-o` — LES DEUX LECTURES DE L'ANTI-LOCKOUT REFUSENT QUAND ELLES N'ONT PAS EU LIEU. `unwrap_or(false)`
    // lisait un rôle illisible comme « pas administrateur » : l'écriture qui suit passait, et le dernier
    // administrateur du tenant était rétrogradé ; un compte non lu valait zéro, donc « dernier administrateur ».
    // `P10.21-r` — LA MATÉRIALISATION DU COMPTE, LA GARDE ET L'ÉCRITURE DANS UNE TRANSACTION, sous un seul verrou
    // (`jouer_le_geste_garde`). Elles vivaient sous quatre verrous successifs : MESURÉ le 2026-09-25 (témoins `mpra_`),
    // deux administrateurs d'un tenant qui se rétrogradaient l'un l'autre rendaient tous deux 200, zéro administrateur.
    use crate::handlers::transaction_validee::{jouer_le_geste_garde, point_de_course, IssueDuGesteGarde as Issue};
    enum RefusDuDroit {
        DernierAdministrateur,
        NonEtabli(String),
        Materialisation,
        NonEcrit(String),
    }
    let issue = {
        let conn = cp.conn.lock();
        jouer_le_geste_garde(&conn, "tenants", "pose d'un droit de tenant", |conn| {
            let uid = ensure_platform_user_conn(conn, &user).ok_or(RefusDuDroit::Materialisation)?;
            if !au.is_superadmin {
                match le_geste_retirerait_le_dernier_administrateur(conn, &id, &uid, Some(&role)) {
                    Ok(false) => {}
                    Ok(true) => return Err(RefusDuDroit::DernierAdministrateur),
                    Err(e) => return Err(RefusDuDroit::NonEtabli(e.to_string())),
                }
            }
            point_de_course(&cp.db_path);
            conn.execute("INSERT OR REPLACE INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3)", params![uid, id, role])
                .map_err(|e| RefusDuDroit::NonEcrit(e.to_string()))?;
            Ok(())
        })
    };
    match issue {
        Issue::Valide(()) => {}
        Issue::Refuse(RefusDuDroit::DernierAdministrateur) => {
            return (StatusCode::BAD_REQUEST, "dernier administrateur du tenant — rétrogradation refusée").into_response()
        }
        Issue::Refuse(RefusDuDroit::NonEtabli(cause)) => return refuser_le_geste_sans_anti_verrouillage_lu(&cause),
        // `P10.30-d` — LE COMPTE DE PLATEFORME NON ÉTABLI EST LE 503 NOMMÉ DE LA POSE NON PRISE (c'était un 500 à phrase
        // fixe) : la transaction du geste est annulée, rien n'a changé. La cause du moteur n'atteint pas ce gestionnaire
        // (`ensure_platform_user_conn`, rbac.rs, rend `None` par `.ok()?`) : le journal dit le fait, sans elle.
        Issue::Refuse(RefusDuDroit::Materialisation) => return refuser_le_droit_non_pose(&id, MOTIF_AU_JOURNAL_COMPTE_DE_PLATEFORME_NON_ETABLI),
        // `P10.30-d` — LE DROIT NON ÉCRIT EST UN 503 NOMMÉ, la cause du moteur au journal du démon seul. Un 500
        // `échec du grant: <cause du moteur>` la servait au client, sans dire que rien n'avait changé.
        Issue::Refuse(RefusDuDroit::NonEcrit(cause)) => return refuser_le_droit_non_pose(&id, &cause),
        Issue::NonOuvert(e) | Issue::NonValide(e) => return refuser_le_droit_non_pose(&id, &e.to_string()),
    }
    // `P10.20-z` — le grant est écrit ; une ligne manquante au journal de contrôle est dite à côté du succès.
    let maillon = control_ledger_append(&st, "grant.set", &au.name, &id, &json!({ "user": user, "role": role, "by": au.name }).to_string());
    // `P10.21-m` — l'événement du tenant rend son issue ; perdu, il est avoué à côté du succès.
    let evenement = audit_tenant_event(
        &st,
        &id,
        "grant.set",
        2,
        &format!("grant {role} accordé à '{user}' par '{}'", au.name),
        json!({ "user": user, "role": role, "by": au.name }),
    );
    let mut corps = json!({ "ok": true, "tenant": id, "user": user, "role": role });
    avouer_le_maillon_de_controle_manquant(&mut corps, &maillon);
    avouer_l_evenement_du_tenant_non_ecrit(&mut corps, &evenement);
    Json(corps).into_response()
}

/// `P10.30-d` — LA POSE DE DROIT QUE LE PLAN DE CONTRÔLE N'A PAS PRISE EST REFUSÉE : 503, rien n'a changé (la
/// transaction du geste est jouée par `jouer_le_geste_garde`, qui n'écrit rien quand elle n'aboutit pas).
pub(crate) const CAUSE_DROIT_NON_POSE: &str =
    "DROIT NON ENREGISTRÉ, RIEN N'A CHANGÉ : le plan de contrôle n'a pas pris la pose de ce droit ; le compte \
     garde le rôle qu'il avait sur ce tenant, ou n'y a toujours aucun accès, et aucune trace ne dit le contraire. \
     Réessayez une fois le plan de contrôle de nouveau écrivable.";

/// `P10.30-d` — LE REFUS D'UNE POSE DE DROIT NON ÉCRITE : la phrase nommée au client, la cause du moteur au
/// journal du démon (jamais dans le corps).
fn refuser_le_droit_non_pose(tenant: &str, cause_du_moteur: &str) -> Response {
    eprintln!("[tenants] WARN droit NON posé sur '{tenant}' : {cause_du_moteur}");
    err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_DROIT_NON_POSE)
}

/// `P10.30-d` — ce que le journal dit d'une pose refusée faute de compte de plateforme (aucune cause du moteur ne
/// parvient jusqu'ici). Jamais servi : le client reçoit `CAUSE_DROIT_NON_POSE`.
const MOTIF_AU_JOURNAL_COMPTE_DE_PLATEFORME_NON_ETABLI: &str = "compte de plateforme ni retrouvé ni créé (cause non rendue)";

/// `P10.30-d` — CE QU'UN SUCCÈS DIT QUAND LA BASE DU TENANT N'EST PAS SERVIE (`EvenementDAuditDuTenant::SansBaseServie`) :
/// le geste est fait au plan de contrôle, mais l'événement qui le montre au tenant n'a pas de destinataire. C'était
/// une limite écrite, rien n'était avoué : un tenant suspendu à qui l'on pose ou retire un droit ne le voit jamais
/// parmi ses événements, même réactivé. Même clé que la perte d'écriture (`CLE_EVENEMENT_DU_TENANT_NON_ECRIT`, lue par
/// la console), phrase distincte : ce n'est pas une écriture refusée. Posée par `avouer_l_evenement_du_tenant_non_ecrit`
/// (rbac.rs), sur les cinq gestes qui écrivent un événement de tenant : création, suspension, réactivation, pose et
/// retrait d'un droit.
pub(crate) const CAUSE_EVENEMENT_DU_TENANT_SANS_BASE_SERVIE: &str =
    "ÉVÉNEMENT DU TENANT NON ÉCRIT : le geste d'administration a bien eu lieu, mais la base de ce tenant n'est pas \
     servie (un tenant suspendu ne l'est pas) — l'événement d'audit qui le lui montre n'y est pas écrit, et ce tenant ne \
     verra pas ce changement parmi ses propres événements, même une fois servi de nouveau.";

/// `P10.21-g` — LE RETRAIT DE DROIT QUE LA BASE N'A PAS PRIS EST REFUSÉ : 503, et l'accès N'EST PAS
/// retiré. La phrase le dit en tête, parce que c'est la lecture qui compte pour un retrait d'accès.
pub(crate) const CAUSE_RETRAIT_DE_DROIT_NON_ECRIT: &str =
    "RETRAIT NON ENREGISTRÉ, L'ACCÈS EST TOUJOURS EN PLACE : le plan de contrôle n'a pas pris la \
     suppression de ce droit ; le compte garde son rôle sur ce tenant, et aucune trace ne dit le \
     contraire. Réessayez une fois le plan de contrôle de nouveau écrivable.";

/// `P10.21-u` — la lecture du tenant visé par une pose de droit a échoué : ni présent ni absent n'est affirmé.
pub(crate) const CAUSE_TENANT_NON_LU_DROIT_NON_POSE: &str = "TENANT NON LU, DROIT NON POSÉ : le plan de contrôle n'a \
     pas pu lire le tenant visé — ce n'est PAS « tenant inconnu », son existence n'est ni affirmée ni niée. Aucun droit \
     n'est posé ni modifié, rien n'est tracé. Réessayez une fois le plan de contrôle de nouveau lisible.";

/// `P10.21-u` — la lecture du droit à retirer a échoué. Distincte de `CAUSE_DERNIER_ADMINISTRATEUR_NON_ETABLI`, que ce
/// refus empruntait depuis `P10.21-r` : pour un super-administrateur — que l'anti-verrouillage ne concerne pas — la
/// phrase « ce geste pourrait lui retirer son dernier administrateur » donnait une raison qui n'était pas la sienne.
pub(crate) const CAUSE_DROIT_NON_LU_RETRAIT_NON_FAIT: &str = "DROIT NON LU, RETRAIT NON FAIT : le plan de contrôle n'a \
     pas pu lire le droit de ce compte sur ce tenant — ce n'est PAS « droit inconnu », sa présence n'est ni affirmée ni \
     niée. L'accès n'est PAS retiré, rien n'est tracé. Réessayez une fois le plan de contrôle de nouveau lisible.";

/// DELETE /api/tenants/{id}/grants/{user} — retire un grant. SUPER-ADMIN (tout tenant) OU admin de CE tenant.
/// Anti-lockout : un non-superadmin ne peut pas retirer le DERNIER admin. Audit control_ledger + event.
pub(crate) async fn grant_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path((id, user)): Path<(String, String)>) -> Response {
    if !st.multi_tenant {
        return (StatusCode::NOT_FOUND, "multi-tenant désactivé (mode 0)").into_response();
    }
    if !can_manage_grants(&au, &id) {
        return (StatusCode::FORBIDDEN, "gestion des grants réservée au super-admin ou à l'admin du tenant").into_response();
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "control-plane indisponible").into_response();
    };
    // Le grant existe-t-il, et est-ce le rôle admin ? (existence + anti-lockout).
    // #64 : autorité admin EFFECTIVE (littéral OU rôle composable base=admin) -> cohérent avec l'anti-lockout
    // de scim.rs/grant demote ; retirer le dernier `gov-admin` d'un tenant serait sinon un lockout DoS.
    // `P10.21-o` — un compte d'administrateurs non lu refuse en 503 nommé : il ne vaut plus zéro, donc il ne
    // fait plus dire « dernier administrateur » à un tenant dont personne n'a lu les droits.
    // `P10.21-g` — LE RETRAIT EST COMPTÉ AVANT D'ÊTRE ATTESTÉ. Avalé, un retrait refusé par la base
    // laissait le droit EN PLACE pendant que le journal de contrôle, l'événement du tenant et la réponse
    // (204) disaient l'accès retiré.
    // `P10.21-r` — L'EXISTENCE, LA GARDE ET LE RETRAIT DANS UNE TRANSACTION, sous un seul verrou (`jouer_le_geste_garde`).
    // Ils vivaient sous trois verrous successifs : MESURÉ le 2026-09-25 (témoins `mpra_`), deux administrateurs d'un
    // tenant qui se retiraient l'un l'autre rendaient tous deux 204, zéro administrateur. La lecture d'existence
    // ratée n'est plus un « grant inconnu » (404) : 503 nommé, sous SA cause depuis `P10.21-u` (elle empruntait celle
    // de l'anti-verrouillage, fausse pour un super-administrateur).
    use crate::handlers::transaction_validee::{jouer_le_geste_garde, point_de_course, IssueDuGesteGarde as Issue};
    enum RefusDuRetrait {
        Inconnu,
        /// `P10.21-u` — la lecture d'EXISTENCE a échoué (et non celle de l'anti-verrouillage).
        DroitNonLu(String),
        DernierAdministrateur,
        NonEtabli(String),
    }
    let issue = {
        let conn = cp.conn.lock();
        jouer_le_geste_garde(&conn, "tenants", "retrait d'un droit de tenant", |conn| {
            use rusqlite::OptionalExtension as _;
            let existant: Option<String> = conn
                .query_row(
                    "SELECT g.role FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id \
                     WHERE g.tenant_id=?1 AND p.name=?2",
                    params![id, user],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| RefusDuRetrait::DroitNonLu(e.to_string()))?;
            let Some(existant) = existant else { return Err(RefusDuRetrait::Inconnu) };
            if !au.is_superadmin && effective_base_role(&existant) == "admin" {
                match effective_admin_grant_count_conn(conn, &id) {
                    Ok(n) if n <= 1 => return Err(RefusDuRetrait::DernierAdministrateur),
                    Ok(_) => {}
                    Err(e) => return Err(RefusDuRetrait::NonEtabli(e.to_string())),
                }
            }
            point_de_course(&cp.db_path);
            // Le retrait est CLASSÉ ici et jugé plus bas, hors de la transaction : refusé, il n'a rien écrit, et la
            // transaction qui se ferme ne porte que les lectures de la garde.
            Ok(EcritureDuPlanDeControle::from(conn.execute(
                "DELETE FROM \"grant\" WHERE tenant_id=?1 AND user_id=(SELECT id FROM platform_user WHERE name=?2)",
                params![id, user],
            )))
        })
    };
    let retrait = match issue {
        Issue::Valide(retrait) => retrait,
        Issue::Refuse(RefusDuRetrait::Inconnu) => return (StatusCode::NOT_FOUND, "grant inconnu").into_response(),
        Issue::Refuse(RefusDuRetrait::DroitNonLu(cause)) => {
            // `P10.31-u` — jamais le nom du compte au journal : la lecture de son droit vient d'échouer, la phrase FIXE
            // le dit sans relire le compte (même forme que `compte_au_journal`, idp.rs). Le tenant n'y sert à rien.
            eprintln!("[tenants] WARN droit d'un compte (identifiant non lu) NON lu au retrait : {cause}");
            return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_DROIT_NON_LU_RETRAIT_NON_FAIT);
        }
        Issue::Refuse(RefusDuRetrait::DernierAdministrateur) => {
            return (StatusCode::BAD_REQUEST, "dernier administrateur du tenant — retrait refusé").into_response()
        }
        Issue::Refuse(RefusDuRetrait::NonEtabli(cause)) => return refuser_le_geste_sans_anti_verrouillage_lu(&cause),
        Issue::NonOuvert(e) | Issue::NonValide(e) => return refuser_le_geste_non_ecrit(CAUSE_RETRAIT_DE_DROIT_NON_ECRIT, &e.to_string()),
    };
    match retrait {
        EcritureDuPlanDeControle::Ecrite => {}
        // Lu dans la même transaction que l'existence : ne peut plus arriver ; dit comme avant si la base le rendait.
        EcritureDuPlanDeControle::AucuneLigne => return (StatusCode::NOT_FOUND, "grant inconnu").into_response(),
        EcritureDuPlanDeControle::Refusee(cause) => return refuser_le_geste_non_ecrit(CAUSE_RETRAIT_DE_DROIT_NON_ECRIT, &cause),
    }
    let maillon = control_ledger_append(&st, "grant.remove", &au.name, &id, &json!({ "user": user, "by": au.name }).to_string());
    let evenement = audit_tenant_event(
        &st,
        &id,
        "grant.remove",
        2,
        &format!("grant de '{user}' retiré par '{}'", au.name),
        json!({ "user": user, "by": au.name }),
    );
    // `P10.20-z` — LE CHEMIN NOMINAL RESTE UN 204 SANS CORPS, byte-identique. Un 204 ne peut porter aucun
    // aveu : quand la ligne manque au journal de contrôle, la réponse devient un 200 dont le corps DIT le
    // retrait ET le trou. Refuser serait faux : le grant est déjà retiré.
    // `P10.21-m` — un événement du tenant PERDU force aussi le deux cents : le 204 ne peut pas l'avouer.
    // `P10.30-d` — une base du tenant NON SERVIE aussi (tenant suspendu) : l'événement n'y est pas écrit, c'est dit.
    if evenement.est_perdu() {
        // Le corps qui avoue est posé plus bas, sous la même forme que l'aveu du maillon.
    } else if matches!(evenement, EvenementDAuditDuTenant::SansBaseServie) {
    } else if maillon.cause_de_non_inscription().is_none() {
        return StatusCode::NO_CONTENT.into_response();
    }
    let mut corps = json!({ "ok": true, "tenant": id, "user": user, "removed": true });
    avouer_le_maillon_de_controle_manquant(&mut corps, &maillon);
    avouer_l_evenement_du_tenant_non_ecrit(&mut corps, &evenement);
    Json(corps).into_response()
}
