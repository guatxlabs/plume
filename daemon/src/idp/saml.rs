use super::*;

// ===================== SAML 2.0 SP (#44) =====================
//
// Le login SAML SP-initié réutilise la MÊME sortie de session qu'OIDC/LDAP (`attach_session_cookies`),
// le MÊME mapping groupe->rôle (`oidc_role_mode0`/`sso_role`), la MÊME réservation admin bootstrap
// (`idp_provision_user`). Le cœur lourd — vérification de signature XML-DSig (C14N + digest + référence),
// parade XSW, parsing XXE-safe — est DÉLÉGUÉ à `samlify`/`saml-rs` (pur-Rust, RustCrypto via `bergshamra`)
// SOUS la feature `saml` ; ON NE RÉ-IMPLÉMENTE JAMAIS C14N/XML-DSig à la main (c'est là que vivent les
// contournements d'auth). Sans la feature, `saml_verify_and_extract` renvoie une erreur « non compilé »
// (le handler la traduit en 501 — miroir strict du précédent LDAP). FAIL-CLOSED partout.

/// Config SAML décodée depuis `idp_provider.config_json`. Tous les champs sont NON-secrets (le cert IdP est
/// public) ; la clé privée SP éventuelle (signature de l'AuthnRequest) vit dans `idp_provider.secret`.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // certains champs ne sont lus que sous `--features saml` (miroir de LdapCfg)
pub(crate) struct SamlCfg {
    pub(crate) idp_sso_url: String,        // endpoint SSO de l'IdP (HTTP-Redirect) — cible de l'AuthnRequest
    pub(crate) idp_entity_id: String,      // entityID de l'IdP — DOIT == Issuer de la réponse (checklist #9)
    pub(crate) sp_entity_id: String,       // NOTRE entityID — DOIT == Audience de l'assertion (checklist #5)
    pub(crate) acs_url: String,            // NOTRE ACS — DOIT == Recipient + Destination (checklist #6)
    pub(crate) idp_x509_cert: String,      // cert de signature de l'IdP (PEM) — clé de vérif PINNÉE (checklist #1)
    pub(crate) attr_username: String,      // nom d'attribut portant le login (vide -> NameID)
    pub(crate) attr_groups: String,        // nom d'attribut portant les groupes (défaut "groups")
    pub(crate) want_assertions_signed: bool, // exige l'ASSERTION signée (défaut true, checklist #1)
    pub(crate) sign_authn_requests: bool,     // signe l'AuthnRequest sortant (défaut false)
    pub(crate) allowed_clock_skew_s: i64,     // tolérance de dérive d'horloge, bornée (défaut 60, checklist #7)
    pub(crate) require_group_match: bool,     // fail-closed group->role (défaut true, checklist #13)
}

impl SamlCfg {
    pub(crate) fn from_json(v: &Value) -> SamlCfg {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let b = |k: &str, d: bool| v.get(k).and_then(|x| x.as_bool()).unwrap_or(d);
        let attr_groups = { let x = s("attr_groups"); if x.is_empty() { "groups".to_string() } else { x } };
        SamlCfg {
            idp_sso_url: s("idp_sso_url"),
            idp_entity_id: s("idp_entity_id"),
            sp_entity_id: s("sp_entity_id"),
            acs_url: s("acs_url"),
            idp_x509_cert: s("idp_x509_cert"),
            attr_username: s("attr_username"),
            attr_groups,
            want_assertions_signed: b("want_assertions_signed", true),
            sign_authn_requests: b("sign_authn_requests", false),
            // borné [0..3600] : un skew négatif ou démesuré ré-ouvrirait la fenêtre temporelle (anti-rejeu #7).
            allowed_clock_skew_s: v.get("allowed_clock_skew_s").and_then(|x| x.as_i64()).unwrap_or(60).clamp(0, 3600),
            require_group_match: b("require_group_match", true),
        }
    }
    /// Config minimale présente ? (fail-closed : refuse tôt une config inexploitable.)
    pub(crate) fn is_usable(&self) -> bool {
        !self.idp_sso_url.is_empty()
            && !self.idp_entity_id.is_empty()
            && !self.sp_entity_id.is_empty()
            && !self.acs_url.is_empty()
            && !self.idp_x509_cert.is_empty()
    }
}

/// RelayState SIGNÉ (checklist #12) : `saml|provider|request_id|exp`, HMAC-SHA256 (session_secret). Porté par
/// le paramètre `RelayState` (echo IdP) — JAMAIS de RelayState brut fiable. `request_id` = l'ID de NOTRE
/// AuthnRequest (généré par saml-rs), source de vérité pour le contrôle `InResponseTo` (#8a). Miroir EXACT de
/// `oidc_state_sign` (même construction que `mint_session`). Le préfixe de domaine `saml` empêche toute
/// confusion avec un blob de state OIDC / ticket MFA / jeton de session.
#[allow(dead_code)] // utilisé sous `--features saml` (build de l'AuthnRequest) + tests ; mort dans un build nu
pub(crate) fn saml_relaystate_sign(secret: &[u8], provider: &str, request_id: &str, ttl_s: i64) -> String {
    let exp = now() + ttl_s.max(1);
    // provider (alnum . _ -) et request_id (saml-rs : `_` + hex) ne contiennent JAMAIS de '|' -> séparateur non ambigu.
    let payload = format!("saml|{provider}|{request_id}|{exp}");
    let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let sig = hmac_sha256(secret, p_b64.as_bytes());
    format!("{p_b64}.{}", hex_encode(&sig))
}

/// Vérifie + décode un RelayState SAML signé : HMAC valide (temps constant) + non expiré -> (provider,
/// request_id). None = signature invalide / expiré / malformé / mauvais domaine -> l'ACS REFUSE.
pub(crate) fn saml_relaystate_verify(secret: &[u8], blob: &str) -> Option<(String, String)> {
    let (p_b64, sig_hex) = blob.split_once('.')?;
    let expect = hmac_sha256(secret, p_b64.as_bytes());
    if !ct_eq(&hex_decode(sig_hex)?, &expect) {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p_b64).ok()?;
    let s = String::from_utf8(raw).ok()?;
    let mut it = s.split('|');
    if it.next()? != "saml" {
        return None;
    }
    let provider = it.next()?.to_string();
    let request_id = it.next()?.to_string();
    let exp: i64 = it.next()?.parse().ok()?;
    if now() >= exp {
        return None;
    }
    Some((provider, request_id))
}

/// NORMALISE une liste de valeurs d'attribut de groupe en chaîne `a|b|c` — le format EXACT attendu par
/// `sso_role`/`oidc_role_mode0` (réutilisation stricte de la sémantique groupe->rôle du SSO trusted-header).
///
/// DURCISSEMENT #4 (anti-élévation) : `sso_role`/`sso_any_group_match` RE-SPLIT ensuite sur `|` ET `,`. Une
/// valeur de groupe UNIQUE assertée par l'IdP qui contiendrait littéralement un séparateur (`x|plume-admin`
/// ou `x,plume-admin`) se ré-éclaterait donc en PLUSIEURS groupes -> fabrication d'un groupe `plume-admin`
/// synthétique = élévation de privilège SI l'IdP émet une telle valeur. On NEUTRALISE donc les séparateurs
/// À L'INTÉRIEUR de chaque valeur AVANT le join (une valeur reste une valeur ; elle ne peut plus en engendrer
/// plusieurs). Les séparateurs ne subsistent qu'entre valeurs distinctes, posés par NOUS.
pub(crate) fn saml_groups_str(values: &[String]) -> String {
    values
        .iter()
        .map(|s| s.trim().replace(|c| c == '|' || c == ',', ""))
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("|")
}

/// GARDE D'ALGORITHME anti-SHA-1/faible (checklist #11) — ALLOWLIST sur valeurs DÉCODÉES.
/// `saml-rs`/`bergshamra` VÉRIFIENT les signatures RSA-SHA1 « pour compatibilité » (prouvé par leurs propres
/// tests) et n'ont AUCUNE allowlist d'algo de signature ; on les REFUSE donc ICI, AVANT toute vérification.
///
/// POURQUOI PAS UN SCAN DE SOUS-CHAÎNES (l'ancienne approche) : scanner le TEXTE brut pour `#rsa-sha1`/`#sha1`
/// est ÉVADABLE par références de caractères XML — `Algorithm="...xmldsig#rsa-sha&#49;"` ne contient AUCUNE
/// sous-chaîne `#rsa-sha1` (le denylist PASSE) mais le parseur de bergshamra décode `&#49;`->`1` au moment
/// de la vérif -> une signature SHA-1 valide serait acceptée. On PARSE donc le XML avec le PROPRE parseur de
/// saml-rs (`saml_rs::xml::dom::parse_roots`, le MÊME que le vérifieur consomme) dont les valeurs d'attribut
/// sont DÉJÀ char-ref-décodées/normalisées (`decoded_and_normalized_value`, cf. dom.rs) -> l'obfuscation ne
/// peut plus se glisser sous la garde. On EXIGE ensuite que CHAQUE `SignatureMethod`/`DigestMethod` porte un
/// `Algorithm` DÉCODÉ dans une ALLOWLIST STRICTE d'algorithmes forts (miroir de la garde OIDC restreinte aux
/// algos asymétriques forts). Toute autre valeur (sha1, md5, ripemd, dsa, inconnu), un `Algorithm` absent,
/// l'absence de toute `SignatureMethod`, ou un XML illisible -> DENY (fail-closed). true = OK ; false = rejet.
#[cfg(feature = "saml")]
pub(crate) fn saml_reject_weak_sig_alg(response_xml: &str) -> bool {
    use samlify::xml::dom::{parse_roots, Node};
    // Fragment d'URI XML-DSig après le dernier '#', en minuscules (robuste au namespace : xmldsig / xmldsig-more
    // / xmldsig11 / xmlenc portent le même suffixe d'algorithme).
    fn frag(alg: &str) -> String {
        alg.rsplit('#').next().unwrap_or(alg).trim().to_ascii_lowercase()
    }
    // Signature FORTE (allowlist) : RSA-SHA2, ECDSA-SHA2, RSA-PSS (SHA-256+). Tout le reste -> refus.
    fn sig_strong(alg: &str) -> bool {
        matches!(
            frag(alg).as_str(),
            "rsa-sha256" | "rsa-sha384" | "rsa-sha512"
                | "ecdsa-sha256" | "ecdsa-sha384" | "ecdsa-sha512"
                | "sha256-rsa-mgf1" | "sha384-rsa-mgf1" | "sha512-rsa-mgf1" // RSA-PSS (xmldsig-more 2007/05)
        )
    }
    // Digest FORT (allowlist) : SHA-256/384/512. Tout le reste (sha1, md5, ripemd, sha3 non requis) -> refus.
    fn digest_strong(alg: &str) -> bool {
        matches!(frag(alg).as_str(), "sha256" | "sha384" | "sha512")
    }
    // Parcours récursif : EXIGE au moins UNE SignatureMethod (une réponse signée en porte toujours une) et que
    // TOUT nœud SignatureMethod/DigestMethod porte un `Algorithm` fort. Un `Algorithm` absent -> refus.
    fn walk(node: &Node, saw_sig: &mut bool, all_strong: &mut bool) {
        match node.local_name.as_str() {
            "SignatureMethod" => {
                *saw_sig = true;
                if !node.attr("Algorithm").map(sig_strong).unwrap_or(false) {
                    *all_strong = false;
                }
            }
            "DigestMethod" => {
                if !node.attr("Algorithm").map(digest_strong).unwrap_or(false) {
                    *all_strong = false;
                }
            }
            _ => {}
        }
        for c in &node.children {
            walk(c, saw_sig, all_strong);
        }
    }
    // Parse via le parseur de saml-rs (attributs char-ref-décodés/normalisés) — miroir du vérifieur.
    let Ok(roots) = parse_roots(response_xml) else {
        return false; // XML illisible -> DENY (fail-closed).
    };
    let mut saw_sig = false;
    let mut all_strong = true;
    for r in &roots {
        walk(r, &mut saw_sig, &mut all_strong);
    }
    saw_sig && all_strong
}

/// Cache anti-rejeu d'IDs d'assertion (checklist #8b). Trait plume (présent dans les DEUX builds) : permet
/// l'injection en test et adapte `samlify::ReplayCache` sous la feature. `now_unix` sert à purger les entrées
/// expirées (borne mémoire) sans dépendre d'une horloge globale.
#[allow(dead_code)] // méthode appelée uniquement sous `--features saml` (via l'adaptateur ReplayCache) + tests
pub(crate) trait SamlReplayStore {
    /// true si `id` est NOUVEAU (mémorisé jusqu'à `expires_unix`) ; false = déjà vu (rejeu -> DENY).
    fn check_and_store(&mut self, id: &str, now_unix: i64, expires_unix: i64) -> bool;
}

/// Set anti-rejeu borné (anti-OOM sous 2 Gi, comme `auth_fails`) : purge d'abord les IDs expirés, puis, si
/// toujours au plafond, évince l'entrée la PLUS PROCHE de l'expiration (jamais un ID neuf refusé — un rejeu
/// reste attrapé par la présence de l'ID ; et un attaquant ne peut pas forger une NOUVELLE assertion valide
/// sans la clé de l'IdP, donc l'éviction n'ouvre aucun contournement).
#[allow(dead_code)] // champs lus uniquement sous `--features saml` (check_and_store) + tests
pub(crate) struct BoundedReplayStore {
    seen: std::collections::HashMap<String, i64>, // id d'assertion -> expires_unix
    cap: usize,
}

impl BoundedReplayStore {
    pub(crate) fn new(cap: usize) -> Self {
        Self { seen: std::collections::HashMap::new(), cap: cap.max(1) }
    }
}

impl SamlReplayStore for BoundedReplayStore {
    fn check_and_store(&mut self, id: &str, now_unix: i64, expires_unix: i64) -> bool {
        if id.is_empty() {
            return false; // une assertion sans ID est un rejeu potentiel non traçable -> DENY fail-closed.
        }
        if self.seen.contains_key(id) {
            return false; // REJEU.
        }
        self.seen.retain(|_, &mut exp| exp > now_unix); // purge des expirés.
        if self.seen.len() >= self.cap {
            // plafond atteint : évince l'entrée la plus proche de l'expiration (min exp).
            if let Some(k) = self.seen.iter().min_by_key(|(_, &e)| e).map(|(k, _)| k.clone()) {
                self.seen.remove(&k);
            }
        }
        self.seen.insert(id.to_string(), expires_unix);
        true
    }
}

/// Set anti-rejeu partagé au niveau processus (mode 0 mono-tenant). Présent dans les DEUX builds (le handler
/// ACS le verrouille sans condition) ; sous `--features saml` seul, `saml_verify_and_extract` s'en sert.
pub(crate) fn saml_replay_store() -> &'static parking_lot::Mutex<BoundedReplayStore> {
    static S: std::sync::OnceLock<parking_lot::Mutex<BoundedReplayStore>> = std::sync::OnceLock::new();
    // 8192 IDs ~ largement au-delà du débit de login réel ; borne dure ~1 Mo -> anti-OOM 2 Gi.
    S.get_or_init(|| parking_lot::Mutex::new(BoundedReplayStore::new(8192)))
}

/// VÉRIFICATION + EXTRACTION de l'assertion SAML (le cœur SÉCURITÉ-CRITIQUE de l'ACS). Sans la feature `saml` :
/// erreur « non compilé » -> 501 (samlify non linké, mode 0 byte-identique). Miroir strict de `ldap_authenticate`.
#[cfg(not(feature = "saml"))]
pub(crate) fn saml_verify_and_extract(
    _cfg: &SamlCfg,
    _saml_response_b64: &str,
    _expected_request_id: &str,
    _now_unix: i64,
    _replay: &mut dyn SamlReplayStore,
) -> Result<(String, Vec<String>), String> {
    Err("support SAML non compilé (recompiler avec --features saml)".into())
}

/// VÉRIFICATION + EXTRACTION de l'assertion SAML. Applique, FAIL-CLOSED, la checklist ACS complète (voir
/// docs/NATIVE-IDP.md §5). Retourne (username, groupes) UNIQUEMENT si TOUT passe. `saml-rs::finish_sso`
/// impose : signature XML-DSig contre le cert PINNÉ (#1), parade XSW (#2), parsing XXE-safe (#3),
/// ordre parse->vérif->confiance (#4), Audience==sp_entity_id (#5), Recipient/Destination==acs_url (#6),
/// NotBefore/NotOnOrAfter avec skew borné (#7), InResponseTo==request_id du RelayState signé (#8a),
/// anti-rejeu par cache d'ID d'assertion (#8b), Issuer==idp_entity_id (#9), StatusCode==Success (#10),
/// SP-initié seulement via `finish_sso` (PAS `accept_unsolicited_sso`) -> IdP-initié DÉSACTIVÉ (#15),
/// XML-Enc RSA logiciel désactivé par défaut => on exige l'assertion signée sur TLS (#14). La garde
/// anti-SHA-1 (#11) est appliquée ICI avant vérif ; le RelayState HMAC (#12) et le mapping fail-closed (#13)
/// sont côté handler/`oidc_role_mode0`.
#[cfg(feature = "saml")]
pub(crate) fn saml_verify_and_extract(
    cfg: &SamlCfg,
    saml_response_b64: &str,
    expected_request_id: &str,
    now_unix: i64,
    replay: &mut dyn SamlReplayStore,
) -> Result<(String, Vec<String>), String> {
    use samlify::{
        AcsEndpoint, AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequestSigningPolicy,
        BrowserInput, ClockSkew, Credentials, CertificatePem, EntityId, FormField, IdpConfig,
        IdpDescriptor, IdpValidationPolicy, MessageSignaturePolicy, MetadataTrustPolicy,
        NameIdCreationPolicy, PendingAuthnRequest, PendingSnapshot, RelayStateParam, ReplayPolicy,
        Saml, SamlValidationContext, SpConfig, SpValidationPolicy, SsoEndpoint, SsoResponse,
        AuthnRequest,
    };
    use std::time::{Duration, SystemTime};

    // 0) Décode la SAMLResponse (POST binding : base64 STANDARD du XML de la Response).
    let xml_bytes = base64::engine::general_purpose::STANDARD
        .decode(saml_response_b64.trim())
        .map_err(|_| "SAMLResponse : base64 invalide".to_string())?;
    let xml = String::from_utf8(xml_bytes).map_err(|_| "SAMLResponse : XML non-UTF8".to_string())?;

    // 1) GARDE ANTI-SHA-1 (#11) — ALLOWLIST sur DOM décodé, AVANT toute vérification/lecture d'attribut.
    if !saml_reject_weak_sig_alg(&xml) {
        return Err("algorithme de signature/digest faible ou non-accepté (SHA-1/MD5/inconnu ; allowlist forte #11)".into());
    }

    // 2) Config SP (policies STRICTES). Assertion signée exigée selon want_assertions_signed (#1) ; audience
    //    validée (#5). Le message-level n'est PAS exigé signé (la confiance vit dans l'assertion signée).
    let sp_validation = SpValidationPolicy {
        assertions: if cfg.want_assertions_signed {
            AssertionSignaturePolicy::RequireSigned
        } else {
            // DURCISSEMENT #7 : footgun réel sur un chemin d'auth SOC. On le GARDE configurable (principe
            // vendor-agnostic : un IdP legacy peut ne signer QUE la Response) mais JAMAIS en silence — on
            // émet un avertissement BRUYANT et auditable (stderr -> logs/SIEM) à chaque usage insécure.
            eprintln!(
                "AVERTISSEMENT SÉCURITÉ SAML — SP '{}' / IdP '{}': want_assertions_signed=false — assertion acceptée NON SIGNÉE (INSÉCURE, réservé à un IdP legacy). Cf. docs/NATIVE-IDP.md §5.",
                cfg.sp_entity_id, cfg.idp_entity_id
            );
            AssertionSignaturePolicy::AllowUnsignedForCompatibility
        },
        messages: MessageSignaturePolicy::AllowUnsignedForCompatibility,
        authn_requests: if cfg.sign_authn_requests {
            AuthnRequestSigningPolicy::Sign
        } else {
            AuthnRequestSigningPolicy::DoNotSignForCompatibility
        },
        audience: AudienceValidationPolicy::Validate,
        name_id_creation: NameIdCreationPolicy::DoNotAllowCreate,
        logout: Default::default(),
    };
    let sp_cfg = SpConfig::builder(EntityId::try_new(cfg.sp_entity_id.clone()).map_err(|e| format!("sp_entity_id: {e}"))?)
        .acs_endpoint(AcsEndpoint::post(cfg.acs_url.clone()).map_err(|e| format!("acs_url: {e}"))?)
        .validation(sp_validation)
        .build()
        .map_err(|e| format!("config SP SAML: {e}"))?;
    let sp = Saml::sp(sp_cfg).map_err(|e| format!("SP SAML: {e}"))?;

    // 3) Descriptor IdP à CERTIFICAT STATIQUE PINNÉ (#1) : on génère NOTRE métadonnée IdP à partir du cert
    //    configuré, puis on la re-parse -> le cert devient la SEULE clé de vérification (aucun TOFU, aucune
    //    clé inline de la réponse importée). `_for` épingle AUSSI l'entityID attendu (défense #9).
    let idp_entity = EntityId::try_new(cfg.idp_entity_id.clone()).map_err(|e| format!("idp_entity_id: {e}"))?;
    let idp_cfg = IdpConfig::builder(idp_entity.clone())
        .sso_endpoint(SsoEndpoint::redirect(cfg.idp_sso_url.clone()).map_err(|e| format!("idp_sso_url: {e}"))?)
        .credentials(Credentials {
            signing_certificate: Some(CertificatePem::new(cfg.idp_x509_cert.clone())),
            ..Default::default()
        })
        .validation(IdpValidationPolicy::compatibility())
        .build()
        .map_err(|e| format!("config IdP SAML: {e}"))?;
    let idp_meta_xml = Saml::idp(idp_cfg).map_err(|e| format!("IdP SAML: {e}"))?.metadata_xml().to_string();
    let idp = IdpDescriptor::from_metadata_xml_for(idp_entity, &idp_meta_xml, MetadataTrustPolicy::UnsignedForCompatibility)
        .map_err(|e| format!("descriptor IdP (cert pinné): {e}"))?;

    // 4) Reconstruit le pending SP-initié depuis le RelayState signé -> corrélation InResponseTo (#8a).
    let snapshot = PendingSnapshot::<AuthnRequest>::authn_request(
        expected_request_id,
        RelayStateParam::absent(),
        &cfg.idp_entity_id,
        "post",
        &cfg.acs_url,
        "post",
    );
    let pending = PendingAuthnRequest::from_snapshot(snapshot).map_err(|e| format!("pending SAML: {e}"))?;

    // 5) Entrée HTTP-POST (SAMLResponse). On n'utilise QUE `finish_sso` (SP-initié) -> IdP-initié désactivé (#15).
    let input = BrowserInput::<SsoResponse>::post(vec![FormField::new("SAMLResponse", saml_response_b64)]);

    // 6) Contexte de validation : skew d'horloge borné (#7) + cache anti-rejeu (#8b). La fenêtre est élargie
    //    de ±skew (notBefore -skew, notOnOrAfter +skew). Rétention de rejeu = skew + 10 min (couvre la fenêtre).
    let skew_ms = cfg.allowed_clock_skew_s.saturating_mul(1000);
    let now_st = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(now_unix.max(0) as u64))
        .ok_or_else(|| "horloge invalide".to_string())?;
    struct Adapter<'a> {
        store: &'a mut dyn SamlReplayStore,
        now_unix: i64,
    }
    impl<'a> samlify::ReplayCache for Adapter<'a> {
        fn check_and_store(&mut self, key: samlify::ReplayKey, expires_at: SystemTime) -> Result<(), samlify::SamlError> {
            let exp_unix = expires_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(self.now_unix);
            // On indexe sur l'ID d'assertion (porteur des attributs) ; les autres clés (response id) passent
            // aussi par le même set borné — la collision de namespace est inoffensive (préfixe kind dans la clé).
            if self.store.check_and_store(&key.cache_key(), self.now_unix, exp_unix) {
                Ok(())
            } else {
                Err(samlify::SamlError::ReplayDetected { key: key.cache_key() })
            }
        }
    }
    let mut adapter = Adapter { store: replay, now_unix };
    let validation = SamlValidationContext::new(now_st, ReplayPolicy::RequireCache(&mut adapter))
        .with_clock_skew(ClockSkew::from_millis(-skew_ms, skew_ms))
        .with_replay_retention(Duration::from_secs(cfg.allowed_clock_skew_s.max(0) as u64 + 600));

    // 7) finish_sso : LE contrôle SÉCURITÉ complet (signature+XSW+audience+recipient+destination+timing+
    //    InResponseTo+issuer+status+replay). Toute anomalie -> Err -> DENY (aucune session, aucun attribut lu).
    let session = sp
        .finish_sso(&idp, &pending, input, validation)
        .map_err(|e| format!("assertion SAML rejetée: {e}"))?;

    // 8) Identité + groupes — lus SEULEMENT après vérification (ordre parse->vérif->confiance #4).
    let username = if cfg.attr_username.is_empty() {
        session.name_id().value().trim().to_string()
    } else {
        session
            .attributes()
            .get(&cfg.attr_username)
            .and_then(|a| a.values().first())
            .map(|v| v.as_str().trim().to_string())
            .unwrap_or_default()
    };
    if username.is_empty() {
        return Err("nom d'utilisateur SAML absent (NameID/attribut vide)".into());
    }
    let groups: Vec<String> = session
        .attributes()
        .get(&cfg.attr_groups)
        .map(|a| a.values().iter().map(|v| v.as_str().to_string()).collect())
        .unwrap_or_default();
    Ok((username, groups))
}

/// Construit l'AuthnRequest SP-initiée (HTTP-Redirect : deflate+base64+urlencode) et le RelayState signé.
/// Retourne (url_de_redirection, relaystate_blob). Sans la feature : 501 (« non compilé »). `sp_secret` porte
/// la clé privée+cert SP (PEM bundle) UNIQUEMENT si `sign_authn_requests`.
#[cfg(not(feature = "saml"))]
pub(crate) fn saml_build_authn_redirect(
    _cfg: &SamlCfg,
    _provider: &str,
    _sp_secret: &str,
    _session_secret: &[u8],
) -> Result<(String, String), String> {
    Err("support SAML non compilé (recompiler avec --features saml)".into())
}

#[cfg(feature = "saml")]
pub(crate) fn saml_build_authn_redirect(
    cfg: &SamlCfg,
    provider: &str,
    sp_secret: &str,
    session_secret: &[u8],
) -> Result<(String, String), String> {
    use samlify::{
        AcsEndpoint, AuthnRequestSigningPolicy, CertificatePem, Credentials, EntityId, IdpConfig,
        IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, PrivateKeyPem, Saml, SpConfig,
        SpValidationPolicy, SsoEndpoint, StartSso,
    };

    let mut validation = SpValidationPolicy::strict();
    validation.authn_requests = if cfg.sign_authn_requests {
        AuthnRequestSigningPolicy::Sign
    } else {
        AuthnRequestSigningPolicy::DoNotSignForCompatibility
    };
    let mut builder = SpConfig::builder(
        EntityId::try_new(cfg.sp_entity_id.clone()).map_err(|e| format!("sp_entity_id: {e}"))?,
    )
    .acs_endpoint(AcsEndpoint::post(cfg.acs_url.clone()).map_err(|e| format!("acs_url: {e}"))?)
    .validation(validation);
    if cfg.sign_authn_requests {
        if sp_secret.is_empty() {
            return Err("signature d'AuthnRequest demandée mais secret SP (clé+cert PEM) absent".into());
        }
        // Le secret DOIT être un bundle PEM (clé privée + certificat) ; sinon le build échoue (fail-closed).
        builder = builder.credentials(Credentials {
            signing_key: Some(PrivateKeyPem::new(sp_secret.to_string())),
            signing_certificate: Some(CertificatePem::new(sp_secret.to_string())),
            ..Default::default()
        });
    }
    let sp = Saml::sp(builder.build().map_err(|e| format!("config SP SAML: {e}"))?)
        .map_err(|e| format!("SP SAML: {e}"))?;

    let idp_entity = EntityId::try_new(cfg.idp_entity_id.clone()).map_err(|e| format!("idp_entity_id: {e}"))?;
    let idp_cfg = IdpConfig::builder(idp_entity.clone())
        .sso_endpoint(SsoEndpoint::redirect(cfg.idp_sso_url.clone()).map_err(|e| format!("idp_sso_url: {e}"))?)
        .validation(IdpValidationPolicy::compatibility())
        .build()
        .map_err(|e| format!("config IdP SAML: {e}"))?;
    let idp_meta = Saml::idp(idp_cfg).map_err(|e| format!("IdP SAML: {e}"))?.metadata_xml().to_string();
    let idp = IdpDescriptor::from_metadata_xml_for(idp_entity, &idp_meta, MetadataTrustPolicy::UnsignedForCompatibility)
        .map_err(|e| format!("descriptor IdP: {e}"))?;

    let started = sp.start_sso(&idp, StartSso::redirect()).map_err(|e| format!("start_sso: {e}"))?;
    let request_id = started.pending.snapshot().id;
    // RelayState signé (#12) porteur de l'ID d'AuthnRequest (source de vérité InResponseTo #8a). TTL 10 min.
    let blob = saml_relaystate_sign(session_secret, provider, &request_id, 600);
    let base = started.outbound.redirect_url().map_err(|e| format!("redirect_url: {e}"))?;
    // RelayState HMAC-protégé (intégrité garantie par NOTRE clé, indépendamment de la signature SP éventuelle).
    let sep = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{sep}RelayState={}", url_encode(&blob));
    Ok((url, blob))
}

/// Génère la métadonnée SP (XML public). Sans la feature : 501 (« non compilé »).
#[cfg(not(feature = "saml"))]
pub(crate) fn saml_sp_metadata_xml(_cfg: &SamlCfg) -> Result<String, String> {
    Err("support SAML non compilé (recompiler avec --features saml)".into())
}

#[cfg(feature = "saml")]
pub(crate) fn saml_sp_metadata_xml(cfg: &SamlCfg) -> Result<String, String> {
    use samlify::{AcsEndpoint, EntityId, Saml, SpConfig, SpValidationPolicy};
    let sp_cfg = SpConfig::builder(
        EntityId::try_new(cfg.sp_entity_id.clone()).map_err(|e| format!("sp_entity_id: {e}"))?,
    )
    .acs_endpoint(AcsEndpoint::post(cfg.acs_url.clone()).map_err(|e| format!("acs_url: {e}"))?)
    .validation(SpValidationPolicy::strict())
    .build()
    .map_err(|e| format!("config SP SAML: {e}"))?;
    Ok(Saml::sp(sp_cfg).map_err(|e| format!("SP SAML: {e}"))?.metadata_xml().to_string())
}
