use super::*;

// ===================== LDAP / Active Directory =====================

/// Échappement d'un composant de FILTRE LDAP (RFC 4515, §3) : neutralise `\ * ( ) NUL` en séquences `\xx`.
/// OBLIGATOIRE sur toute entrée utilisateur injectée dans un filtre -> ZÉRO injection LDAP (ex. un login
/// `*)(uid=*` ne peut pas altérer la structure du filtre). PUR & testé.
#[allow(dead_code)] // utilisé sous `--features ldap` (bind réseau) + tests ; mort dans un build nu
pub(crate) fn ldap_escape_filter(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'\\' => out.push_str("\\5c"),
            b'*' => out.push_str("\\2a"),
            b'(' => out.push_str("\\28"),
            b')' => out.push_str("\\29"),
            0 => out.push_str("\\00"),
            _ => out.push(b as char),
        }
    }
    out
}

/// Échappement d'un composant de DN (RFC 4514) pour construire un bind-DN à partir d'un login utilisateur
/// (mode `user_dn_template` avec `{user}`). Neutralise les métacaractères de DN.
#[allow(dead_code)] // utilisé sous `--features ldap` (bind réseau) + tests ; mort dans un build nu
pub(crate) fn ldap_escape_dn(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        match c {
            '\\' | ',' | '+' | '"' | '<' | '>' | ';' | '=' => { out.push('\\'); out.push(c); }
            '#' if i == 0 => { out.push('\\'); out.push(c); }
            ' ' if i == 0 || i == s.chars().count() - 1 => { out.push('\\'); out.push(c); }
            _ => out.push(c),
        }
    }
    out
}

/// Config LDAP décodée depuis `idp_provider.config_json` (le mot de passe de bind est dans `.secret`).
#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // utilisé sous `--features ldap` (bind réseau) + tests ; mort dans un build nu
pub(crate) struct LdapCfg {
    pub(crate) url: String,             // ldap://host:389 ou ldaps://host:636
    pub(crate) start_tls: bool,         // StartTLS sur ldap:// (sinon ldaps:// pour du TLS implicite)
    pub(crate) bind_dn: String,         // DN du compte de service (recherche) — optionnel si user_dn_template
    pub(crate) user_base_dn: String,    // base de recherche des utilisateurs
    pub(crate) user_filter: String,     // filtre, `{user}` = login échappé (ex "(uid={user})" / "(sAMAccountName={user})")
    pub(crate) user_dn_template: String,// alternative directe : "uid={user},ou=people,dc=ex,dc=com" (bind direct)
    pub(crate) group_base_dn: String,   // base de recherche des groupes (optionnel)
    pub(crate) group_filter: String,    // filtre d'appartenance, `{dn}`/`{user}` échappés
    pub(crate) group_attr: String,      // attribut listant les groupes sur l'entrée user (ex "memberOf")
    pub(crate) admin_group: String,     // DN/nom de groupe -> rôle admin
    pub(crate) editor_group: String,    // -> rôle editor
    pub(crate) viewer_group: String,    // -> rôle viewer (sinon : DENY si require_group_match)
    pub(crate) require_group_match: bool,
}

#[allow(dead_code)] // utilisé sous `--features ldap` (bind réseau) + tests ; mort dans un build nu
impl LdapCfg {
    pub(crate) fn from_json(v: &Value) -> LdapCfg {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let group_attr = { let x = s("group_attr"); if x.is_empty() { "memberOf".to_string() } else { x } };
        LdapCfg {
            url: s("url"),
            start_tls: v.get("start_tls").and_then(|x| x.as_bool()).unwrap_or(false),
            bind_dn: s("bind_dn"),
            user_base_dn: s("user_base_dn"),
            user_filter: s("user_filter"),
            user_dn_template: s("user_dn_template"),
            group_base_dn: s("group_base_dn"),
            group_filter: s("group_filter"),
            group_attr,
            admin_group: s("admin_group"),
            editor_group: s("editor_group"),
            viewer_group: s("viewer_group"),
            require_group_match: v.get("require_group_match").and_then(|x| x.as_bool()).unwrap_or(true),
        }
    }
    /// Construit le filtre de recherche utilisateur, `{user}` -> login ÉCHAPPÉ (RFC 4515). Défaut raisonnable.
    pub(crate) fn build_user_filter(&self, user: &str) -> String {
        let esc = ldap_escape_filter(user);
        let tpl = if self.user_filter.is_empty() { "(uid={user})" } else { self.user_filter.as_str() };
        tpl.replace("{user}", &esc)
    }
    /// Construit le bind-DN direct depuis le template `user_dn_template` (`{user}` -> login échappé DN).
    pub(crate) fn build_user_dn(&self, user: &str) -> String {
        self.user_dn_template.replace("{user}", &ldap_escape_dn(user))
    }
}

/// Mapping appartenance-de-groupes -> rôle Plume (PUR & testé). `groups` = DNs/noms de groupes de l'user.
/// Priorité admin > editor > viewer. None = aucun groupe mappé (DENY si require_group_match).
#[allow(dead_code)] // utilisé sous `--features ldap` (bind réseau) + tests ; mort dans un build nu
pub(crate) fn ldap_role_from_groups(cfg: &LdapCfg, groups: &[String]) -> Option<String> {
    let has = |target: &str| !target.is_empty() && groups.iter().any(|g| g.eq_ignore_ascii_case(target));
    if has(&cfg.admin_group) {
        Some("admin".to_string())
    } else if has(&cfg.editor_group) {
        Some("editor".to_string())
    } else if has(&cfg.viewer_group) {
        Some("viewer".to_string())
    } else if cfg.require_group_match {
        None
    } else {
        Some("viewer".to_string())
    }
}

/// BIND LDAP réseau — feature-gated (`ldap`). Vérifie les identifiants contre l'annuaire (bind), récupère
/// l'appartenance aux groupes, mappe -> rôle. FAIL-CLOSED : toute erreur (connexion, bind, TLS) -> Err.
/// SANS la feature : 501 explicite (le code est présent, ldap3 non linké -> budget 2 Go préservé).
#[cfg(not(feature = "ldap"))]
pub(crate) fn ldap_authenticate(_cfg: &LdapCfg, _bind_pw: &str, _user: &str, _pass: &str) -> Result<String, String> {
    Err("support LDAP non compilé (recompiler avec --features ldap)".into())
}

#[cfg(feature = "ldap")]
pub(crate) fn ldap_authenticate(cfg: &LdapCfg, bind_pw: &str, user: &str, pass: &str) -> Result<String, String> {
    use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
    if cfg.url.is_empty() {
        return Err("URL LDAP manquante".into());
    }
    if pass.is_empty() {
        // un mot de passe vide provoquerait un "unauthenticated bind" (succès LDAP mais NON authentifié) -> DENY.
        return Err("mot de passe vide refusé (anti unauthenticated-bind)".into());
    }
    let settings = LdapConnSettings::new().set_starttls(cfg.start_tls);
    let mut ldap = LdapConn::with_settings(settings, &cfg.url).map_err(|e| format!("connexion LDAP: {e}"))?;

    // Détermine le DN de l'utilisateur : template direct, sinon recherche via un compte de service.
    let (user_dn, groups_from_search): (String, Vec<String>) = if !cfg.user_dn_template.is_empty() {
        (cfg.build_user_dn(user), Vec::new())
    } else {
        // bind du compte de service (ou anonyme si bind_dn vide) puis recherche de l'utilisateur.
        if !cfg.bind_dn.is_empty() {
            ldap.simple_bind(&cfg.bind_dn, bind_pw).map_err(|e| format!("bind service: {e}"))?
                .success().map_err(|_| "bind du compte de service refusé".to_string())?;
        }
        let filter = cfg.build_user_filter(user);
        let attrs = vec![cfg.group_attr.as_str()];
        let (rs, _res) = ldap.search(&cfg.user_base_dn, Scope::Subtree, &filter, attrs)
            .map_err(|e| format!("recherche user: {e}"))?
            .success().map_err(|_| "recherche user échouée".to_string())?;
        let entry = rs.into_iter().next().ok_or("utilisateur introuvable dans l'annuaire")?;
        let se = SearchEntry::construct(entry);
        let groups = se.attrs.get(&cfg.group_attr).cloned().unwrap_or_default();
        (se.dn, groups)
    };

    // BIND de l'utilisateur avec SON mot de passe = vérification des identifiants (le cœur de l'auth LDAP).
    ldap.simple_bind(&user_dn, pass).map_err(|e| format!("bind user: {e}"))?
        .success().map_err(|_| "identifiants LDAP invalides".to_string())?;

    // Appartenance aux groupes : celle récupérée à la recherche, complétée par un group_filter optionnel.
    let mut groups = groups_from_search;
    if groups.is_empty() && !cfg.group_filter.is_empty() && !cfg.group_base_dn.is_empty() {
        let gf = cfg.group_filter
            .replace("{dn}", &ldap_escape_filter(&user_dn))
            .replace("{user}", &ldap_escape_filter(user));
        if let Ok(sr) = ldap.search(&cfg.group_base_dn, Scope::Subtree, &gf, vec!["dn"]) {
            if let Ok((rs, _)) = sr.success() {
                for e in rs {
                    groups.push(SearchEntry::construct(e).dn);
                }
            }
        }
    }
    let _ = ldap.unbind();
    ldap_role_from_groups(cfg, &groups).ok_or_else(|| "aucun groupe LDAP mappé à un rôle Plume (accès refusé)".to_string())
}
