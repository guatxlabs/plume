# IdP natif (#44) — OIDC / LDAP / MFA, et la conception SAML 2.0

> **Statut.** OIDC (Authorization-Code + PKCE), LDAP/AD (bind), et TOTP MFA sont **implémentés et testés**.
> SAML 2.0 SP est **implémenté et testé**, mais **derrière la feature de compilation `saml`** (cf. §5) :
> compilé **sans** cette feature, le login SAML renvoie **501**. ⚠️ **L'image Docker livrée est construite
> avec `--features ldap` uniquement** (cf. `Dockerfile`) — donc **SAML y répond 501** ; il faut recompiler
> avec `--features saml` pour l'activer.
> Cet incrément est **additif et fail-closed** : sans fournisseur configuré ni MFA enrôlée, toute
> l'authentification existante (Basic / cookie de session / token d'agent / HEC / SSO d'en-tête Authentik)
> est **strictement inchangée** (mode 0 byte-identique, prouvé par la suite de tests).

## 1. Modèle de configuration

Un **fournisseur d'identité** est une ligne de la table `idp_provider` (migration v85), configurée par un
**admin** via l'UI (`Administration → Identité fédérée (SSO)`) ou l'API `/api/idp/providers` (admin-only) :

| colonne       | rôle |
|---------------|------|
| `name`        | identifiant unique (segment d'URL sûr : alnum + `. _ -`) |
| `kind`        | `oidc` \| `ldap` \| `saml` |
| `enabled`     | un fournisseur désactivé n'accorde **aucun** login |
| `config_json` | paramètres **non-secrets** (issuer, client_id, redirect_uri, scopes, group_claim ; url LDAP, base_dn, filtres, groupes) |
| `secret`      | **le seul** credential (client_secret OIDC / mot de passe de bind LDAP) — colonne dédiée, **jamais** dans `config_json`, **jamais** projetée en réponse, chiffrée au repos par SQLCipher |

**Secret write-only** : identique à `connectors`/`notifiers`. La liste ne renvoie qu'un booléen `has_secret` ;
en mise à jour, un secret **vide/omis conserve** l'existant (jamais d'écrasement par vide, jamais de fuite).

La **MFA TOTP** est stockée par compte dans `user_mfa` (secret base32, `enabled`, hachages SHA-256 des codes
de secours). Vide par défaut → aucun challenge.

**Mapping groupe → rôle** : réutilise **exactement** la table du SSO d'en-tête Authentik (`sso_role` /
`sso_grants`). Les groupes de l'IdP (claim OIDC `groups` ; `memberOf`/`group_filter` LDAP) sont mappés vers
`admin`/`editor`/`viewer`. **Fail-closed** : `require_group_match` (défaut **true**) refuse (DENY) un
utilisateur qui ne matche **aucun** groupe connu — contrairement au repli viewer implicite, on ne délivre
jamais d'accès sur un mapping vide.

### 1bis. SSO d'en-tête « trusted-header » (forward-auth) — noms d'en-têtes VENDOR-AGNOSTIQUES

Chemin optionnel (activé **uniquement** si `PLUME_SSO_HEADER_SECRET` est posé) où un forward-auth de confiance
(Traefik/oauth2-proxy/nginx auth_request…) injecte l'identité en en-têtes HTTP, accompagnée d'un **secret
partagé** `x-plume-sso-secret` (comparé en temps constant). Sans le bon secret, les en-têtes d'identité ne
sont **jamais** lus.

- **Noms d'en-têtes configurables** (v107) : `PLUME_SSO_HEADER_USER` (défaut **`x-authentik-username`**) et
  `PLUME_SSO_HEADER_GROUPS` (défaut **`x-authentik-groups`**). Défauts inchangés → déploiement Authentik
  existant **byte-identique**. Un client derrière Okta/Keycloak/Azure/Ping pose les noms d'en-têtes que **son**
  proxy émet. Le mapping groupe→rôle reste `PLUME_SSO_GROUP_*` (déjà configurable).
- **Le nom ne contourne PAS le modèle de confiance** : ces en-têtes ne sont lus **que** sur le chemin déjà
  authentifié par `x-plume-sso-secret`. Changer le NOM n'ouvre aucun chemin de lecture hors du gate secret.
- **Concern de DÉPLOIEMENT (à respecter)** : la confiance vient de ce que le middleware forward-auth
  **écrase** (overwrite) les en-têtes fournis par le client. Si vous configurez des noms personnalisés, le
  middleware **doit écraser CES noms-là** (sinon un client pourrait injecter `PLUME_SSO_HEADER_GROUPS`
  directement). C'est une exigence de configuration du proxy, pas une faiblesse du daemon.
- **AUCUN COMPTE N'EST CRÉÉ PAR CE CHEMIN**, et c'est délibéré : contrairement à OIDC et LDAP (qui
  provisionnent un compte à la volée, cf. §2 et §3), le SSO d'en-tête ne pose **aucune** ligne dans la table
  des comptes — le nom et le rôle sont recalculés à chaque requête depuis les en-têtes. Conséquence à
  connaître : un compte d'annuaire **n'est ni créé, ni modifiable, ni révocable** depuis `Administration →
  Comptes & accès` ; son rôle vient de ses groupes et se change **dans l'annuaire**.
- **« QUI A ACCÈS » se lit quand même** (`P11.5-c`). Comme ces comptes n'ont pas de ligne, la liste des
  comptes ne pouvait pas les montrer : ils administraient la console sans figurer nulle part. Le point de
  passage d'authentification consigne désormais **chaque identité résolue** — nom, provenance (annuaire
  externe / compte local / jeton / identifiant d'amorçage), rôle effectif, origine de ce rôle, première et
  dernière vue — et `Administration → Comptes & accès` rend cet inventaire **à côté** de la liste des
  comptes locaux (lecture seule : on n'administre pas ici un compte dont l'autorité vient d'ailleurs).
  Aucun secret n'y entre — ni empreinte, ni jeton, ni la valeur brute des groupes de l'annuaire.

## 2. OIDC (implémenté)

- `GET /api/auth/oidc/{name}/start` → génère `state`, `nonce`, et un **PKCE** `code_verifier`/`code_challenge`
  (S256), pose un **cookie de state signé HMAC** (`plume_oidc`, `SameSite=Lax`, HttpOnly, 10 min) et redirige
  (302) vers l'`authorization_endpoint` (résolu par **discovery** `.well-known/openid-configuration`, ou
  overrides explicites). Aucun état serveur (stateless).
- `GET /api/auth/oidc/callback` → vérifie le cookie de state (HMAC + exp), compare `state` (anti-CSRF, temps
  constant), échange le `code` (+ `code_verifier`) au `token_endpoint`, récupère le **JWKS**, et **valide
  l'`id_token`** : signature **RS256/ES256** (clé choisie par `kid`, algo **restreint à l'asymétrique** → pas
  de confusion d'algorithme HS256), `iss` == issuer **configuré**, `aud` contient `client_id`, `exp` valide
  (leeway 60 s), `nonce` == nonce du state. Puis mapping groupe→rôle, **provisioning JIT** du compte, session.
- **Anti open-redirect** : le `redirect_uri` est celui **configuré** (re-servi tel quel, jamais depuis la
  requête) ; la redirection finale est **fixe** (`/`). Endpoints forcés **https** (anti-fuite de secret/clé).

## 3. LDAP / Active Directory (implémenté, feature `ldap`)

- `POST /api/auth/ldap {provider?, user, pass}` → **bind** contre l'annuaire (StartTLS/LDAPS via `ldap3` +
  tokio-rustls, **pas d'OpenSSL**), résout l'appartenance aux groupes (`memberOf` ou `group_filter`), mappe
  vers un rôle, provisionne JIT, pose la session. Anti-brute-force réutilisé (lockout `(user,ip)`).
- **Injection-safe** : tout composant utilisateur d'un filtre est échappé **RFC 4515** (`\\ * ( ) NUL`) et
  tout composant de DN **RFC 4514** — un login `*)(uid=*` ne peut pas altérer la structure du filtre (testé).
  Bind avec mot de passe **vide refusé** (anti *unauthenticated-bind*).
- **Feature `ldap`** : les **fonctions pures** (échappement, mapping) sont compilées/testées **sans** la
  feature ; seul le bind réseau est derrière `#[cfg(feature = "ldap")]` (sans la feature : 501 explicite).
  **DEPUIS v107 : `--features ldap` est activé PAR DÉFAUT dans l'image stock** (`plume/Dockerfile`) — le
  login LDAP/AD natif fonctionne sans rebuild (bring-your-own-directory). Coût : ~40 crates **pur-Rust** en
  plus (ldap3/lber, asn1/x509, url/idna/icu) ; **aucune** nouvelle dépendance C (`openssl-sys` vient déjà de
  SQLCipher). **INERTE tant qu'aucun provider LDAP n'est configuré+activé** : `POST /api/auth/ldap` répond
  `404 aucun provider LDAP activé` (aucun endpoint ouvert, aucun bind sortant, aucune surface active) — un
  déploiement stock sans LDAP se comporte à l'identique feature ON ou OFF.

## 4. TOTP MFA (implémenté, RFC 6238)

- Self-service (`/api/mfa/*`, tout compte, opère sur `au.name`) : `enroll` (graine base32 + URI `otpauth://`
  show-once), `verify` (1er code → active + **codes de secours** show-once, seuls leurs SHA-256 sont
  persistés), `disable` (exige un code valide), `status`.
- **Challenge au login local** : si le compte a une MFA active, `POST /api/login` renvoie
  `{mfa_required:true, ticket}` (ticket HMAC court) **sans** poser de session ; `POST /api/login/mfa
  {ticket, code}` valide le TOTP (fenêtre de dérive ±1 pas, temps constant) **ou** un code de secours à
  **usage unique**, puis pose la session. `user_mfa` vide → flux de login **byte-identique**.

## 5. SAML 2.0 SP (implémenté — **feature `saml`**, SP-initiated, POST binding)

`kind = 'saml'` est accepté par le CRUD des fournisseurs, et le login SAML est **implémenté derrière la
feature de compilation `saml`** (comme LDAP). **Sans `--features saml`, les routes renvoient 501** (samlify
non linké → build/test DÉFAUT byte-identique, budget 2 Go préservé). La validation XML-DSig/C14N/XSW est
**déléguée à `samlify`/`saml-rs`** (pur-Rust, RustCrypto via `bergshamra`) — **on ne ré-implémente jamais**
C14N/XML-DSig (c'est là que vivent les contournements d'auth). `samael` (bindings C) est **banni** (doctrine
image minimale).

**Config** (`config_json`, tout NON-secret) : `idp_sso_url`, `idp_entity_id`, `sp_entity_id`, `acs_url`,
`idp_x509_cert` (cert de signature IdP, PEM), `attr_username` (vide → NameID), `attr_groups` (défaut `groups`),
`want_assertions_signed` (défaut **true**), `sign_authn_requests` (défaut false), `allowed_clock_skew_s`
(défaut 60, borné 0..3600), `require_group_match` (défaut **true**). La **clé+cert privés SP** (bundle PEM,
UNIQUEMENT si `sign_authn_requests`) vont dans `secret` (write-only, comme les autres credentials).

> ⚠️ **`want_assertions_signed=false` est un footgun.** Il reste configurable (principe vendor-agnostic : un
> IdP legacy peut ne signer QUE la `Response`), mais il fait accepter des **assertions NON SIGNÉES** sur un
> chemin d'auth SOC. Il n'est **jamais silencieux** : un avertissement `eprintln!` BRUYANT est émis à la
> création du provider (`idp_provider_create`, avec le nom du provider) **et** à chaque usage insécure
> (`saml_verify_and_extract`), routé vers stderr → logs/SIEM. Ne l'activez que pour un IdP legacy avéré.

**Endpoints** (routes PUBLIQUES, exemptées de l'allowlist Host + rate-limit `auth_route`) :

1. **`GET /api/auth/saml/{name}/start`** — construit l'`AuthnRequest` (HTTP-Redirect : deflate+base64+urlencode
   via samlify), pose un `RelayState` **signé HMAC** (`saml_relaystate_sign`, réutilise le pattern
   `oidc_state_sign`) porteur de l'ID d'AuthnRequest, pose un cookie de flux `plume_saml` (Lax, défense en
   profondeur — peut ne pas survivre au POST cross-site → le RelayState reste autoritatif), 302 vers l'IdP.
2. **`POST /api/auth/saml/acs`** — l'Assertion Consumer Service SÉCURITÉ-CRITIQUE. `saml-rs::finish_sso`
   applique **fail-closed** : signature XML-DSig contre le cert **STATIQUEMENT PINNÉ** (`verify_signature`,
   pas de TOFU métadonnées) ; parade **XSW** (garde SubjectConfirmationData, rejet d'ID dupliqués, rejet
   multi-racine, liaison stricte référence→élément, couverture d'UNE seule assertion, rejet de référence
   externe, cert inline non-fiable) ; parsing XXE-safe ; `Audience`==`sp_entity_id` ; `Recipient`/
   `Destination`==`acs_url` ; `NotBefore`/`NotOnOrAfter` (±skew borné) ; `InResponseTo`==ID du RelayState
   signé ; anti-rejeu par **cache d'ID d'assertion borné** (`BoundedReplayStore`, anti-OOM comme `auth_fails`) ;
   `Issuer`==`idp_entity_id` ; `StatusCode`==Success ; **IdP-initiated DÉSACTIVÉ** (on n'utilise que
   `finish_sso`, jamais `accept_unsolicited_sso`). En amont, **garde d'algorithme anti-SHA-1 par ALLOWLIST**
   plume (`saml_reject_weak_sig_alg` — saml-rs/bergshamra vérifient SHA-1 « pour compat » et n'ont aucune
   allowlist d'algo, on le refuse). ⚠️ Cette garde **ne scanne PAS le texte brut** (un denylist de sous-chaînes
   `#rsa-sha1` est **évadable** par référence de caractère XML — `#rsa-sha&#49;` ne contient pas la sous-chaîne
   mais bergshamra le décode en `rsa-sha1` à la vérif) : elle **parse le XML avec le PROPRE parseur de saml-rs**
   (`saml_rs::xml::dom::parse_roots`, valeurs d'attribut char-ref-décodées/normalisées — le MÊME décodage que
   le vérifieur) et exige que **CHAQUE** `SignatureMethod`/`DigestMethod` porte un `Algorithm` **décodé** dans
   une allowlist STRICTE d'algos forts (signature : RSA/ECDSA-SHA2, RSA-PSS SHA-256+ ; digest : SHA-256/384/512).
   Tout le reste (SHA-1, MD5, RIPEMD, inconnu), un `Algorithm` absent, l'absence de toute `SignatureMethod`, ou
   un XML illisible → **DENY (fail-closed)**. Puis extraction des attributs → `saml_groups_str` → **mapping
   groupe→rôle réutilisé** (`oidc_role_mode0`/`sso_role`, fail-closed `require_group_match`) → provisioning JIT
   (`idp_provision_user`) → session (`attach_session_cookies`, **exactement** le même aval qu'OIDC/LDAP).
   `saml_groups_str` **neutralise les séparateurs `|`/`,` à l'intérieur de chaque valeur de groupe** avant de
   joindre → une valeur IdP unique `x|plume-admin` ne peut pas se ré-éclater en un groupe `plume-admin`
   synthétique (anti-élévation de privilège).
3. **`GET /api/auth/saml/{name}/metadata`** — métadonnée SP (XML public) à fournir à l'IdP.
4. **SLO** : différé (non implémenté).

**EncryptedAssertion : HORS PÉRIMÈTRE** — on exige l'assertion signée sur TLS (le déchiffrement RSA logiciel
de XML-Enc, exposé à `RUSTSEC-2023-0071`, reste **désactivé par défaut** dans saml-rs). **Crate choisie :**
`samlify` 0.3 (re-export de `saml-rs` 0.3, pur-Rust). Verdict d'adéquation : vérification de signature contre
cert statique **OUI** ; robustesse XSW **OUI** (défenses en profondeur + suite de tests `xsw.rs`/`hardening.rs`
dédiée en amont). Vecteurs de test adverses (`src/tests/saml.rs`, gated `saml`) : valide/non-signé/altéré/
mauvaise-audience/mauvais-recipient/mauvais-issuer/expiré/pas-encore-valide/InResponseTo-divergent/rejeu/
mauvais-cert/SHA-1/**SHA-1-obfusqué-par-char-ref (`&#49;`/`&#x31;`, régression permanente)**/XSW(dup+2e-assertion)/
statut≠Success ; plus **anti-élévation par séparateur de groupe interne** (`saml_groups_str`).

## 6. Multi-tenant (mode 1)

Dans cet incrément, IdP/MFA sont **mode-0 uniquement** (comme le provisioning de jetons UI) : en multi-tenant,
ces routes renvoient **501** (les identités plateforme vivent au control-plane ; l'intégration OIDC/LDAP→tenant
via les grants `plume-<tenant>-<role>` — déjà supportés par `sso_grants` — est un suivi). Mode 1 reste donc
**fail-closed et inchangé**.
