# IdP natif (#44) — OIDC / LDAP / MFA, et la conception SAML 2.0

> **Statut.** OIDC (Authorization-Code + PKCE), LDAP/AD (bind), et TOTP MFA sont **implémentés et testés**.
> SAML 2.0 SP est **implémenté et testé**, mais **derrière la feature de compilation `saml`** (cf. §5) :
> compilé **sans** cette feature, le login SAML renvoie **501**. ⚠️ **L'image Docker livrée est bâtie
> `ldap,cold_tier`** — jeu déclaré une seule fois par `ARG PLUME_FEATURES` dans le
> [`Dockerfile`](../Dockerfile), depuis `971de7a` (2026‑08‑08) — et **`saml` n'en fait pas partie** :
> **SAML y répond donc 501**. Pour l'activer, rajoutez-le au jeu sans toucher au fichier :
> `docker build --build-arg PLUME_FEATURES=ldap,cold_tier,saml .`
> ⚠️ **Le mode hôte natif ne compile AUCUNE feature optionnelle** : le README et `bootstrap.sh`
> prescrivent `cargo build --release` **nu**. Sur un binaire hôte ainsi bâti, **le login LDAP/AD répond
> 501 lui aussi** (et le tier froid est absent) — cf. §3 et
> [`TROIS-MODES.md` §3.9](TROIS-MODES.md#39-mettre-à-jour). OIDC, TOTP MFA et le SSO d'en-tête, eux, ne
> dépendent d'aucune feature : ils sont là dans les trois modes.
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
  **DEPUIS v107 : `--features ldap` est activé PAR DÉFAUT dans l'image stock** — il fait partie du jeu
  `ldap,cold_tier` que déclare `ARG PLUME_FEATURES` ([`Dockerfile`](../Dockerfile)) — le
  login LDAP/AD natif fonctionne sans rebuild (bring-your-own-directory). **Ce défaut-ON ne vaut QUE
  pour l'image** : la recette hôte compile nu, donc un `plume-daemon` installé par `bootstrap.sh` sans
  `--features ldap` répond **501** à `POST /api/auth/ldap` — le prendre :
  `cargo build --release --features cold_tier,ldap`. Coût : ~40 crates **pur-Rust** en
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

Les sous-sections suivantes décrivent les refus et les freins de ce flux. Les contrôles y sont nommés, entre
accents graves, par la constante ou la fonction qui les porte ; les causes sont servies telles quelles dans le
champ `error` de la réponse. Le témoin `documentation_du_second_facteur` vérifie trois choses, et seulement
celles-là : chaque contrôle qu'il exige a sa phrase, qui cite le symbole défini qui le porte ; tout nom composé
(qui contient un souligné) cité ici figure dans une ligne de code de `daemon/src` hors tests, une ligne de
commentaire ne comptant pas ; le 409 de réactivation, la remise à zéro et l'arbitrage du frein ont leur phrase
dans leur sous-section, et le 409 est servi par `mfa_verify` avant tout essai compté. Il ne lit pas le sens des
phrases : un statut faux à côté d'un symbole juste passe, la relecture le tient.

### 4.1 Enrôlement : le mot de passe du compte est exigé

- `POST /api/mfa/enroll {password}` exige le mot de passe du compte, jugé **avant** toute graine par
  `prouver_le_premier_facteur` (`session.rs`), avec la **même** résolution que `POST /api/login` et au **même**
  verrou (compte, adresse) : la route n'offre aucun essai de plus que la connexion. Une session seule ne suffit
  pas — elle permettrait à qui l'a volée d'enfermer le titulaire derrière une graine qu'il ne détient pas.
  - champ absent ou vide → **403** `CAUSE_MOT_DE_PASSE_EXIGE_POUR_ENROLER` (rien examiné, rien compté) ;
  - mot de passe faux → **403** `CAUSE_MOT_DE_PASSE_REFUSE_A_L_ENROLEMENT` (échec compté par
    `auth_record_failure`, ligne au registre) ;
  - verrou (compte, adresse) posé → **429** `CAUSE_MOT_DE_PASSE_VERROUILLE_A_L_ENROLEMENT` + `Retry-After`,
    le mot de passe n'est pas examiné ;
  - compte non lu → **503** `CAUSE_COMPTE_NON_LU_A_L_ENROLEMENT`.
- **Comptes sans mot de passe local** — compte fédéré OIDC, SAML ou LDAP (hachage `IDP_HASH_SENTINEL`), ou
  identité SSO par en-têtes — → **403** `CAUSE_ENROLEMENT_SANS_MOT_DE_PASSE_LOCAL`, décidé par
  `le_compte_a_un_mot_de_passe_local`. Le second facteur de plume n'est demandé qu'à la connexion par mot de
  passe local, que ces comptes n'empruntent pas : leur second facteur est celui de leur fournisseur
  d'identité. Leur connexion n'est pas modifiée ; seul l'enrôlement est refusé.
- Une MFA **déjà active** n'est jamais écrasée : **409** « MFA déjà active (désactivez-la d'abord) ». L'écriture
  de l'enrôlement rejuge la condition (`WHERE user_mfa.enabled=0`) : une activation survenue pendant la preuve
  du mot de passe rend aussi 409. Écriture refusée → **503** `CAUSE_ENROLEMENT_NON_ECRIT`, aucune graine
  posée ni montrée.

### 4.2 Activation : le 409 de réactivation

- `POST /api/mfa/verify` sur une MFA **déjà active** → **409** « MFA déjà active (désactivez-la d'abord) »,
  **avant** tout examen du code et avant tout essai compté (`mfa_verify`) : la réponse est la même que le code
  soit juste ou faux, aucun code de secours neuf n'est servi. Sans ce refus, la route serait un oracle du TOTP
  pour une session volée.
- L'activation est un compare-et-pose sur l'enrôlement lu (`enabled=0 AND secret=<graine lue>`) : une autre
  requête l'a activé, remplacé ou supprimé entre-temps → **409** `CAUSE_ENROLEMENT_CHANGE_PENDANT_LA_VERIFICATION`,
  rien n'est activé ; écriture refusée → **503** `CAUSE_MFA_NON_ACTIVEE`, aucun code de secours servi.
- Un code dont le pas est déjà consommé → **401** (anti-rejeu).

### 4.3 Frein du second facteur, par compte

- **Clé** : le compte — jamais l'adresse, jamais le ticket. Les trois routes qui jugent un code
  (`login_mfa_post`, `mfa_verify`, `mfa_disable` sur une MFA active) le traversent.
- **L'essai est compté avant d'être examiné** : `reserver_un_essai` (`handlers/frein_du_second_facteur.rs`)
  écrit l'échec possible, dans sa propre transaction validée, **avant** que le code soit jugé. Compte freiné →
  **429** `CAUSE_SECOND_FACTEUR_FREINE` + `Retry-After`, le code n'est pas examiné (un code juste est refusé
  comme un faux). Écriture du frein refusée → **503** `CAUSE_ESSAI_DU_SECOND_FACTEUR_NON_COMPTE`, le code
  n'est ni accepté ni refusé.
- **Seuil et délai** : les réglages du verrou de connexion, `lock_threshold`, `lock_base_s`, `lock_max_s`,
  posés par `PLUME_AUTH_LOCK_THRESHOLD` (défaut 10), `PLUME_AUTH_LOCK_BASE_S` (délai de base, défaut 30 s) et
  `PLUME_AUTH_LOCK_MAX_S` (plafond, défaut 900 s) ; les deux délais valent au moins 1 s. Au seuil, le délai vaut `lock_base_s` × 2^(échecs au-delà du seuil), plafonné à `lock_max_s`. Seuil
  0 : frein coupé, rien n'est lu ni écrit.
- **Oubli** : un jour sans échec efface les échecs consécutifs (`MEMOIRE_DES_ECHECS_S`).
- **Remise à zéro** (`remettre_a_zero`) : un code juste **accepté** remet le compte à zéro ; une connexion par
  mot de passe, jamais. Une exception, qui n'examine aucun code : `mfa_disable` sur un enrôlement **en attente**
  (jamais activé) supprime la graine et remet aussi le compte à zéro — les échecs comptés par `mfa_verify` contre
  cette graine sont effacés avec elle. Ce n'est pas une porte : la graine visée n'existe plus, son titulaire la
  connaissait (l'enrôlement la montre), et un nouvel enrôlement exige le mot de passe.
- **Refus qui ne juge pas le code** (pas non consommé, enrôlement changé, écriture refusée) : l'essai réservé
  est rendu (`rendre_l_essai`). Un retour refusé laisse un échec de trop — le sens qui freine.
- **Durable** : l'état vit dans la table `setting`, portée `frein.second_facteur`
  (`PORTEE_DU_FREIN_DU_SECOND_FACTEUR`), clé = le nom du compte, aucune migration de schéma. Un redémarrage ou
  une autre réplique ne rouvre pas la fenêtre. La ligne est retirée dans la transaction qui supprime le compte
  (`oublier_dans_la_transaction`). Aucune route de réglages ne sert une portée autre que `global` ; le SQL brut,
réservé aux administrateurs, peut lire la ligne (son autorisateur refuse des colonnes de secrets, pas la table
`setting`) : elle ne porte que des compteurs et des instants (`consecutifs`, `freine_jusqu_a`, `dernier`), aucun
code ni graine.
- **Vu du SIEM** (`tracer_l_echec`, source `plume-auth`) : à l'activation et à la désactivation, un code faux
  émet `failure` de sévérité 3 (la connexion émet déjà le sien par `auth_record_failure`) ; sur les trois
  routes, l'échec qui pose le frein émet `lockout` de sévérité 4. Les champs portent `facteur: "second"` et
  la route, jamais le code présenté, la graine ni le ticket.
- **Arbitrage** : le frein n'est atteignable qu'avec un ticket signé (donc le mot de passe) ou une session du
  compte ; des tickets forgés ou des mots de passe faux ne freinent personne. Celui qui tient le mot de passe
  peut geler l'étape du code au titulaire, au plus `lock_max_s` à la fois : prix assumé, l'alternative étant
  de le laisser deviner le second facteur ; la parade est celle d'une compromission du mot de passe (le
  changer). Le premier facteur n'est pas freiné par ce compteur : le titulaire obtient toujours son ticket. Un
  frein par ticket est écarté : le ticket se réémet à volonté avec le mot de passe.

### 4.4 Consommation du facteur

- Un pas TOTP n'est accepté que **consommé** : `consommer_le_pas_totp` est un compare-et-pose en base
  (`last_step < pas`). Un pas déjà consommé — rejeu séquentiel ou concurrent — → **401** « code MFA invalide »,
  échec compté. La base n'a pas pris l'écriture → **503** `CAUSE_PAS_TOTP_NON_CONSOMME` : aucune session, le
  code n'est pas brûlé, l'essai est rendu.
- Même règle pour un code de secours, retiré de la liste avant toute session : retrait refusé → **503**
  `CAUSE_CODE_DE_SECOURS_NON_CONSOMME`, le code reste utilisable.
- La désactivation juge le pas par la **même** `consommer_le_pas_totp`, dans la transaction qui supprime la
  ligne : un code déjà utilisé à la connexion ne désactive pas la MFA (401).

### 4.5 Ticket MFA et révocation

- Le ticket (`mfa_challenge_response`, signé par `mfa_ticket_sign`) sert **cinq minutes**. Il est signé avec
  l'époque de session globale **et** l'époque du compte (`epoque_du_compte`, `session.rs`), dans un domaine
  (`mfa-ticket|`) distinct de celui des cookies de session. Époque du compte non lue → **503**
  `CAUSE_EPOQUE_DU_COMPTE_NON_LUE`, aucun ticket émis.
- `login_mfa_post` refuse en **401** `CAUSE_TICKET_MFA_INVALIDE_EXPIRE_OU_REVOQUE`, **avant** tout examen du
  code et sans rien compter, un ticket invalide, expiré, ou **révoqué** : l'époque globale a avancé
  (déconnexion de portée `globale`), ou celle du compte a avancé (`avancer_l_epoque_du_compte` : déconnexion du
  compte, changement de son mot de passe, réinitialisation par un administrateur), ou n'a pas pu être relue.
  Toutes ces causes partagent la même phrase, à dessein : la distinguer renseignerait le porteur d'un vieux
  ticket sur ce qui s'est passé depuis.
- À époques inchangées, un ticket reste rejouable pendant ses cinq minutes : chaque rejeu doit présenter un code
  frais, borné par le pas consommé et par le frein du compte.
- La session posée est frappée à l'époque du compte que le ticket a prouvée (`mint_session_du_compte`) : une
  révocation survenue depuis la rend caduque dès la requête suivante.

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
