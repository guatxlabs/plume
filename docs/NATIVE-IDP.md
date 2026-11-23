# Native IdP (#44) — OIDC / LDAP / MFA, and the SAML 2.0 design

[English](NATIVE-IDP.md) | [Français](NATIVE-IDP.fr.md)

> **Status.** OIDC (Authorization-Code + PKCE), LDAP/AD (bind), and TOTP MFA are **implemented and tested**.
> SAML 2.0 SP is **implemented and tested**, but **behind the `saml` compile feature** (see §5):
> compiled **without** that feature, SAML login returns **501**. ⚠️ **The shipped Docker image is built
> with `ldap,cold_tier`** — a set declared only once, by `ARG PLUME_FEATURES` in the
> [`Dockerfile`](../Dockerfile), since `971de7a` (2026‑08‑08) — and **`saml` is not part of it**:
> **SAML therefore answers 501 there**. To enable it, add it to the set without touching the file:
> `docker build --build-arg PLUME_FEATURES=ldap,cold_tier,saml .`
> ⚠️ **Native host mode compiles NO optional feature**: the README and `bootstrap.sh`
> prescribe a **bare** `cargo build --release`. On a host binary built that way, **LDAP/AD login answers
> 501 as well** (and the cold tier is absent) — see §3 and
> [`TROIS-MODES.md` §3.9](TROIS-MODES.md#39-updating). OIDC, TOTP MFA and header SSO, on the other hand,
> depend on no feature: they are present in all three modes.
> This increment is **additive and fail-closed**: with no provider configured and no MFA enrolled, all
> existing authentication (Basic / session cookie / agent token / HEC / Authentik header SSO)
> is **strictly unchanged** (mode 0 byte-identical, proven by the test suite).

## 1. Configuration model

An **identity provider** is a row of the `idp_provider` table (migration v85), configured by an
**admin** through the UI (`Administration → Identité fédérée (SSO)`) or the `/api/idp/providers` API (admin-only):

| column        | role |
|---------------|------|
| `name`        | unique identifier (URL-safe segment: alnum + `. _ -`) |
| `kind`        | `oidc` \| `ldap` \| `saml` |
| `enabled`     | a disabled provider grants **no** login |
| `config_json` | **non-secret** parameters (issuer, client_id, redirect_uri, scopes, group_claim; LDAP url, base_dn, filters, groups) |
| `secret`      | **the only** credential (OIDC client_secret / LDAP bind password) — dedicated column, **never** in `config_json`, **never** projected into a response, encrypted at rest by SQLCipher |

**Write-only secret**: identical to `connectors`/`notifiers`. The list only returns a `has_secret` boolean;
on update, an **empty/omitted** secret **keeps** the existing one (never overwritten by an empty value, never leaked).

**TOTP MFA** is stored per account in `user_mfa` (base32 secret, `enabled`, SHA-256 hashes of the recovery
codes). Empty by default → no challenge.

**Group → role mapping**: reuses **exactly** the Authentik header SSO table (`sso_role` /
`sso_grants`). The IdP's groups (OIDC `groups` claim; LDAP `memberOf`/`group_filter`) are mapped to
`admin`/`editor`/`viewer`. **Fail-closed**: `require_group_match` (default **true**) refuses (DENY) a
user who matches **no** known group — unlike the implicit viewer fallback, access is
never granted on an empty mapping.

### 1bis. "Trusted-header" SSO (forward-auth) — VENDOR-AGNOSTIC header names

Optional path (enabled **only** if `PLUME_SSO_HEADER_SECRET` is set) where a trusted forward-auth
(Traefik/oauth2-proxy/nginx auth_request…) injects the identity as HTTP headers, together with a **shared
secret** `x-plume-sso-secret` (compared in constant time). Without the right secret, the identity headers are
**never** read.

- **Configurable header names** (v107): `PLUME_SSO_HEADER_USER` (default **`x-authentik-username`**) and
  `PLUME_SSO_HEADER_GROUPS` (default **`x-authentik-groups`**). Unchanged defaults → existing Authentik
  deployment **byte-identical**. A client behind Okta/Keycloak/Azure/Ping sets the header names that **its**
  proxy emits. The group→role mapping remains `PLUME_SSO_GROUP_*` (already configurable).
- **The name does NOT bypass the trust model**: these headers are read **only** on the path already
  authenticated by `x-plume-sso-secret`. Changing the NAME opens no read path outside the secret gate.
- **DEPLOYMENT concern (to be respected)**: the trust comes from the forward-auth middleware
  **overwriting** the headers supplied by the client. If you configure custom names, the
  middleware **must overwrite THOSE names** (otherwise a client could inject `PLUME_SSO_HEADER_GROUPS`
  directly). This is a proxy configuration requirement, not a weakness of the daemon.
- **NO ACCOUNT IS CREATED BY THIS PATH**, and that is deliberate: unlike OIDC and LDAP (which
  provision an account on the fly, see §2 and §3), header SSO writes **no** row into the accounts
  table — the name and the role are recomputed on every request from the headers. A consequence to
  know: a directory account **is neither created, nor editable, nor revocable** from `Administration →
  Comptes & accès`; its role comes from its groups and is changed **in the directory**.
- **"WHO HAS ACCESS" can still be read** (`P11.5-c`). Since these accounts have no row, the accounts
  list could not show them: they administered the console without appearing anywhere. The authentication
  choke-point now records **every resolved identity** — name, provenance (external
  directory / local account / token / bootstrap credential), effective role, origin of that role, first and
  last seen — and `Administration → Comptes & accès` renders this inventory **next to** the list of
  local accounts (read-only: an account whose authority comes from elsewhere is not administered here).
  No secret goes into it — no fingerprint, no token, nor the raw value of the directory groups.

## 2. OIDC (implemented)

- `GET /api/auth/oidc/{name}/start` → generates `state`, `nonce`, and a **PKCE** `code_verifier`/`code_challenge`
  (S256), sets an **HMAC-signed state cookie** (`plume_oidc`, `SameSite=Lax`, HttpOnly, 10 min) and redirects
  (302) to the `authorization_endpoint` (resolved by **discovery** `.well-known/openid-configuration`, or
  explicit overrides). No server state (stateless).
- `GET /api/auth/oidc/callback` → checks the state cookie (HMAC + exp), compares `state` (anti-CSRF, constant
  time), exchanges the `code` (+ `code_verifier`) at the `token_endpoint`, fetches the **JWKS**, and **validates
  the `id_token`**: **RS256/ES256** signature (key chosen by `kid`, algorithm **restricted to asymmetric** → no
  HS256 algorithm confusion), `iss` == **configured** issuer, `aud` contains `client_id`, `exp` valid
  (leeway 60 s), `nonce` == nonce from the state. Then group→role mapping, **JIT provisioning** of the account, session.
- **Anti open-redirect**: the `redirect_uri` is the **configured** one (served back as is, never taken from the
  request); the final redirect is **fixed** (`/`). Endpoints forced to **https** (prevents secret/key leaks).

## 3. LDAP / Active Directory (implemented, `ldap` feature)

- `POST /api/auth/ldap {provider?, user, pass}` → **bind** against the directory (StartTLS/LDAPS via `ldap3` +
  tokio-rustls, **no OpenSSL**), resolves group membership (`memberOf` or `group_filter`), maps
  to a role, provisions JIT, sets the session. Anti-brute-force reused (lockout `(user,ip)`).
- **Injection-safe**: every user-supplied component of a filter is escaped per **RFC 4515** (`\\ * ( ) NUL`) and
  every DN component per **RFC 4514** — a login `*)(uid=*` cannot alter the structure of the filter (tested).
  Bind with an **empty password refused** (prevents *unauthenticated bind*).
- **Egress guard** (`P7.20-a`): before any connection, the directory URL is judged by the egress guard
  (`ldap_garde_de_sortie`) — only `ldap://` (port 389 by default) and `ldaps://` (636) are admitted, `ldapi://` and an
  empty host are refused; the literal and every resolved address go through the guard: loopback, link-local and ULA
  refused whatever `PLUME_SSRF_BLOCK_PRIVATE` says (only a target listed in `PLUME_SSRF_ALLOW` escapes it),
  private address (`10/8`, `172.16/12`, `192.168/16`) refused by default and admitted by `PLUME_SSRF_ALLOW` (listed host or
  CIDR) or `PLUME_SSRF_BLOCK_PRIVATE=0`. The route runs it before the bind, with or without the `ldap` feature: a
  refusal — whatever its cause — serves a 502 with a fixed phrase on `POST /api/auth/ldap` (never the address; a build
  without `ldap` serves it too, before its 501), the cause to the `[idp]` log, and counts no failure against the throttle. An
  empty directory URL (absent or blank) is not a refused target but an unconfigured provider: the guard is not
  run, the response stays what it was before (501 without `ldap`, 401 with it). The judged authority stops, like the one `ldap3`
  reads, at the first `/`, `?` or `#` (`ldap://10.0.0.5?@192.0.2.10` is judged on `10.0.0.5`); the only known
  difference, a tab or a line feed INSIDE the authority is kept by the guard and removed by `ldap3`: the judged
  name does not resolve, so the URL is refused. A directory URL, an OIDC token endpoint or JWKS written with
  a private address — and the issuer when discovery is required, that is when it is contacted — are refused at entry
  (400, creation and update of a provider), with the phrase that names these two settings; loopback, the
  metadata target, `ldapi://` or an unresolved name are only refused at connection time.
- **`ldap` feature**: the **pure functions** (escaping, mapping) are compiled/tested **without** the
  feature; only the network bind is behind `#[cfg(feature = "ldap")]` (without the feature: explicit 501).
  **SINCE v107: `--features ldap` is enabled BY DEFAULT in the stock image** — it is part of the
  `ldap,cold_tier` set that `ARG PLUME_FEATURES` declares ([`Dockerfile`](../Dockerfile)) — native
  LDAP/AD login works without a rebuild (bring-your-own-directory). **This default-ON applies ONLY
  to the image**: the host recipe compiles bare, so a `plume-daemon` installed by `bootstrap.sh` without
  `--features ldap` answers **501** to `POST /api/auth/ldap` — to get it:
  `cargo build --release --features cold_tier,ldap`. Cost: ~40 additional **pure-Rust** crates
  (ldap3/lber, asn1/x509, url/idna/icu); **no** new C dependency (`openssl-sys` already comes from
  SQLCipher). **INERT as long as no LDAP provider is configured+enabled**: `POST /api/auth/ldap` answers
  `404 aucun provider LDAP activé` (no endpoint open, no outbound bind, no active surface) — a
  stock deployment without LDAP behaves identically with the feature ON or OFF.

## 4. TOTP MFA (implemented, RFC 6238)

- Self-service (`/api/mfa/*`, any account, operates on `au.name`): `enroll` (base32 seed + `otpauth://` URI
  shown once), `verify` (first code → activates + **recovery codes** shown once, only their SHA-256 are
  persisted), `disable` (requires a valid code), `status`.
- **Challenge at local login**: if the account has an active MFA, `POST /api/login` returns
  `{mfa_required:true, ticket}` (short HMAC ticket) **without** setting a session; `POST /api/login/mfa
  {ticket, code}` validates the TOTP (drift window ±1 step, constant time) **or** a **single-use**
  recovery code, then sets the session. Empty `user_mfa` → **byte-identical** login flow.

The following subsections describe the refusals and the throttles of this flow. The controls are named there, in
backticks, by the constant or the function that carries them; the causes are served as is in the
`error` field of the response. The `documentation_du_second_facteur` witness checks three things, and only
those: every control it requires has its sentence, which cites the defined symbol that carries it; every compound name
(containing an underscore) cited here appears in a code line of `daemon/src` outside tests, a comment
line not counting; the reactivation 409, the reset and the throttle trade-off have their sentence
in their subsection, and the 409 is served by `mfa_verify` before any counted attempt. It does not read the meaning of the
sentences: a wrong status next to a correct symbol passes, review catches it.

### 4.1 Enrollment: the account password is required

- `POST /api/mfa/enroll {password}` requires the account password, judged **before** any seed by
  `prouver_le_premier_facteur` (`session.rs`), with the **same** resolution as `POST /api/login` and under the **same**
  lock (account, address): the route offers no attempt beyond what login offers. A session alone is not
  enough — it would let whoever stole it lock the holder out behind a seed they do not hold.
  - field absent or empty → **403** `CAUSE_MOT_DE_PASSE_EXIGE_POUR_ENROLER` (nothing examined, nothing counted);
  - wrong password → **403** `CAUSE_MOT_DE_PASSE_REFUSE_A_L_ENROLEMENT` (failure counted by
    `auth_record_failure`, an entry in the register);
  - (account, address) lock set → **429** `CAUSE_MOT_DE_PASSE_VERROUILLE_A_L_ENROLEMENT` + `Retry-After`,
    the password is not examined;
  - account not read → **503** `CAUSE_COMPTE_NON_LU_A_L_ENROLEMENT`.
- **Accounts without a local password** — OIDC, SAML or LDAP federated account (hash `IDP_HASH_SENTINEL`), or
  SSO identity through headers — → **403** `CAUSE_ENROLEMENT_SANS_MOT_DE_PASSE_LOCAL`, decided by
  `le_compte_a_un_mot_de_passe_local`. plume's second factor is only asked for at login by local
  password, which these accounts do not use: their second factor is that of their identity
  provider. Their login is not modified; only enrollment is refused.
- An MFA that is **already active** is never overwritten: **409** « MFA déjà active (désactivez-la d'abord) ». The enrollment
  write re-judges the condition (`WHERE user_mfa.enabled=0`): an activation that happened during the password
  proof also returns 409. Write refused → **503** `CAUSE_ENROLEMENT_NON_ECRIT`, no seed
  set nor shown.

### 4.2 Activation: the reactivation 409

- `POST /api/mfa/verify` on an **already active** MFA → **409** « MFA déjà active (désactivez-la d'abord) »,
  **before** any examination of the code and before any counted attempt (`mfa_verify`): the response is the same whether the code
  is right or wrong, no new recovery code is served. Without this refusal, the route would be a TOTP oracle
  for a stolen session.
- Activation is a compare-and-set on the enrollment that was read (`enabled=0 AND secret=<graine lue>`): another
  request activated, replaced or deleted it in the meantime → **409** `CAUSE_ENROLEMENT_CHANGE_PENDANT_LA_VERIFICATION`,
  nothing is activated; write refused → **503** `CAUSE_MFA_NON_ACTIVEE`, no recovery code served.
- A code whose step is already consumed → **401** (anti-replay).

### 4.3 Second-factor throttle, per account

- **Key**: the account — never the address, never the ticket. The three routes that judge a code
  (`login_mfa_post`, `mfa_verify`, `mfa_disable` on an active MFA) go through it.
- **The attempt is counted before it is examined**: `reserver_un_essai` (`handlers/frein_du_second_facteur.rs`)
  writes the possible failure, in its own committed transaction, **before** the code is judged. Throttled account →
  **429** `CAUSE_SECOND_FACTEUR_FREINE` + `Retry-After`, the code is not examined (a correct code is refused
  like a wrong one). Throttle write refused → **503** `CAUSE_ESSAI_DU_SECOND_FACTEUR_NON_COMPTE`, the code
  is neither accepted nor refused.
- **Threshold and delay**: the login lock settings, `lock_threshold`, `lock_base_s`, `lock_max_s`,
  set by `PLUME_AUTH_LOCK_THRESHOLD` (default 10), `PLUME_AUTH_LOCK_BASE_S` (base delay, default 30 s) and
  `PLUME_AUTH_LOCK_MAX_S` (ceiling, default 900 s); both delays are at least 1 s. At the threshold, the delay is `lock_base_s` × 2^(failures beyond the threshold), capped at `lock_max_s`. Threshold
  0: throttle off, nothing is read or written.
- **Forgetting**: a day without failure erases the consecutive failures (`MEMOIRE_DES_ECHECS_S`).
- **Reset** (`remettre_a_zero`): a correct code that is **accepted** resets the account; a password
  login, never. One exception, which examines no code: `mfa_disable` on a **pending** enrollment
  (never activated) deletes the seed and also resets the account — the failures counted by `mfa_verify` against
  that seed are erased with it. This is not a loophole: the targeted seed no longer exists, its holder
  knew it (enrollment shows it), and a new enrollment requires the password.
- **Refusal that does not judge the code** (step not consumed, enrollment changed, write refused): the reserved attempt
  is given back (`rendre_l_essai`). A refused give-back leaves one failure too many — the direction that throttles.
- **Durable**: the state lives in the `setting` table, scope `frein.second_facteur`
  (`PORTEE_DU_FREIN_DU_SECOND_FACTEUR`), key = the account name, no schema migration. A restart or
  another replica does not reopen the window. The row is removed in the transaction that deletes the account
  (`oublier_dans_la_transaction`). No settings route serves a scope other than `global`; raw SQL,
reserved to administrators, can read the row (its authorizer refuses secret columns, not the
`setting` table): it carries only counters and instants (`consecutifs`, `freine_jusqu_a`, `dernier`), no
code nor seed.
- **Seen from the SIEM** (`tracer_l_echec`, source `plume-auth`): at activation and at deactivation, a wrong code
  emits `failure` with severity 3 (login already emits its own through `auth_record_failure`); on the three
  routes, the failure that sets the throttle emits `lockout` with severity 4. The fields carry `facteur: "second"` and
  the route, never the presented code, the seed nor the ticket.
- **Trade-off**: the throttle can only be reached with a signed ticket (hence the password) or a session of the
  account; forged tickets or wrong passwords throttle nobody. Whoever holds the password
  can freeze the code step for the holder, at most `lock_max_s` at a time: an accepted price, the alternative being
  to let them guess the second factor; the countermeasure is that of a password compromise (changing
  it). The first factor is not throttled by this counter: the holder always gets their ticket. A
  per-ticket throttle is ruled out: the ticket is reissued at will with the password.

### 4.4 Consumption of the factor

- A TOTP step is only accepted once **consumed**: `consommer_le_pas_totp` is a compare-and-set in the database
  (`last_step < pas`). A step already consumed — sequential or concurrent replay — → **401** « code MFA invalide »,
  failure counted. The database did not take the write → **503** `CAUSE_PAS_TOTP_NON_CONSOMME`: no session, the
  code is not burned, the attempt is given back.
- Same rule for a recovery code, removed from the list before any session: removal refused → **503**
  `CAUSE_CODE_DE_SECOURS_NON_CONSOMME`, the code remains usable.
- Deactivation judges the step through the **same** `consommer_le_pas_totp`, in the transaction that deletes the
  row: a code already used at login does not deactivate the MFA (401).

### 4.5 MFA ticket and revocation

- The ticket (`mfa_challenge_response`, signed by `mfa_ticket_sign`) is valid for **five minutes**. It is signed with
  the global session epoch **and** the account epoch (`epoque_du_compte`, `session.rs`), in a domain
  (`mfa-ticket|`) distinct from that of the session cookies. Account epoch not read → **503**
  `CAUSE_EPOQUE_DU_COMPTE_NON_LUE`, no ticket issued.
- `login_mfa_post` refuses with **401** `CAUSE_TICKET_MFA_INVALIDE_EXPIRE_OU_REVOQUE`, **before** any examination of the
  code and without counting anything, a ticket that is invalid, expired, or **revoked**: the global epoch has advanced
  (logout with `globale` scope), or the account's has advanced (`avancer_l_epoque_du_compte`: logout of the
  account, change of its password, reset by an administrator), or could not be read again.
  All these causes share the same phrase, on purpose: distinguishing them would tell the bearer of an old
  ticket what has happened since.
- With epochs unchanged, a ticket remains replayable during its five minutes: each replay must present a fresh
  code, bounded by the consumed step and by the account throttle.
- The session set is minted at the account epoch that the ticket proved (`mint_session_du_compte`): a
  revocation that happened since makes it void from the next request on.

## 5. SAML 2.0 SP (implemented — **`saml` feature**, SP-initiated, POST binding)

`kind = 'saml'` is accepted by the providers CRUD, and SAML login is **implemented behind the
`saml` compile feature** (like LDAP). **Without `--features saml`, the routes return 501** (samlify
not linked → DEFAULT build/test byte-identical, 2 GB budget preserved). XML-DSig/C14N/XSW validation is
**delegated to `samlify`/`saml-rs`** (pure Rust, RustCrypto via `bergshamra`) — **C14N/XML-DSig is never
re-implemented here** (that is where authentication bypasses live). `samael` (C bindings) is **banned** (minimal
image doctrine).

**Config** (`config_json`, all NON-secret): `idp_sso_url`, `idp_entity_id`, `sp_entity_id`, `acs_url`,
`idp_x509_cert` (IdP signing cert, PEM), `attr_username` (empty → NameID), `attr_groups` (default `groups`),
`want_assertions_signed` (default **true**), `sign_authn_requests` (default false), `allowed_clock_skew_s`
(default 60, bounded 0..3600), `require_group_match` (default **true**). The **SP private key+cert** (PEM bundle,
ONLY if `sign_authn_requests`) go into `secret` (write-only, like the other credentials).

> ⚠️ **`want_assertions_signed=false` is a footgun.** It remains configurable (vendor-agnostic principle: a
> legacy IdP may sign ONLY the `Response`), but it makes the daemon accept **UNSIGNED assertions** on an
> SOC authentication path. It is **never silent**: a LOUD `eprintln!` warning is emitted at
> provider creation (`idp_provider_create`, with the provider name) **and** at every insecure use
> (`saml_verify_and_extract`), routed to stderr → logs/SIEM. Only enable it for a proven legacy IdP.

**Endpoints** (PUBLIC routes, exempt from the Host allowlist + `auth_route` rate-limit):

1. **`GET /api/auth/saml/{name}/start`** — builds the `AuthnRequest` (HTTP-Redirect: deflate+base64+urlencode
   via samlify), sets an **HMAC-signed** `RelayState` (`saml_relaystate_sign`, reuses the
   `oidc_state_sign` pattern) carrying the AuthnRequest ID, sets a `plume_saml` flow cookie (Lax, defense in
   depth — may not survive the cross-site POST → the RelayState stays authoritative), 302 to the IdP.
2. **`POST /api/auth/saml/acs`** — the SECURITY-CRITICAL Assertion Consumer Service. `saml-rs::finish_sso`
   applies **fail-closed**: XML-DSig signature against the **STATICALLY PINNED** cert (`verify_signature`,
   no metadata TOFU); **XSW** countermeasure (SubjectConfirmationData guard, rejection of duplicated IDs, rejection of
   multiple roots, strict reference→element binding, coverage of ONE single assertion, rejection of external
   reference, untrusted inline cert); XXE-safe parsing; `Audience`==`sp_entity_id`; `Recipient`/
   `Destination`==`acs_url`; `NotBefore`/`NotOnOrAfter` (±bounded skew); `InResponseTo`==ID of the signed
   RelayState; anti-replay through a **bounded assertion ID cache** (`BoundedReplayStore`, anti-OOM like `auth_fails`);
   `Issuer`==`idp_entity_id`; `StatusCode`==Success; **IdP-initiated DISABLED** (only
   `finish_sso` is used, never `accept_unsolicited_sso`). Upstream, an **anti-SHA-1 algorithm guard by ALLOWLIST**
   in plume (`saml_reject_weak_sig_alg` — saml-rs/bergshamra verify SHA-1 "for compatibility" and have no algorithm
   allowlist, so plume refuses it). ⚠️ This guard does **NOT scan the raw text** (a denylist of `#rsa-sha1`
   substrings is **evadable** through an XML character reference — `#rsa-sha&#49;` does not contain the substring
   but bergshamra decodes it to `rsa-sha1` at verification): it **parses the XML with saml-rs's OWN parser**
   (`saml_rs::xml::dom::parse_roots`, attribute values char-ref-decoded/normalized — the SAME decoding as
   the verifier) and requires that **EVERY** `SignatureMethod`/`DigestMethod` carry a **decoded** `Algorithm` in
   a STRICT allowlist of strong algorithms (signature: RSA/ECDSA-SHA2, RSA-PSS SHA-256+; digest: SHA-256/384/512).
   Everything else (SHA-1, MD5, RIPEMD, unknown), an absent `Algorithm`, the absence of any `SignatureMethod`, or
   unreadable XML → **DENY (fail-closed)**. Then attribute extraction → `saml_groups_str` → **reused group→role
   mapping** (`oidc_role_mode0`/`sso_role`, fail-closed `require_group_match`) → JIT provisioning
   (`idp_provision_user`) → session (`attach_session_cookies`, **exactly** the same downstream path as OIDC/LDAP).
   `saml_groups_str` **neutralizes the `|`/`,` separators inside each group value** before
   joining → a single IdP value `x|plume-admin` cannot split again into a synthetic `plume-admin`
   group (anti privilege escalation).
3. **`GET /api/auth/saml/{name}/metadata`** — SP metadata (public XML) to provide to the IdP.
4. **SLO**: deferred (not implemented).

**EncryptedAssertion: OUT OF SCOPE** — the signed assertion over TLS is required (software RSA decryption
of XML-Enc, exposed to `RUSTSEC-2023-0071`, stays **disabled by default** in saml-rs). **Crate chosen:**
`samlify` 0.3 (re-export of `saml-rs` 0.3, pure Rust). Fitness verdict: signature verification against a
static cert **YES**; XSW robustness **YES** (defenses in depth + dedicated `xsw.rs`/`hardening.rs` test suite
upstream). Adversarial test vectors (`src/tests/saml.rs`, gated `saml`): valid/unsigned/tampered/
wrong-audience/wrong-recipient/wrong-issuer/expired/not-yet-valid/divergent-InResponseTo/replay/
wrong-cert/SHA-1/**SHA-1-obfuscated-by-char-ref (`&#49;`/`&#x31;`, permanent regression)**/XSW(dup+2nd-assertion)/
status≠Success; plus **anti escalation through an internal group separator** (`saml_groups_str`).

## 6. Multi-tenant (mode 1)

In this increment, IdP/MFA are **mode-0 only** (like UI token provisioning): in multi-tenant,
these routes return **501** (platform identities live in the control plane; OIDC/LDAP→tenant integration
through the `plume-<tenant>-<role>` grants — already supported by `sso_grants` — is a follow-up). Mode 1 therefore stays
**fail-closed and unchanged**.
