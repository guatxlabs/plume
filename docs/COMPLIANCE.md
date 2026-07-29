# Conformité — POSTURE & COUVERTURE (pas certification) — #38

> **Honnêteté (invariant dur).** Plume expose une **posture / couverture de conformité** : quels
> contrôles réglementaires sont **couverts** (pass/fail SCA ingérés) et quelles **détections** sont
> mappées à un cadre — le tout adossé au **ledger d'intégrité** (Ed25519, tamper-evident). Plume **ne
> certifie pas** la conformité et ne produit **pas un audit certifié**. Toute étiquette dit « posture /
> couverture », jamais « conforme / certifié ».

## Ce que couvre cet incrément

1. **Tags de conformité PAR RÈGLE.** Une règle de détection porte, à côté de son tag MITRE ATT&CK, des
   tags de cadre réglementaire (`rule.compliance`, schéma **v88**, additif). Format : CSV de
   `cadre[:contrôle]` — ex `pci_dss:8.7,hipaa:164.312,nist_800_53:AU-2`.
   - **Vocabulaire de cadres CONTRÔLÉ** (fail-closed) : `guatx_core::cim::COMPLIANCE_FRAMEWORKS` =
     `pci_dss, hipaa, nist_800_53, gdpr, tsc, iso_27001, cis`. Un cadre hors-vocab est **rejeté**.
   - **Contrôle LIBRE** mais charset-borné (`A-Za-z0-9 . _ - / ( ) espace`, ≤64) — stocké en valeur,
     jamais interpolé dans du SQL.
   - CRUD : API `POST /api/rules` + UI (champ « Conformité » du formulaire de règle). Import **Sigma** :
     les `tags` du doc (namespaces `pci_dss.*`, `hipaa.*`, `nist.*`, `cis.*`, alias inclus) sont mappés.

2. **Dashboards de posture PAR CADRE** (seedés au boot, GXQL, vue « Conformité (posture) ») :
   **PCI DSS**, **HIPAA**, **NIST 800-53**. Chacun filtre la posture SCA ingérée (#57,
   `category=posture`) au cadre (`posture_framework=*<id>*`) : pass/fail global, échecs par contrôle,
   par hôte, détail. Lecture via le **chemin GXQL masqué** (#45 field-filters + RBAC hérités).

3. **Rollup de posture** — `GET /api/compliance/posture[?framework=<id>][&since=<epoch_s>]` (viewer+).
   Compose **(a)** pass/fail SCA **par contrôle** (posture ingérée, agrégée en Rust — aucune concat SQL)
   et **(b)** les **détections** qui mappent ce cadre (`rule.compliance`). Sans `framework` : synthèse
   par cadre. `GET /api/compliance/frameworks` liste le vocabulaire effectif.

4. **Rapport de posture** — `GET /api/compliance/report?framework=<id>` (viewer+, read-only, JSON
   exportable). = rollup + **ancrage de preuve en lecture seule** sur le ledger (tête de chaîne + dernier
   checkpoint signé) + disclaimer d'honnêteté. **Aucune écriture, aucun export d'entrées de ledger.**

## Vendor-agnostic / extensible

Le vocabulaire est **DONNÉE**, pas un set fermé codé en dur. Le socle (`COMPLIANCE_FRAMEWORKS`, core CIM)
est **UNIONNÉ** avec une liste additionnelle de config :

```
PLUME_COMPLIANCE_FRAMEWORKS="soc2,dora"   # CSV, minuscule/_ ; ajouté au socle, sans rebuild
```

Les IDs sont **alignés Wazuh** (`data.sca.check.compliance.{pci_dss,hipaa,nist_800_53,gdpr,tsc,cis}`,
cf. `ingest/endpoint.rs::flatten_compliance` -> `posture_framework`/`posture_compliance`) : la posture
ingérée et le tag de règle **joignent sur le même token**. Ajouter un cadre côté ingestion se fait aussi
via le DSL de parseur déclaratif (`config.d/parsers/`) en visant `posture_framework`/`posture_compliance`.

## Mode 0 / byte-identique

- Migration v88 **additive** : `rule.compliance` NULL pour l'existant -> règle non taguée -> sélection
  d'ordonnancement (`run_due_rules`), coverage et `rules_list` **inchangés**.
- Aucun dashboard de conformité défini avant ce boot -> les seeds sont idempotents (par nom) et **VIDES**
  tant qu'aucune posture SCA n'est ingérée.

## Différé (sous-tâches #38 séparées — NON construites ici)

- Rétention **WORM / legal-hold**.
- **Export / streaming du ledger** (sensible — revue sécu séparée).
- Provisioning **SCIM**.
- Rôles **RBAC composables / custom**.
