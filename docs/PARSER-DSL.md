# Plume — Parseur déclaratif (DSL CIM) — Slice #7, pièce 2

> **Statut : contrat opérateur.** Ce document décrit le format d'un **parseur déclaratif** : un fichier
> JSON posé sous `config.d/parsers/` qui **mappe une source vers le CIM** (`docs/CIM.md`) **sans recompiler
> Rust**. Il répond au blocage « est-ce que mes 40 sources vont parser ? » : ajouter une source = ajouter
> un fichier.

- **Ancre code** : `dparser_compile` / `dparsers_reload` / `dparsers_apply` (`daemon/src/parsers.rs`),
  table `dparser` (migration v78), loader `load_overlay_dparsers`.
- **Exemple livré** : [`config.d/parsers/example-cim-firewall.json`](../config.d/parsers/example-cim-firewall.json).

---

## 0. Principe directeur — ENRICH / MAP, jamais DROP

Un parseur déclaratif **parse, mappe, enrichit**. Il **ne peut pas supprimer ni filtrer** un événement :
une capture absente = **aucun enrichissement** (jamais une suppression). Toute réduction de collecte est un
**filtre**, qui appartient au panneau *whitelists* (#10), **pas à un parseur**.

**Mode 0 / byte-identique** : tant qu'aucun parseur déclaratif ne cible une source, l'événement est stocké
**à l'octet près** comme aujourd'hui. Le mécanisme est **purement additif**.

---

## 1. Où et comment

- Fichier `config.d/parsers/<nom>.json`. Le **discriminant** d'un parseur déclaratif est la présence d'un
  objet **`map`** (les parseurs *regex legacy* à `pattern` vivent dans le même dossier et sont chargés
  séparément — un fichier va à exactement un loader).
- Chargé au boot par `load_overlay_dparsers` (`managed=1`, source git), **validé-ou-ignoré** : une spec
  invalide (regex/`match`/`map` cassés) est **WARN + skip**, jamais un crash boot.
- Compilé au registre par `dparsers_reload`, puis **exécuté à l'ingest** (chemin `kind=events`), **après**
  `parsers_apply`/`extract_generic` et **avant** la promotion `src_ip`/`dst_ip`/`url` en colonnes.

---

## 2. Format

```jsonc
{
  "name": "…",              // requis, clé d'UPSERT
  "source": "firewall",      // source d'event ciblée ('*' = toutes). Défaut '*'
  "enabled": true,           // défaut true

  "match": "action=",        // OPTIONNEL : regex de garde. Le parseur ne s'applique QU'AUX
                              //   messages qui matchent. Absent = s'applique à toute la source.

  "extract": [               // OPTIONNEL : étapes ORDONNÉES d'extraction -> sac de captures.
    { "regex": "SRC=(?P<src>\\S+) DST=(?P<dst>\\S+)" },  // groupes NOMMÉS Rust (?P<nom>…)
    { "kv": true },          // balaye key=value / key="quoté" / logfmt   (alias: "logfmt": true)
    { "json": true }         // message = objet JSON top-level, aplati 1 niveau (k, k.sous-clé)
  ],

  "map": {                   // REQUIS : assigne des valeurs aux champs CIM.
    "category": "firewall",   //   littéral OU "$capture". Pose la colonne `category`.
    "severity": 2,            //   entier 0..4 (ou "$capture" numérique). Hors plage -> ignoré.
    "src_ip":  "$src",        //   -> fields.src_ip  (PROMU en colonne src_ip par le daemon)
    "dst_ip":  "$dst",        //   -> fields.dst_ip  (PROMU en colonne dst_ip)
    "url":     "$url",        //   -> fields.url     (PROMU en colonne url)
    "action":  "$act",        //   -> fields.action  (outcome CIM : cf. action_vocab)
    "fields":  { "proto": "$proto", "vendor": "acme" }  // champs étendus arbitraires
  }
}
```

**Valeurs de `map`** : une chaîne `"$nom"` référence une **capture** (issue des étapes `extract`) ; toute
autre chaîne/nombre est un **littéral**. Une référence `$nom` **absente ou vide** => la cible est **laissée
telle quelle** (jamais un champ vide écrit, jamais un drop).

**Précédence** (ENRICH) : `fields` **fusionne sans écraser** (une clé déjà posée par le collecteur gagne) ;
`category`/`severity` sont posés par le **premier** parseur qui les produit. `src_ip`/`dst_ip`/`url` sont
écrits **dans `fields`** puis **promus en colonnes** par l'infra existante (`fields_ip`/`fields_dst`/`fields_url`).

**Bornes** (budget RAM) : ≤ 8 étapes `extract`, ≤ 32 captures, valeur ≤ 256 c., regex ≤ 1000 c., message
tronqué à 8192. Clés de `map.fields` : doivent passer `soql_ident_ok` (`[A-Za-z0-9_]`), sinon ignorées.

---

## 3. Exemple — firewall générique (key=value) → CIM

Message ingéré (`source=firewall`) :

```
action=deny proto=tcp src=203.0.113.7 dst=198.51.100.2 dport=22
```

Avec l'exemple livré → événement CIM : `category=firewall`, `severity=2`, colonne `src_ip=203.0.113.7`,
colonne `dst_ip=198.51.100.2`, `fields.action=deny`, `fields.proto=tcp`.

Une **règle de détection** compose alors dessus **sans connaître le vendeur** (cf. `docs/CIM.md`) :
`search category=firewall action=deny | stats count by src_ip | where count > 20`.

---

## 4. Catégories & vocabulaire

`map.category` **devrait** cibler une catégorie de la taxonomie CIM (`docs/CIM.md` §2). Une valeur
hors-taxonomie est **acceptée mais signalée** (`warn` au chargement) — ENRICH, jamais SUPPRESS.
`map.action` **devrait** réutiliser le vocabulaire neutre d'outcome (`success/failure/allowed/blocked/…`).
