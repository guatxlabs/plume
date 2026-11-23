# Politique de sécurité

[English](SECURITY.md) | [Français](SECURITY.fr.md)

Plume est un **SOC/SIEM poids plume** : il ingère de la télémétrie de sécurité, la stocke chiffrée,
et sert une API + une interface + un moteur de détection sur une **grammaire de lecture GXQL fermée**,
avec le **masquage des champs comme point de passage unique**. Sa valeur dépend de ce que ce chemin de
lecture reste scellé et de ce que les secrets ne fuient jamais dans ce qu'il stocke ou sert. Une faille
dans ces contrôles est un bug grave, et nous voulons en entendre parler.

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique pour une vulnérabilité de sécurité.**

**À privilégier :** signalez-la en privé par les **GitHub Security Advisories** — le bouton « Report a
vulnerability » de l'onglet **Security** du dépôt. Il garde le signalement et le correctif coordonnés
et privés, et il vous permet de joindre des détails à un fil privé par défaut.

**Autre voie :** si vous ne pouvez pas utiliser les GitHub Security Advisories — pas de compte, dépôt
mis en miroir ailleurs, ou vous préférez ne pas en créer un —, écrivez à **security@guatx.com**. Les
deux canaux sont surveillés ; le circuit des advisories n'est privilégié que parce qu'il garde le
signalement et le correctif dans un même lieu privé.

Merci d'indiquer : la version ou le commit concerné, une description, les étapes de reproduction ou une
preuve de concept, et l'impact. Si vous nous écrivez et que le signalement est sensible, dites-le : nous
déplacerons l'échange dans une advisory privée avant que vous n'envoyiez les détails.

Nous visons un **accusé de réception sous 3 jours ouvrés** et à convenir avec vous d'un calendrier de
correction. Nous pratiquons la **divulgation coordonnée** et vous créditerons (sauf si vous préférez
rester anonyme) une fois le correctif publié.

## Ce qui est dans le périmètre

Un bug de sécurité dans Plume est tout ce qui rompt le scellement du chemin de lecture, échappe à une
frontière d'isolation, ou fait fuir des secrets. En particulier :

- **Contournement du masquage / de `soql_field`** — tout chemin de requête qui rend en clair une colonne
  masquée (empreintes de mots de passe, empreintes de jetons, secrets), ou qui atteint les lignes brutes
  avant que le point de passage `soql_field`/`soql_filter_field` n'applique le masquage.
- **Exposition du SQL brut** — un appelant non privilégié (non admin) qui atteint une surface de SQL
  brut, ou un chemin de SQL brut qui échappe au DENY de l'autorisateur SQLite sur les colonnes protégées
  (par ex. lire `user.hash` / `token.token_hash`, même en admin).
- **Contournement du RBAC / de l'autorisateur** — un `editor` (ou moins) qui atteint une route de
  mutation réservée à l'admin (réinitialisation de mot de passe, mode/ban/kill, armement de playbook), ou
  une ouverture par défaut (fail-open) dans la porte RBAC.
- **Rupture de l'isolation des tenants** — lire les événements, constats ou secrets d'un autre tenant en
  mode multi-tenant (`PLUME_MULTI_TENANT`), y compris par la surface GXQL ou une clé partagée.
- **Fuite de secrets** — clés de base, identifiants de session, clés d'API ou de connecteur, ou secrets
  SSO qui s'échappent dans un événement, un agrégat, un rapport, une ligne de journal ou une réponse
  d'API.
- **AuthN/AuthZ** — contournement de l'authentification, élévation de privilèges, IDOR inter-tenants.
- **Injection / RCE** dans le daemon (SQL, traversée de chemin, désérialisation, bombes de
  décompression sur les chemins ingest/OTLP, exécution de commandes).

## Ce qui n'est PAS une vulnérabilité

- **Faire tourner Plume contre une infrastructure qui ne vous appartient pas ou que vous n'êtes pas
  autorisé à surveiller.** C'est la responsabilité de l'exploitant, pas une faille de Plume.
- **Les compromis de durcissement du déploiement que Plume documente explicitement**, avec la mitigation
  opt-in qui les ferme (la documentation énonce le compromis là où il s'applique). N'en signalez un que
  si vous pouvez **mettre en échec la mitigation documentée** ou montrer un impact *nouveau* au-delà de
  ce qui est énoncé.

## Versions prises en charge

Plume est en pré-1.0 et n'a **encore aucune version étiquetée**. Les correctifs de sécurité arrivent
sur `main`, qui est la seule chose maintenue : citez donc un commit de `main` dans votre signalement.

| Version | Prise en charge |
|---------|-----------|
| `main` | ✅ |
| versions étiquetées | aucune n'existe encore |

Cette section nommera les versions prises en charge une fois que des étiquettes existeront — pas avant.
Annoncer une prise en charge par version alors qu'aucune version n'existe serait une fausse promesse, et
enverrait un auteur de signalement chercher un numéro de version qu'il ne peut pas trouver.

## Durcissement et audits

Plume livre un modèle de sécurité documenté et une chaîne de CI qui exécute `cargo audit` et la
recherche de secrets. Les contrôles centraux — le compilateur GXQL fermé, le masquage des champs comme
point de passage unique, la porte RBAC fail-closed + l'autorisateur SQLite DENY, l'isolation
cryptographique par tenant, et le cloisonnement par features mode-0 byte-identique — sont couverts par
des tests et ont fait l'objet d'une revue adversariale.
