# Feuille de route de plume

plume est un SOC/XDR écrit en Rust, conçu pour tenir dans un budget mémoire de **2 Gio**. Ce
document est l'**index public des chantiers**, pas un journal de développement : chaque ligne dit ce
qu'une clé désigne, dans quel état elle se trouve, et rien de plus. Les messages de commit de ce
dépôt citent ces clés ; l'index existe pour qu'un lecteur puisse retrouver à quoi une clé correspond.
Ce n'est **ni** une liste de fonctionnalités, **ni** un calendrier, **ni** un argumentaire, et il ne
contient aucune mesure prise sur une installation particulière : les chiffres qui restent sont des
propriétés du code (nombre de routes, d'index déclarés, de sondes), jamais l'état d'une machine. Les
limites connues sont nommées, y compris quand elles sont gênantes.

## Comment lire

**La clé** — P*phase*.*chantier*-*constat*, par exemple P10.14-a. Une clé est **stable** : une fois
attribuée elle ne bouge plus, et elle se cite du constat jusqu'au commit. Les numéros de phase de cet
index sont ceux de l'audit interne ; ils ne coïncident pas avec les phases produit du cahier des
charges, où P10 désigne un tout autre sujet.

| État | Signification |
|---|---|
| ✅ | corrigé et vérifié |
| 🔵 | mesuré, décision prise, **pas encore construit** |
| ⬜ | ouvert |
| 🔒 | bloqué : le geste appartient à l'exploitant |
| ❓ | numéro réservé, sans constat attesté |

Une clé peut désigner un **thème** dont plusieurs constats relèvent ; l'index en donne alors une
ligne unique et nomme le résidu dans la phrase. Quelques clés couvrent l'outillage de déploiement,
qui vit hors de ce dépôt ; elles sont conservées parce que des commits les citent. Une clé sans
rapport avec le produit n'est pas listée.

---

## P3 — Ingestion, déduplication, sondes de fraîcheur

| Clé | Périmètre | État | Ce que la clé désigne |
|---|---|---|---|
| **P3.1-a** | Déduplication | ✅ | La clé de déduplication était fabriquée par l'émetteur, qui ne voit que lui-même : deux machines faisant le même travail produisaient la même clé et la seconde ligne était rejetée sans un mot. La clé porte désormais l'hôte. |
| **P3.2-a** | Sondes de fraîcheur | ⬜ | Vingt sondes d'événements et une sonde de métriques gardent une portée « tous hôtes confondus » : un parc dont une seule machine parle encore peut être vu comme sain. Dette déclarée, ancrée par un test qui exige que le compte baisse et ne monte jamais en silence. |
| **P3.6-a** | Ingestion Loki | ✅ | Deux documents promettaient une déduplication exactly-once que cette surface ne tient pas. La garantie réelle est at-least-once, et les documents le disent — aucune clé dérivée du contenu n'a été inventée, elle transformerait un doublon visible en perte invisible. |
| **P3.6-b** | Ingestion Loki | ✅ | Cette route insérait directement en base : les processeurs d'ingestion (rejet, masquage de données personnelles, routage) ne s'y appliquaient pas, alors que le code affirmait le contraire en la nommant. |
| **P3.6-c** | Garde d'ingestion | ✅ | La garde voisine ne se déclenchait que si l'ordre SQL mentionnait la déduplication : elle contrôlait la **forme** de la clé, jamais la **présence** du mécanisme. Fermée par le répertoire — tout chemin d'ingestion qui écrit sans passer par le point d'extension échoue. |
| **P3.7-a** | Coût des sondes | ✅ | Le type des sondes figeait la table et la colonne, jamais le **coût** : plusieurs sondes filtraient sur une colonne non indexée, en O(N), sous le verrou d'écriture, à cadence courte. Fermé par un index partiel. Reste ouvert : l'ablation en débit, qui établirait que ce coût était le contributeur dominant, n'est pas faite. |

---

## P4 — Exploitation : CLI, service, collecteurs, plafonds

| Clé | Périmètre | État | Ce que la clé désigne |
|---|---|---|---|
| **P4.1-a** | Collecteur Windows | ✅ | Le tampon était vidé inconditionnellement et le filigrane avancé **avant** l'envoi : une indisponibilité du central perdait définitivement et silencieusement les événements du cycle. |
| **P4.1-b** | CLI | ✅ | L'option d'aide n'imprimait pas que l'aide : elle migrait la base, imprimait un jeton d'installation à usage unique, puis se mettait à écouter. La garde est le complément calculé du flot de contrôle, donc une sous-commande future est couverte sans y penser. |
| **P4.1-c** | Observabilité HTTP | ✅ | Une réponse 5xx ne laissait rien côté serveur : ni couche de trace, ni journal d'accès, ni identifiant de requête. La condition porte sur la classe du code, pas sur une liste. |
| **P4.1-d** | Build Windows | ✅ | La bibliothèque C statique n'était que **documentée** ; sur un Windows sans redistribuable, l'exécutable s'arrêtait avant sa première instruction. |
| **P4.1-e** | Surveillance des capteurs | ✅ | Des capteurs qui n'avaient jamais rien émis étaient déclarés muets par une surface et « inconnus » par une autre : deux verdicts pour la même observation, avec un écart de seuil accidentel et écrit nulle part. |
| **P4.1-f** | Désinstallation | ✅ | La commande de désinstallation annonçait un succès qu'elle n'avait pas obtenu, avec un code de sortie nul et zéro fichier supprimé. Le type de résultat ne permet plus de conclure sans dire ce qui a été retiré. |
| **P4.1-g** … **P4.1-n** | — | ❓ | Lettres réservées : aucun constat ne les porte dans ce dépôt. Le trou n'est pas comblé par déduction. |
| **P4.1-o** | Plafonds d'ingestion | ✅ | Deux plafonds gardaient le même chemin, et c'est **celui qui ne parle pas** qui mordait en premier : le plafond d'octets rendait inatteignable le plafond en nombre d'événements, dont le message était pourtant le seul à nommer compte, limite et levier. |
| **P4.1-p** | Plafonds d'ingestion | ✅ | Trois défauts de la même famille : une route accusait réception de ce qu'elle avait **retenu** et non reçu ; trois sites de rejet ne comptaient rien, et le seul compteur existant nommait mal ce qu'il comptait ; un refus conseillait un levier sans effet dans la configuration par défaut. Le verdict est désormais dérivé de la comparaison des plafonds, donc changer une constante change le message. |
| **P4.2-a** | Service systemd | ✅ | L'installation annonçait « service installé et démarré » et sortait 0 sur un service **mort**. La garde observe une durée d'activité, un instantané pouvant dire « actif » juste avant l'échec. |
| **P4.2-b** | Build et messages d'erreur | ✅ | Un échec de compilation croisée ne nommait pas le paquet manquant, et un échec TLS sur certificat auto-signé était classé comme une erreur d'entrée-sortie sans son remède. Les remèdes ont été exécutés avant d'être écrits ; l'un était faux et n'est donc pas conseillé. |
| **P4.3-a** | Collecteur Windows | ✅ | En accès refusé sur le journal de sécurité, le collecteur rendait zéro événement, zéro aveu et un code de sortie nul, pendant que son battement de santé annonçait « ok ». Le discriminant retenu est l'identifiant d'erreur, jamais le message, qui est localisé. |

### P4.4 — Porte de déploiement

Ces clés couvrent l'outillage qui décide qu'un déploiement est sain. Il vit hors de ce dépôt ; les
constats sont conservés ici parce que des commits les citent et parce que les défauts sont
génériques.

| Clé | Périmètre | État | Ce que la clé désigne |
|---|---|---|---|
| **P4.4-a** | Porte de déploiement | ✅ | La porte interrogeait la **santé** du service et jamais l'**identité** de ce qui sert : toutes ses conditions restaient vraies sur la version précédente, donc elle ne pouvait pas échouer tant que l'ancien processus vivait. Le premier correctif a lui-même désactivé en silence le contrôle de schéma — corrigé à son tour, la garde qui cesse de mordre étant la même famille de défaut. |
| **P4.4-b** | Porte de déploiement | ✅ | Le script poussait le changement puis rendait un verdict sans jamais constater que l'orchestrateur avait vu et appliqué la nouvelle révision. |
| **P4.4-c** | Retour arrière | ✅ | La porte promettait un retour arrière automatique qu'elle ne pouvait pas tenir : une base déjà migrée est refusée par le binaire précédent. La porte est désormais à **sens unique** quand le schéma monte, le dit, et exige un acquittement explicite. Reste : la table de décision est prouvée par un harnais jetable, pas par une garde permanente. |
| **P4.4-d** | Dérive dépôt / production | ✅ | Un changement de build livré mais jamais construit n'a été crié par personne : la porte vérifie l'identité **au moment** du déploiement, rien ne regardait l'écart entre deux déploiements. |
| **P4.4-e** | Porte de déploiement | ✅ | Le script annonçait un échec après avoir réussi et sautait son propre filet : une étape devenue sans objet rend un code non nul, ce qui court-circuitait la porte de santé et laissait le retour arrière non armé. |
| **P4.4-f** | Fraîcheur de la référence | ✅ | La référence annoncée désignait une copie de travail et non le dépôt de vérité, et la mesure avait lieu avant tout rafraîchissement : un commit poussé pouvait être invisible, le script concluant « rien à construire » puis « succès ». Aucune phrase n'était fausse isolément ; l'ensemble décrivait un état périmé et l'appelait un succès. |
| **P4.4-g** | Sonde de dérive | ✅ | La sonde de dérive était elle-même dérivée : installée une fois, jamais réinstallée après modification. Le périmètre vient désormais d'une table unique, et l'installé est comparé au **rendu**, la plupart des fichiers surveillés étant engendrés et n'ayant aucune source à comparer. |
| **P4.4-h** | Fraîcheur de la référence | ✅ | La fraîcheur de la copie de travail reposait sur un mécanisme absent de tout dépôt, désactivable, et muet quand il refuse. Les seuls fichiers dont le rendu dépend sont désormais certifiés contre le dépôt de vérité, et une comparaison non certifiée est **sautée** plutôt que faussée. |
| **P4.4-i** | Pose de configuration | ✅ | Un fichier de configuration posé sur un hôte avait divergé de sa version au dépôt sans que rien ne le rapporte. L'écart était inerte, mais il établissait que la version du dépôt était une reconstruction jamais confrontée aux octets vivants. |
| **P4.4-j** | Banc de test | ✅ | Un banc qui **exécute** le geste de réparation imprimé par une table exécute ce que la table nomme : une mutation lui a fait lancer un installateur système. Le geste imprimé est désormais confiné avant exécution, sans affaiblir la détection. |
| **P4.4-k** | Porte de déploiement | ✅ | La porte sondait la seule route que les sondes d'orchestration évitent délibérément, parce qu'elle prend un verrou bloquant. Le défaut n'est pas le délai mais l'ambiguïté : « ne répond pas » et « écrivain occupé » rendaient la même phrase. Une phrase les départage désormais, aux deux sites. |

### P4.5 — Ce que l'image contient vraiment

| Clé | Périmètre | État | Ce que la clé désigne |
|---|---|---|---|
| **P4.5-a** | Image et fonctionnalités | ✅ | Une consolidation a retiré le tier froid de l'image, en silence : le déploiement déclarait cinq variables que le binaire ne pouvait pas honorer. |
| **P4.5-b** | Garde d'image | ✅ | La garde comparait des **commits** et non des **capacités** : deux recettes de build pouvaient différer d'un jeu de fonctionnalités sans que rien ne le voie. La garde est désormais dérivée du manifeste jusqu'au symbole présent dans le binaire, et elle accuse l'instrument plutôt que l'image quand son témoin positif tombe. |

---

## P5 — Taxonomie, autorité, portée d'un jeton

| Clé | Périmètre | État | Ce que la clé désigne |
|---|---|---|---|
| **P5.1-a** | Détection | ✅ | Les deux règles de force brute livrées et activées compilent un filtre sur un champ d'action qu'aucun émetteur Windows ne posait : la technique était aveugle sur l'OS où elle est la plus courante. |
| **P5.1-b** | Taxonomie | ✅ | Le contrôle de taxonomie sortait avant tout contrôle sur une catégorie vide, au motif écrit dans le code que le parseur trancherait — ce qu'aucun parseur livré ne faisait pour ces sources. Des événements sans catégorie étaient acceptés, stockés, sans une ligne de journal. Aucune valeur d'office n'a été inventée : c'est le silence qui est fermé. |
| **P5.2-a** | Portée des jetons | ✅ | Le liage « un jeton de machine n'écrit que sous son hôte » existait à trois exemplaires écrits séparément et manquait sur quatre surfaces d'ingestion, alors que la documentation n'annonçait qu'une exception. |
| **P5.2-b** | Portée des jetons | ✅ | La forme la plus courte de la commande de création de jeton — celle de la documentation — produisait un jeton **non lié**, capable d'écrire sous n'importe quel nom d'hôte. La portée est désormais une somme fermée que le compilateur impose, et le point d'écriture est unique pour la CLI comme pour l'interface. |
| **P5.3-a** | Autorité HTTP | ✅ | Le garde d'hôte ne lisait que l'en-tête Host, qui n'existe pas en HTTP/2 où l'autorité est un pseudo-en-tête ; l'absence était traduite en refus. En TLS natif, la quasi-totalité des routes était injoignable depuis un navigateur, tous les émetteurs internes étant en HTTP/1.1. |
| **P5.4-a** | Collecte Windows | ✅ | Les identifiants Kerberos manquaient à la liste du collecteur : une cécité que seul un contrôleur de domaine révèle. La liste est désormais dérivée d'une table identifiant → issue, et chaque exécution recense ce que le canal produit et qu'on ne collecte pas. |
| **P5.4-b** | Collecte Windows | ✅ | Une catégorie d'exécution sans ligne de commande n'est pas vide, elle est **trompeuse** : un tableau de bord voit un chiffre non nul et stable et ne surveille rien. Le collecteur déclare désormais l'amputation ; aucune valeur n'est fabriquée. |
| **P5.5-a** | Secrets | ✅ | Le secret passait par la ligne de commande : les arguments d'un processus sont publics, et le capteur de journal les expédiait au SOC que ce secret protège. Non fermable côté produit — l'audit d'exécution du système capte ce qu'un opérateur tape. |
| **P5.5-b** | Confidentialité de la collecte | ✅ | Trente-deux champs de journal système étaient expédiés alors que neuf sont lus, dont la ligne de commande complète de l'émetteur, sur le réseau et dans le tampon disque. La restriction est sondée dans les deux sens et son absence **dégrade en le disant**. |
| **P5.6** | — | ❓ | Numéro réservé : aucun constat ne le porte. |
| **P5.7-a** | Règles semées | ✅ | Une règle semée, activée et taguée d'une technique ATT&CK portait une requête qui ne contraignait que la sévérité : la technique était annoncée **couverte** alors que rien n'observait l'authentification. La migration ne corrige que les règles restées à leur forme livrée, jamais celles qu'un exploitant a éditées. |
| **P5.7-b** | Auto-surveillance | 🔵 | Le collecteur d'intégrité surveille le répertoire d'unités système, et une règle livrée y voit un vecteur de persistance : toute mise à jour de plume lève une alerte sur le SOC lui-même. Aucune exemption par nom n'est faite — elle offrirait un angle mort taillé sur mesure. Ce qui est fermé, c'est la croissance silencieuse du nombre d'unités livrées. |
| **P5.8-a** | Privilèges d'exploitation | 🔵🔒 | Une entrée sudo « bornée » ne vaut pas mieux qu'un octroi total tant que le code élevé appartient à l'utilisateur qui l'invoque : sudo résout le chemin à l'exécution, posséder le répertoire suffit. Le vrai obstacle est la **propriété du code élevé**, pas une ligne de configuration. Garde dérivée, filet et procédure sont livrés ; le geste appartient à l'exploitant. |

---

## P6 — Mémoire, performance, indexation

| Clé | Périmètre | État | Ce que la clé désigne |
|---|---|---|---|
| **P6.1-a** | Diagnostic mémoire | ✅ | Un indicateur de « prise sous swap » était dérivé du swap **système** alors que le service tourne avec le swap interdit : il mesurait les autres processus de la machine et marquait des relevés parfaitement sains. |
| **P6.1-b** | Budget mémoire | ✅ | Le budget mémoire était **publié** et rien ne l'imposait : le paramètre invoqué ne borne que le cache de pages, et le trieur n'a aucun budget. Fermé par une limite de tas dérivée du budget publié, qui vit dans l'allocateur : une agrégation trop large reçoit un refus explicite au lieu de tuer le processus. |
| **P6.2-a** | Généralité des mesures | ✅ | Un chiffre mesuré sur un profil prouve ce profil. La matrice rejouée montre que le nom des sources, le nom des champs, la taille d'événement, la cardinalité et le nombre d'hôtes déplacent les résultats de plusieurs ordres de grandeur — et que la distribution de sévérité, elle, ne les déplace pas. |
| **P6.8-a** | Index adaptatif | ✅ | Un champ indexé à chaud n'est pas compilé comme un champ chaud : comparé à un nombre, la requête porte une conversion que l'index d'expression ne peut pas apparier, et le plan dégénère de recherche en balayage. |
| **P6.8-b** | Index adaptatif | ✅ | Rien dans l'interface ne disait si l'indexation adaptative était active ni quels champs avaient été indexés. Mesuré avec contrôle positif, le mécanisme était actif et n'indexait rien : il a été retiré, une frontière de crate rendant sa chaîne de comptage morte pour toujours. |
| **P6.8-c** | Index et détection | ✅ | Le retrait de l'indexation adaptative a supprimé en fond trois index orphelins, dont deux servaient de la détection **active**. L'erreur n'est pas d'avoir mal mesuré : c'est d'avoir agi comme si un trou nommé était comblé. Deux champs entrent dans la liste chaude, la divergence entre crates devient inexprimable, et le troisième n'est pas restauré (aucun usage livré, cardinalité de 1). Reste à confirmer sur une base réelle que les index correspondants sont bien créés. |

---

## P7 — Hygiène, chaîne d'approvisionnement, surface d'autorisation

| Clé | Périmètre | État | Ce que la clé désigne |
|---|---|---|---|
| **P7.1-a** | Hygiène des tests | ✅ | Les fixtures nettoyaient en **énumérant** le chemin qu'elles avaient nommé, alors que SQLite en crée deux autres à côté. Le correctif possède le contenant et l'efface entièrement, donc y compris sur panique ; une garde de compilation a trouvé les sites que la conversion par motif avait manqués. |
| **P7.3-b** | Export | ✅ | L'export ne reprenait pas la sonde de plafond des agrégats et sortait « non tronqué » alors que le plafond avait mordu ; puis, une fois téléchargé, rien dans le fichier ne l'avouait. La marque est portée par le **nom** du fichier, le corps CSV et le tableau JSON servant des consommateurs qu'une enveloppe casserait. |
| **P7.3-c** | Export | ✅ | La marque de troncature ne disait pas l'**ampleur**. Elle porte désormais le nombre de lignes manquantes, ou « ampleur inconnue » quand la sonde ne l'a pas établi — jamais un repli sur zéro. |
| **P7.4-a** | Tier froid | ✅ | **Réfuté** : le constat annonçait des tranches froides antérieures à une migration qui ne touche pas le tier froid. Le format et la disposition des colonnes sont figés depuis l'origine ; une telle tranche ne peut pas exister. |
| **P7.5-a** | Avertissements de compilation | ✅ | La nature des avertissements résiduels était mal énoncée ; le seul qui signalait vraiment quelque chose a ouvert son propre constat, ci-dessous. Le décompte n'a pas été revérifié depuis. |
| **P7.7-b** | Chaîne d'approvisionnement | ✅ | Le contrôle de licences, de bans et de sources ne couvrait qu'un crate sur quatre — pas celui qui est installé sur les postes clients. La liste est désormais dérivée des manifestes trouvés, avec une garde d'instrument si la découverte en rend moins que prévu. |
| **P7.8-a** | Observabilité des requêtes | ✅ | Le constat annonçait **dix-neuf** routes sans métrique de latence, en avouant que le décompte n'avait pas été refait. **Refait le 2026-08-20 par dérivation depuis la source : dix-huit sites d'acquisition, qui servent vingt et un gabarits de route** — quatre sites vivent dans des fonctions d'aide partagées, d'où l'écart entre les deux nombres. Le sémaphore borne la ressource la plus contrainte du projet ; il est désormais mesuré **au point de passage unique** qui le délivre, donc sans une ligne de mesure dans aucune route, et une route ajoutée demain est comptée sans qu'on y pense. Deux grandeurs **séparées**, parce qu'un total les confond et désigne le mauvais levier : l'**attente** du permit (la file) et le **travail** permit en main. La **saturation** est publiée (acquisitions ayant dû attendre, permis détenus, taille de la borne). Cardinalité **bornée deux fois** — l'étiquette est le *gabarit* de route et jamais l'URL, et le registre est plafonné : au pire quarante-neuf valeurs d'étiquette, six séries chacune. Gardes dérivées prouvées par mutation : une acquisition hors du point de passage et un permit nu hors du module qui mesure sa détention sont refusés, en **nommant le site fautif**. Au passage, la garde d'origine a été **réfutée** : elle exigeait le nom du sémaphore et le mot « acquire » sur la MÊME ligne, et laissait donc passer la même acquisition écrite en deux lignes. |
| **P7.9-a** | SQL brut | ✅ | Un chemin acceptait du SQL brut sans trace là où son jumeau le refuse avec commentaire, audit et test. La décision est désormais **déclarée** et tracée au registre d'audit aux deux sites, et la documentation ne prétend plus l'uniformité que le code contredisait. |
| **P7.13-a** | SQL brut et autorisation | ✅ | La porte « SQL brut réservé aux administrateurs » tenait à l'**écriture** mais pas au **choix de ce qui s'exécute** : un compte éditeur pouvait faire exécuter un panneau d'administrateur et lire des lignes de la table des utilisateurs, puis figer le résultat dans un instantané partageable. Borne vérifiée : l'autorizer SQLite refuse les colonnes de secrets même à un administrateur. |
| **P7.14-a** | Pagination keyset | ✅ | Un commentaire promettait un repli silencieux quand la compilation d'une pagination par curseur échoue. Le drapeau correspondant n'était jamais consulté, le curseur restait armé sur un SQL de repli, et la requête produisait l'erreur que la phrase excluait. |
| **P7.15-a** | Provenance affichée | ✅ | Un panneau déclarait une provenance dont la moitié est une fonction jamais appelée : l'exploitant croyait lire un état d'indexation à l'exécution, il lisait une constante figée à la compilation. Une provenance fausse est pire qu'absente — elle fait cesser de chercher. |
| **P7.16-a** *(clé neuve)* | Ban natif : câblage | ✅ | Le ban d'une adresse est une promesse de **composition** — « toutes les routes d'un coup » tient à une couche du routeur, pas aux fonctions qu'elle appelle. Or toutes ses gardes étaient prouvées à la couture, sur des fonctions pures et des chemins choisis à la main : en retirant la couche, la suite entière restait verte. Une garde **dérivée** de la table de routage interroge désormais chaque route déclarée — plus les chemins servis par la fallback — à travers le routeur réel ; sous la même mutation elle en nomme 328 (route, méthode). Le verdict porte sur ce que la couche **écrit**, pas sur son code : une route d'ingestion rend le même 403 pour une clé de livraison invalide, et c'est le témoin négatif qui l'a montré. Les exemptions — sondes d'orchestrateur, valve de récupération — sont déclarées, justifiées, et vérifiées dans les deux sens. |
| **P7.16-b** *(clé neuve)* | Ban natif : borne mémoire | ✅ | La banlist vivante était une structure en mémoire **sans plafond**, alimentée entre autres par un chemin d'auto-ban optionnel : la croissance devenait pilotable par l'attaquant, à raison d'une entrée par adresse source. Elle est désormais bornée aux deux bouts — lignes lues et entrées construites — avec l'ordre de priorité de l'**enforcement** (bans permanents d'abord, puis les échéances les plus lointaines, départage stable). Au plafond, la pose est **refusée** avec un code explicite plutôt qu'enregistrée sans rien bloquer, et la saturation est publiée en métrique : une borne qui ne se dit pas est indistinguable d'une borne absente. |
| **P7.2 · P7.6 · P7.10 · P7.11 · P7.12** | — | ❓ | Numéros réservés : aucun constat ne les porte. |

---

## P8 — Chaîne de livraison : sauvegarde, restauration, gardes de dépôt

| Clé | Périmètre | État | Ce que la clé désigne |
|---|---|---|---|
| **P8.2-a** | Gardes de dépôt | ✅ | Les dépôts nus n'avaient que des hooks de **post**-réception, qui journalisent et ne peuvent rien refuser — et la ligne imprimée au push ressemblait à une garde ayant laissé passer. Une règle de pré-réception dérivée d'une partition fermée protège tout sauf ce qui est déclaré jetable, avec une sortie de secours auditable exigeant un motif. |
| **P8.2-b** | — | ❓ | Numéro réservé : aucun constat ne le porte. |
| **P8.3-a** | Restauration | ✅ | La vérification automatisée annonçait « déchiffre et ouvre la base » ; elle restaurait vers une base jetable qu'elle **n'ouvrait jamais**. Une archive parfaitement chiffrée, parfaitement rejouée, et **VIDE**, en sortait verte — mesuré par mutation : la garde retirée, la vérification rend `full_decrypt_verified` sur une archive à **0 ligne**. Elle rouvre désormais la base restaurée avec sa clé et en **compte le contenu** (tables dérivées du schéma, jamais énumérées) ; une restauration sans une seule ligne est un ÉCHEC. Reste hors de portée **délibérément** : le mode d'escrow, dont l'identité privée ne doit vivre ni près des sauvegardes, ni dans un test, ni dans l'intégration continue — l'exercice y est donc **hors ligne**, et c'est son ABSENCE qui était invisible. Une vérification complète réussie émet une **attestation** (une ligne de faits, aucun secret) que le nœud enregistre ; l'état daté qui en découle **vieillit**, se lit dans la santé par composant, dans `plume_restore_drill_overdue` et dans un événement SOC non purgeable, et refuse de compter un exercice mené sur le chemin symétrique pour une installation qui séquestre en asymétrique. Ce qu'il ne prouve pas, écrit pour être opposable : il défend contre l'oubli, pas contre une attestation recopiée à la main. |
| **P8.4-a** | Sauvegarde | ✅ | Un ratio de compression publié sans date. La chaîne incriminée avait déjà disparu du code ; ce qui restait vrai est l'écart entre l'archive et le fichier de base, qui se lit comme une perte de données si personne n'explique que la charge est un export **logique** — sans contenu d'index, sans tables d'index plein texte, sans pages libres, tous reconstruits à la restauration. Aucun ratio de référence n'est gravé dans le binaire : il dépend de la composition de chaque installation. |
| **P8.5-a** | Compteurs de tests | ✅ | La garde de compteurs de tests s'exécutait bien à chaque envoi ; ce qui manquait est la **boucle de retour** — son verdict s'affiche sur une page qu'on n'ouvre pas au moment de commiter. Un contrôle local énumère les tests, sans les exécuter, en quelques secondes. Il ne prouve pas qu'ils passent, et il le dit. |
| **P8.5-b** | Compteurs de tests | ✅ | La garde confondait deux mots français par une classe de caractères trop permissive et lisait des « passes » de fusion comme des tests « passés » : l'intégration continue publique était rouge. Témoins des deux sens ajoutés. |
| **P8.6-a** | Tests et mémoire | ✅ | Un test assertait sur la mémoire résidente du **processus** depuis une suite parallèle : vert ici, rouge là. Remplacé par une preuve par construction — un allocateur de test qui tient, par fil, l'écart entre alloué et libéré et son maximum — et par une invariance en volume à largeur constante, qui ne peut ni rater un pic ni voir celui d'un voisin. |
| **P8.6-b** | Sauvegarde et dérivation de clé | ✅ | La dérivation de clé de l'archive s'étalonnait au chronomètre à chaque sauvegarde, avec un coût mémoire dépendant du profil de compilation, et pouvait réserver une part importante du budget. Le plafond de **lecture**, recalculé sur la machine qui déchiffre, rendait en outre la restaurabilité dépendante de cette machine. Facteur fixé, borne de lecture fixe, réglage exposé pour qui utilise une véritable phrase de passe humaine. |
| **P8.7-a** | Configuration | ✅ | Sur le déploiement natif systemd, l'ordonnanceur lisait le fichier de configuration pour trouver la base mais ignorait le destinataire de séquestre écrit deux lignes plus bas : la grande majorité des variables n'étaient lisibles que depuis l'environnement. Router ces lectures est un sur-ensemble strict, jamais une bascule ; l'alternative par fichier d'environnement a été **rejetée** parce qu'elle exporterait des secrets dans l'environnement du processus. Un registre de dette ne peut plus que rétrécir. |
| **P8.7-b** | Chiffrement au repos | ✅ | Une clé écrite dans le fichier de configuration chiffrait le tier froid et laissait la base chaude **en clair**, sans un mot : deux voies de lecture distinctes pour la même clé. Voie unique désormais, fail-closed conservé, bascule annoncée au démarrage — et aucune valeur n'est jamais journalisée. |
| **P8.8-a** | Configuration hors dépôt | 🔒 | Un collecteur d'hôte tire à cadence courte contre des cibles qui n'existent plus, et il le **dit** : le défaut est dans la boucle de retour, pas dans l'instrument. Non corrigé délibérément — sa configuration vit hors de tout contrôle de version, et c'est cela le vrai défaut. |
| **P8.9-a** | Tenue de l'index | ✅ | L'index se trompait sur ses entrées les plus coûteuses, closes et déployées depuis deux jours. Cause structurelle : sans la clé dans le message de commit, aucune vérification ne peut relier un correctif à sa ligne. Le remède est en amont — citer la clé — et non une garde qui ne mordrait que sur les clés déjà citées, c'est-à-dire précisément pas sur celles qui dérivent. |
| **P8.9-b** | Tenue de l'index | ✅ | Le document pouvait se contredire sans que rien ne le dise : une clé réutilisée pour deux constats sans rapport, et une ligne périmée en double. La règle « une clé, une ligne » a été **mesurée fausse** — plusieurs clés nomment légitimement un thème. La règle retenue est celle que le document se donne à lui-même : une ligne qui se déclare neuve doit être la seule définition de sa clé. |
| **P8.10-a** | Reprise après sinistre | ✅ | Une reprise ne savait pas distinguer un échange de fichiers interrompu d'une copie de base périmée : son marqueur était l'existence d'un fichier, qui n'a pas de durée de vie. Le témoin est dérivé de la séquence d'échange, et le conteneur **refuse de démarrer** plutôt que de choisir à la place de l'humain entre « périmé » et « vide ». |
| **P8.11-a** | Déploiement piloté par dépôt | ✅ | Dans un déploiement piloté par dépôt, modifier un manifeste surveillé **est** un déploiement. Un hook de pré-envoi refuse désormais un envoi qui touche ces chemins sans se déclarer ; le périmètre est dérivé des applications déclarées, pas d'une énumération. Limite assumée : la configuration de hooks est locale à un clone, donc à réinstaller après clonage. |
| **P8.12-a** | Verrou de déploiement | ✅ | Un fichier de verrou persistant prend le propriétaire du premier qui l'a créé : une seule exécution privilégiée rendait la voie non privilégiée définitivement inaccessible. Le remède **préserve l'inode** au lieu de supprimer le nom — le verrou porte sur l'inode ouvert, supprimer ne libère rien et ferait croire à un lancement qu'il est seul. |
| **P8.13-a** | Démarrage et volume | ✅ | « Volume neuf » se déduisait de la seule absence du fichier de base : un démon pouvait repartir sur une base **vide**, en silence. Pour un SOC, perdre l'historique sans un mot est pire que ne pas démarrer. Le critère est dérivé de l'état complet du volume, tout résidu prouvant qu'il a servi. |
| **P8.14-a** | Communication publique | ✅ | Une garde automatique confrontant les technologies annoncées publiquement à celles qui tournent réellement a été **refusée**, avec sa raison : une page de présentation a le droit de simplifier, et un automate qui la surveillerait ajouterait une dépendance et une surface d'attaque pour un gain rédactionnel. La correction ponctuelle est faite ; le contrôle reste humain, à la relecture. Écrit pour que la garde ne soit pas reproposée comme un manque. |
| **P8.15-a** | Historique public | ✅ | L'historique et les documents publiés s'adressaient à un lecteur interne et portaient une identité personnelle. Messages réécrits à la voix impersonnelle en conservant mesure, réfutation et clé ; identité de projet posée ; deux gardes versionnées refusent une identité non canonique et les familles objectives de fuite. Le **style** n'est pas mécanisé — une garde qui prétendrait juger le ton ferait du bruit et finirait désarmée. INTEGRATION CONTINUE VERTE SUR LES DEUX DEPOTS, ce qui clot la campagne. SEPT causes distinctes l'en separaient, et aucune n'etait celle annoncee en premier : un verrou epingle sur une revision que la reecriture avait supprimee, avec des tags publies pointant sur des commits orphelins ; un outil d'audit incapable de lire un format d'avis recent, qui echouait AVANT de scanner et rendait donc sans effet les correctifs de vulnerabilite ; deux avis de dependance dont un inatteignable ; deux valeurs-temoins de test prises pour des secrets ; une course sur des reglages partages entre tests, intermittente donc lue comme un alea ; un marqueur de vocabulaire disparu d'un document refondu puis remis sans son accent ; et une garde qui se comptait elle-meme, protegee par un controle positif satisfait du meme faux positif. CINQ hypotheses ont ete REFUTEES par la mesure en cours de route, chaque fois pour moins cher que le correctif qu'elles auraient fait poser. RESTE, comme COUT et non comme defaut : le job de tier froid dure environ 45 minutes. |
| **P8.16-a** | Reecriture et consommateurs | ✅ | Reecrire l'historique d'une bibliotheque deplace tous ses SHA derriere des noms de tags inchanges. Deux consequences ont ete mesurees APRES coup, et c'est le defaut : le verrou du consommateur epinglait la revision par SHA et cargo echouait sur « revision not found », bloquant compilation, tests et tier froid ; et les tags publies, pousses AVANT deux reecritures ulterieures qui n'ont force-pousse que la branche par defaut, designaient des commits ORPHELINS hors de l'histoire publiee. REGLE : une reecriture repousse ses TAGS dans le meme geste, et tout consommateur epinglant un SHA est remis a jour dans la foulee. Correctif verifie par MUTATION : le job de verification par fonctionnalite est passe de ROUGE a VERT. |
| **P8.17-a** | Avis de securite des dependances  | ✅ | Deux avis remontes par l'audit de dependances, aucun lie a une modification du depot. h2 0.4.15 (RUSTSEC-2026-0258, avis du 2026-08-17) se corrige par un bump de patch vers 0.4.16. rkyv 0.7.46 (RUSTSEC-2026-0235) demande un SAUT MAJEUR vers 0.8.17, probablement via le parent du tier froid colonnaire : l'atteignabilite du correctif depend de ce parent, et se mesure avant d'agir. | FERMEE : h2 corrige par bump de patch, la crate etant transitive le verrou suffit. rkyv reste, correctif INATTEIGNABLE — son parent declare une dependance NORMALE compatible 0.7 seulement, et epingler la version corrigee echoue a la resolution ; surface NULLE par ailleurs, la fonctionnalite qui le tire n'etant activee par personne et l'arbre toutes fonctionnalites confondues ne rendant rien. L'ignore porte sa date et sa CONDITION DE LEVEE. Ce correctif ne pouvait a lui seul rendre le job vert : la cause etait le chargement de la base d'avis, traite par la cle suivante.
| **P8.18-a** | Outil et base d'audit non epingles | ✅ | PERIMETRE CORRIGE DEUX FOIS. Il a d'abord ete cantonne a un depot, puis elargi a tous : les DEUX cadrages etaient faux. Le job porte DEUX controles sous un seul nom, et ils echouent pour des raisons DIFFERENTES selon le depot — un nom de job qui recouvre deux controles rend son verdict illisible. L'audit de dependances n'atteint meme pas l'etape de scan : la base d'avis contient une entree en CVSS 4.0 que la version installee ne sait pas lire, et l'outil s'arrete sur une erreur d'analyse. Ce n'est ni une vulnerabilite ni une regression du code — c'est un outil non epingle qui derive de sa base. Ni l'outil ni la base ne sont epingles : l'outil est installe en derniere version publiee, la base est recuperee telle qu'elle est au moment du run. Un verdict de porte peut donc changer sans qu'une seule ligne du depot ait bouge — c'est la chaine d'approvisionnement de la GARDE elle-meme qui n'est pas tenue. Corollaire MESURE : un correctif de vulnerabilite et une entree d'ignore, tous deux justes, ne peuvent pas rendre ce job vert, puisqu'il echoue AVANT de lire la liste d'ignore. Correctif : epingler l'outil ET la revision de la base, et nommer les deux. | FERMEE par l'epinglage de l'outil en version capable de lire le format CVSS 4.0. TROIS CORRECTIONS AU CONSTAT : l'hypothese que le verrouillage des dependances de l'outil etait en cause est REFUTEE — c'est la VERSION ; un depot epinglait une version trop ancienne et echouait, l'autre n'epinglait RIEN et passait deja, son defaut etant l'absence d'epinglage et non l'echec ; et la base compte 59 entrees dans ce format, le defaut est donc systemique et croissant, pas lie a une advisory. On epingle l'OUTIL, dont on veut un comportement reproductible, PAS la base, dont on veut le contenu frais : l'epingler rendrait la porte aveugle a toute advisory posterieure. Verifie par mutation dans les deux sens, et par contre-epreuve : audite sans sa liste d'ignore, le depot enumere exactement les entrees qu'elle couvre.
| **P8.19-a** *(clé neuve)* | Secrets signales dans l'arbre et l'historique | ✅ | Le controle de fuites signale DEUX trouvailles sur 159 commits scannes, et il echoue depuis le premier run — elles PRECEDENT donc la reecriture des messages. La configuration du controle porte une liste d'exceptions pour des fixtures de test connues : soit ces deux trouvailles sont hors de cette liste et sont reelles, soit la liste a un trou. TANT QUE LES DEUX NE SONT PAS NOMMEES, AUCUNE DES DEUX HYPOTHESES NE VAUT — et l'outil n'etant pas disponible hors integration continue, il faut le journal du job ou une execution locale pour les designer. Priorite haute : depot public. | FERMEE. Les deux trouvailles sont des VALEURS-TEMOINS, tranchees sur le corps des fichiers et non sur leur chemin : une cle de banc employee uniquement sur des bases jetables que le banc fabrique lui-meme, et une chaine qu'un test de confidentialite insere PUIS asserte ABSENTE — c'est la sonde d'une garde. L'allowlist porte sur les deux VALEURS exactes, ligne a ligne : ni fichier, ni regle, ni chemin elargi, une liste trop large etant une garde desarmee. CORRECTION D'UNE MESURE : un premier scan local rendait 10 trouvailles au lieu de 2 ; l'ecart ne venait PAS d'une config differente mais du PERIMETRE — un scan local lit tous les depots distants par defaut, dont un depot interne anterieur a la publication. Rien de ces 8 supplementaires n'est publie. Preuve par mutation dans les deux sens, dont l'insertion de chaines ressemblant a de vrais jetons JUSTE A COTE des lignes allowlistees, toutes retrouvees.
| **P8.20-a** *(clé neuve)* | Reglages de sauvegarde partages entre tests | ✅ | Les reglages de sauvegarde sont relus dans l'environnement PROCESS-global a chaque sauvegarde, et les tests d'un meme binaire partagent ce processus. Des tests les mutaient pendant que d'autres les lisaient : l'un forcait un chemin d'ecriture chez son voisin, un autre faisait REFUSER sa sauvegarde. L'echec etait INTERMITTENT — 2 tirs sur 5 — et se lisait donc comme un alea alors qu'il nommait une course. Corrige par un verrou lecteurs/ecrivain qui n'exclut que la fenetre de mutation, et une garde de portee qui RESTAURE la valeur anterieure meme lorsqu'un test panique : les retraits ecrits en ligne droite etaient sautes par le deroulement de pile et laissaient le reglage en place pour tout le reste du binaire. Ferme par une garde DERIVEE des sources de production plutot que par quatre correctifs — elle a trouve un declencheur qu'une recherche par nom aurait manque. Verifiee par mutation dans les deux sens. |
| **P8.21-a** | Garde des temporaires qui se comptait elle-meme | ✅ | Le job nomme son repertoire temporaire avec le PREFIXE que cette garde recherche, et l'enumeration ne posait pas de profondeur minimale : la recherche rendait donc aussi le repertoire lui-meme, compte comme residu. La garde echouait sur un repertoire VIDE, a chaque execution. CE QUI L'A CACHE EST LE PLUS INSTRUCTIF : son propre CONTROLE POSITIF comptait les correspondances au lieu de chercher son temoin par son NOM, et se trouvait donc satisfait par le meme faux positif — l'instrument se validait a l'aide du defaut qu'il devait exclure, et son « controle positif : OK » ne prouvait rien. Le defaut est en outre reste invisible tant que des echecs anterieurs dans le meme job empechaient d'atteindre cette etape : CORRIGER UN DEFAUT EN REVELE UN AUTRE QUI ATTENDAIT DERRIERE. Corrige par une profondeur minimale sur les quatre enumerations et un controle positif qui exige SON temoin nomme ; verifie dans les deux sens. |
| **P8.22-a** *(clé neuve)* | Destination objet de la sauvegarde | ✅ | L'ordonnanceur de sauvegarde ne savait écrire que sur un système de fichiers : une destination objet était détectée et refusée, et l'orchestration hors du nœud restait à un outil externe. Elle est désormais tenue par le binaire, sous une fonctionnalité de compilation ÉTEINTE PAR DÉFAUT qui n'ajoute **aucune dépendance** — la signature de requête est de l'arithmétique HMAC-SHA256 et SHA-256, déjà présente, et le transport réutilise le client HTTP interne. Les deux bibliothèques candidates ont été MESURÉES avant d'être écartées (2026-08-19) : la trousse complète du fournisseur historique ajoutait 103 caisses au graphe, dont un outillage de compilation que ce dépôt déclare absent de l'hôte visé ; la bibliothèque tierce généraliste en ajoutait 44, dont une seconde pile HTTP et un second jeu de racines. CE QUI FAIT L'OBJET DU LOT n'est pas l'envoi, qui est banal, mais son VERDICT : un dépôt n'est annoncé que si le service a répondu favorablement ET qu'une relecture rend la même taille ; toute autre issue se lit « refusé » (le service a répondu non) ou « impossible » (aucun verdict), jamais succès, et l'archive locale est conservée. Les quatre portes par lesquelles un envoi raté aurait pu ressortir en succès sont exercées contre un service factice local, et la propriété est vérifiée par MUTATION : annoncer le dépôt dès la réponse favorable fait rougir trois tests. LIMITES NOMMÉES : pas de téléversement en plusieurs parties (donc un plafond par archive), pas de rétention côté dépôt distant (règle de cycle de vie du bucket), pas de restauration depuis l'objet, pas d'identifiants par rôle d'instance. |
| **P8.23-a** *(clé neuve)* | Cout d'execution de la suite du tier froid | ✅ | Le job d'integration continue du tier froid durait environ 45 minutes. L'HYPOTHESE DU CACHE DE COMPILATION EST REFUTEE : une compilation totale depuis un cible vide coute 279 s, quand l'EXECUTION des tests en coute 2393, soit 90 % du job — le cout n'etait pas dans le build. Cause reelle : les DEPENDANCES etaient baties sans optimisation, donc le decodage colonnaire, la compression et le moteur chiffre, exactement la ou cette suite passe son temps. Une derogation de profil appliquee aux seules dependances rend 2393 s -> 590 s, mesure en A/B sur le MEME arbre source, les deux verts, avec temoins verifiant que les caisses tierces recoivent l'optimisation et que le binaire de test n'en recoit AUCUNE. Ecartes sur mesure : ne pas rejouer les tests du job par defaut (au mieux 198 s sur 2393, et cela DETRUIRAIT l'assertion de compte que ce job existe pour porter) et le decoupage en tranches (multiplie les minutes sans reduire le travail). LES COMPTEURS SONT INCHANGES : c'est la preuve que la couverture l'est aussi. Ne rend rien plus rapide en production — le profil de livraison est intact. |

---

## P10 — Tenir sous 2 Gio : stockage, index, agrégation

| Clé | Périmètre | État | Ce que la clé désigne |
|---|---|---|---|
| **P10.1-a** | Confidentialité du tri | ✅ | Le déversement des tris sur disque était livré **inconditionnellement**. Il fait exister un plafond de tri, mais il l'obtient en écrivant des valeurs d'événement en clair hors de la base chiffrée : SQLCipher chiffre le fichier, pas les temporaires de SQLite. Le défaut est revenu en mémoire ; le déversement est un échange qui se prend **explicitement**. Reste ouvert : aucun quota ne borne la taille du déversement quand il est activé. |
| **P10.2-a** | Composition de la base | ✅ | Le produit devait tenir sous 2 Gio et ne savait pas dire ce qui remplit sa propre base ; l'outil rendait de surcroît un rapport de **zéros** quand la base était illisible, ce qui se lit « base vide » et non « lecture impossible ». Désormais fail-closed, classification dérivée du schéma, refus de publier si la comptabilité ne ferme pas, et ce qui n'est pas classé est imprimé. |
| **P10.2-b** · **P10.0** | — | ❓ | Numéros réservés ou cités sans définition ; aucun constat ne les porte. |
| **P10.2-c** | Schéma et démarrage | ✅ | Une tâche de fond supprimait deux index que le schéma **recréait à chaque ouverture de connexion d'écriture**, de façon synchrone avant l'ouverture du service : chaque démarrage les reconstruisait sur toute la table, la tâche les supprimait, le démarrage suivant recommençait. Ce qui rendait la boucle invisible est l'affirmation, écrite dans le code, que le schéma ne les déclarait plus. La garde lit les suppressions et vérifie qu'aucune n'est recréée. Volet jumeau : une liste de champs chauds dupliquée dans deux crates sans lien de compilation, dont la divergence est devenue inexprimable. |
| **P10.2-d** | Index inutiles | ✅ | Neuf index que le schéma posait sans qu'aucune requête en ait besoin — doublons exacts d'une contrainte et préfixes stricts —, établis avec l'instrument de SQLite lui-même et prouvés par mutation, le planificateur nommant l'index subsumant. Le résidu associé s'est révélé une **réfutation** : sa prémisse sur les statistiques d'index était fausse, et le filet invoqué pour minorer le risque n'existe pas. |
| **P10.2-e** | Série de composition | ✅ | La composition de la base n'existait qu'en relevé ponctuel, coûteux et donc jamais répété : impossible de dire si une part croît ou si le fichier grossit à composition constante. Elle est désormais écrite périodiquement dans la table de métriques du produit — sans HTTP, sans jeton — et lue par le langage de requête existant. Quand la comptabilité ne ferme pas, la série porte un **trou** nommé, jamais un zéro d'octets. |
| **P10.5-a** | Observabilité du vieillissement | ✅ | Le passage au tier froid était muet en **succès**, donc indiscernable d'un démon arrêté, et plusieurs chemins d'échec n'écrivaient que sur la sortie d'erreur. Trois états sont portés par le type — passe faite avec compteurs même à zéro, passe suspendue avec cause nommée, aucun point du tout — avec un invariant qui refuse de publier plutôt que de publier un compteur faux. Un piège trouvé en chemin : la requête de découverte avalait ses erreurs, et une instrumentation naïve aurait publié « zéro candidat » pour une passe qui n'a rien pu regarder. |
| **P10.6-a** | Sauvegarde en flux | ✅ | La sauvegarde compressée était déjà en flux, contrairement au constat de départ. Ce qui manquait : le balayage des temporaires en clair était devenu du code mort, la ligne opérateur annonçait un format faux, et rien ne prouvait que la zone de préparation reste vide ni que la fidélité survive aux données binaires. Contrepartie nommée : la restauration reconstruit index et index plein texte, ce que le délai de reprise doit provisionner. |
| **P10.6-b** | Reprise après sinistre | ✅ | Le vieillissement retire du chaud les lignes déjà scellées en froid : suivie à la lettre, la procédure de restauration ne rendait que la fenêtre chaude et déclarait le succès. Il n'y avait pas de perte — les fichiers froids sont séquestrés — mais rien dans le chemin de restauration ne le savait. Le verdict nomme désormais sa portée. |
| **P10.6-c** | Fraîcheur des sauvegardes | ✅ | Le test de restauration validait l'artefact le plus récent quel que soit son **âge** : une sauvegarde bloquée aurait fait revalider le même artefact périmé chaque jour, en vert. Le seuil est dérivé de la cadence **observée** des dépôts, le test n'ayant délibérément aucun accès à la configuration. |
| **P10.7-b** | Index plein texte | ✅ | Sortir un événement de la fenêtre chaude faisait **grossir** l'index plein texte : sur une table à contenu externe, la suppression écrit un enregistrement qui s'ajoute, et l'espace n'est rendu qu'à la fusion — qu'aucun code n'appelait jamais. Une compaction incrémentale rend l'espace par passes courtes ; la variante en une seule opération tient le verrou d'écriture bien plus longtemps et gonfle le journal d'écriture anticipée. Les octets sont rendus à la liste libre, pas au système de fichiers. |
| **P10.8-a** | Ordre des leviers | ✅ | L'ordre des leviers d'échelle était dérivé d'un banc et non d'une installation réelle, et aucune série n'était conservée. La composition est désormais mesurée périodiquement, avec un coût borné **par construction** (le sommeil suivant est dérivé de la durée du parcours précédent), et l'ordre des leviers est re-dérivé de parts réelles au lieu d'être promis. |
| **P10.9-a** | Usage des index | 🔵 | On ne savait pas quels index servent, alors que l'index b-tree est un poste majeur du fichier. La mesure est un instrument, pas un verdict : **aucun index n'a été retiré**. Un seul candidat ressort, et son cas dépend d'un trou nommé — l'absence de statistiques d'index détaillées — qui doit être comblé avant qu'un choix de plan puisse être qualifié de représentatif. |
| **P10.10-a** | Carte des leviers | ✅ | Un défaut de build passager avait été promu en état permanent de conception, et l'ordre des leviers en avait été dérivé : le tier froid n'a jamais été « construit mais éteint » en dehors de cette fenêtre. Mesuré, le vieillissement rend beaucoup d'espace d'un coup — lignes, quote-part d'index et quote-part d'index plein texte partent ensemble — mais l'activité reconsomme la liste libre plus vite qu'il ne la remplit : **il freine la croissance du fichier, il ne l'annule pas**. |
| **P10.11-a** | Latence sous vieillissement | ⬜ | La latence des requêtes pendant une passe de vieillissement n'est corrélable par rien : l'attente du verrou est rendue **dans la réponse** d'une requête, pas dans une série. Mesurée de l'extérieur, l'exposition est rare et très concentrée — une poignée d'échantillons porte la quasi-totalité du temps d'attente —, donc une moyenne la masquerait entièrement. Ce que la mesure ne dit pas est écrit : c'est une borne inférieure du coût pour un analyste, et elle ne traverse pas le sémaphore. |
| **P10.12-a** | Vocabulaire des compteurs | ✅ | Une passe qui ne faisait **rien** était comptée comme une passe qui avait travaillé, tout en coûtant du temps réel et du CPU. Le vocabulaire distingue désormais les deux. Le résidu de lignes chaudes sur des jours déjà scellés est le compromis « traînards », assumé, testé et borné par la purge finale : ces lignes restent visibles et interrogeables, sans perte. |
| **P10.13-a** | Cadence du détecteur | ✅ | Un détecteur horaire balayait la table d'événements entière et gelait la base pour découvrir une poignée de lignes de travail, alors qu'une seule passe par jour peut avoir quelque chose à faire. Le pari d'une réécriture de la requête a été posé, mesuré, puis **perdu** : le coût suit la taille de la table, pas la forme de l'énoncé. Le levier retenu est la cadence — elle ne supprime aucun travail, elle supprime les passes qui n'en avaient aucun, sans changer ce qui est détecté. L'état de cadence vit dans la base, donc il survit à un redémarrage ; la condition de tir est de niveau et non de front, donc un tir sauté retarde l'alarme sans jamais la manquer. |
| **P10.14-a** | Gardes de promesses | ✅ | Deux lots consécutifs avaient livré un chemin d'échec non gardé : ce sont des promesses écrites **quand le code est juste**, donc invisibles au compilateur comme à une relecture. Une garde dérivée exige de chaque cause publiée une citation capable de la **distinguer** ; le seuil a été tranché par mesure, la règle intuitive n'attrapant rien. Limite déclarée : la garde prouve une condition nécessaire, pas que le test exerce le chemin émetteur — la couverture, elle, se mesure par mutation. |
| **P10.15-a** | Fiabilité d'une sonde | ✅ | Une sonde de diagnostic présentait des durées mesurées **à froid** comme le prix de la passe réelle, avec des écarts de plusieurs ordres de grandeur d'une exécution à l'autre selon l'état des caches. Chaque énoncé est désormais mesuré deux fois, seule la mesure à chaud est annoncée comme **plancher** — un majorant qui varie n'est pas un majorant —, et le type interdit au compilateur de republier une durée nue. La sonde consomme de la mémoire, ce qui compte sous 2 Gio, et sa sortie le dit. |
| **P10.16-a** | Empreinte du journal d'écriture | 🔵 | La moitié observabilité est close par la ligne suivante. Reste à borner la crête du journal d'écriture anticipée, dont le pic pèse une fraction notable de la taille de la base. Ce n'est pas de l'observabilité mais un **changement de comportement** sous 2 Gio : il demande sa propre campagne — choix de la borne, effet sur les écritures en rafale, vérification que le journal ne redevienne pas un goulot. |
| **P10.17-a** | Point de contrôle du journal | ✅ | Les appels de troncature du journal d'écriture anticipée étaient aveugles à leur propre verdict : ce PRAGMA ne rend pas un code d'erreur mais une **ligne**, et un lecteur concurrent fait échouer la troncature en silence. Voie unique, verdict à trois états nommés, journalisation du refus, garde qui refuse le PRAGMA hors de cette voie. Aucun changement de comportement : on ne réessaie pas et on ne force aucun verrou — la base d'un SOC ne doit pas geler pour une troncature refusée —, on rapporte. |

---

## Constats sans clé encore ouverts

| Réf. | Périmètre | État | Ce que la référence désigne |
|---|---|---|---|
| S4 | Multi-tenant | ⬜ | La génération de clé par tenant garde un repli d'entropie dérivé de l'horloge et du processus, même figure que celle fermée sur le chemin d'installation. Elle avertit, et le mode multi-tenant est désactivé par défaut. |
| S5 | Bancs | ⬜ | Des références mortes à l'indexation adaptative retirée subsistent dans les scripts de banc et leur documentation. |
| S6 | Surveillance d'intégrité | ✅ | Le collecteur d'intégrité **annonçait** surveiller les clés SSH autorisées — un vecteur de persistance, livré comme détection — que le durcissement lui retirait **en silence** : la protection des répertoires personnels est un réglage **scalaire**, et le fragment de durcissement partagé, lu *après* l'unité, écrasait la valeur plus permissive que l'unité posait exprès. Mesuré, capteur exécuté tel quel : la référence d'intégrité perd **exactement une famille**, sans erreur ni avertissement — et les deux installeurs ne s'accordaient même pas, le central couvrant ce que l'agent laissait aveugle. Le réglage appartient désormais à chaque unité, le fragment partagé ne le pose plus pour personne, et une garde **dérivée** de la liste annoncée refuse tout chemin annoncé devenu injoignable. **Ce que le correctif ouvre, dit franchement** : ce collecteur peut lire l'intégralité des répertoires personnels, pas seulement les clés ; l'écriture reste refusée et les répertoires d'exécution de session restent masqués, aucune re-exposition d'un sous-chemin n'étant possible sous la protection stricte (mesuré : aucune des trois directives candidates n'y parvient). Resserrer ce bac à sable reste un arbitrage d'**exploitant** — qui le resserre verra désormais le capteur **avouer** son angle mort dans sa sortie au lieu de se taire. |
| S7 | Alertes de fraîcheur | ⬜ | L'alerte de capteur indisponible est **globale** : elle ne fait pas basculer l'état de la source fautive, l'imputation cherchant un nom de source dans le texte de la règle, qu'une règle générique ne porte pas. |
| S16 | Comptage des agrégats | 🔵 | Un sur-comptage sur l'une des routes d'agrégat est **laissé délibérément**, avec sa raison : le corriger reviendrait à effacer de la réponse des événements réels sur le seul chemin qui les compte encore. |
| S24 | Documentation | ⬜ | Le document de conception qui porte l'état le plus frais des travaux d'échelle n'est référencé par aucun index de la documentation. |
| S25 | Allegation de bac a sable non reproduite | ⬜ | Un commentaire du code d'installation de service affirme qu'une directive de re-exposition rend de nouveau lisible un chemin place sous protection du repertoire personnel. MESURE sur une version recente de l'ordonnanceur de services : cela NE SE REPRODUIT PAS — l'execution echoue de la meme facon avec et sans la directive, la seule difference etant l'absence d'echec quand aucune protection n'est posee. CONSEQUENCE VIVANTE, non corrigee : la fonction qui decide si un chemin est cache rend « non cache » sur la foi de cette allegation, et laisserait donc installer une unite dont l'executable est injoignable. La garde de couverture posee par S6 ne s'appuie DELIBEREMENT pas sur cette allegation. Meme famille que S6 : une propriete affirmee en prose que rien ne verifie, et qui a cesse d'etre vraie sans que personne le remarque. |

Les autres constats sans clé sont clos : sécurisation de la route d'installation initiale, capteurs
qui sortaient en succès sans pouvoir fonctionner, trous de couverture des agrégats préconstruits,
marques de troncature, mesures de concurrence et de débit.

---

## Limites connues

**Le budget de 2 Gio est une contrainte de conception, pas une observation.** Tout arbitrage de
stockage, d'index et d'agrégation est tranché contre lui. Au repos, le service en consomme une
fraction ; cela ne dit rien du pire cas, et il ne faut pas le lire comme une garantie.

**Le tri de très gros résultats reste le poste de mémoire dominant.** Le moteur délègue le tri et
l'agrégation à SQLite, dont le trieur n'a pas de budget propre. Une limite de tas dérivée du budget
publié transforme le dépassement en **refus explicite** plutôt qu'en mort du processus : la requête
échoue, le service survit. C'est une fermeture par le refus, pas par la réponse.

**Le déversement des tris sur disque est opt-in, et c'est un choix de confidentialité.** SQLCipher
chiffre le fichier de base, pas les fichiers temporaires de SQLite : activer le déversement fait
exister un plafond de tri au prix de valeurs d'événement écrites en clair hors de la base. Le
réglage existe, il est documenté comme un échange, et il n'est pas le défaut. Aucun quota ne borne
encore la taille du déversement quand il est activé.

**Le tier froid colonnaire est optionnel et n'est pas actif par défaut.** Il se demande à la
compilation puis s'active par configuration ; une image construite sans lui ne peut honorer aucune
de ses variables. Quand il est actif, il retire du chaud les lignes déjà scellées : la fenêtre
chaude ne contient plus tout l'historique, et **toute procédure de restauration doit en tenir
compte** sous peine de rendre une fraction en annonçant un succès.

**Le vieillissement freine la croissance du fichier, il ne l'annule pas.** Il rend beaucoup d'espace
d'un coup, mais cet espace retourne à la liste libre de la base et l'activité le reconsomme.
Réduire durablement la taille demande de réduire les octets **par événement chaud** — c'est le
chantier de compression au repos, conçu et non construit.

**Une passe de vieillissement tient le verrou d'écriture.** L'exposition est rare et prévisible
depuis que le détecteur ne tire qu'une fois par jour, mais franche quand elle a lieu : une très
faible part des requêtes porte la quasi-totalité du temps d'attente, donc ne jamais résumer cet axe
par une moyenne. La corrélation n'est pas encore une série (P10.11-a). Autre poste non borné : **la
crête du journal d'écriture anticipée**, qui oscille et est rendue sans dérive nette, mais dont le
pic pèse une fraction notable de la taille de la base — sous 2 Gio, c'est une empreinte maximale à
porter au budget (P10.16-a).

**Le débit d'ingestion décroît quand le volume croît**, et cette chute se factorise en un coût CPU
par événement qui monte : c'est le volume, pas la machine ni le stockage. La cible affichée n'est
pas atteinte, et elle n'est pas maquillée. Corollaire : **la concurrence de requêtes n'est pas un
réglage de confort** — le sémaphore interactif est ce qui maintient le service dans son budget, et
l'élargir fait baisser le débit, monter la latence de queue, et peut faire tuer le processus sous
charge d'analystes. **Vingt et un gabarits de route le consomment** (décompte dérivé de la source,
2026-08-20, refait à chaque exécution de la suite), et l'exposition sépare désormais l'attente du
permit du travail fait une fois le permit obtenu — sans quoi une saturation ne se distingue pas
d'une requête lente (P7.8-a).

**Les sondes de fraîcheur ont une portée « tous hôtes confondus »** (P3.2-a) : celles dont le statut
dérive d'une valeur peuvent rendre sain un parc où une seule machine parle encore. Celles qui
suivent la fraîcheur du pipeline ne présentent pas ce risque ; la distinction est comptée à part.

**La sauvegarde est un export logique**, sans contenu d'index, sans tables d'index plein texte et
sans pages libres : tout cela est reconstruit à la restauration, ce qui coûte du CPU et allonge le
délai de reprise. L'archive est donc bien plus petite que le fichier de base, et ce n'est pas une
perte. La **vérification** d'une archive (P8.3-a) restaure et compte ce qui revient quand la clé de
lecture est disponible — c'est le cas du mode par passphrase ; sur le mode d'escrow, elle dégrade en
contrôle structurel, aucune clé privée de séquestre n'étant placée à côté des sauvegardes. **Un
exercice de restauration réel reste donc un geste d'exploitant, hors ligne** — mais il n'est plus
invisible : il laisse une attestation datée que le nœud enregistre, et dont l'absence ou
l'ancienneté se lisent dans la santé par composant et dans les métriques.

**Le mode multi-tenant est désactivé par défaut** et n'est pas destiné à la production en l'état ;
son repli d'entropie de clé (S4) est ouvert. De même, **une part des variables de configuration
n'est encore lisible que depuis l'environnement** : sur le déploiement natif systemd, un exploitant
qui les écrit dans le fichier de configuration n'obtient rien. Le registre de cette dette ne peut
que rétrécir. Enfin, le retrait du blanket sudo est un geste d'exploitant (P5.8-a) : une entrée
bornée ne le remplace pas tant que le code élevé appartient à l'utilisateur qui l'invoque.

---

## Conçu, non construit

**Agrégation bornée native.** Un accumulateur à état borné — comptage distinct probabiliste, top-N
borné — au lieu de déléguer au trieur de SQLite. Cela fermerait la question mémoire **par la
réponse** (l'agrégat sort, borné et marqué) là où la limite de tas la ferme par le refus. Ne coûte
aucune confidentialité, rien ne touchant le disque, et s'appuie sur des types de réponse déjà en
place. Conçu et ordonné, pas construit.

**Compression au repos des données chaudes.** Les valeurs textuelles et les champs JSON se
compressent fortement ; la variante retenue est **par valeur**, en gardant en clair les colonnes qui
servent les index et les filtres pour que ni l'index ni la clause de sélection ne paient. Le coût de
lecture doit être mesuré avant toute généralisation. La variante **par page**, au niveau de la
couche de fichier virtuelle, est écartée par défaut pour la même raison que le déversement des tris :
elle déplace la frontière de confidentialité.

**Réduction d'index.** Déjà entamée, et il reste peu de gras : ce qui subsiste est nécessaire — la
contrainte d'unicité qui porte la déduplication — ou sert de la détection active. Rien n'y sera
retouché sans mesure d'usage.

**Trois chantiers plus courts, décidés et non livrés** : borner la crête du journal d'écriture
anticipée (P10.16-a), qui change le comportement d'exécution et demande sa propre campagne ; un
index partiel couvrant pour le détecteur de retard de vieillissement (P10.13-a), chiffré à la sonde,
qui supprimerait le balayage au prix d'un coût d'ingestion et d'octets — un index sur le chemin
chaud sous 2 Gio se décide, il ne se glisse pas dans un lot ; et la publication en série de
l'attente de verrou, pour corréler latence de requête et fenêtre de vieillissement (P10.11-a), la
fenêtre étant désormais publiée mais pas l'attente. S'y ajoute une garde permanente sur la table de
décision du retour arrière (P4.4-c), dont les cas sont prouvés par un harnais jetable.

---

*Les états de cet index sont tenus à jour avec le code : une ligne ✅ porte un correctif et une
vérification, une ligne ❓ attend une re-mesure et ne doit être citée comme acquise par personne. Le
document de conception qui détaille les travaux d'échelle est docs/DESIGN-P10-echelle-2go.md.*
