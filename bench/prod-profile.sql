-- bench/prod-profile.sql — EXTRACTION DU PROFIL DE DONNÉES, LECTURE SEULE, AGRÉGATS UNIQUEMENT.
--
-- Ce fichier est la PROVENANCE de `bench/profile-prod.json`. Il est publié pour qu'un tiers
-- puisse rejouer l'extraction sur SA production et contredire le profil.
--
-- CONTRAT DE CONFIDENTIALITÉ — ce script n'extrait AUCUNE valeur de ligne :
--   * il sort des COMPTES, des CARDINALITÉS, des LONGUEURS et des NOMS DE CHAMP ;
--   * il ne sort JAMAIS le contenu de `message`, `host`, `src_ip`, `url`, `dedup`,
--     ni la valeur d'une clé du blob JSON `fields` (seulement sa clé, son type, sa longueur) ;
--   * `source`, `category` et `severity` sont des ÉNUMÉRATIONS du produit (elles sont déjà
--     dans le code et la doc), pas des données client — elles sont donc sorties en clair.
--
-- MODE D'EMPLOI (sur l'hôte qui porte le fichier, à côté du daemon VIVANT) :
--
--   DB=/chemin/vers/plume.db
--   KEY=<contenu de PLUME_DB_KEY>            # jamais écrit sur disque, jamais journalisé
--   { printf "PRAGMA key = '%s';\n" "$KEY"; cat bench/prod-profile.sql; } > /tmp/p.sql
--   chmod 600 /tmp/p.sql
--   sqlcipher "file:$DB?mode=ro" < /tmp/p.sql   # mode=ro : AUCUNE écriture possible
--   rm -f /tmp/p.sql
--
-- SÛRETÉ D'EXPLOITATION — ce qu'il faut savoir avant de le lancer sur une prod :
--   * `mode=ro` interdit toute écriture ; le daemon continue d'ingérer pendant l'extraction.
--   * MAIS un lecteur SQLite tient un instantané : tant qu'une passe tourne, le WAL ne peut pas
--     être checkpointé et il GROSSIT. Les passes sont donc découpées et courtes (la plus longue
--     mesurée : de l'ordre de la minute sur une base d'un million et plus d'événements ; croissance
--     du WAL observée : quelques Mio).
--     Sur une base beaucoup plus grosse, lancer les sections UNE PAR UNE.
--   * Coût CPU : un cœur saturé le temps de la passe (déchiffrement SQLCipher + scan).

.mode list
.separator |
.timeout 8000

-- ============================================================ 1. FORME DE LA BASE
SELECT '### DDL_EVENT';
SELECT sql FROM sqlite_master WHERE name='event' AND type='table';
SELECT '### INDEXES_EVENT';
SELECT ifnull(sql,'(auto) '||name) FROM sqlite_master WHERE type='index' AND tbl_name='event';
SELECT '### FTS_OBJECTS';
SELECT type||'|'||name FROM sqlite_master WHERE name LIKE '%fts%';
SELECT '### PRAGMAS';
SELECT 'page_size='||(SELECT * FROM pragma_page_size());
SELECT 'page_count='||(SELECT * FROM pragma_page_count());
SELECT 'freelist='||(SELECT * FROM pragma_freelist_count());
SELECT 'journal='||(SELECT * FROM pragma_journal_mode());
SELECT 'auto_vacuum='||(SELECT * FROM pragma_auto_vacuum());

-- ============================================================ 2. VOLUME ET FENÊTRE
SELECT '### EVENT_COUNT_AND_RANGE';
SELECT 'n='||COUNT(*) FROM event;
SELECT 'min_ts='||MIN(ts)||' max_ts='||MAX(ts) FROM event;
SELECT 'min_id='||MIN(id)||' max_id='||MAX(id) FROM event;   -- (max_id - min_id) - n = lignes purgées

-- ============================================================ 3. CARDINALITÉS ET LONGUEURS
-- (les 4 premières utilisent un index -> peu coûteuses ; les suivantes scannent la table)
SELECT '### CARD_EXACT';
SELECT 'source',COUNT(*) FROM (SELECT DISTINCT source FROM event);
SELECT 'category',COUNT(*) FROM (SELECT DISTINCT category FROM event);
SELECT 'host',COUNT(*) FROM (SELECT DISTINCT host FROM event);
SELECT 'src_ip',COUNT(*) FROM (SELECT DISTINCT src_ip FROM event);
SELECT '### GLOBAL_ONEPASS';
SELECT 'null_category',SUM(category IS NULL),'null_host',SUM(host IS NULL),'null_message',SUM(message IS NULL),
       'null_fields',SUM(fields IS NULL),'null_srcip',SUM(src_ip IS NULL),'null_dstip',SUM(dst_ip IS NULL),
       'null_url',SUM(url IS NULL),'null_xff',SUM(xff IS NULL),'null_dedup',SUM(dedup IS NULL) FROM event;
SELECT 'msglen_min',MIN(LENGTH(message)),'avg',ROUND(AVG(LENGTH(message)),1),'max',MAX(LENGTH(message)),'sum',SUM(LENGTH(message)) FROM event;
SELECT 'fldlen_min',MIN(LENGTH(fields)),'avg',ROUND(AVG(LENGTH(fields)),1),'max',MAX(LENGTH(fields)),'sum',SUM(LENGTH(fields)) FROM event;
SELECT 'card_dstip',COUNT(DISTINCT dst_ip),'card_url',COUNT(DISTINCT url),'card_xff',COUNT(DISTINCT xff),
       'card_msg',COUNT(DISTINCT message),'card_env',COUNT(DISTINCT env_id),'card_origin',COUNT(DISTINCT origin),
       'card_eng',COUNT(DISTINCT engagement_id),'card_dedup',COUNT(DISTINCT dedup) FROM event;
SELECT '### MSGLEN_HIST';
SELECT CASE WHEN message IS NULL THEN 'null' WHEN LENGTH(message)<=32 THEN '0-32' WHEN LENGTH(message)<=64 THEN '33-64'
            WHEN LENGTH(message)<=128 THEN '65-128' WHEN LENGTH(message)<=256 THEN '129-256'
            WHEN LENGTH(message)<=512 THEN '257-512' WHEN LENGTH(message)<=1024 THEN '513-1024'
            WHEN LENGTH(message)<=4096 THEN '1025-4096' ELSE '4097+' END b, COUNT(*) FROM event GROUP BY b ORDER BY b;
SELECT '### FLDLEN_HIST';
SELECT CASE WHEN fields IS NULL THEN 'null' WHEN LENGTH(fields)<=32 THEN '0-32' WHEN LENGTH(fields)<=64 THEN '33-64'
            WHEN LENGTH(fields)<=128 THEN '65-128' WHEN LENGTH(fields)<=256 THEN '129-256'
            WHEN LENGTH(fields)<=512 THEN '257-512' WHEN LENGTH(fields)<=1024 THEN '513-1024'
            WHEN LENGTH(fields)<=4096 THEN '1025-4096' ELSE '4097+' END b, COUNT(*) FROM event GROUP BY b ORDER BY b;

-- ============================================================ 4. RÉPARTITIONS
SELECT '### BY_SOURCE';
SELECT source, COUNT(*), COUNT(DISTINCT host), COUNT(DISTINCT category),
       ROUND(AVG(LENGTH(message)),1), ROUND(AVG(LENGTH(fields)),1), SUM(src_ip IS NOT NULL)
  FROM event GROUP BY source ORDER BY 2 DESC;
SELECT '### BY_CATEGORY';
SELECT ifnull(category,'(null)'), COUNT(*) FROM event GROUP BY category ORDER BY 2 DESC;
SELECT '### BY_SEVERITY';
SELECT severity, COUNT(*) FROM event GROUP BY severity ORDER BY 1;
SELECT '### BY_ENV_ORIGIN';
SELECT env_id, origin, engagement_id, COUNT(*) FROM event GROUP BY 1,2,3 ORDER BY 4 DESC LIMIT 20;
SELECT '### SRC_SEV';
SELECT source, severity, COUNT(*) FROM event GROUP BY 1,2 ORDER BY 1,2;
SELECT '### SRC_CAT';
SELECT source, ifnull(category,''), COUNT(*) FROM event GROUP BY 1,2 ORDER BY 1,3 DESC;
SELECT '### SRC_MSGLEN';
SELECT source, MIN(LENGTH(message)), ROUND(AVG(LENGTH(message)),1), MAX(LENGTH(message)),
       ROUND(AVG(LENGTH(fields)),1), MAX(LENGTH(fields)) FROM event GROUP BY 1;

-- ============================================================ 5. DENSITÉ TEMPORELLE
SELECT '### DENSITY_PER_DAY';
SELECT date(ts,'unixepoch') d, COUNT(*) FROM event GROUP BY d ORDER BY d;
SELECT '### DENSITY_PER_HOUR_OF_DAY';
SELECT CAST(strftime('%H',ts,'unixepoch') AS INTEGER) h, COUNT(*) FROM event GROUP BY h ORDER BY h;

-- ============================================================ 6. CHAMPS ÉTENDUS (blob JSON)
-- La passe la plus coûteuse : `json_each` déplie chaque paire clé/valeur (~7,6 par événement).
-- Elle sort les CLÉS, leur TYPE, la LONGUEUR de leurs valeurs et leur CARDINALITÉ. Jamais une valeur.
SELECT '### JSON_KEYS_FULL';
SELECT j.key, COUNT(*) n, ROUND(AVG(LENGTH(j.value)),1), MAX(LENGTH(j.value)), COUNT(DISTINCT j.value), j.type
  FROM event e, json_each(e.fields) j GROUP BY j.key ORDER BY n DESC;
SELECT '### JSON_NKEYS_HIST';
SELECT k, COUNT(*) FROM (SELECT (SELECT COUNT(*) FROM json_each(e.fields)) k FROM event e) GROUP BY k ORDER BY k;
SELECT '### JSON_KEY_TOTALS';
SELECT 'distinct_keys', COUNT(*) FROM (SELECT DISTINCT j.key FROM event e, json_each(e.fields) j);
SELECT 'total_kv_pairs', COUNT(*) FROM event e, json_each(e.fields) j;
SELECT '### SRC_KEY_SETS';
SELECT e.source, j.key, COUNT(*) n, ROUND(AVG(LENGTH(j.value)),1), COUNT(DISTINCT j.value), j.type
  FROM event e, json_each(e.fields) j GROUP BY 1,2 HAVING n >= 5 ORDER BY 1, 3 DESC;

-- ============================================================ 7. POIDS RÉEL SUR DISQUE
SELECT '### ROLLUP_SIZES';
SELECT 'event_rollup', COUNT(*) FROM event_rollup;
SELECT 'event_dim_rollup', COUNT(*) FROM event_dim_rollup;
SELECT 'event_fts_rows', COUNT(*) FROM event_fts_docsize;
SELECT '### FIELD_FILTER_ROWS';
SELECT COUNT(*) FROM field_filter;         -- 0 = ENSEMBLE DE MASQUAGE VIDE en production
SELECT '### DBSTAT_BY_NAME';
-- dbstat parcourt TOUS les b-trees : c'est la mesure exacte du poids table / index / FTS.
-- Nécessite SQLITE_ENABLE_DBSTAT_VTAB (présent dans le paquet `sqlcipher` de Debian/Ubuntu).
-- `P7.20-l` — CE PRÉREQUIS EST UN OUTIL D'HÔTE QU'AUCUN SCRIPT DE CE DÉPÔT N'INSTALLE. Sans lui,
-- la recette s'arrête à mi-chemin, et on l'apprend au moment où l'on en a besoin. Le vérifier
-- AVANT de commencer :
--   sqlcipher :memory: "SELECT 1 FROM pragma_compile_options WHERE compile_options='ENABLE_DBSTAT_VTAB';"
-- une ligne « 1 » = utilisable ; aucune sortie = ce client ne sait pas mener ces passes.
SELECT name, SUM(pgsize), COUNT(*) FROM dbstat GROUP BY name ORDER BY 2 DESC;
