/* banc_fts.c — banc de mesure de la COMPACTION FTS5, sur la SQLite EXACTE de plume.
 *
 * Instrument : l'amalgamation SQLCipher vendorée par libsqlite3-sys 0.28 (SQLite 3.39.4 /
 * SQLCipher 4.5.3), compilée avec LES MÊMES -D que build.rs, à -O2 (le profil debug de cargo
 * compile ce C à -O0, ce qui fausserait toute mesure de DURÉE).
 *
 * Sous-commandes :
 *   version                       -> valide l'instrument (versions + FTS5 + dbstat + codec)
 *   build   <db> <n> <seed>       -> fabrique la base (schéma event + event_fts réels)
 *   sizes   <db>                  -> tailles dbstat par objet FTS + segments + freelist
 *   del     <db> <frac>           -> DELETE chunké des <frac> plus vieilles lignes
 *   opt     <db>                  -> 'optimize' (une rafale)
 *   merge   <db> <npages> <passes> <usermerge>  -> 'merge' incrémental borné
 *   killopt <db> <ms>             -> 'optimize' puis _exit(9) au bout de <ms> ms (pas de commit)
 *   check   <db>                  -> integrity-check FTS5 + requête MATCH réelle
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include "sqlite3.h"

static const char *KEY = "banc-fts-cle-sqlcipher-32-octets";

/* ------------------------------------------------------------------ horloge + échantillonneur */
static double maintenant(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static volatile int echantillonne = 0;
static volatile long wal_max = 0;
static volatile long rss_max = 0;
static char chemin_wal[4096];

static long rss_ko(void) {
    FILE *f = fopen("/proc/self/statm", "r");
    if (!f) return 0;
    long taille = 0, resident = 0;
    if (fscanf(f, "%ld %ld", &taille, &resident) != 2) resident = 0;
    fclose(f);
    return resident * (sysconf(_SC_PAGESIZE) / 1024);
}

static void *fil_echantillon(void *arg) {
    (void)arg;
    while (echantillonne) {
        struct stat st;
        if (stat(chemin_wal, &st) == 0 && st.st_size > wal_max) wal_max = st.st_size;
        long r = rss_ko();
        if (r > rss_max) rss_max = r;
        usleep(5000);
    }
    return NULL;
}

/* ------------------------------------------------------------------ ouverture */
static void verifier(sqlite3 *db, int rc, const char *quoi) {
    if (rc != SQLITE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW) {
        fprintf(stderr, "ERREUR %s : (%d) %s\n", quoi, rc, db ? sqlite3_errmsg(db) : "?");
        exit(1);
    }
}

static void exec(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "ERREUR sql <%s> : %s\n", sql, err ? err : "?");
        exit(1);
    }
}

static sqlite3 *ouvrir(const char *chemin) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(chemin, &db);
    verifier(db, rc, "open");
    char pragma[512];
    snprintf(pragma, sizeof pragma, "PRAGMA key='%s';", KEY);
    exec(db, pragma);
    /* LES PRAGMA DE PRODUCTION, à l'identique (daemon/src/server.rs::tune + sqlite_plafond) */
    exec(db,
         "PRAGMA journal_mode=WAL;"
         "PRAGMA synchronous=NORMAL;"
         "PRAGMA busy_timeout=5000;"
         "PRAGMA temp_store=MEMORY;"
         "PRAGMA mmap_size=268435456;"
         "PRAGMA cache_size=-65536;"
         "PRAGMA wal_autocheckpoint=1000;"
         "PRAGMA foreign_keys=ON;");
    snprintf(chemin_wal, sizeof chemin_wal, "%s-wal", chemin);
    return db;
}

static sqlite3_int64 scalaire(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &st, NULL);
    if (rc != SQLITE_OK) { sqlite3_finalize(st); return -1; }
    sqlite3_int64 v = -1;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* ------------------------------------------------------------------ générateur déterministe */
static uint64_t etat_rng;
static uint64_t rng(void) {
    uint64_t z = (etat_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static uint32_t borne(uint32_t n) { return (uint32_t)(rng() % n); }

static const char *SOURCES[] = {
    "auditd","syslog","sshd","nginx","kernel","systemd","cron","sudo","fail2ban","postfix",
    "dovecot","docker","containerd","kubelet","traefik","authentik","vault","argocd","crowdsec","ufw",
    "clamav","rsyslog","chronyd","dbus","polkit","networkd","resolved","logind","apparmor","snapd",
    "plume-agent","plume-config"
};
static const char *CATEGORIES[] = {
    "exec","auth","network","config","tamper","web","mail","dns","process","file",
    "health","policy","container","scan","alert","audit","session","kernel","service"
};
/* vocabulaire commun : ~200 mots, l'essentiel des occurrences, peu de termes distincts */
static const char *COMMUN[] = {
    "session","opened","closed","for","user","by","uid","from","port","ssh2",
    "accepted","publickey","password","failed","invalid","preauth","disconnect","received","sent","bytes",
    "request","response","status","method","path","query","header","agent","client","server",
    "connection","established","refused","timeout","retry","attempt","error","warning","notice","info",
    "started","stopped","reload","restart","enable","disable","active","inactive","running","exited",
    "process","thread","memory","cpu","disk","network","interface","address","route","gateway",
    "packet","dropped","allowed","denied","rule","chain","target","input","output","forward",
    "file","directory","created","deleted","modified","permission","owner","group","mode","size",
    "service","unit","daemon","socket","timer","mount","device","module","driver","firmware",
    "certificate","expired","renewed","issuer","subject","serial","fingerprint","chain","valid","trust",
    "token","scope","grant","refresh","revoke","claim","audience","issuer","subject","expiry",
    "database","table","index","query","transaction","commit","rollback","lock","cache","flush",
    "queue","worker","job","task","schedule","cron","interval","backoff","batch","offset",
    "container","image","pod","namespace","label","volume","limit","probe","liveness","readiness",
    "backup","restore","snapshot","archive","retention","purge","rotate","compress","encrypt","decrypt",
    "login","logout","account","credential","policy","role","admin","viewer","editor","guest",
    "scan","detected","signature","threat","malware","quarantine","clean","suspicious","blocked","banned",
    "syscall","execve","openat","unlink","chmod","setuid","ptrace","mmap","socket","connect",
    "http","https","tcp","udp","icmp","tls","sni","cipher","handshake","alpn",
    "sudo","command","pwd","tty","runas","env","shell","binary","argument","exit"
};
/* vocabulaire moyen : suffixé d'un indice -> ~20 000 termes distincts */
static const char *MOYEN[] = {
    "svc","mod","pkg","lib","bin","cfg","tmp","var","opt","usr",
    "host","node","zone","site","rack","pool","shard","slot","peer","link"
};

#define NB(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* Compose un message de longueur ~cible, au profil mesuré (bench/profile-prod.json) :
 *   ~60 % de tokens du vocabulaire COMMUN (peu de termes distincts, postings très longs)
 *   ~25 % du vocabulaire MOYEN indicé (20 k termes)
 *   ~15 % de tokens QUASI-UNIQUES (ip / hexa / identifiants) -> c'est eux qui font le dictionnaire
 */
static int message(char *buf, int cap, int cible) {
    int n = 0;
    while (n < cible - 24) {
        uint32_t d = borne(100);
        if (d < 60) {
            n += snprintf(buf + n, cap - n, "%s ", COMMUN[borne(NB(COMMUN))]);
        } else if (d < 85) {
            n += snprintf(buf + n, cap - n, "%s%u ", MOYEN[borne(NB(MOYEN))], borne(1000));
        } else if (d < 93) {
            n += snprintf(buf + n, cap - n, "192.0.2.%u ", borne(254) + 1);
        } else {
            n += snprintf(buf + n, cap - n, "%08x ", (unsigned)(rng() & 0xFFFFFFFFu));
        }
    }
    if (n > 0 && buf[n - 1] == ' ') buf[--n] = 0;
    return n;
}

/* Histogramme des longueurs de `message` MESURÉ en production (colonne message_len_hist du profil,
 * 1 395 968 lignes). On tire la classe, puis une longueur uniforme dans la classe. */
static int longueur_cible(void) {
    uint32_t r = borne(1395968);
    if ((r -= 45855) > 3000000000u) return 24 + borne(9);        /* 0-32    :   45 855 */
    if ((r -= 690252) > 3000000000u) return 33 + borne(32);      /* 33-64   :  690 252 */
    if ((r -= 303843) > 3000000000u) return 65 + borne(64);      /* 65-128  :  303 843 */
    if ((r -= 84702) > 3000000000u) return 129 + borne(128);     /* 129-256 :   84 702 */
    if ((r -= 236346) > 3000000000u) return 257 + borne(256);    /* 257-512 :  236 346 */
    if ((r -= 51) > 3000000000u) return 513 + borne(512);        /* 513-1024:       51 */
    return 1025 + borne(3072);                                   /* 1025-4096: 34 919 */
}

static void cmd_build(const char *chemin, long n, uint64_t graine) {
    unlink(chemin);
    sqlite3 *db = ouvrir(chemin);
    /* Le schéma RÉEL de plume, extrait de db/schema.sql (colonnes de `event` indexées par le FTS,
     * la vtable à CONTENU EXTERNE et ses DEUX déclencheurs, à l'identique). */
    exec(db,
         "CREATE TABLE IF NOT EXISTS event("
         " id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, source TEXT NOT NULL,"
         " host TEXT NOT NULL DEFAULT '', severity INTEGER NOT NULL DEFAULT 0,"
         " category TEXT NOT NULL DEFAULT '', message TEXT NOT NULL DEFAULT '', fields TEXT,"
         " src_ip TEXT, dst_ip TEXT, action TEXT, user TEXT, env_id TEXT NOT NULL DEFAULT 'prod',"
         " origin TEXT NOT NULL DEFAULT '');"
         "CREATE INDEX IF NOT EXISTS idx_event_ts ON event(ts);"
         "CREATE VIRTUAL TABLE IF NOT EXISTS event_fts USING fts5("
         "  message, source, category, content='event', content_rowid='id');"
         "CREATE TRIGGER IF NOT EXISTS event_ai AFTER INSERT ON event BEGIN"
         "  INSERT INTO event_fts(rowid,message,source,category)"
         "  VALUES (new.id,new.message,new.source,new.category);"
         "END;"
         "CREATE TRIGGER IF NOT EXISTS event_ad AFTER DELETE ON event BEGIN"
         "  INSERT INTO event_fts(event_fts,rowid,message,source,category)"
         "  VALUES ('delete',old.id,old.message,old.source,old.category);"
         "END;");

    etat_rng = graine;
    sqlite3_stmt *st = NULL;
    verifier(db, sqlite3_prepare_v2(db,
        "INSERT INTO event(ts,source,host,severity,category,message,fields) VALUES(?1,?2,'h1',1,?3,?4,'{}')",
        -1, &st, NULL), "prepare insert");

    char buf[8192];
    double t0 = maintenant();
    sqlite3_int64 ts = 1782897564;
    exec(db, "BEGIN");
    for (long i = 0; i < n; i++) {
        int len = message(buf, sizeof buf, longueur_cible());
        sqlite3_bind_int64(st, 1, ts + i * 2);
        sqlite3_bind_text(st, 2, SOURCES[borne(NB(SOURCES))], -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 3, CATEGORIES[borne(NB(CATEGORIES))], -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 4, buf, len, SQLITE_TRANSIENT);
        verifier(db, sqlite3_step(st), "insert");
        sqlite3_reset(st);
        if ((i + 1) % 50000 == 0) {
            exec(db, "COMMIT");
            exec(db, "BEGIN");
            fprintf(stderr, "\r  %ld / %ld  (%.0f s)", i + 1, n, maintenant() - t0);
        }
    }
    exec(db, "COMMIT");
    sqlite3_finalize(st);
    fprintf(stderr, "\n");
    exec(db, "PRAGMA wal_checkpoint(TRUNCATE);");
    printf("build : %ld events en %.1f s\n", n, maintenant() - t0);
    sqlite3_close(db);
}

/* ------------------------------------------------------------------ tailles */
static sqlite3_int64 octets_objet(sqlite3 *db, const char *nom) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COALESCE(SUM(pgsize),0) FROM dbstat WHERE name=?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, nom, -1, SQLITE_STATIC);
    sqlite3_int64 v = 0;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static void imprimer_tailles(sqlite3 *db, const char *etiquette) {
    static const char *objets[] = {"event_fts_data", "event_fts_idx", "event_fts_docsize", "event_fts_config"};
    sqlite3_int64 total = 0;
    printf("[%s]\n", etiquette);
    for (int i = 0; i < 4; i++) {
        sqlite3_int64 o = octets_objet(db, objets[i]);
        total += o;
        printf("  %-20s %12lld o  %8.2f Mio\n", objets[i], (long long)o, o / 1048576.0);
    }
    printf("  %-20s %12lld o  %8.2f Mio\n", "FTS TOTAL", (long long)total, total / 1048576.0);
    printf("  %-20s %12lld\n", "segments", (long long)scalaire(db, "SELECT COUNT(DISTINCT segid) FROM event_fts_idx"));
    printf("  %-20s %12lld\n", "events", (long long)scalaire(db, "SELECT COUNT(*) FROM event"));
    printf("  %-20s %12lld o\n", "event (table)", (long long)octets_objet(db, "event"));
    printf("  %-20s %12lld pages\n", "page_count", (long long)scalaire(db, "PRAGMA page_count"));
    printf("  %-20s %12lld pages\n", "freelist", (long long)scalaire(db, "PRAGMA freelist_count"));
}

static void cmd_sizes(const char *chemin) {
    sqlite3 *db = ouvrir(chemin);
    imprimer_tailles(db, "tailles");
    sqlite3_close(db);
}

/* ------------------------------------------------------------------ purge */
static void cmd_del(const char *chemin, double frac) {
    sqlite3 *db = ouvrir(chemin);
    sqlite3_int64 n = scalaire(db, "SELECT COUNT(*) FROM event");
    sqlite3_int64 cible = (sqlite3_int64)(n * frac);
    sqlite3_int64 idmax = scalaire(db, "SELECT MIN(id)+CAST(? AS INTEGER) FROM event");
    (void)idmax;
    /* borne d'id telle que ~frac des lignes soient dessous (ids denses) */
    char sql[512];
    snprintf(sql, sizeof sql, "SELECT id FROM event ORDER BY id LIMIT 1 OFFSET %lld", (long long)(cible - 1));
    sqlite3_int64 borne_id = scalaire(db, sql);
    double t0 = maintenant();
    /* purge CHUNKÉE, exactement comme rollups.rs::chunked_purge (lots de 10 000) */
    snprintf(sql, sizeof sql,
             "DELETE FROM event WHERE rowid IN (SELECT rowid FROM event WHERE id <= %lld LIMIT 10000)",
             (long long)borne_id);
    long total = 0;
    for (;;) {
        exec(db, sql);
        int c = sqlite3_changes(db);
        total += c;
        if (c < 10000) break;
    }
    exec(db, "PRAGMA wal_checkpoint(TRUNCATE);");
    printf("del : %ld lignes supprimées (%.1f %%) en %.1f s\n", total, 100.0 * total / (double)n, maintenant() - t0);
    imprimer_tailles(db, "apres purge");
    sqlite3_close(db);
}

/* ------------------------------------------------------------------ compaction */
static void demarrer_echantillon(pthread_t *fil) {
    wal_max = 0;
    rss_max = rss_ko();
    echantillonne = 1;
    pthread_create(fil, NULL, fil_echantillon, NULL);
}
static void arreter_echantillon(pthread_t fil) {
    echantillonne = 0;
    pthread_join(fil, NULL);
}

/* `sqlite3_memory_highwater(1)` REMET LE PIC À LA VALEUR COURANTE, pas à zéro. Lire le pic seul
 * ferait passer pour « coût de la fusion » un cache de pages déjà rempli par le scan précédent.
 * On publie donc les TROIS nombres : occupé AVANT, pic, occupé APRÈS — le coût propre de
 * l'opération est (pic − occupé avant). `sans_prescan` permet en outre de partir cache FROID. */
static int sans_prescan(void) {
    const char *v = getenv("BANC_SANS_PRESCAN");
    return v && *v == '1';
}

static void cmd_opt(const char *chemin) {
    sqlite3 *db = ouvrir(chemin);
    if (!sans_prescan()) imprimer_tailles(db, "avant optimize");
    sqlite3_int64 avant = octets_objet(db, "event_fts_data");
    pthread_t fil;
    long rss0 = rss_ko();
    sqlite3_int64 occupe0 = sqlite3_memory_used();
    sqlite3_memory_highwater(1);
    demarrer_echantillon(&fil);
    double t0 = maintenant();
    exec(db, "INSERT INTO event_fts(event_fts) VALUES('optimize')");
    double dt = maintenant() - t0;
    arreter_echantillon(fil);
    sqlite3_int64 pic = sqlite3_memory_highwater(0);
    sqlite3_int64 occupe1 = sqlite3_memory_used();
    printf("OPTIMIZE : %.2f s | WAL pic %.1f Mio | sqlite occupe %.1f -> pic %.1f -> %.1f Mio (COUT PROPRE %.2f Mio) | RSS %ld -> %ld Kio\n",
           dt, wal_max / 1048576.0, occupe0 / 1048576.0, pic / 1048576.0, occupe1 / 1048576.0,
           (pic - occupe0) / 1048576.0, rss0, rss_max);
    exec(db, "PRAGMA wal_checkpoint(TRUNCATE);");
    imprimer_tailles(db, "apres optimize");
    sqlite3_int64 apres = octets_objet(db, "event_fts_data");
    printf("RENDU event_fts_data : %lld -> %lld o (%+.1f %%)\n",
           (long long)avant, (long long)apres, 100.0 * (apres - avant) / (double)avant);
    sqlite3_close(db);
}

static void cmd_merge(const char *chemin, int npages, int passes_max, int usermerge) {
    sqlite3 *db = ouvrir(chemin);
    if (usermerge > 0) {
        char sql[128];
        snprintf(sql, sizeof sql, "INSERT INTO event_fts(event_fts, rank) VALUES('usermerge', %d)", usermerge);
        exec(db, sql);
        printf("usermerge=%d posé\n", usermerge);
    }
    if (!sans_prescan()) imprimer_tailles(db, "avant merge");
    sqlite3_int64 avant = octets_objet(db, "event_fts_data");
    char sql[128];
    snprintf(sql, sizeof sql, "INSERT INTO event_fts(event_fts, rank) VALUES('merge', %d)", npages);
    pthread_t fil;
    sqlite3_int64 occupe0 = sqlite3_memory_used();
    sqlite3_memory_highwater(1);
    demarrer_echantillon(&fil);
    double t0 = maintenant();
    int passe = 0, utiles = 0;
    double pire_passe = 0;
    for (passe = 1; passe <= passes_max; passe++) {
        int avant_ch = sqlite3_total_changes(db);
        double p0 = maintenant();
        exec(db, sql);
        double pdt = maintenant() - p0;
        if (pdt > pire_passe) pire_passe = pdt;
        int delta = sqlite3_total_changes(db) - avant_ch;
        /* FTS5 : total_changes +1 = rien à faire ; +2 ou plus = du travail a été fait. */
        if (delta <= 1) {
            printf("  passe %d : AUCUN TRAVAIL (delta_changes=%d) -> convergé\n", passe, delta);
            break;
        }
        utiles++;
        if (passe <= 8 || passe % 25 == 0)
            printf("  passe %-3d : %6.3f s  delta_changes=%-6d  data=%8.2f Mio  seg=%lld  WAL=%.1f Mio\n",
                   passe, pdt, delta, octets_objet(db, "event_fts_data") / 1048576.0,
                   (long long)scalaire(db, "SELECT COUNT(DISTINCT segid) FROM event_fts_idx"),
                   wal_max / 1048576.0);
    }
    double dt = maintenant() - t0;
    arreter_echantillon(fil);
    sqlite3_int64 pic = sqlite3_memory_highwater(0);
    printf("MERGE(%d) : %d passes utiles / %d | total %.2f s | pire passe %.3f s | WAL pic %.1f Mio | sqlite occupe %.1f -> pic %.1f Mio (COUT PROPRE %.2f Mio) | RSS max %ld Kio\n",
           npages, utiles, passe, dt, pire_passe, wal_max / 1048576.0,
           occupe0 / 1048576.0, pic / 1048576.0, (pic - occupe0) / 1048576.0, rss_max);
    exec(db, "PRAGMA wal_checkpoint(TRUNCATE);");
    imprimer_tailles(db, "apres merge");
    sqlite3_int64 apres = octets_objet(db, "event_fts_data");
    printf("RENDU event_fts_data : %lld -> %lld o (%+.1f %%)\n",
           (long long)avant, (long long)apres, 100.0 * (apres - avant) / (double)avant);
    sqlite3_close(db);
}

/* ------------------------------------------------------------------ interruption brutale */
struct tueur { int ms; };
static void *fil_tueur(void *a) {
    struct tueur *t = a;
    usleep(t->ms * 1000);
    fprintf(stderr, "  [tueur] _exit(9) a %d ms — aucun commit, aucun close\n", t->ms);
    _exit(9);
}

static void cmd_killopt(const char *chemin, int ms) {
    sqlite3 *db = ouvrir(chemin);
    pthread_t f;
    static struct tueur t;
    t.ms = ms;
    pthread_create(&f, NULL, fil_tueur, &t);
    exec(db, "INSERT INTO event_fts(event_fts) VALUES('optimize')");
    printf("optimize TERMINÉ avant le tueur (augmenter le délai)\n");
    sqlite3_close(db);
}

static void cmd_check(const char *chemin) {
    sqlite3 *db = ouvrir(chemin);
    imprimer_tailles(db, "apres interruption");
    double t0 = maintenant();
    char *err = NULL;
    int rc = sqlite3_exec(db, "INSERT INTO event_fts(event_fts) VALUES('integrity-check')", NULL, NULL, &err);
    printf("integrity-check FTS5 : %s (%.1f s)\n", rc == SQLITE_OK ? "OK" : (err ? err : "ECHEC"), maintenant() - t0);
    printf("PRAGMA integrity_check : %lld\n", (long long)scalaire(db, "SELECT CASE WHEN (SELECT * FROM pragma_integrity_check)='ok' THEN 1 ELSE 0 END"));
    sqlite3_stmt *st = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM event_fts WHERE event_fts MATCH 'accepted'", -1, &st, NULL);
    if (rc == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
        printf("MATCH 'accepted' : %lld lignes\n", (long long)sqlite3_column_int64(st, 0));
    else
        printf("MATCH 'accepted' : ECHEC (%s)\n", sqlite3_errmsg(db));
    sqlite3_finalize(st);
    sqlite3_close(db);
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: banc_fts <cmd> ...\n"); return 2; }
    if (!strcmp(argv[1], "version")) {
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        printf("sqlite_version=%s source=%s\n", sqlite3_libversion(), sqlite3_sourceid());
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, "PRAGMA cipher_version", -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
            printf("cipher_version=%s\n", sqlite3_column_text(st, 0));
        else printf("cipher_version=ABSENT (l'instrument N'EST PAS SQLCipher)\n");
        sqlite3_finalize(st);
        printf("fts5=%s\n", sqlite3_exec(db, "CREATE VIRTUAL TABLE t USING fts5(a)", NULL, NULL, NULL) == SQLITE_OK ? "OUI" : "NON");
        printf("dbstat=%s\n", sqlite3_exec(db, "SELECT * FROM dbstat LIMIT 0", NULL, NULL, NULL) == SQLITE_OK ? "OUI" : "NON");
        sqlite3_close(db);
        return 0;
    }
    if (argc < 3) { fprintf(stderr, "usage: banc_fts <cmd> <db> ...\n"); return 2; }
    const char *db = argv[2];
    if (!strcmp(argv[1], "build")) cmd_build(db, atol(argv[3]), strtoull(argv[4], NULL, 10));
    else if (!strcmp(argv[1], "sizes")) cmd_sizes(db);
    else if (!strcmp(argv[1], "del")) cmd_del(db, atof(argv[3]));
    else if (!strcmp(argv[1], "opt")) cmd_opt(db);
    else if (!strcmp(argv[1], "merge")) cmd_merge(db, atoi(argv[3]), atoi(argv[4]), argc > 5 ? atoi(argv[5]) : 0);
    else if (!strcmp(argv[1], "killopt")) cmd_killopt(db, atoi(argv[3]));
    else if (!strcmp(argv[1], "check")) cmd_check(db);
    else { fprintf(stderr, "commande inconnue %s\n", argv[1]); return 2; }
    return 0;
}
