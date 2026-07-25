#!/usr/bin/env python3
# Plume relais/collecteur HOST (OPT-IN, LONG-RUNNING) : telemetrie d'acces objet MinIO -> source=minio-audit.
#
# POURQUOI : aujourd'hui une suppression de backup (ransomware/insider) n'est detectee par RIEN. Ce relais
# rend les operations objet MinIO (surtout DELETE/GET sur example-backups / velero-backups) interrogeables dans
# Plume avec {bucket, object, api, accessKey, src_ip, status, request_id} et une severite ELEVEE sur les DELETE.
#
# MECANISME :
#   MinIO (pod) --audit_webhook--> ce relais (HOST, bind cni0 10.42.0.1)  --reformate--> /var/lib/plume/spool
#                                                                          --ship.sh(mTLS)--> plume /api/ingest
#   - Le hop webhook est pod->hote sur le bridge interne cni0 (jamais expose en public) : metadata d'audit
#     (pas de secret/credential) en clair, authentifie par un Bearer token partage (MinIO auth_token).
#   - Le hop relais->Plume REUTILISE ship.sh (mTLS via votre ingress) : vos NetworkPolicies d'ingress vers
#     le daemon restent INTACTES, aucun nouveau certificat, aucun rebuild daemon.
#   - Reversible : `systemctl disable --now plume-minio-audit` + `mc admin config reset local audit_webhook:plume`.
#   - Durabilite : cote MinIO on pose queue_dir -> si le relais/Plume est down, MinIO bufferise et rejoue
#     (pas de trou dans la piste d'audit, contrairement a un `mc admin trace` qui perd les events hors fenetre).
#
# DEUX CHEMINS POSSIBLES — pourquoi ce relais existe. Le daemon expose aussi un endpoint natif
# (POST /api/ingest/minio) sur lequel MinIO peut poster son audit_webhook EN DIRECT, sans relais. Le
# direct suppose que le pod MinIO puisse presenter un cert client mTLS et faire confiance a votre CA
# interne : selon le chart / l'image utilises, cela demande de MONTER des certs dans le pod, donc un
# REDEMARRAGE de MinIO et une fenetre de maintenance. Ce relais HOST evite ce redemarrage (le hop
# pod->hote reste sur le bridge interne, et le hop relais->Plume reutilise ship.sh + mTLS), au prix
# d'un service supplementaire a exploiter. Choisissez selon vos contraintes : direct si vous pouvez
# redemarrer MinIO et gerer ses certs, relais sinon.
#
# ----------------------------------------------------------------------------------------------------------
# FORMAT NATIF recu de MinIO (audit_webhook, batch_size=1 -> 1 objet JSON par POST ; tolere aussi array /
# ND-JSON). Capture REELLE (MinIO DEVELOPMENT.2025-03-12). >>> a repercuter dans le parseur daemon <<< si un jour
# MinIO poste en direct sur /api/ingest via mTLS (option preferee de la roadmap) :
#   {
#     "version":"1","deploymentid":"<uuid>","time":"2026-06-28T05:46:28.007Z","event":"","trigger":"incoming",
#     "api":{ "name":"DeleteObject", "bucket":"example-backups", "object":"<key>",
#             "status":"OK", "statusCode":204, "rx":..,"tx":.. },
#     "remotehost":"10.42.0.5",          # IP cliente (src_ip) ; "[::1]" si op intra-pod
#     "requestID":"18BD28870CA90E93",    # request_id (idempotence : dedup)
#     "userAgent":"MinIO (linux; amd64) minio-go/...",
#     "requestPath":"/example-backups/<key>", "requestHost":"localhost:9000",
#     "requestQuery":{ "versionId":"<uuid>" },   # present => suppression de VERSION
#     "requestHeader":{...}, "responseHeader":{...},
#     "accessKey":"example-backup"         # credential MinIO utilise (attribution WHO)
#   }
# Champs cles : api.name | api.bucket | api.object | api.status | api.statusCode | remotehost | requestID |
#               accessKey | requestQuery.versionId | time.
#
# EVENT Plume PRODUIT (source=minio-audit, category=data). fields = ce sur quoi votre REGLE doit matcher :
#   { "bucket","object","api","accessKey","src_ip","status","statusCode","request_id","user_agent",
#     "version_delete" ("1" si suppression de version) }
#   severity : DELETE*/DeleteBucket/suppression de version = 4 ; GetObject = 3 ; Put/Copy/Multipart = 2 ; autre = 1.
# REGLE SUGGEREE (a creer dans Detection) : source=minio-audit AND api ~ ^Delete AND bucket IN
#   (example-backups,velero-backups)  -> alerte HIGH "backup object/version supprime". Variante GET (exfil) sur
#   les memes buckets -> MEDIUM. Variante status=AccessDenied sur un Delete -> tentative de tamper.
# ----------------------------------------------------------------------------------------------------------
#
# OPT-IN, tourne en User=soc (non-root), bind sur cni0 uniquement. Aucune dependance hors stdlib.
import json
import os
import socket
import sys
import time
import zlib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SPOOL = os.environ.get("PLUME_SPOOL", "/var/lib/plume/spool")
BIND = os.environ.get("PLUME_MINIO_AUDIT_BIND", "10.42.0.1")  # cni0 (pod-facing only) ; PAS 0.0.0.0
PORT = int(os.environ.get("PLUME_MINIO_AUDIT_PORT", "9099"))
TOKEN_FILE = os.environ.get("PLUME_MINIO_AUDIT_TOKEN_FILE", "/etc/plume/minio-audit.token")
# Buckets a remonter (CSV). Vide => TOUS. Defaut = backups (scope haute-valeur, faible volume).
_b = os.environ.get("PLUME_MINIO_AUDIT_BUCKETS", "example-backups,velero-backups").strip()
BUCKETS = {x.strip() for x in _b.split(",") if x.strip()} if _b else set()
MAXBODY = int(os.environ.get("PLUME_MINIO_AUDIT_MAXBODY", str(1 << 20)))  # 1 MiB/req garde-fou
MAXEVENTS = int(os.environ.get("PLUME_MINIO_AUDIT_MAXEVENTS", "500"))     # evts/req garde-fou
HOSTNAME = socket.gethostname()

# Ops "bruit" (metadata/list/head) IGNOREES par defaut : velero liste velero-backups en boucle (~toutes
# les 35s) -> noyer Plume pour rien (cf. directive "optimiser, pas grossir Plume"). Les ops de DONNEES
# (Get/Put/Delete/Copy/version) ET les changements d'object-lock/retention (prep tamper) restent TOUJOURS
# captures. Mettre PLUME_MINIO_AUDIT_DROP_APIS="" pour TOUT capturer (ex. detecter la recon par List).
_drop = os.environ.get("PLUME_MINIO_AUDIT_DROP_APIS",
    "ListObjects,ListObjectsV2,ListObjectVersions,ListBuckets,ListMultipartUploads,HeadObject,HeadBucket,"
    "GetBucketLocation,GetBucketObjectLockConfig,GetBucketVersioning,GetBucketPolicy,GetBucketTagging,"
    "GetBucketLifecycle,GetBucketReplication,GetBucketEncryption,GetBucketNotification,GetBucketCors,"
    "GetObjectTagging,StatObject")
DROP_APIS = {x.strip() for x in _drop.split(",") if x.strip()}

DELETE_APIS = {
    "DeleteObject", "DeleteObjects", "DeleteMultipleObjects", "DeleteObjectVersion",
    "DeleteObjectTagging", "DeleteBucket", "DeleteBucketTagging",
}
PUT_APIS = {
    "PutObject", "CopyObject", "CompleteMultipartUpload", "NewMultipartUpload",
    "PutObjectTagging", "PutObjectRetention", "PutObjectLegalHold", "PostPolicyBucket",
}


def expected_auth():
    try:
        with open(TOKEN_FILE, "r") as f:
            tok = f.read().strip()
        return ("Bearer " + tok) if tok else ""
    except OSError:
        return ""


def to_epoch(s):
    if not s:
        return int(time.time())
    try:
        s2 = s.replace("Z", "+00:00")
        # tronque les nanosecondes -> microsecondes pour fromisoformat
        if "." in s2:
            head, frac = s2.split(".", 1)
            tzpart = ""
            for sep in ("+", "-"):
                i = frac.find(sep)
                if i > 0:
                    frac, tzpart = frac[:i], frac[i:]
                    break
            frac = frac[:6]
            s2 = f"{head}.{frac}{tzpart}"
        return int(datetime.fromisoformat(s2).timestamp())
    except Exception:
        return int(time.time())


def jesc(v):
    return json.dumps("" if v is None else str(v))


def sev_for(api, version_delete):
    if version_delete or api in DELETE_APIS:
        return 4
    if api == "GetObject":
        return 3
    if api in PUT_APIS:
        return 2
    return 1


def record_to_event(rec):
    api_o = rec.get("api") or {}
    api = api_o.get("name", "") or ""
    bucket = api_o.get("bucket", "") or ""
    obj = api_o.get("object", "") or ""
    status = api_o.get("status", "") or ""
    code = api_o.get("statusCode", "")
    src = (rec.get("remotehost", "") or "").strip("[]")  # [::1] -> ::1
    reqid = rec.get("requestID", "") or ""
    ak = rec.get("accessKey", "") or ""
    ua = rec.get("userAgent", "") or ""
    q = rec.get("requestQuery") or {}
    version_delete = bool(q.get("versionId")) and api in DELETE_APIS
    # scope : buckets backups par defaut ; on ignore les events admin/sans bucket
    if BUCKETS and bucket not in BUCKETS:
        return None
    if not bucket:
        return None
    # bruit metadata/list/head (velero poll en boucle) ignore par defaut
    if api in DROP_APIS:
        return None
    sev = sev_for(api, version_delete)
    vtag = " VERSION-DELETE" if version_delete else ""
    msg = (f"minio-audit {api} {bucket}/{obj} status={status} code={code} "
           f"ak={ak} src={src} req={reqid}{vtag}")
    fields = {
        "bucket": bucket, "object": obj, "api": api, "accessKey": ak,
        "src_ip": src, "status": status, "statusCode": str(code),
        "request_id": reqid, "user_agent": ua,
    }
    if version_delete:
        fields["version_delete"] = "1"
    ev = {
        "ts": to_epoch(rec.get("time")),
        "source": "minio-audit", "category": "data", "severity": sev,
        "message": msg,
        # dedup = requestID -> idempotent si MinIO rejoue via queue_dir
        "dedup": f"minioaudit-{reqid}" if reqid else f"minioaudit-{api}-{bucket}-{obj}",
        "fields": fields,
    }
    if src:
        ev["src_ip"] = src
    return ev


def parse_body(raw):
    """Tolere : 1 objet JSON, un array JSON, ou du ND-JSON (1 objet/ligne)."""
    raw = raw.strip()
    if not raw:
        return []
    try:
        v = json.loads(raw)
        return v if isinstance(v, list) else [v]
    except json.JSONDecodeError:
        out = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return out


_seq = [0]


def write_spool(events):
    if not events:
        return
    _seq[0] += 1
    ts = int(time.time())
    env = {"ts": ts, "host": HOSTNAME, "kind": "events", "events": events}
    tmp = os.path.join(SPOOL, f".minio-audit-{ts}-{os.getpid()}-{_seq[0]}.tmp")
    dst = os.path.join(SPOOL, f"minio-audit-{ts}-{os.getpid()}-{_seq[0]}.json")
    with open(tmp, "w") as f:
        json.dump(env, f, separators=(",", ":"))
    os.chmod(tmp, 0o640)
    os.rename(tmp, dst)


class Handler(BaseHTTPRequestHandler):
    server_version = "plume-minio-audit/1"

    def _reply(self, code, body=b"ok"):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):  # healthcheck
        self._reply(200, b"plume-minio-audit ok\n")

    def do_POST(self):
        exp = expected_auth()
        if exp and self.headers.get("Authorization", "") != exp:
            self._reply(401, b"unauthorized\n")
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n <= 0 or n > MAXBODY:
            self._reply(413, b"bad length\n")
            return
        try:
            raw = self.rfile.read(n).decode("utf-8", "replace")
        except Exception:
            self._reply(400, b"read error\n")
            return
        events = []
        for rec in parse_body(raw):
            if not isinstance(rec, dict):
                continue
            try:
                ev = record_to_event(rec)
            except Exception:
                ev = None
            if ev is not None:
                events.append(ev)
                if len(events) >= MAXEVENTS:
                    break
        try:
            write_spool(events)
        except Exception as e:
            sys.stderr.write(f"plume-minio-audit: spool write error: {e}\n")
            self._reply(500, b"spool error\n")
            return
        self._reply(200)

    def log_message(self, *a):  # pas de bruit dans le journal (1 ligne/req sinon)
        pass


def write_config_report():
    # CHANTIER whitelists->webui : AUTO-REPORT de config (source=minio-audit category=config).
    # Surface PLUME_MINIO_AUDIT_DROP_APIS dans le panneau read-only « Suppressions & whitelists actives ».
    # VISIBILITE cote daemon, CONTROLE ici (frontiere hote). collection-reducing (drop des APIs read-noise).
    # Emis au demarrage (config statique du process) ; dedup par empreinte -> pas de doublon a l'ingest.
    ts = int(time.time())
    fields = {
        "type": "collection-reducing",
        "collector": "minio-audit",
        "filters": {"drop_apis": sorted(DROP_APIS), "buckets": sorted(BUCKETS) or "ALL"},
        "note": "drop les APIs read-noise (List*/Head*/Get*/Stat*) — mettre DROP_APIS=\"\" pour tout capturer. collecte reduite",
    }
    dd = "cfg-minio-audit-%d" % (zlib.crc32(json.dumps(fields, sort_keys=True).encode()) & 0xffffffff)
    ev = {"ts": ts, "source": "minio-audit", "category": "config", "severity": 0,
          "message": "config collecteur minio-audit (filtres de collecte)", "dedup": dd, "fields": fields}
    env = {"ts": ts, "host": HOSTNAME, "kind": "events", "events": [ev]}
    tmp = os.path.join(SPOOL, f".config-minio-audit-{ts}-{os.getpid()}.tmp")
    dst = os.path.join(SPOOL, f"config-minio-audit-{ts}-{os.getpid()}.json")
    try:
        with open(tmp, "w") as f:
            json.dump(env, f, separators=(",", ":"))
        os.chmod(tmp, 0o640)
        os.rename(tmp, dst)
    except Exception as e:
        sys.stderr.write(f"plume-minio-audit: config report write error: {e}\n")


def main():
    os.makedirs(SPOOL, exist_ok=True)
    if not expected_auth():
        sys.stderr.write("plume-minio-audit: WARNING aucun token (%s vide/absent) -> relais OUVERT.\n" % TOKEN_FILE)
    write_config_report()  # surface les filtres DROP_APIS au panneau Suppressions (read-only)
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    sys.stderr.write(f"plume-minio-audit: ecoute http://{BIND}:{PORT}/ buckets={sorted(BUCKETS) or 'ALL'} -> {SPOOL}\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
