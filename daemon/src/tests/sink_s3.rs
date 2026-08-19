// ================================================================================================
// SINK OBJET COMPATIBLE S3 DE L'ORDONNANCEUR DE SAUVEGARDE — feature `s3_backup`.
//
// TOUS les tests de ce fichier sont gated `#[cfg(feature = "s3_backup")]` : la suite par DÉFAUT
// n'en compile aucun et son compte ne bouge pas. C'est l'invariant « mode 0 » du dépôt, et c'est
// aussi la preuve la plus simple que la feature n'ajoute rien au binaire livré par défaut.
//
// CE QUE CES TESTS CHERCHENT À METTRE EN DÉFAUT, dans l'ordre d'importance :
//   1. UN ENVOI RATÉ ANNONCÉ COMME RÉUSSI. C'est la famille de défauts que ce dépôt poursuit, et
//      elle a ici quatre portes distinctes — le service refuse ; le service accepte puis ne relit
//      pas ; le service accepte puis relit un objet d'une AUTRE taille ; rien ne répond. Les quatre
//      sont exercées, et aucune ne doit rendre `est_depose()`.
//   2. UNE SIGNATURE FAUSSE, qui ne se verrait qu'en production contre un vrai service. Elle est
//      opposée à un ORACLE INDÉPENDANT (cf. le bloc de vecteurs ci-dessous), pas à elle-même.
//   3. UN SECRET DANS UNE LIGNE DE JOURNAL. Le type interdit la fuite ; le test la CHERCHE quand
//      même, sur les chaînes réellement produites par les chemins d'échec.
//
// AUCUN SERVICE RÉEL n'est joint : un `TcpListener` sur la boucle locale joue le service objet, et
// il est SCRIPTÉ — il rend ce que le test veut éprouver, y compris des réponses malhonnêtes qu'un
// vrai service ne rendrait pas. C'est précisément ce qu'un test contre un vrai service ne peut pas
// faire.
// ================================================================================================

// ── VECTEURS DE CONFORMITÉ ──────────────────────────────────────────────────────────────────────
// Les valeurs attendues ci-dessous n'ont PAS été produites par le code testé. Elles ont été
// calculées le 2026-08-19 par `botocore` 1.42.91 (`botocore.auth.SigV4Auth` /
// `botocore.auth.S3SigV4Auth`), implémentation tierce de la signature v4, avec un horodatage figé.
// Un oracle indépendant est ce qui distingue « les deux moitiés de mon code sont d'accord » de
// « ma signature est celle que le protocole définit » : une erreur de conception (mauvais ordre des
// en-têtes, portée mal composée, clé dérivée dans le mauvais sens) passerait le premier contrôle et
// échoue au second. Les vecteurs couvrent aussi ce qui diffère d'un fournisseur à l'autre : un hôte
// sans port explicite et un hôte AVEC port, un envoi et une relecture, avec et sans jeton de session.
//
// La matière employée ici est une chaîne de dictionnaire, sans entropie et sans forme
// d'identifiant : ce n'est pas un secret masqué, c'est une valeur-témoin.

#[cfg(feature = "s3_backup")]
const V4_ACCES: &str = "temoin-acces-v4";
#[cfg(feature = "s3_backup")]
const V4_MATIERE: &str = "matiere-de-signature-v4-temoin";
#[cfg(feature = "s3_backup")]
const V4_JETON: &str = "jeton-de-session-temoin";
#[cfg(feature = "s3_backup")]
const V4_REGION: &str = "region-temoin";
#[cfg(feature = "s3_backup")]
const V4_HORODATAGE: &str = "20260819T101500Z";

// ── HARNAIS : UN SERVICE OBJET FACTICE, SCRIPTÉ ─────────────────────────────────────────────────

/// Ce que le service factice a REÇU. Sert à prouver que l'octet envoyé est bien l'octet du fichier
/// et que la requête porte les en-têtes que la signature couvre.
#[cfg(feature = "s3_backup")]
struct EchangeRecu {
    methode: String,
    chemin: String,
    entetes: Vec<(String, String)>,
    corps: Vec<u8>,
}

#[cfg(feature = "s3_backup")]
impl EchangeRecu {
    fn entete(&self, nom: &str) -> Option<&str> {
        self.entetes.iter().find(|(k, _)| k.eq_ignore_ascii_case(nom)).map(|(_, v)| v.as_str())
    }
}

/// Une réponse SCRIPTÉE. `fermer_sans_repondre` fabrique le cas « la socket s'ouvre, la requête
/// part, et rien ne revient » — c'est-à-dire un état distant INCONNU, qui doit se dire et non se
/// deviner.
#[cfg(feature = "s3_backup")]
struct ReponseScriptee {
    statut: u16,
    entetes: Vec<(&'static str, String)>,
    fermer_sans_repondre: bool,
}

#[cfg(feature = "s3_backup")]
impl ReponseScriptee {
    fn ok(statut: u16, entetes: Vec<(&'static str, String)>) -> Self {
        ReponseScriptee { statut, entetes, fermer_sans_repondre: false }
    }
    fn muette() -> Self {
        ReponseScriptee { statut: 0, entetes: Vec::new(), fermer_sans_repondre: true }
    }
}

#[cfg(feature = "s3_backup")]
struct ServiceFactice {
    port: u16,
    recus: std::sync::Arc<std::sync::Mutex<Vec<EchangeRecu>>>,
}

#[cfg(feature = "s3_backup")]
impl ServiceFactice {
    fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
    fn recus(&self) -> std::sync::MutexGuard<'_, Vec<EchangeRecu>> {
        self.recus.lock().expect("journal du service factice")
    }
}

/// Démarre le service factice. Il sert EXACTEMENT `reponses.len()` connexions, dans l'ordre, puis
/// relâche l'écoute — une requête de plus obtient donc un refus de connexion, ce qui est aussi un
/// cas à éprouver.
#[cfg(feature = "s3_backup")]
fn service_factice(reponses: Vec<ReponseScriptee>) -> ServiceFactice {
    use std::io::{Read, Write};
    let ecoute = std::net::TcpListener::bind("127.0.0.1:0").expect("écoute locale");
    let port = ecoute.local_addr().expect("adresse locale").port();
    let recus = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let journal = recus.clone();
    std::thread::spawn(move || {
        for rep in reponses {
            let Ok((mut sock, _)) = ecoute.accept() else { return };
            let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(15)));
            let _ = sock.set_write_timeout(Some(std::time::Duration::from_secs(15)));

            // Tête : on lit octet par octet jusqu'à la ligne vide (jamais au-delà, sinon on
            // mangerait le corps).
            let mut tete = Vec::new();
            let mut octet = [0u8; 1];
            while !tete.ends_with(b"\r\n\r\n") {
                match sock.read(&mut octet) {
                    Ok(1) => tete.push(octet[0]),
                    _ => break,
                }
            }
            let texte = String::from_utf8_lossy(&tete).into_owned();
            let mut lignes = texte.split("\r\n");
            let demande = lignes.next().unwrap_or("").to_string();
            let mut mots = demande.split_whitespace();
            let methode = mots.next().unwrap_or("").to_string();
            let chemin = mots.next().unwrap_or("").to_string();
            let mut entetes: Vec<(String, String)> = Vec::new();
            for l in lignes {
                if l.is_empty() {
                    continue;
                }
                if let Some((k, v)) = l.split_once(':') {
                    entetes.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
            let longueur: usize = entetes
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            let mut corps = vec![0u8; longueur];
            if longueur > 0 {
                let _ = sock.read_exact(&mut corps);
            }
            journal
                .lock()
                .expect("journal du service factice")
                .push(EchangeRecu { methode, chemin, entetes, corps });

            if rep.fermer_sans_repondre {
                let _ = sock.shutdown(std::net::Shutdown::Both);
                continue;
            }
            let mut sortie = format!("HTTP/1.1 {} REPONSE\r\n", rep.statut);
            for (k, v) in &rep.entetes {
                sortie.push_str(&format!("{k}: {v}\r\n"));
            }
            sortie.push_str("Connection: close\r\n\r\n");
            let _ = sock.write_all(sortie.as_bytes());
            let _ = sock.flush();
            let _ = sock.shutdown(std::net::Shutdown::Both);
        }
    });
    ServiceFactice { port, recus }
}

/// Une cible qui pointe sur le service factice. Style CHEMIN (celui des passerelles auto-hébergées),
/// aucun jeton de session.
#[cfg(feature = "s3_backup")]
fn cible_factice(endpoint: &str, prefixe: &str) -> crate::sink_s3::CibleS3 {
    crate::sink_s3::CibleS3::neuve(
        endpoint.to_string(),
        V4_REGION.to_string(),
        "sauvegardes".to_string(),
        prefixe.to_string(),
        V4_ACCES.to_string(),
        crate::sink_s3::Matiere::neuve(V4_MATIERE),
        None,
        true,
    )
}

/// Écrit un fichier d'épreuve et rend son chemin. Le contenu est BINAIRE (octets 0..=255 répétés),
/// pas du texte : une troncature ou une transformation en route se verrait.
#[cfg(feature = "s3_backup")]
fn fichier_epreuve(dir: &crate::tmp_possede::TmpPossede, nom: &str, octets: usize) -> Vec<u8> {
    let contenu: Vec<u8> = (0..octets).map(|i| (i % 256) as u8).collect();
    std::fs::write(dir.sous(nom).chemin(), &contenu).expect("écriture du fichier d'épreuve");
    contenu
}

// ── 1. LA SIGNATURE, OPPOSÉE À UN ORACLE INDÉPENDANT ────────────────────────────────────────────

/// L'ENVOI. Requête canonique, chaîne à signer, signature et en-tête d'autorisation sont comparés
/// AUX QUATRE valeurs de l'oracle — pas seulement à la dernière. Une divergence dit alors LAQUELLE
/// des quatre étapes a bougé, ce qu'une comparaison du seul résultat final ne dirait pas.
#[cfg(feature = "s3_backup")]
#[test]
fn sink_s3_signature_de_depot_egale_un_oracle_independant() {
    let charge = b"charge-de-test";
    let empreinte = crate::sha256_hex(charge);
    assert_eq!(
        empreinte, "626fe0ca566970edd9b1a2732c5d2f6ddd4b0252b12a271cdd7de1db39677050",
        "l'empreinte de la charge d'épreuve est elle-même un vecteur : si elle bouge, la comparaison \
         qui suit ne prouve plus rien"
    );
    let entetes = vec![
        ("x-amz-content-sha256".to_string(), empreinte.clone()),
        ("x-amz-date".to_string(), V4_HORODATAGE.to_string()),
    ];
    let sig = crate::sink_s3::signer_v4(
        "PUT",
        "/sauvegardes/plume/plume-20260819T101500Z.db.age",
        "",
        "objets.exemple.invalid",
        V4_HORODATAGE,
        V4_REGION,
        V4_ACCES,
        &crate::sink_s3::Matiere::neuve(V4_MATIERE),
        &entetes,
        &empreinte,
    )
    .expect("signature");

    let canonique_attendue = format!(
        "PUT\n/sauvegardes/plume/plume-20260819T101500Z.db.age\n\n\
         host:objets.exemple.invalid\n\
         x-amz-content-sha256:{empreinte}\n\
         x-amz-date:{V4_HORODATAGE}\n\n\
         host;x-amz-content-sha256;x-amz-date\n{empreinte}"
    );
    assert_eq!(sig.canonique, canonique_attendue, "requête canonique");
    assert_eq!(
        sig.a_signer,
        format!(
            "AWS4-HMAC-SHA256\n{V4_HORODATAGE}\n20260819/{V4_REGION}/s3/aws4_request\n\
             d5ef327366c06ee65b90d2d932b135c4ef6cf17f2b88958986bce28d0db4bf4e"
        ),
        "chaîne à signer"
    );
    assert_eq!(
        sig.signature, "72cbbf2a2962d4f6f156533bf582d7af6b0b0977617c734c9e5f207f71145ad6",
        "signature"
    );
    assert_eq!(
        sig.autorisation,
        format!(
            "AWS4-HMAC-SHA256 Credential={V4_ACCES}/20260819/{V4_REGION}/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=72cbbf2a2962d4f6f156533bf582d7af6b0b0977617c734c9e5f207f71145ad6"
        ),
        "en-tête d'autorisation"
    );
}

/// LA RELECTURE, sur un hôte À PORT EXPLICITE et AVEC jeton de session — les deux différences que
/// présente un service auto-hébergé par rapport au cas précédent.
///
/// Ce test porte en outre une CONTRE-ÉPREUVE de conception : les en-têtes sont fournis dans le
/// DÉSORDRE, et la signature obtenue doit être la même. Le tri est donc bien fait par le code et non
/// hérité de l'ordre d'écriture — une propriété qu'un vecteur unique, écrit dans le bon ordre, ne
/// distinguerait pas d'un code qui ne trie rien.
#[cfg(feature = "s3_backup")]
#[test]
fn sink_s3_signature_de_relecture_egale_un_oracle_independant() {
    let vide = crate::sink_s3::SHA256_CHARGE_VIDE;
    assert_eq!(vide, crate::sha256_hex(b""), "la constante d'empreinte vide est bien celle de la charge vide");
    let ordre_desordonne = vec![
        ("x-amz-security-token".to_string(), V4_JETON.to_string()),
        ("x-amz-date".to_string(), V4_HORODATAGE.to_string()),
        ("x-amz-content-sha256".to_string(), vide.to_string()),
    ];
    let sig = crate::sink_s3::signer_v4(
        "HEAD",
        "/sauvegardes/prefixe/plume-20260819T101500Z.db.age",
        "",
        "objets.exemple.invalid:9000",
        V4_HORODATAGE,
        V4_REGION,
        V4_ACCES,
        &crate::sink_s3::Matiere::neuve(V4_MATIERE),
        &ordre_desordonne,
        vide,
    )
    .expect("signature");

    assert_eq!(
        sig.signes, "host;x-amz-content-sha256;x-amz-date;x-amz-security-token",
        "les en-têtes signés sont triés par le code, pas par l'ordre d'appel"
    );
    assert_eq!(
        sig.a_signer,
        format!(
            "AWS4-HMAC-SHA256\n{V4_HORODATAGE}\n20260819/{V4_REGION}/s3/aws4_request\n\
             f54a4bf6e14ffe2366894b264c70b6667b45106d98b06eb3e5aad5d005cfa81b"
        ),
        "chaîne à signer"
    );
    assert_eq!(
        sig.signature, "a299b0c55659319502388328a20a9a919f27a80077f6254246888e10dec1a308",
        "signature"
    );
    assert!(
        sig.canonique.contains("host:objets.exemple.invalid:9000\n"),
        "le port explicite entre dans la chaîne canonique — sinon la signature ne couvre pas l'hôte joint"
    );
}

// ── 2. CE QUI EST REFUSÉ AVANT TOUT RÉSEAU ──────────────────────────────────────────────────────

/// Une destination ou une clé mal formée doit être refusée AVANT qu'une socket s'ouvre. Le test est
/// écrit en deux moitiés : la fonction pure refuse, ET le dépôt complet contre un service factice
/// n'a établi AUCUNE connexion. La seconde moitié est ce qui distingue « le code sait dire non » de
/// « le code dit non au bon moment ».
#[cfg(feature = "s3_backup")]
#[test]
fn sink_s3_destinations_et_cles_invalides_refusees_avant_toute_socket() {
    // Destinations refusées : schéma absent, bucket trop court, bucket majuscule, préfixe remontant.
    for mauvaise in [
        "/data/backups",
        "https://exemple.invalid/bucket",
        "s3://ab",
        "s3://Sauvegardes",
        "s3://sauvegardes/../ailleurs",
        "s3://sauvegardes/pre fixe",
    ] {
        assert!(
            crate::sink_s3::parse_url_s3(mauvaise).is_err(),
            "destination {mauvaise:?} doit être REFUSÉE"
        );
    }
    // Destinations acceptées, et ce qu'elles produisent.
    assert_eq!(
        crate::sink_s3::parse_url_s3("s3://sauvegardes").expect("bucket seul"),
        ("sauvegardes".to_string(), String::new())
    );
    assert_eq!(
        crate::sink_s3::parse_url_s3("s3://sauvegardes/plume/noeud-1/").expect("préfixe"),
        ("sauvegardes".to_string(), "plume/noeud-1".to_string()),
        "la barre finale est retirée — sinon la clé porterait une barre doublée"
    );
    // Clés refusées.
    for mauvaise in ["", "/absolue", "double//barre", "a/../b", "espace dans la clé", "guillemet\""] {
        assert!(
            crate::sink_s3::valider_cle_objet(mauvaise).is_err(),
            "clé {mauvaise:?} doit être REFUSÉE"
        );
    }
    assert!(crate::sink_s3::valider_cle_objet("plume/noeud-1/plume-20260819T101500Z.db.age").is_ok());
    // Sur le jeu admis, l'encodeur de chemin est l'IDENTITÉ — vérifié, pas supposé.
    let cle = "/sauvegardes/plume/plume-20260819T101500Z.db.age";
    assert_eq!(crate::sink_s3::encoder_chemin(cle), cle);
    assert_eq!(crate::sink_s3::encoder_chemin("/a b"), "/a%20b", "hors du jeu admis, l'encodeur échappe");

    // La moitié qui compte : AUCUNE socket. Le service factice est prêt à servir une réponse ; si le
    // dépôt en ouvrait une, son journal ne serait pas vide.
    let service = service_factice(vec![ReponseScriptee::ok(200, vec![])]);
    let dir = crate::tmp_possede::TmpPossede::neuf("s3-cle-invalide");
    fichier_epreuve(&dir, "archive.bin", 32);
    let cible = cible_factice(&service.endpoint(), "prefixe valide"); // préfixe hors du jeu admis
    let issue = crate::sink_s3::deposer_fichier(
        &cible,
        "plume-20260819T101500Z.db.age",
        dir.sous("archive.bin").chemin(),
        V4_HORODATAGE,
    );
    assert!(!issue.est_depose(), "une clé invalide ne peut pas être un dépôt");
    assert!(
        matches!(issue, crate::sink_s3::IssueDepot::Impossible { etape: crate::sink_s3::Etape::Configuration, .. }),
        "refus à l'étape configuration, pas plus loin : {issue}"
    );
    assert!(service.recus().is_empty(), "aucune requête ne doit avoir atteint le service");
}

/// Un réglage incomplet doit ARRÊTER la résolution, jamais produire une cible boiteuse. Chaque pièce
/// manquante est éprouvée SÉPARÉMENT : un test qui n'en retirerait qu'une laisserait les autres
/// gardes invérifiées.
#[cfg(feature = "s3_backup")]
#[test]
fn sink_s3_reglages_incomplets_refuses_piece_par_piece() {
    use crate::sink_s3::*;
    let complet = || {
        let mut m = std::collections::HashMap::new();
        m.insert(CLE_S3_ENDPOINT.to_string(), "http://127.0.0.1:1".to_string());
        m.insert(CLE_S3_REGION.to_string(), V4_REGION.to_string());
        m.insert(CLE_S3_ACCESS.to_string(), V4_ACCES.to_string());
        m.insert(CLE_S3_MATIERE.to_string(), V4_MATIERE.to_string());
        m
    };
    // Témoin POSITIF : complet -> résolution réussie. Sans lui, les refus ci-dessous ne prouveraient
    // pas que le refus vient de la pièce retirée.
    let cible = depuis_reglages(&complet(), "s3://sauvegardes/plume").expect("réglages complets");
    assert_eq!(cible.bucket, "sauvegardes");
    assert_eq!(cible.prefixe, "plume");
    assert!(cible.chemin_style, "style CHEMIN par défaut — le seul qui marche sans DNS par bucket");
    assert_eq!(
        cible.cle_objet("plume-20260819T101500Z.db.age"),
        "plume/plume-20260819T101500Z.db.age"
    );
    assert_eq!(
        cible.chemin_canonique(&cible.cle_objet("plume-20260819T101500Z.db.age")),
        "/sauvegardes/plume/plume-20260819T101500Z.db.age"
    );

    for manquante in [CLE_S3_ENDPOINT, CLE_S3_ACCESS, CLE_S3_MATIERE] {
        let mut m = complet();
        m.remove(manquante);
        let r = depuis_reglages(&m, "s3://sauvegardes/plume");
        assert!(r.is_err(), "{manquante} manquante doit REFUSER la résolution");
        let e = r.err().unwrap();
        assert!(e.contains(manquante), "le refus doit NOMMER la pièce manquante ({manquante}) : {e}");
    }
    // Un endpoint illisible est refusé lui aussi — et il l'est à la résolution, pas au premier cycle.
    let mut m = complet();
    m.insert(CLE_S3_ENDPOINT.to_string(), "127.0.0.1:9000".to_string()); // schéma absent
    assert!(depuis_reglages(&m, "s3://sauvegardes").is_err(), "endpoint sans schéma refusé");
    // Une destination qui n'est pas une destination objet est refusée AVANT de lire un réglage.
    assert!(depuis_reglages(&complet(), "/data/backups").is_err());
}

// ── 3. LE CHEMIN HEUREUX, ET CE QU'IL PROUVE VRAIMENT ───────────────────────────────────────────

/// Dépôt CONFIRMÉ. Au-delà du verdict, ce test vérifie que ce qui est arrivé sur la socket est bien
/// le fichier : mêmes octets, même empreinte annoncée, même longueur — et que la relecture a bien
/// eu lieu (deux échanges, pas un).
#[cfg(feature = "s3_backup")]
#[test]
fn sink_s3_depot_confirme_par_relecture() {
    let dir = crate::tmp_possede::TmpPossede::neuf("s3-depot-ok");
    let contenu = fichier_epreuve(&dir, "archive.bin", 200_000);
    let taille = contenu.len() as u64;
    let service = service_factice(vec![
        ReponseScriptee::ok(200, vec![("ETag", "\"etiquette-du-service\"".to_string())]),
        ReponseScriptee::ok(200, vec![("Content-Length", taille.to_string())]),
    ]);
    let cible = cible_factice(&service.endpoint(), "plume/noeud-1");
    let issue = crate::sink_s3::deposer_fichier(
        &cible,
        "plume-20260819T101500Z.db.age",
        dir.sous("archive.bin").chemin(),
        V4_HORODATAGE,
    );
    assert!(issue.est_depose(), "dépôt confirmé attendu, obtenu : {issue}");
    assert_eq!(
        issue,
        crate::sink_s3::IssueDepot::Depose { octets: taille, etiquette: "etiquette-du-service".to_string() },
        "l'issue porte la taille CONFIRMÉE et l'étiquette rendue par le service"
    );
    assert!(format!("{issue}").starts_with("DÉPOSÉ ET CONFIRMÉ"), "ligne d'exploitation sans ambiguïté");

    let recus = service.recus();
    assert_eq!(recus.len(), 2, "un dépôt PUIS une relecture — la confirmation n'est pas facultative");
    assert_eq!(recus[0].methode, "PUT");
    assert_eq!(recus[0].chemin, "/sauvegardes/plume/noeud-1/plume-20260819T101500Z.db.age");
    assert_eq!(recus[0].corps, contenu, "l'octet reçu est l'octet du fichier (aucune troncature)");
    assert_eq!(recus[0].entete("Content-Length"), Some(taille.to_string().as_str()));
    assert_eq!(
        recus[0].entete("x-amz-content-sha256"),
        Some(crate::sha256_hex(&contenu).as_str()),
        "l'empreinte annoncée est celle de la charge réellement envoyée"
    );
    let autorisation = recus[0].entete("Authorization").expect("en-tête d'autorisation");
    assert!(autorisation.starts_with("AWS4-HMAC-SHA256 Credential="), "requête signée : {autorisation}");
    assert_eq!(recus[1].methode, "HEAD", "la relecture est un HEAD (aucun octet retéléchargé)");
    assert_eq!(recus[1].chemin, recus[0].chemin, "on relit EXACTEMENT l'objet qu'on a déposé");
    assert!(recus[1].entete("Content-Length").is_none(), "une relecture n'a pas de corps");
}

// ── 4. LES QUATRE PORTES DU FAUX SUCCÈS ─────────────────────────────────────────────────────────

/// PORTE 1 — le service REFUSE. Un statut non-2xx est un verdict : il doit ressortir en `Refuse`,
/// avec son statut, et surtout PAS en dépôt. La relecture n'a même pas lieu (rien à relire).
#[cfg(feature = "s3_backup")]
#[test]
fn sink_s3_refus_du_service_n_est_jamais_un_depot() {
    let dir = crate::tmp_possede::TmpPossede::neuf("s3-refus");
    fichier_epreuve(&dir, "archive.bin", 4_096);
    let service = service_factice(vec![ReponseScriptee::ok(403, vec![])]);
    let cible = cible_factice(&service.endpoint(), "plume");
    let issue = crate::sink_s3::deposer_fichier(
        &cible,
        "plume-20260819T101500Z.db.age",
        dir.sous("archive.bin").chemin(),
        V4_HORODATAGE,
    );
    assert!(!issue.est_depose(), "403 ne peut pas être un dépôt : {issue}");
    match &issue {
        crate::sink_s3::IssueDepot::Refuse { etape, statut, .. } => {
            assert_eq!(*etape, crate::sink_s3::Etape::Envoi);
            assert_eq!(*statut, 403);
        }
        autre => panic!("refus attendu, obtenu {autre:?}"),
    }
    assert!(format!("{issue}").starts_with("REFUSÉ"), "ligne d'exploitation sans ambiguïté");
    assert_eq!(service.recus().len(), 1, "un refus n'est pas suivi d'une relecture");
}

/// PORTE 2 — LE MENSONGE LE PLUS COÛTEUX. Le service ACCEPTE (200, étiquette comprise), puis la
/// relecture annonce une AUTRE taille : l'objet distant n'est pas l'archive. Un sink qui se
/// contenterait du 2xx annoncerait ici un succès, et la sauvegarde n'existerait pas.
///
/// C'est ce test qui tient la propriété centrale du module. Sa MUTATION est simple à écrire et à
/// exécuter : rendre `Depose` dès le 2xx du dépôt le fait échouer, et lui seul de cette famille.
#[cfg(feature = "s3_backup")]
#[test]
fn sink_s3_confirmation_qui_annonce_une_autre_taille_est_un_refus() {
    let dir = crate::tmp_possede::TmpPossede::neuf("s3-taille");
    let contenu = fichier_epreuve(&dir, "archive.bin", 50_000);
    let tronquee = (contenu.len() - 17).to_string(); // ce que le service prétend avoir stocké
    let service = service_factice(vec![
        ReponseScriptee::ok(200, vec![("ETag", "\"etiquette\"".to_string())]),
        ReponseScriptee::ok(200, vec![("Content-Length", tronquee.clone())]),
    ]);
    let cible = cible_factice(&service.endpoint(), "plume");
    let issue = crate::sink_s3::deposer_fichier(
        &cible,
        "plume-20260819T101500Z.db.age",
        dir.sous("archive.bin").chemin(),
        V4_HORODATAGE,
    );
    assert!(
        !issue.est_depose(),
        "un objet distant de taille DIFFÉRENTE n'est pas la sauvegarde : {issue}"
    );
    let texte = format!("{issue}");
    assert!(texte.starts_with("REFUSÉ"), "ligne d'exploitation : {texte}");
    assert!(
        texte.contains(&tronquee) && texte.contains(&contenu.len().to_string()),
        "le refus nomme LES DEUX tailles — sinon l'exploitant ne peut pas savoir ce qui cloche : {texte}"
    );

    // ET LA MOITIÉ QUI FAIT LA DIFFÉRENCE : la MÊME séquence, avec la BONNE taille, rend un dépôt.
    // Sans ce témoin, le test passerait aussi si le module refusait TOUT.
    let service2 = service_factice(vec![
        ReponseScriptee::ok(200, vec![("ETag", "\"etiquette\"".to_string())]),
        ReponseScriptee::ok(200, vec![("Content-Length", contenu.len().to_string())]),
    ]);
    let cible2 = cible_factice(&service2.endpoint(), "plume");
    let issue2 = crate::sink_s3::deposer_fichier(
        &cible2,
        "plume-20260819T101500Z.db.age",
        dir.sous("archive.bin").chemin(),
        V4_HORODATAGE,
    );
    assert!(issue2.est_depose(), "témoin positif : la bonne taille CONFIRME le dépôt ({issue2})");
}

/// PORTE 3 — le service accepte, puis la relecture n'obtient RIEN (socket ouverte, aucune réponse)
/// ou refuse. Aucun verdict sur l'existence de l'objet : ni succès, ni certitude d'échec. C'est
/// exactement ce que dit `Impossible`, et il ne faut surtout pas le confondre avec un dépôt.
#[cfg(feature = "s3_backup")]
#[test]
fn sink_s3_relecture_sans_reponse_est_impossible_jamais_un_depot() {
    let dir = crate::tmp_possede::TmpPossede::neuf("s3-relecture-muette");
    fichier_epreuve(&dir, "archive.bin", 8_192);
    let service = service_factice(vec![
        ReponseScriptee::ok(200, vec![("ETag", "\"etiquette\"".to_string())]),
        ReponseScriptee::muette(),
    ]);
    let cible = cible_factice(&service.endpoint(), "plume");
    let issue = crate::sink_s3::deposer_fichier(
        &cible,
        "plume-20260819T101500Z.db.age",
        dir.sous("archive.bin").chemin(),
        V4_HORODATAGE,
    );
    assert!(!issue.est_depose(), "sans relecture, il n'y a pas de dépôt établi : {issue}");
    assert!(
        matches!(issue, crate::sink_s3::IssueDepot::Impossible { etape: crate::sink_s3::Etape::Confirmation, .. }),
        "état distant INCONNU -> impossible à l'étape confirmation, obtenu {issue:?}"
    );
    assert!(format!("{issue}").contains("INCONNU"), "la ligne doit dire que l'état distant est inconnu");

    // Variante : la relecture RÉPOND, mais 404. Il y a un verdict, et il est négatif -> refus.
    let service2 = service_factice(vec![
        ReponseScriptee::ok(200, vec![("ETag", "\"etiquette\"".to_string())]),
        ReponseScriptee::ok(404, vec![]),
    ]);
    let cible2 = cible_factice(&service2.endpoint(), "plume");
    let issue2 = crate::sink_s3::deposer_fichier(
        &cible2,
        "plume-20260819T101500Z.db.age",
        dir.sous("archive.bin").chemin(),
        V4_HORODATAGE,
    );
    assert!(!issue2.est_depose());
    assert!(
        matches!(issue2, crate::sink_s3::IssueDepot::Refuse { etape: crate::sink_s3::Etape::Confirmation, statut: 404, .. }),
        "un 404 à la relecture est un REFUS (verdict), pas un impossible : {issue2:?}"
    );
}

/// PORTE 4 — rien n'écoute. Le cas le plus banal en exploitation (service arrêté, réseau coupé,
/// mauvais port) doit rendre `Impossible` à l'étape d'envoi, avec le motif du système.
#[cfg(feature = "s3_backup")]
#[test]
fn sink_s3_service_injoignable_est_impossible() {
    let dir = crate::tmp_possede::TmpPossede::neuf("s3-injoignable");
    fichier_epreuve(&dir, "archive.bin", 128);
    // Port réservé sur la boucle locale : l'écoute est fermée AVANT le dépôt, donc la connexion est
    // refusée de façon déterministe (aucune attente d'expiration).
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("écoute locale");
        l.local_addr().expect("adresse locale").port()
    };
    let cible = cible_factice(&format!("http://127.0.0.1:{port}"), "plume");
    let issue = crate::sink_s3::deposer_fichier(
        &cible,
        "plume-20260819T101500Z.db.age",
        dir.sous("archive.bin").chemin(),
        V4_HORODATAGE,
    );
    assert!(!issue.est_depose(), "aucun service joint ne peut valoir dépôt : {issue}");
    assert!(
        matches!(issue, crate::sink_s3::IssueDepot::Impossible { etape: crate::sink_s3::Etape::Envoi, .. }),
        "impossible à l'étape envoi, obtenu {issue:?}"
    );
}

/// L'archive locale a disparu entre le cycle et le dépôt (nettoyage concurrent, volume démonté).
/// Rien ne doit partir sur le réseau, et le verdict ne doit pas se lire comme un problème DISTANT.
#[cfg(feature = "s3_backup")]
#[test]
fn sink_s3_archive_locale_absente_n_ouvre_aucune_socket() {
    let dir = crate::tmp_possede::TmpPossede::neuf("s3-absent");
    let service = service_factice(vec![ReponseScriptee::ok(200, vec![])]);
    let cible = cible_factice(&service.endpoint(), "plume");
    let issue = crate::sink_s3::deposer_fichier(
        &cible,
        "plume-20260819T101500Z.db.age",
        dir.sous("archive-qui-n-existe-pas.bin").chemin(),
        V4_HORODATAGE,
    );
    assert!(!issue.est_depose());
    assert!(
        matches!(issue, crate::sink_s3::IssueDepot::Impossible { etape: crate::sink_s3::Etape::Empreinte, .. }),
        "l'échec est LOCAL (empreinte), pas distant : {issue:?}"
    );
    assert!(service.recus().is_empty(), "aucune requête ne doit avoir atteint le service");
}

// ── 5. AUCUN SECRET, NULLE PART ─────────────────────────────────────────────────────────────────

/// La matière de signature ne doit apparaître dans AUCUNE chaîne que le module produit. Le test ne
/// se contente pas du chemin heureux : il collecte les représentations de la cible ET les lignes de
/// TOUS les chemins d'échec — c'est là qu'un message trop bavard naît, jamais dans le succès.
///
/// Ce que ce test ne prouve pas, et il faut le dire : il examine les chaînes RENDUES, pas celles
/// qu'un appelant fabriquerait lui-même. La garantie de fond n'est pas ici, elle est dans le type —
/// `Matiere` n'a ni `Display`, ni `as_str`, ni `Deref`, et son `Debug` est masqué, donc il n'existe
/// aucun chemin qui la convertisse en texte hors de l'arithmétique de signature.
#[cfg(feature = "s3_backup")]
#[test]
fn sink_s3_aucune_matiere_secrete_dans_les_lignes_produites() {
    let dir = crate::tmp_possede::TmpPossede::neuf("s3-secret");
    fichier_epreuve(&dir, "archive.bin", 1_024);
    let chemin = dir.sous("archive.bin");

    let mut produites: Vec<String> = Vec::new();

    // (a) la cible elle-même, telle qu'un journal l'écrirait.
    let avec_jeton = crate::sink_s3::CibleS3::neuve(
        "http://127.0.0.1:1".to_string(),
        V4_REGION.to_string(),
        "sauvegardes".to_string(),
        "plume".to_string(),
        V4_ACCES.to_string(),
        crate::sink_s3::Matiere::neuve(V4_MATIERE),
        Some(crate::sink_s3::Matiere::neuve(V4_JETON)),
        true,
    );
    produites.push(format!("{avec_jeton:?}"));
    produites.push(format!("{:?}", crate::sink_s3::Matiere::neuve(V4_MATIERE)));

    // (b) les trois familles d'issue, obtenues pour de vrai.
    let service_refus = service_factice(vec![ReponseScriptee::ok(403, vec![])]);
    let cible_refus = cible_factice(&service_refus.endpoint(), "plume");
    let i1 = crate::sink_s3::deposer_fichier(&cible_refus, "plume-20260819T101500Z.db.age", chemin.chemin(), V4_HORODATAGE);
    let i2 = crate::sink_s3::deposer_fichier(&avec_jeton, "plume-20260819T101500Z.db.age", chemin.chemin(), V4_HORODATAGE);
    let service_ok = service_factice(vec![
        ReponseScriptee::ok(200, vec![("ETag", "\"etiquette\"".to_string())]),
        ReponseScriptee::ok(200, vec![("Content-Length", "1024".to_string())]),
    ]);
    let cible_ok = cible_factice(&service_ok.endpoint(), "plume");
    let i3 = crate::sink_s3::deposer_fichier(&cible_ok, "plume-20260819T101500Z.db.age", chemin.chemin(), V4_HORODATAGE);
    assert!(i3.est_depose(), "témoin positif du lot : {i3}");
    for i in [&i1, &i2, &i3] {
        produites.push(format!("{i}"));
        produites.push(format!("{i:?}"));
    }

    // (c) les refus de résolution, qui NOMMENT des clés de configuration — et pourraient nommer des
    //     valeurs si personne n'y prenait garde.
    let mut m = std::collections::HashMap::new();
    m.insert(crate::sink_s3::CLE_S3_ENDPOINT.to_string(), "http://127.0.0.1:1".to_string());
    m.insert(crate::sink_s3::CLE_S3_ACCESS.to_string(), V4_ACCES.to_string());
    m.insert(crate::sink_s3::CLE_S3_MATIERE.to_string(), V4_MATIERE.to_string());
    if let Err(e) = crate::sink_s3::depuis_reglages(&m, "s3://ab") {
        produites.push(e);
    }
    produites.push(format!("{:?}", crate::sink_s3::depuis_reglages(&m, "s3://sauvegardes").map(|c| format!("{c:?}"))));

    assert!(produites.len() >= 10, "le lot de chaînes examinées est maigre : {}", produites.len());
    for s in &produites {
        assert!(!s.contains(V4_MATIERE), "matière de signature présente dans une chaîne produite : {s}");
        assert!(!s.contains(V4_JETON), "jeton de session présent dans une chaîne produite : {s}");
    }
    // CONTRÔLE NÉGATIF : la recherche fonctionne. Sans lui, un test qui ne trouve rien ne prouve
    // rien — c'est le défaut que ce dépôt a déjà rencontré sur une garde satisfaite du vide.
    let temoin = format!("ligne fabriquée contenant {V4_MATIERE}");
    assert!(temoin.contains(V4_MATIERE), "le contrôle négatif doit, lui, trouver la matière");
}

// ── 6. LA MÉMOIRE ───────────────────────────────────────────────────────────────────────────────

/// L'empreinte de la charge est calculée EN FLUX : la mémoire tenue ne suit pas la taille du
/// fichier. Mesuré par l'allocateur de test (écart alloué−libéré du fil, pas le RSS du processus :
/// une suite parallèle rend le RSS inexploitable, cf. `tas_du_fil`).
///
/// La borne est exprimée par rapport au TAMPON du module, pas par un nombre écrit à la main : si la
/// taille de tranche change un jour, la garde suit. Le témoin est l'INVARIANCE en volume — le pic
/// d'un fichier huit fois plus gros ne doit pas être huit fois plus grand.
#[cfg(feature = "s3_backup")]
#[test]
fn sink_s3_empreinte_en_flux_ne_retient_pas_le_fichier() {
    let dir = crate::tmp_possede::TmpPossede::neuf("s3-empreinte");
    let petit = 1 << 20; // 1 Mio
    let gros = 8 << 20; // 8 Mio
    let attendu_petit = crate::sha256_hex(&fichier_epreuve(&dir, "petit.bin", petit));
    let attendu_gros = crate::sha256_hex(&fichier_epreuve(&dir, "gros.bin", gros));

    let ((h1, n1), pic_petit) = crate::tas_du_fil::pic_vivant_pendant(|| {
        crate::sink_s3::empreinte_fichier(dir.sous("petit.bin").chemin()).expect("empreinte")
    });
    let ((h2, n2), pic_gros) = crate::tas_du_fil::pic_vivant_pendant(|| {
        crate::sink_s3::empreinte_fichier(dir.sous("gros.bin").chemin()).expect("empreinte")
    });
    assert_eq!((h1.as_str(), n1), (attendu_petit.as_str(), petit as u64), "empreinte et taille du petit");
    assert_eq!((h2.as_str(), n2), (attendu_gros.as_str(), gros as u64), "empreinte et taille du gros");

    // Borne DÉRIVÉE du tampon du module (et non un chiffre posé) : le tampon, plus une marge pour
    // l'état du condensat et les chaînes rendues.
    let plafond = (crate::sink_s3::TAMPON as u64) * 2;
    assert!(pic_petit <= plafond, "pic {pic_petit} o au-dessus de la borne {plafond} o (1 Mio)");
    assert!(pic_gros <= plafond, "pic {pic_gros} o au-dessus de la borne {plafond} o (8 Mio)");
    // L'INVARIANCE : huit fois le volume, pas huit fois la mémoire.
    assert!(
        pic_gros <= pic_petit + (crate::sink_s3::TAMPON as u64),
        "le pic suit le VOLUME ({pic_petit} o pour 1 Mio contre {pic_gros} o pour 8 Mio) — \
         l'empreinte ne serait alors pas en flux"
    );
}
