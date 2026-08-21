// `S36` — LA GARDE DÉRIVÉE DE LA SURFACE D'ENTRÉE DU COLLECTEUR MAIL.
//
// CE QU'ELLE REFUSE. Ce collecteur ARME UNE DÉTECTION : il applique des motifs IOC/phishing/URL à des
// messages. Chacun de ses replis rendait la MÊME conclusion — « 0 alerte » — que le cas où tout est
// sain, et trois d'entre eux étaient définitifs :
//   * un message qu'on ne sait pas LIRE était marqué « vu » AVANT sa lecture, puis sauté : il n'était
//     jamais analysé et ne le serait PLUS JAMAIS ;
//   * un message que le décodeur REFUSE donnait des champs entièrement vides, auxquels aucun motif ne
//     s'applique — une réponse « rien à signaler » qu'un expéditeur peut PROVOQUER ;
//   * un compte ou un dossier illisible était sauté en silence, pendant que le rapport le comptait
//     parmi les comptes balayés.
//
// LE COLLECTEUR EST EXÉCUTÉ TEL QU'IL EST LIVRÉ, contre une arborescence de courrier FABRIQUÉE dans un
// temporaire possédé : rien de la machine qui exécute la garde n'entre dans le verdict. Les deux
// témoins portent sur la MÊME arborescence, à une variable près.
//   ① SOURCE NON EXAMINABLE -> un aveu `collect_status=unavailable` NOMME la cause, et le message qui
//      n'a pas pu être ouvert n'est PAS marqué vu.
//   ② SOURCE PRÉSENTE ET SAINE -> AUCUN aveu, le message est examiné et marqué vu. Sans ce second
//      témoin, une version qui avouerait en permanence passerait le premier sans rien prouver, et
//      noierait le SOC d'aveux faux.

#![cfg(test)]

use crate::lisibilite;
use std::path::{Path, PathBuf};

/// Plancher de NON-DÉGÉNÉRESCENCE : sous ce nombre de familles de trou réellement exercées, c'est
/// l'instrument qui est cassé, pas la surface. La garde refuse alors de conclure.
const MIN_FAMILLES: usize = 2;

struct TmpPossede(PathBuf);

impl TmpPossede {
    fn neuf(tag: &str) -> Self {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("plume-s36-mail-garde-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
    fn chemin(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpPossede {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Un message parfaitement ordinaire et ANODIN : décodable, et qui ne déclenche aucun motif. C'est le
/// témoin ② — sans lui, on ne saurait pas distinguer « examiné et sain » de « jamais examiné ».
const MESSAGE_SAIN: &[u8] = b"From: expediteur@example.org\r\n\
To: destinataire@example.test\r\n\
Subject: compte rendu de reunion\r\n\
Message-ID: <sain-1@example.org>\r\n\
Date: Mon, 1 Jan 2035 10:00:00 +0000\r\n\
\r\n\
Voici le compte rendu demande. Rien de particulier a signaler.\r\n";

/// UNE ENTRÉE QUE LE DÉCODEUR REFUSE. Le décodeur livré est très tolérant : SONDÉ pour ce lot, il
/// n'a refusé qu'une entrée VIDE — des octets arbitraires, des blancs seuls et une ligne sans en-tête
/// sont tous acceptés. Le témoin est donc un fichier de message à ZÉRO octet, ce qu'une écriture
/// tronquée ou un disque plein laisse derrière eux ; il se lisait « message sain ».
const MESSAGE_INDECODABLE: &[u8] = b"";

fn ecrire_message(dossier: &Path, nom: &str, octets: &[u8]) {
    std::fs::create_dir_all(dossier).unwrap();
    std::fs::write(dossier.join(nom), octets).unwrap();
}

/// Exécute le collecteur TEL QU'IL EST LIVRÉ sur l'arborescence fabriquée, et rend les enveloppes
/// écrites dans le spool.
fn executer(racine: &Path, spool: &Path, etat: &Path, dossier: &str) -> Vec<serde_json::Value> {
    std::env::set_var("PLUME_MAIL_ROOT", racine);
    std::env::set_var("PLUME_SPOOL", spool);
    std::env::set_var("PLUME_MAIL_STATE", etat);
    std::env::set_var("PLUME_MAIL_DOMAIN", "example.test");
    std::env::set_var("PLUME_MAIL_FOLDER", dossier);
    // L'identité est DÉCLARÉE : la garde ne doit pas dépendre du nom de la machine qui l'exécute, ni
    // avouer une identité illisible qui n'est pas ce qu'elle mesure ici.
    std::env::set_var("PLUME_HOST", "hote-de-garde");
    let _ = std::fs::create_dir_all(spool);
    crate::run().expect("le collecteur ne doit pas échouer sur une arborescence lisible");
    let mut out = Vec::new();
    for e in std::fs::read_dir(spool).unwrap() {
        let p = e.unwrap().path();
        if p.extension().map(|x| x == "json").unwrap_or(false) {
            let t = std::fs::read_to_string(&p).unwrap();
            out.push(serde_json::from_str(&t).unwrap());
        }
    }
    out
}

/// Les aveux d'indisponibilité présents dans les enveloppes — repérés par le contrat déjà livré, pas
/// par un nom de fichier.
fn aveux(envs: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for env in envs {
        for ev in env["events"].as_array().cloned().unwrap_or_default() {
            if ev["fields"]["collect_status"] == "unavailable" {
                out.push(ev);
            }
        }
    }
    out
}

fn evenements(envs: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for env in envs {
        for ev in env["events"].as_array().cloned().unwrap_or_default() {
            if ev["fields"]["collect_status"] != "unavailable" {
                out.push(ev);
            }
        }
    }
    out
}

/// LA GARDE. Elle n'énumère aucun message ni aucun compte : elle fabrique une boîte, la rend
/// successivement saine puis non examinable, et exige les deux verdicts.
#[test]
fn une_boite_qu_on_ne_sait_pas_examiner_ne_se_conclut_pas_par_zero_alerte() {
    let tmp = TmpPossede::neuf("boite");
    let racine = tmp.chemin().join("maildir");
    let boite = racine.join("alice");
    let mut familles = 0usize;

    // =============================================================================================
    // ② LE TÉMOIN NOMINAL : une boîte lisible dont le contenu est SAIN. Aucun aveu, le message est
    //    examiné, et l'état incrémentiel le marque vu.
    // =============================================================================================
    ecrire_message(&boite.join("cur"), "1700000000.M1.hote:2,S", MESSAGE_SAIN);
    let spool = tmp.chemin().join("spool-sain");
    let etat = tmp.chemin().join("etat-sain");
    let envs = executer(&racine, &spool, &etat, "*");
    assert!(
        aveux(&envs).is_empty(),
        "une boîte lisible et saine ne doit lever AUCUN aveu : {:?}",
        aveux(&envs)
    );
    let vus = std::fs::read_to_string(&etat).unwrap_or_default();
    assert!(
        vus.contains("1700000000.M1.hote:2,S"),
        "un message EXAMINÉ doit être marqué vu (sinon il sera rejoué sans fin) : {vus:?}"
    );

    // =============================================================================================
    // ① PREMIÈRE FAMILLE : UN MESSAGE QUE LE DÉCODEUR REFUSE. Il ne déclenche aucun motif — c'est
    //    précisément ce qui le rendait invisible. Il doit produire un événement qui le DÉSIGNE, et
    //    un aveu qui NOMME la cause.
    // =============================================================================================
    let racine2 = tmp.chemin().join("maildir-indecodable");
    ecrire_message(&racine2.join("bob").join("cur"), "1700000001.M2.hote:2,S", MESSAGE_INDECODABLE);
    let spool2 = tmp.chemin().join("spool-indecodable");
    let envs2 = executer(&racine2, &spool2, &tmp.chemin().join("etat-indecodable"), "*");
    let a2 = aveux(&envs2);
    assert!(
        a2.iter().any(|e| e["fields"]["cause"] == lisibilite::CAUSE_FORME_INCONNUE),
        "un message refusé par le décodeur doit être AVOUÉ (`forme_inconnue`) : {a2:?}"
    );
    let e2 = evenements(&envs2);
    assert!(
        e2.iter().any(|e| e["fields"]["scan_status"] == "non-examine"),
        "le message non examiné doit être DÉSIGNÉ pour un analyste : {e2:?}"
    );
    familles += 1;

    // =============================================================================================
    // ① DEUXIÈME FAMILLE : UN COMPTE DONT LE DOSSIER DEMANDÉ N'EXISTE PAS. Il était sauté en
    //    silence, et le rapport le comptait quand même parmi les comptes balayés.
    // =============================================================================================
    let racine3 = tmp.chemin().join("maildir-dossier");
    ecrire_message(&racine3.join("carol").join("cur"), "1700000002.M3.hote:2,S", MESSAGE_SAIN);
    ecrire_message(&racine3.join("carol").join(".Archive").join("cur"), "1700000003.M4.hote:2,S", MESSAGE_SAIN);
    ecrire_message(&racine3.join("dave").join("cur"), "1700000004.M5.hote:2,S", MESSAGE_SAIN);
    let spool3 = tmp.chemin().join("spool-dossier");
    // `dave` n'a pas de dossier `Archive` : son compte entier sort du périmètre pour ce passage.
    let envs3 = executer(&racine3, &spool3, &tmp.chemin().join("etat-dossier"), "Archive");
    let a3 = aveux(&envs3);
    assert!(
        a3.iter().any(|e| {
            e["fields"]["cause"] == lisibilite::CAUSE_SOURCE_ABSENTE
                && e["fields"]["detail"].as_str().map(|d| d.contains("dave")).unwrap_or(false)
        }),
        "un compte qu'on n'a PAS pu ouvrir doit être NOMMÉ dans l'aveu : {a3:?}"
    );
    familles += 1;

    // =============================================================================================
    // ① TROISIÈME FAMILLE : UN MESSAGE QU'ON NE SAIT PAS LIRE. Il était marqué vu AVANT sa lecture,
    //    donc perdu pour toujours. Cette famille demande un fichier réellement illisible, ce qui
    //    dépend du PRIVILÈGE de qui exécute la garde : un processus privilégié lit un fichier en
    //    mode 000. L'instrument est donc VALIDÉ avant d'être cru, et la famille n'est comptée que si
    //    la privation d'accès mord réellement.
    // =============================================================================================
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let racine4 = tmp.chemin().join("maildir-illisible");
        let cur = racine4.join("erin").join("cur");
        ecrire_message(&cur, "1700000005.M6.hote:2,S", MESSAGE_SAIN);
        let cible = cur.join("1700000005.M6.hote:2,S");
        std::fs::set_permissions(&cible, std::fs::Permissions::from_mode(0o000)).unwrap();
        // VALIDATION DE L'INSTRUMENT : la garde vérifie qu'elle-même ne peut plus lire le fichier.
        // Si elle le peut (exécution privilégiée), la privation ne mord pas et la famille n'est pas
        // comptée — plutôt que d'être déclarée couverte sans avoir été vue.
        if std::fs::read(&cible).is_err() {
            let spool4 = tmp.chemin().join("spool-illisible");
            let etat4 = tmp.chemin().join("etat-illisible");
            let envs4 = executer(&racine4, &spool4, &etat4, "*");
            let a4 = aveux(&envs4);
            assert!(
                a4.iter().any(|e| e["fields"]["cause"] == lisibilite::CAUSE_SOURCE_REFUSEE),
                "un message non lu doit être AVOUÉ (`source_refusee`) : {a4:?}"
            );
            let vus4 = std::fs::read_to_string(&etat4).unwrap_or_default();
            assert!(
                !vus4.contains("1700000005.M6.hote:2,S"),
                "un message qu'on n'a PAS pu lire ne doit PAS être marqué vu — sinon il est perdu \
                 pour toujours : {vus4:?}"
            );
            familles += 1;
        }
        // Rendu lisible avant le nettoyage du temporaire.
        let _ = std::fs::set_permissions(&cible, std::fs::Permissions::from_mode(0o600));
    }

    assert!(
        familles >= MIN_FAMILLES,
        "seulement {familles} famille(s) de trou réellement exercée(s) (plancher {MIN_FAMILLES}) — \
         l'instrument ne voit plus rien, il ne doit pas conclure"
    );
}
