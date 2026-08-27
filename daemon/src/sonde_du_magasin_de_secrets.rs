//! `P9.8-a` — UN MAGASIN DE SECRETS QUI NE PEUT PLUS SERVIR EST UNE ROTATION DE CLÉS ÉTEINTE, ET IL LE DIT.
//!
//! CE QUI A ÉTÉ MESURÉ, ET CE QUI MANQUAIT. Un coffre scellé plusieurs jours a empêché le
//! rafraîchissement de vingt-sept secrets externes de tous les espaces d'un cluster — dont ceux de
//! l'émetteur de certificats et du fournisseur d'identité — et rien ne l'a dit : l'état n'a été
//! découvert qu'en tapant une commande d'inspection. Le démon, lui, servait normalement : il tourne
//! avec les secrets DÉJÀ injectés. C'est la famille « un composant qui sait son résultat incomplet et
//! le présente comme complet », appliquée au chemin des secrets.
//!
//! LA QUESTION A ÉTÉ TRANCHÉE PAR LA MESURE AVANT D'ÉCRIRE CE MODULE : le signal n'existait PAS.
//! Ce que le démon produisait quand une référence de secret ne résolvait plus se compte sur les
//! doigts d'une main, et aucune de ces sorties n'est un signal :
//!   * `state.rs` (`catalog_route`, `for_each_active_tenant`) : `eprintln!` sur la sortie d'erreur ;
//!   * `main.rs` (`cfg_secret`) : `eprintln!` puis `exit(78)` ;
//!   * `ledger.rs` (`emit_ledger_unsigned`) : le SEUL qui lève une alerte — mais il parle du
//!     CONSOMMATEUR (la clé de journal absente ou vide), et dans l'épisode mesuré le fichier était
//!     présent et valide : il n'avait rien à dire, et il s'est tu à raison.
//! Le plus proche parent côté capteurs — `kube_sts_notready`, émis par `collectors/kube-state.sh` —
//! parle du POD du coffre, pas de l'approvisionnement, et la règle qui le consomme est semée
//! `enabled=0` (`seeds.rs::seed_sts_rules`) : un mécanisme posé mais non armé n'est pas un signal.
//!
//! CE QUE CE MODULE OBSERVE, ET CE QU'IL N'OBSERVE PAS — ÉCRIT POUR ÊTRE OPPOSABLE.
//! Le démon ne lit pas le coffre. Ce qu'il peut lire, c'est ce qu'un capteur livré RAPPORTE du
//! MAGASIN lui-même : la série `secretstore_notready` (`collectors/kube-state.sh`), un COMPTE de
//! magasins de secrets qui ne se déclarent pas prêts. Le contrat entre le capteur et le démon est un
//! NOM DE SÉRIE, exactement comme celui de `kube_sts_ready_<nom>` que `seeds.rs` et `kube-state.sh`
//! partagent déjà.
//! ET LE CRITÈRE PAR LEQUEL CE MODULE DISQUALIFIE SON VOISIN VAUT CONTRE LUI — ÉCRIT PLUTÔT QU'ÉVITÉ.
//! Ci-dessus, `kube_sts_notready` est écarté parce que « un mécanisme posé mais non armé n'est pas un
//! signal » : sa règle est semée `enabled=0`. LE MÊME REPROCHE ATTEINT CE MODULE, par un autre bout, et il
//! est MESURÉ, pas supposé :
//!   * l'UNIQUE producteur de `secretstore_notready` est `collectors/kube-state.sh`, et ce capteur est
//!     livré ÉTEINT — `bootstrap.sh` l'installe puis fait `systemctl disable --now plume-kube-state.timer`,
//!     et `deploy/K8S.md` titre sa section « Capteurs (sur l'hôte, OFF par défaut) » ;
//!   * AUCUNE entrée de `COLLECTORS` (`sondes.rs`) n'observe la source de ce capteur : aucun
//!     dead-man's-switch de capteur muet ne couvre le producteur de ce dead-man's-switch. Son silence est
//!     donc absorbé comme un tick propre, indistinguable de la santé ;
//!   * conséquence, dite sans détour : SUR UN DÉPLOIEMENT OÙ L'EXPLOITANT N'A PAS ARMÉ LE TIMER, CE
//!     SIGNAL EST MUET, y compris sur le cluster où le constat a été mesuré. `EtatDuMagasin::NonObserve`
//!     est la forme honnête de ce silence — le module ne conclut rien et surtout pas « tout va bien » —
//!     mais rien, dans ce lot, ne MESURE si le timer est armé quelque part.
//! CE QUI FERMERAIT VRAIMENT, ET QUI N'EST PAS FAIT : une entrée de capteur muet pour `kube-state`
//! crierait sur tout déploiement hors k3s, où ce capteur n'a aucune raison de tourner — ce serait un
//! faux positif universel, pas une garde. La voie reste à trancher par une mesure qu'on n'a pas :
//! « ce déploiement est-il un cluster ? » n'est déclaré nulle part. La cellule reste donc OUVERTE, et
//! l'annoncer fermée serait exactement la faute « posé mais non armé » reprochée au voisin.
//! Le témoin `mds_le_module_avoue_que_son_producteur_n_est_pas_arme` DÉRIVE ces deux faits de l'arbre et
//! exige cet aveu tant qu'ils tiennent — il exigera son RETRAIT le jour où ils cesseront de tenir.
//!
//! CE QUI RESTE DEHORS, ET QUI EST UNE DETTE NOMMÉE, PAS UN ANGLE MORT : un secret PROJETÉ EN FICHIER
//! par un agent extérieur (le montage d'un `Secret` k8s) ne dit RIEN de la santé de son magasin. La
//! projection ne change que lorsque la VALEUR change ; sa date de modification n'avance donc pas à
//! chaque rafraîchissement réussi, et elle ne permet pas de distinguer « rafraîchi, valeur inchangée »
//! de « plus rafraîchi du tout ». Un instrument bâti sur cette date aurait été FAUX dans les deux
//! sens. Sans relevé du magasin, ce module ne conclut donc rien — et surtout pas « tout va bien ».
//!
//! PORTÉE DU SIGNAL : LE MAGASIN, JAMAIS SES CONSOMMATEURS. Vingt-sept alertes pour une cause unique
//! seraient un second défaut. Il n'y a donc qu'UNE clé de déduplication pour toute la famille, et
//! elle ne porte pas de nom de secret : ce qui est en panne, c'est l'approvisionnement.
//!
//! LE RANG DU SIGNAL. Famille `heartbeat.` — celle des angles morts (capteur muet, flotte muette,
//! détection aveugle) : elle arrive dans la liste des alertes sans qu'aucune règle n'ait à être
//! activée, le bulletin de support la relit (`handlers/system.rs`), et la table `alert` n'est jamais
//! purgée. Sévérité 4, celle de son plus proche parent `emit_ledger_unsigned` — que le MÊME
//! re-scellement produit, et pour la même raison.
//!
//! LES DEUX SEUILS SONT DÉRIVÉS, PAS CHOISIS, ET ILS SONT ASYMÉTRIQUES À DESSEIN :
//!   * pour LEVER, il faut que TOUS les relevés de la fenêtre disent « pas prêt », et qu'il y en ait
//!     au moins `PLANCHER_DE_RELEVES` : un relevé isolé est le régime transitoire (un magasin qui
//!     vient d'être créé n'a pas encore de condition de disponibilité), exactement la raison qui
//!     donne son plancher à `detection_aveugle` — d'où la réutilisation de SA constante plutôt qu'un
//!     second chiffre qui divergerait ;
//!   * la FENÊTRE est `detection_aveugle::HORIZON_DE_CECITE_S`, l'horizon que les signaux de santé
//!     non purgeables utilisent déjà (`emit_disk_health`, `emit_ledger_unsigned` : un seau horaire) ;
//!   * pour RÉSOUDRE, UN seul relevé « prêt » de la fenêtre suffit : le rafraîchissement qui repart
//!     doit éteindre l'alerte tout de suite.
//!
//! ET « PRÊT » EXIGE UN DÉNOMINATEUR, PARCE QUE ZÉRO SUR ZÉRO N'EST PAS UNE SANTÉ. Le capteur livré
//! publie un VRAI zéro dès qu'il a pu regarder et n'a rien trouvé : `secretstore_total=0` avec
//! `secretstore_notready=0`. Décider sur le seul numérateur faisait donc qu'EFFACER les magasins
//! pendant l'incident — opérateur désinstallé, espace de noms vidé, CRD retirée — RÉSOLVAIT l'alerte et
//! affirmait la santé, c'est-à-dire qu'un dead-man's-switch s'éteignait quand ce qu'il surveille
//! disparaît. Un relevé ne témoigne d'un approvisionnement qui SERT que s'il porte, au même instant,
//! « aucun pas prêt » ET « au moins un déclaré » ; l'appariement se fait sur `ts`, que le contrat
//! d'ingestion garantit (toutes les métriques d'une enveloppe partagent son horodatage). Sans
//! dénominateur PUBLIÉ du tout, rien n'est apparié et le comportement d'origine est conservé — sans
//! quoi un émetteur d'une version antérieure hériterait d'une alerte que plus rien ne peut résoudre.
//!
//! CE QUE CETTE ASYMÉTRIE COÛTE, ÉCRIT PARCE QUE C'EST UN VRAI PRIX ET QU'UN TEST LE TIENT : après
//! une reprise, un NOUVEL arrêt ne se dit qu'une fois le dernier relevé sain sorti de la fenêtre —
//! jusqu'à une heure de retard sur un second épisode qui suivrait le premier de près. L'échange est
//! délibéré : l'épisode mesuré a duré des jours, et une alerte qui se rouvre à chaque oscillation
//! d'un magasin qui redémarre serait désarmée en une semaine.
//!
//! CE QUE CE MODULE NE FAIT PAS : il ne lit aucun secret, n'ouvre aucune socket, ne connaît aucun
//! fournisseur. Il lit une série de la base et rend un verdict.
use crate::mesure_environnement::Mesure;
use rusqlite::{params, Connection};

/// LE CONTRAT AVEC LE CAPTEUR — le nom de la série qui porte le COMPTE de magasins pas prêts.
/// `collectors/kube-state.sh` l'émet ; ce module le lit. Un nom écrit deux fois finit par diverger :
/// il est écrit ici, et le capteur le cite dans son commentaire de bloc.
pub(crate) const SERIE_MAGASINS_NON_PRETS: &str = "secretstore_notready";
/// Le DÉNOMINATEUR, même contrat. Sans lui, « 1 magasin pas prêt » ne se lit pas.
pub(crate) const SERIE_MAGASINS_TOTAL: &str = "secretstore_total";

/// La clé de déduplication de la famille : UNE seule, pour tout l'approvisionnement. Elle est libérée
/// à la résolution, comme `hb-{id}` et `rule-{id}`.
pub(crate) const DEDUP_MAGASIN: &str = "hb-magasin-de-secrets";
/// La famille dans `alert.rule`. `heartbeat.` est celle des angles morts, et aucune jointure sur
/// `rule` ne la prend pour un tir de règle (cf. `handlers/alerts.rs`).
pub(crate) const FAMILLE_ALERTE: &str = "heartbeat.magasin-de-secrets";
/// Sévérité : celle d'`emit_ledger_unsigned`, le signal que le MÊME re-scellement produit côté journal.
pub(crate) const SEVERITE: i64 = 4;

/// La fenêtre sur laquelle le verdict est rendu — l'horizon des signaux de santé non purgeables.
/// DÉRIVÉE de `detection_aveugle`, jamais recopiée.
pub(crate) const FENETRE_DE_JUGEMENT_S: i64 = crate::detection_aveugle::HORIZON_DE_CECITE_S;
/// Sous ce nombre de relevés dans la fenêtre, on ne LÈVE pas : un relevé isolé est le régime
/// transitoire. Même constante — donc même chiffre, pour la même raison — que le plancher d'abandons.
pub(crate) const PLANCHER_DE_RELEVES: usize = crate::detection_aveugle::PLANCHER_D_ABANDONS as usize;

/// CE QUE LA FENÊTRE DIT DE L'APPROVISIONNEMENT. Trois cas EXCLUSIFS, et aucun n'est un défaut : il
/// n'existe PAS de constructeur qui rende « sain » faute d'avoir observé.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum EtatDuMagasin {
    /// RIEN N'A ÉTÉ OBSERVÉ DE L'APPROVISIONNEMENT — et ce cas a DEUX formes, qui ont exactement la
    /// même conséquence : personne n'a rapporté dans la fenêtre (capteur non déployé, non privilégié,
    /// mort), OU le capteur a rapporté qu'il n'y a AUCUN magasin déclaré (`secretstore_total=0`,
    /// installation sans magasin de secrets, ou magasins effacés). Dans les deux cas on ne lève RIEN
    /// et on ne résout RIEN : résoudre serait affirmer un approvisionnement sain qu'on n'a pas
    /// observé — et « zéro pas prêt sur zéro déclaré » n'est pas une santé, c'est une absence.
    /// C'est le même sens d'échec que `Inconnu` côté capteur muet, et c'est la dette nommée du bandeau.
    NonObserve,
    /// Des relevés existent, tous disent « pas prêt », mais ils sont MOINS de `PLANCHER_DE_RELEVES` :
    /// c'est le régime transitoire, et il n'établit rien. Ni levée (ce serait une alerte sur un
    /// unique instantané) ni résolution (ce serait affirmer un retour à la normale que RIEN n'a
    /// observé — le défaut exact que ce module ferme). Un cas à part, parce que le confondre avec
    /// l'un des deux voisins ferait une faute dans un sens ou dans l'autre.
    Indecis { releves: usize },
    /// Au moins un relevé de la fenêtre dit que tous les magasins DÉCLARÉS sont prêts — c'est-à-dire
    /// qu'au même instant le compte des non-prêts vaut zéro ET le dénominateur vaut au moins un. Un
    /// « zéro sur zéro » n'entre PAS ici : voir `NonObserve`.
    Sert { releves: usize },
    /// TOUS les relevés de la fenêtre (au moins `PLANCHER_DE_RELEVES`) disent qu'au moins un magasin
    /// n'est pas prêt. C'est l'approvisionnement qui est arrêté, pas un consommateur.
    NeSertPlus {
        /// Le PIRE compte observé sur la fenêtre (jamais une moyenne : une moyenne masque une panne
        /// qui commence).
        non_prets: i64,
        /// Le dénominateur, quand le capteur l'a publié. `None` = il ne l'a pas publié — on le DIT
        /// au lieu d'écrire un total inventé.
        total: Option<i64>,
        releves: usize,
        /// Depuis combien de temps le plus ANCIEN relevé de la fenêtre dit déjà « pas prêt ». Borné
        /// par la fenêtre : ce module ne prétend pas dater le début d'un épisode plus vieux qu'elle.
        au_moins_depuis_s: i64,
    },
}

/// L'ÉNONCÉ DE LA FENÊTRE, ÉCRIT UNE SEULE FOIS. `etat_du_magasin` l'exécute et le test de coût
/// l'inspecte : aucun des deux ne peut diverger de l'autre. C'est la mécanique de `Sonde::requete`,
/// et elle existe pour la même raison — un coût mesuré sur une requête recopiée ne mesure rien.
/// Paramètres LIÉS : `?1` = le nom de la série, `?2` = la borne basse de la fenêtre.
pub(crate) const ENONCE_FENETRE: &str =
    "SELECT COUNT(*), MAX(value), MIN(value), MIN(ts) FROM metric WHERE name=?1 AND ts>=?2";
/// L'énoncé du DÉNOMINATEUR — le relevé le plus récent de la fenêtre. Même index, même borne.
pub(crate) const ENONCE_TOTAL: &str =
    "SELECT value FROM metric WHERE name=?1 AND ts>=?2 ORDER BY ts DESC LIMIT 1";
/// L'ÉNONCÉ QUI FAIT FOI POUR DIRE « ÇA SERT » — et il en faut un À PART, parce qu'un compte de
/// magasins pas prêts qui vaut ZÉRO ne dit rien tant qu'on ignore SUR COMBIEN. Un relevé ne témoigne
/// d'un approvisionnement qui fonctionne que s'il porte, AU MÊME INSTANT, « aucun pas prêt » ET « au
/// moins un déclaré ». L'appariement se fait sur `ts` parce que le contrat d'ingestion le permet :
/// toutes les métriques d'une même enveloppe de capteur sont écrites avec le `ts` de l'enveloppe
/// (`ingest/mod.rs`, voie `kind=metrics`) — les deux séries d'un même passage partagent donc leur
/// horodatage. `?1` = la série des non-prêts, `?2` = la borne basse, `?3` = la série du total.
pub(crate) const ENONCE_SERT_APPARIE: &str =
    "SELECT COUNT(*) FROM metric nr JOIN metric tot ON tot.name=?3 AND tot.ts=nr.ts \
     WHERE nr.name=?1 AND nr.ts>=?2 AND nr.value<1.0 AND tot.value>=1.0";

/// LA SONDE. `None` = LA LECTURE A ÉCHOUÉ (table absente, verrou, ligne indécodable) — DÉLIBÉRÉMENT
/// distinct de `NonObserve` : les deux interdisent de lever, mais seul le second est un fait établi
/// sur la base ; le premier est un aveu que l'appelant doit porter dans son bilan de tick.
///
/// COÛT, DÉRIVÉ DE L'INDEX ET NON SUPPOSÉ : `idx_metric(name, ts)` est ts-leading DANS le nom, donc
/// les deux énoncés SEEK la série puis parcourent la seule PLAGE de la fenêtre. Ce qui borne le coût
/// n'est donc pas le volume ingéré mais la CADENCE de la série — douze relevés par heure pour un
/// capteur à cinq minutes. L'invariance sous mutation du volume est vérifiée par mutation dans
/// `tests/magasin_de_secrets.rs`, jamais par relecture du plan.
pub(crate) fn etat_du_magasin(conn: &Connection, now_ts: i64) -> Option<EtatDuMagasin> {
    let depuis = now_ts - FENETRE_DE_JUGEMENT_S;
    // Une seule passe sur la plage : le compte des relevés, le pire, le meilleur, et la borne basse
    // de l'épisode. `MIN(value)` est ce qui décide : il vaut 0 dès qu'UN relevé a vu tout prêt.
    let (releves, pire, meilleur, plus_ancien): (i64, Option<f64>, Option<f64>, Option<i64>) = conn
        .query_row(
            ENONCE_FENETRE,
            params![SERIE_MAGASINS_NON_PRETS, depuis],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .ok()?;
    let releves = usize::try_from(releves).ok()?;
    if releves == 0 {
        return Some(EtatDuMagasin::NonObserve);
    }
    // `meilleur` et `pire` sont `Some` dès qu'il y a une ligne : un `None` ici voudrait dire que la
    // colonne a rendu NULL sur une série non vide, c'est-à-dire une base dont on ne peut rien
    // conclure — on l'avoue plutôt que de la traiter comme un zéro.
    let (pire, meilleur) = (pire?, meilleur?);
    // UN relevé « tout prêt » suffit à dire que le magasin sert : c'est l'asymétrie voulue (lever
    // lentement, résoudre tout de suite). Il est cherché sur TOUTE la fenêtre, pas seulement sur le
    // dernier relevé, pour que la levée exige bien l'unanimité.
    //
    // MAIS ZÉRO SUR ZÉRO N'EST PAS UNE SANTÉ, ET C'EST MESURÉ SUR LE CAPTEUR LIVRÉ. `collectors/
    // kube-state.sh` entre dans sa branche de publication dès qu'un `get` RÉUSSIT — y compris sur zéro
    // ressource, et son commentaire revendique ce « vrai zéro ». Il publie alors `secretstore_total=0`
    // ET `secretstore_notready=0`. Décider sur le seul numérateur faisait donc qu'EFFACER les magasins
    // pendant l'incident — désinstaller l'opérateur, vider l'espace de noms, retirer la CRD — RÉSOLVAIT
    // l'alerte et affirmait la santé. Un dead-man's-switch que la disparition de ce qu'il surveille
    // ÉTEINT est exactement le défaut que ce module poursuit, retourné contre lui.
    if meilleur < 1.0 {
        // Le dénominateur est-il seulement publié sur cette fenêtre ? S'il ne l'est pas (capteur d'une
        // version antérieure, autre émetteur), on ne peut RIEN apparier : le comportement historique est
        // conservé tel quel, et l'alerte reste résolvable. Ce qu'on refuse, c'est de conclure « sain »
        // quand le dénominateur EST là et dit zéro.
        let denominateur_publie: i64 = conn
            .query_row(ENONCE_FENETRE, params![SERIE_MAGASINS_TOTAL, depuis], |r| r.get(0))
            .ok()?;
        if denominateur_publie == 0 {
            return Some(EtatDuMagasin::Sert { releves });
        }
        let temoins_de_service: i64 = conn
            .query_row(
                ENONCE_SERT_APPARIE,
                params![SERIE_MAGASINS_NON_PRETS, depuis, SERIE_MAGASINS_TOTAL],
                |r| r.get(0),
            )
            .ok()?;
        if temoins_de_service > 0 {
            return Some(EtatDuMagasin::Sert { releves });
        }
        // Des relevés existent, mais AUCUN ne témoigne d'un magasin DÉCLARÉ et prêt. Rien n'a été
        // observé de l'approvisionnement : on ne lève pas (il n'y a personne à accuser) et surtout ON
        // NE RÉSOUT PAS — résoudre ici serait précisément affirmer une santé qu'on n'a pas observée.
        return Some(EtatDuMagasin::NonObserve);
    }
    if releves < PLANCHER_DE_RELEVES {
        return Some(EtatDuMagasin::Indecis { releves });
    }
    let total = conn
        .query_row(
            ENONCE_TOTAL,
            params![SERIE_MAGASINS_TOTAL, depuis],
            |r| r.get::<_, f64>(0),
        )
        .ok()
        .map(|v| v as i64);
    Some(EtatDuMagasin::NeSertPlus {
        non_prets: pire as i64,
        total,
        releves,
        au_moins_depuis_s: plus_ancien.map(|t| now_ts - t).unwrap_or(0).max(0),
    })
}

/// LE TITRE — ce qu'un exploitant lit dans une liste, et ce qui remonte au bulletin de support
/// (`handlers/system.rs` sélectionne `rule LIKE 'heartbeat.%'`). Il ne porte que des NOMBRES.
pub(crate) fn titre_du_magasin(non_prets: i64, total: Option<i64>) -> String {
    match total {
        Some(t) => format!("Magasin de secrets indisponible : {non_prets} sur {t}"),
        None => format!("Magasin de secrets indisponible : {non_prets}"),
    }
}

/// LE TEXTE DE L'ALERTE, séparé de sa levée pour être éprouvable sans base. Il dit la CONSÉQUENCE
/// (ce n'est pas « un objet est rouge », c'est « plus aucune clé ne tourne »), la durée observée, et
/// CE QU'IL NE COUVRE PAS — sans quoi l'exploitant croirait le silence de ce signal probant sur les
/// secrets qu'un agent extérieur lui projette en fichiers.
pub(crate) fn detail_du_magasin(non_prets: i64, total: Option<i64>, releves: usize, au_moins_depuis_s: i64) -> String {
    let denominateur = match total {
        Some(t) => format!(" sur {t} déclaré(s)"),
        None => " (dénominateur non publié par le capteur)".to_string(),
    };
    format!(
        "{non_prets} magasin(s) de secrets{denominateur} ne se déclarent pas prêts, sur la TOTALITÉ des \
         {releves} relevé(s) de la dernière heure (au moins {} min). Tant que c'est le cas, AUCUN secret \
         approvisionné par ce magasin ne se renouvelle : la rotation des clés est éteinte, pour tous ses \
         consommateurs à la fois — c'est la raison pour laquelle il n'y a qu'UNE alerte ici et pas une par \
         secret. Le démon, lui, continue de servir avec les secrets déjà injectés : ce signal n'est PAS une \
         panne de Plume. Cette alerte se résout d'elle-même au premier relevé qui voit les magasins prêts. \
         CE QU'ELLE NE COUVRE PAS : un secret projeté en FICHIER par un agent extérieur ne dit rien de la \
         santé de son magasin — sans relevé du magasin lui-même, ce signal ne conclut rien.",
        au_moins_depuis_s / 60
    )
}

/// LÈVE OU RÉSOUT, et rend son bilan de tick. Appelé depuis `check_heartbeats` (même tick, même
/// verrou, même famille d'alertes que le capteur muet et la flotte muette).
///
/// LES TROIS SORTIES SONT DISTINCTES, ET C'EST LE CŒUR :
///   * lecture ÉCHOUÉE -> on ne lève ni ne résout, ET on le DIT (`Mesure::Illisible`) : un
///     dead-man's-switch qui ne sait plus lire n'a pas le droit de s'éteindre en silence ;
///   * `NonObserve` -> on ne lève ni ne résout, et ce n'est PAS un aveu : rien n'a échoué, personne
///     n'a simplement rapporté. Un aveu ici ferait crier tous les déploiements sans magasin ;
///   * observé -> lève ou résout.
pub(crate) fn verifier_le_magasin_de_secrets(conn: &Connection, now_ts: i64) -> Mesure<u32> {
    let Some(etat) = etat_du_magasin(conn, now_ts) else {
        return Mesure::Illisible {
            cause: crate::mesure_environnement::CAUSE_SOURCE_ILLISIBLE,
            detail: format!(
                "magasin de secrets : la série `{SERIE_MAGASINS_NON_PRETS}` n'a pas pu être lue — \
                 l'approvisionnement des secrets n'a pas été observé ce tick"
            ),
        };
    };
    match etat {
        // Rien n'a été rapporté : on se tait, et on ne résout rien. Le silence de ce signal ne vaut
        // PAS « l'approvisionnement va bien » — c'est la dette nommée du bandeau.
        // Ni observé, ni assez observé : dans les DEUX cas on se tait ET on laisse l'épisode ouvert.
        // Ce ne sont pas des aveux — rien n'a échoué, il n'y a simplement pas de quoi conclure.
        EtatDuMagasin::NonObserve | EtatDuMagasin::Indecis { .. } => {}
        EtatDuMagasin::Sert { .. } => {
            let _ = conn.execute(
                "UPDATE alert SET status='resolved', dedup=NULL WHERE dedup=?1 AND status IN ('new','ack')",
                params![DEDUP_MAGASIN],
            );
        }
        EtatDuMagasin::NeSertPlus { non_prets, total, releves, au_moins_depuis_s } => {
            let titre = titre_du_magasin(non_prets, total);
            let detail = detail_du_magasin(non_prets, total, releves, au_moins_depuis_s);
            // L'IMPUTATION est l'INCONNU NOMMÉ : cette alerte se rapporte à un MAGASIN, pas à un
            // flux. Lui imputer la source qui l'a rapportée (`k8s`) ferait basculer la pastille d'un
            // capteur qui fonctionne parfaitement — la même raison que pour la flotte muette.
            let sources = crate::imputation_encoder(&[crate::SOURCE_INDETERMINABLE.to_string()]);
            let _ = conn.execute(
                "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,sources) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![now_ts, FAMILLE_ALERTE, SEVERITE, titre, detail, DEDUP_MAGASIN, sources],
            );
            // Épisode DÉJÀ ouvert : on rafraîchit le texte et l'horodatage SANS toucher `notified`
            // (pas de re-notification à chaque tick), exactement comme `detection_aveugle`.
            let _ = conn.execute(
                "UPDATE alert SET ts=?1, title=?2, detail=?3, sources=?4 WHERE dedup=?5 AND status IN ('new','ack')",
                params![now_ts, titre, detail, sources, DEDUP_MAGASIN],
            );
        }
    }
    Mesure::Lue(0)
}
