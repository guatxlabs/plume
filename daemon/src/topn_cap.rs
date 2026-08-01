//! topn_cap — LE PLAFOND TOP-N NE PEUT PLUS ÊTRE DÉCLARÉ SANS SON AMPLEUR.
//!
//! LE DÉFAUT QU'IL FERME — ET CE QU'IL N'EST PAS. Contrairement aux quatre précédents (le tier froid
//! agrégeant sur un échantillon, la route de rollups servant une table incomplète sous `approx:false`,
//! la route dimensionnelle rendant `0` pour 5 696 événements, les capteurs sortant en succès sans rien
//! collecter), la perte dont il est question ici est VOULUE : le rollup par dimension ne garde que les
//! `PLUME_ROLLUP_DIM_TOPN` valeurs les plus fréquentes de chaque (bucket, env) et jette la queue. La
//! route l'a TOUJOURS déclaré (`approx:true, truncated:true`). Elle ne mentait donc pas.
//!
//! Elle n'était simplement pas INTERPRÉTABLE. `truncated: true` dit « des valeurs manquent ». Il ne dit
//! pas « il en manque seize fois plus que ce que tu vois ». Un analyste qui lit 24 055 ne peut pas
//! deviner que la vérité est 395 043 ; et un drapeau qui ne change jamais de valeur cesse d'être lu.
//!
//! MESURÉ (2026-08-01, base de banc de 1 436 026 événements sur 28 jours, binaire du dépôt, fenêtre
//! ENTIÈREMENT contenue dans la bande que la couverture témoigne — donc à couverture égale, la seule
//! perte restante étant celle du plafond). Sur les 37 couples (source, dim) réellement pré-agrégés :
//!
//!     23 couples          perdent ZÉRO           (cardinalité sous le plafond : le compte est exact)
//!     auditd/exe          24 055 servis / 395 043 vrais   -> x16,4  (370 988 événements écartés, 93,9 %)
//!     auditd/key          24 206 / 395 043                -> x16,3
//!     auditd/comm         24 235 / 395 043                -> x16,3
//!     auditd/action       24 431 / 395 043                -> x16,2
//!     sshd-session/action 24 021 /  74 664                -> x3,1
//!     sshd-session/user   29 960 /  74 664                -> x2,5
//!     kube-audit/resource 24 016 /  42 807                -> x1,8   (verb x1,77 ; action x1,78)
//!     ufw/dport           25 545 /  38 150                -> x1,5
//!     fail2ban/jail       24 239 /  33 053                -> x1,4
//!     vault-audit/path    22 319 /  25 808                -> x1,2
//!     cloudflare/action   19 009 /  20 180                -> x1,06  (cf_source idem)
//!
//! L'étendue réelle va donc de x1,00 à x16,4 — et non de x4 à x5,7 comme une lecture antérieure le
//! retenait. Le maximum n'est pas un cas de bord : c'est la source la plus volumineuse du jeu.
//!
//! OÙ LE NOMBRE EXISTE, ET OÙ IL N'EXISTE PLUS. L'ampleur n'est PAS calculable au moment de la lecture
//! sans refaire le travail que le plafond évite : reconstituer le compte complet demanderait le balayage
//! d'`event` que le pré-agrégé remplace (MESURÉ sur la même base : `SUM(n)` par source sur `event_rollup`
//! coûte 668 ms à froid / ~100 ms à chaud, contre ~25 ms pour la route entière — l'ampleur coûterait
//! quatre fois la réponse). Elle existe en revanche À L'ÉCRITURE, gratuitement : le job tient l'agrégat
//! complet dans la main juste avant de le tronquer. C'est donc lui qui l'écrit — une LIGNE DE RESTE par
//! (bucket, source, dim, env), sous une dimension réservée (`rollups::reste_dim`), dans la MÊME
//! instruction et le MÊME balayage. La route ne fait plus que la LIRE, sur le MÊME index, en même temps
//! qu'elle lit ce qu'elle sert.
//!
//! POURQUOI UN TYPE PLUTÔT QU'UN `bool`. Le `bool` était le problème : il se pose sans rien fournir, et
//! il s'est posé pendant des mois sans que personne ne puisse le chiffrer. Ici :
//!   1. le seul moyen de DÉCLARER un plafond est `Cap::top_n(sonde)`, qui EXIGE la requête qui le mesure ;
//!   2. le seul moyen d'obtenir une `CapMesure` est `Cap::mesurer` (dérivation depuis la base) ou
//!      `Cap::sans_base` (aveu : aucune connexion sous la main) — aucun constructeur littéral ;
//!   3. `apply_rollup_stats` prend une `CapMesure`, pas un `bool` : une route qui déclarerait une
//!      troncature sans l'avoir mesurée NE COMPILE PAS ;
//!   4. la dérivation est DÉFAUT-AVEU : sonde illisible, lignes de reste absentes (base agrégée par un
//!      binaire antérieur, tranche froide scellée avant ce correctif) -> `non établie`, et la route le
//!      DIT au lieu de publier un 0 rassurant.
//!
//! CE QUI RESTE HORS DE PORTÉE, ET DOIT LE RESTER. Le nombre de VALEURS distinctes absentes de la
//! réponse n'est pas additif entre buckets : une valeur écartée d'une heure peut être gardée à l'heure
//! suivante. L'établir, c'est énumérer l'ensemble complet des valeurs — exactement le travail que le
//! plafond existe pour éviter. On ne le publie donc pas, et on ne le remplace par aucune estimation.

use crate::*;

/// CE QUE LA ROUTE ÉCARTE. Deux états, et le second ne se construit pas sans de quoi le chiffrer.
pub(crate) enum Cap {
    /// La route n'écarte RIEN : grain exact, aucune valeur abandonnée (ROUTE A, ROUTE A-multi).
    Aucun,
    /// Le plafond top-N écarte — et voici la SONDE qui en mesure l'ampleur.
    TopN(Sonde),
}

/// La requête qui chiffre le reste écarté sur EXACTEMENT les bandes que la route sert. Champ privé :
/// un appelant ne peut ni la fabriquer ailleurs, ni déclarer un plafond sans elle.
pub(crate) struct Sonde {
    sql: String,
}

impl Cap {
    /// DÉCLARE un plafond top-N. `sql` doit rendre UNE ligne de quatre entiers, dans cet ordre :
    /// écartés, servis, heures dont le reste est CONNU, heures SERVIES. Construit uniquement par la
    /// route qui pose le plafond, à partir des mêmes conditions que le SQL qu'elle rend.
    pub(crate) fn top_n(sql: String) -> Self {
        Cap::TopN(Sonde { sql })
    }

    /// MESURE l'ampleur depuis la base. DÉFAUT = AVEU : sonde en erreur, ou lignes de reste absentes des
    /// heures servies -> `non établie` (la route le dit), jamais un zéro inventé.
    pub(crate) fn mesurer(&self, conn: &Connection) -> CapMesure {
        let Cap::TopN(s) = self else { return CapMesure(Etat::Aucun) };
        let lu = conn.query_row(&s.sql, [], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?))
        });
        match lu {
            // AUCUNE heure ne porte son reste alors que des heures sont servies : ces buckets ont été
            // agrégés par un binaire qui ne l'écrivait pas -> on ne sait RIEN, et on le dit. Le cas
            // `0 servi, 0 connu` (bande vide) n'est pas celui-là : il n'y a rien d'écarté, et c'est établi.
            Ok((_, _, 0, servies)) if servies > 0 => CapMesure(Etat::NonEtablie),
            Ok((ecartes, servis, heures_connues, heures_servies)) => {
                CapMesure(Etat::Etablie { ecartes, servis, heures_connues, heures_servies })
            }
            Err(_) => CapMesure(Etat::NonEtablie),
        }
    }

    /// Cette route POSE-T-ELLE un plafond ? Question de LECTURE sur une route déjà construite (tests,
    /// journalisation) — elle n'ouvre aucun chemin pour en DÉCLARER un : `Cap::top_n` reste le seul
    /// constructeur, et il exige toujours sa sonde.
    pub(crate) fn plafonne(&self) -> bool {
        matches!(self, Cap::TopN(_))
    }

    /// AVEU : aucune connexion sous la main (pool indisponible). Un plafond reste un plafond — il est
    /// déclaré, son ampleur ne l'est pas. C'est la valeur par défaut du `read_with` qui le mesure.
    pub(crate) fn sans_base(&self) -> CapMesure {
        match self {
            Cap::Aucun => CapMesure(Etat::Aucun),
            Cap::TopN(_) => CapMesure(Etat::NonEtablie),
        }
    }
}

/// L'état d'un plafond APRÈS mesure. Privé : voir `CapMesure`.
enum Etat {
    /// Rien n'est écarté.
    Aucun,
    /// Le plafond écarte, et son ampleur n'a PAS pu être établie. Ce n'est pas « zéro écarté ».
    NonEtablie,
    /// Le plafond écarte, et voici de combien, sur les heures dont le reste est connu.
    Etablie { ecartes: i64, servis: i64, heures_connues: i64, heures_servies: i64 },
}

/// L'AMPLEUR DE CE QUE LA ROUTE ÉCARTE, MESURÉE. **Aucun constructeur littéral** : on l'obtient par
/// `Cap::mesurer` (dérivation depuis la base) ou `Cap::sans_base` (aveu). Un site d'appel ne peut donc
/// pas AFFIRMER qu'une réponse est tronquée — ni qu'elle ne l'est pas — sans passer par la mesure.
pub(crate) struct CapMesure(Etat);

impl CapMesure {
    /// La réponse est-elle INCOMPLÈTE du fait du plafond ? (`stats.truncated`, OR-é avec le plafond de
    /// lignes existant par `apply_rollup_stats`.)
    ///
    /// LE DRAPEAU DEVIENT INFORMATIF DANS LES DEUX SENS, et c'est la contrepartie de la mesure. Avant,
    /// toute réponse de la ROUTE B sortait `truncated: true` — y compris les 23 couples (source, dim) sur
    /// 37 qui, MESURE À L'APPUI, n'écartent RIEN (leur cardinalité tient sous le plafond). Un drapeau qui
    /// ne varie jamais cesse d'être lu, et crier au loup est le défaut MIROIR de taire l'ampleur. Une
    /// perte NULLE, ÉTABLIE sur TOUTE la bande servie, rend donc `false` : la réponse est complète, et on
    /// est en mesure de le prouver. `NonEtablie` rend `true` — le plafond est posé et rien ne permet de
    /// dire qu'il n'a pas mordu ; l'ignorance penche du côté sûr.
    pub(crate) fn tronque(&self) -> bool {
        match self.0 {
            Etat::Aucun => false,
            Etat::NonEtablie => true,
            Etat::Etablie { ecartes, heures_connues, heures_servies, .. } => {
                ecartes > 0 || heures_connues < heures_servies
            }
        }
    }

    /// Les trois nombres publiés dans `stats` : écartés, servis, total réel (servis + écartés) sur la
    /// bande servie. `None` tant que l'ampleur n'est pas établie — on ne publie pas de chiffre qu'on
    /// n'a pas.
    pub(crate) fn chiffres(&self) -> Option<(i64, i64, i64)> {
        match self.0 {
            Etat::Etablie { ecartes, servis, .. } => Some((ecartes, servis, servis + ecartes)),
            _ => None,
        }
    }

    /// LA PHRASE. Elle dit l'ampleur en chiffres, la part du total, et — quand toutes les heures
    /// servies ne portent pas leur reste — sur combien d'heures cette ampleur est établie. `None`
    /// quand il n'y a rien à écarter (le silence est alors la vérité).
    pub(crate) fn note(&self) -> Option<String> {
        match self.0 {
            Etat::Aucun => None,
            Etat::NonEtablie => Some(
                "le plafond top-N écarte une partie des valeurs et l'AMPLEUR de ce qu'il écarte n'est pas \
                 établie sur cette fenêtre (heures agrégées par un binaire antérieur, ou tranche froide \
                 scellée avant ce correctif) : le compte affiché est un PLANCHER, d'un écart inconnu."
                    .to_string(),
            ),
            Etat::Etablie { ecartes, servis, heures_connues, heures_servies } => {
                let total = servis + ecartes;
                if ecartes == 0 && heures_connues >= heures_servies {
                    return None; // rien d'écarté, et on le sait sur toute la bande : il n'y a rien à dire.
                }
                let part = if total > 0 { (ecartes * 100) / total } else { 0 };
                let partiel = if heures_connues < heures_servies {
                    format!(
                        " Ampleur établie sur {heures_connues} heure(s) servie(s) sur {heures_servies} — \
                         le reste des heures peut écarter davantage, sans qu'on sache combien."
                    )
                } else {
                    String::new()
                };
                Some(format!(
                    "le plafond top-N a écarté {ecartes} événement(s) sur {total} ({part} %) : le compte \
                     affiché ({servis}) est un PLANCHER, pas une approximation à quelques unités près. Le \
                     nombre de VALEURS distinctes absentes n'est pas connu (l'établir demanderait le \
                     balayage que le plafond évite). Pour un compte complet, refaire la requête sous une \
                     forme non routable (ajouter un filtre) ou relever PLUME_ROLLUP_DIM_TOPN.{partiel}"
                ))
            }
        }
    }

    /// TEST SEULEMENT — fabrique une mesure ARBITRAIRE (miroir de
    /// `RollupCoverage::asserted_by_the_test`) : `cfg(test)`, donc aucun chemin de production ne peut
    /// affirmer une ampleur qu'il n'a pas dérivée.
    #[cfg(test)]
    pub(crate) fn affirmee_par_le_test(ecartes: i64, servis: i64, heures_connues: i64, heures_servies: i64) -> Self {
        CapMesure(Etat::Etablie { ecartes, servis, heures_connues, heures_servies })
    }
}
