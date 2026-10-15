//! `P10.32-q` — LE MOTIF D'EXPRESSION RÉGULIÈRE D'UNE REQUÊTE : un seul constructeur BORNÉ, un cache à
//! plusieurs motifs qui sert le motif PAR RÉFÉRENCE.
//!
//! Un motif de requête vient de l'utilisateur (`champ=~motif`, `| rex`, règle Sigma traduite) : il est
//! compilé par les UDF `regexp`/`re_cap` du chemin chaud (`query_exec::install_query_udfs`) ET par le
//! planificateur vectorisé du tier froid (`cold_store::planner::build_leaf`). Les deux passent par
//! `compiler_motif`, de sorte que le plafond de longueur et les limites du programme sont LES MÊMES des
//! deux côtés : un motif refusé au chaud ne se compile pas au froid (le froid rend alors la main au chemin
//! chaud, qui dit le refus).
//!
//! CE QUI EST BORNÉ, ET COMMENT :
//! * la longueur du motif : `LONGUEUR_MAX_DU_MOTIF` octets, refus `MotifRefuse::TropLong` ;
//! * la taille de chaque automate de Thompson (avant ET arrière) : `PLAFOND_DU_PROGRAMME` octets
//!   (`RegexBuilder::size_limit`, dont le défaut de la bibliothèque est dix fois plus grand) — un motif court
//!   peut dépasser, `\w` étant Unicode : refus `MotifRefuse::Invalide(CompiledTooBig)` ;
//! * le cache de transitions du DFA paresseux : `PLAFOND_DU_DFA_PARESSEUX` octets
//!   (`RegexBuilder::dfa_size_limit`, qui règle la capacité du cache hybride, pas un DFA complet) ;
//! * le nombre de motifs gardés compilés par UDF et par connexion de lecture : `MOTIFS_EN_CACHE`.
//!
//! MÉMOIRE PIRE CAS, LUE DANS LA SOURCE DE `regex` 1.12 / `regex-automata` 0.4 ET NON MESURÉE (sauf le cache
//! du DFA paresseux, témoigné par le pic de tas dans `tests/regex_de_requete_bornee.rs`). Deux parts :
//! * COMPILÉE, une fois par motif : deux automates de Thompson (avant, arrière ; un troisième, l'arrière du
//!   préfixe, pour la stratégie « reverse inner ») d'au plus `PLAFOND_DU_PROGRAMME` chacun, PLUS un DFA
//!   onepass quand le motif s'y prête, borné par le défaut de `regex-automata` (`onepass_size_limit`, 1 Mio) —
//!   `regex::RegexBuilder` n'expose pas ce réglage, ce module ne le borne donc PAS ;
//! * CACHES DE RECHERCHE, un jeu par fil qui sert le motif (le `Pool` de `meta::Regex` : le fil propriétaire,
//!   plus un jeu par pile, `thread_id % 8`, soit jusqu'à neuf jeux pour une connexion servie tour à tour par
//!   des fils différents). Chaque jeu : jusqu'à trois caches de DFA paresseux (avant, arrière, et l'arrière
//!   des stratégies « reverse suffix/inner ») d'au plus `PLAFOND_DU_DFA_PARESSEUX` chacun, le tableau du
//!   retour arrière borné (`visited_capacity`, 256 Kio par défaut), et le cache du PikeVM, proportionnel au
//!   nombre d'états du programme.
//! Par connexion de lecture, deux UDF de `MOTIFS_EN_CACHE` motifs chacune multiplient ces deux parts par
//! `2 × MOTIFS_EN_CACHE`.
//!
//! POURQUOI PAR RÉFÉRENCE. `Clone` de `regex::Regex` ne recompile pas, mais `regex_automata::meta::Regex`
//! se clone avec un `Pool` NEUF : le cache du DFA paresseux repart vide au premier appel. Cloner à chaque
//! ligne, c'était reconstruire ce cache à chaque ligne. `MotifCompile` n'implémente donc PAS `Clone` et garde
//! son expression privée : le cache ne peut que la PRÊTER.
//!
//! CE QUE CE MODULE NE TIENT PAS : la famine du sémaphore interactif (`query_timing::acquire_query_permit`,
//! politique de file non écrite) ; le coût de recherche d'un motif admis à la limite ; la valeur parcourue
//! recopiée en `String` à chaque ligne par les UDF ; les autres compilations de motifs d'utilisateur
//! (`handlers/detection.rs`, `processors.rs`).

/// Longueur maximale d'un motif de requête, en octets — LE plafond, commun au chaud et au froid.
pub(crate) const LONGUEUR_MAX_DU_MOTIF: usize = 512;
/// Taille maximale de chaque automate compilé (`RegexBuilder::size_limit`), même chiffre que `parsers.rs`.
pub(crate) const PLAFOND_DU_PROGRAMME: usize = 1 << 20;
/// Capacité du cache de transitions du DFA paresseux (`RegexBuilder::dfa_size_limit`).
pub(crate) const PLAFOND_DU_DFA_PARESSEUX: usize = 1 << 20;
/// Nombre de motifs gardés compilés par UDF et par connexion : couvre une requête qui combine quelques
/// expressions (`OR`, `| rex` + filtre) sans recompiler à chaque ligne.
pub(crate) const MOTIFS_EN_CACHE: usize = 4;

/// Le message servi par les UDF pour un motif trop long — inchangé depuis l'UDF d'origine.
pub(crate) const MESSAGE_MOTIF_TROP_LONG: &str = "motif regex trop long (max 512)";

/// Pourquoi un motif n'est pas compilé.
#[derive(Debug)]
pub(crate) enum MotifRefuse {
    /// Plus de `LONGUEUR_MAX_DU_MOTIF` octets.
    TropLong,
    /// Rejeté par la bibliothèque : syntaxe, ou programme au-delà de `PLAFOND_DU_PROGRAMME`.
    Invalide(regex::Error),
}

impl MotifRefuse {
    /// L'erreur rendue par une UDF : mêmes messages qu'avant ce module (texte fixe pour la longueur,
    /// erreur de la bibliothèque telle quelle sinon).
    pub(crate) fn en_erreur_udf(self) -> rusqlite::Error {
        match self {
            MotifRefuse::TropLong => rusqlite::Error::UserFunctionError(MESSAGE_MOTIF_TROP_LONG.into()),
            MotifRefuse::Invalide(e) => rusqlite::Error::UserFunctionError(Box::new(e)),
        }
    }
}

/// Refus de longueur seul, sans compiler — l'UDF `regexp` le juge AVANT de lire la valeur (un motif trop
/// long est refusé même sur une valeur NULL, comme avant).
pub(crate) fn motif_admissible(pat: &str) -> Result<(), MotifRefuse> {
    if pat.len() > LONGUEUR_MAX_DU_MOTIF {
        return Err(MotifRefuse::TropLong);
    }
    Ok(())
}

/// LE constructeur borné : plafond de longueur puis `RegexBuilder` aux limites explicites.
pub(crate) fn compiler_motif(pat: &str) -> Result<regex::Regex, MotifRefuse> {
    motif_admissible(pat)?;
    #[cfg(test)]
    COMPILATIONS_DU_FIL.with(|c| c.set(c.get() + 1));
    regex::RegexBuilder::new(pat)
        .size_limit(PLAFOND_DU_PROGRAMME)
        .dfa_size_limit(PLAFOND_DU_DFA_PARESSEUX)
        .build()
        .map_err(MotifRefuse::Invalide)
}

/// Un motif compilé, PRÊTÉ par le cache. Pas de `Clone` : voir l'en-tête du module.
pub(crate) struct MotifCompile(regex::Regex);

impl MotifCompile {
    pub(crate) fn correspond(&self, valeur: &str) -> bool {
        self.0.is_match(valeur)
    }
    /// Texte du groupe NOMMÉ `groupe` de la première correspondance, ou `None`.
    pub(crate) fn capture(&self, valeur: &str, groupe: &str) -> Option<String> {
        self.0.captures(valeur).and_then(|caps| caps.name(groupe).map(|m| m.as_str().to_string()))
    }
}

/// Cache borné à `capacite` motifs, éviction du moins récemment servi. Les entrées sont rangées par usage :
/// la plus récente en FIN. `capacite` est petit : la recherche linéaire coûte moins qu'un hachage.
pub(crate) struct CacheDeMotifs {
    capacite: usize,
    entrees: Vec<(String, MotifCompile)>,
}

impl CacheDeMotifs {
    pub(crate) fn new() -> Self {
        Self::avec_capacite(MOTIFS_EN_CACHE)
    }

    pub(crate) fn avec_capacite(capacite: usize) -> Self {
        let capacite = capacite.max(1);
        CacheDeMotifs { capacite, entrees: Vec::with_capacity(capacite) }
    }

    /// Le motif compilé pour `pat`, compilé au premier usage, PRÊTÉ ensuite sans recompilation ni copie.
    pub(crate) fn motif(&mut self, pat: &str) -> Result<&MotifCompile, MotifRefuse> {
        match self.entrees.iter().position(|(p, _)| p == pat) {
            Some(i) => {
                if i + 1 != self.entrees.len() {
                    let entree = self.entrees.remove(i);
                    self.entrees.push(entree);
                }
            }
            None => {
                let re = compiler_motif(pat)?;
                if self.entrees.len() >= self.capacite {
                    self.entrees.remove(0);
                }
                self.entrees.push((pat.to_owned(), MotifCompile(re)));
            }
        }
        // L'entrée servie est la dernière : elle vient d'y être remise ou posée (le vecteur n'est pas vide).
        let derniere = self.entrees.len() - 1;
        Ok(&self.entrees[derniere].1)
    }
}

// TEST-ONLY — compte des compilations tentées sur CE fil (les UDF s'exécutent sur le fil qui pose la requête) :
// le témoin lit combien de fois une requête a compilé, sans couture dans `query_exec.rs`.
#[cfg(test)]
thread_local! {
    static COMPILATIONS_DU_FIL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
pub(crate) fn compilations_du_fil() -> u64 {
    COMPILATIONS_DU_FIL.with(|c| c.get())
}
