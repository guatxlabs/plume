//! `P10.27-k` — LA VÉRIFICATION HORS LIGNE D'UNE COPIE CHAÎNÉE : le registre des tenants (`ledger-verify-export`) et
//! le journal du plan de contrôle. La lecture des lignes, les deux ancrages de la chaîne et la règle de répétition
//! n'existent qu'ici ; chaque journal n'apporte que SA recette de hachage (`RecetteDeChaine`). Module pur : aucune
//! base, aucun état partagé.
//!
//! D'OÙ VIENNENT LES RÉPÉTITIONS. L'envoi vers un puits écrit la tranche dans la copie PUIS valide l'avance de son
//! curseur (« exporter puis avancer » : jamais de trou). Un `COMMIT` refusé après l'écriture laisse la tranche dans la
//! copie et le curseur en arrière ; l'envoi suivant relit depuis l'ANCIEN curseur et réécrit la tranche, éventuellement
//! suivie de maillons neufs. Une écriture interrompue sur une fin de ligne laisse une tranche partielle, que l'envoi
//! suivant réécrit en entier. Relancer `ledger-export --out` sur un fichier existant (ouverture en ajout), ou mettre
//! bout à bout des téléchargements recouvrants, produit la même forme. Le vérificateur d'avant `P10.27-k` lisait la
//! première ligne répétée comme une rupture de chaîne et déclarait la copie COMPROMISE — une fausse accusation, portée
//! par l'outil qu'un tiers emploie pour juger l'intégrité.
//!
//! LA RÈGLE. Une ligne IDENTIQUE OCTET POUR OCTET à une ligne déjà retenue est écartée et comptée, où qu'elle se trouve.
//! Toute autre ligne passe par les deux ancrages — `prev_hash` égal au hachage de la dernière ligne retenue (la tête),
//! et hachage recalculé égal au hachage porté — puis devient la tête. L'invariant, qui est tout ce que la vérification
//! affirme : les lignes retenues forment, dans l'ordre de la copie, une chaîne valide depuis `expect_prev`, et chaque
//! ligne écartée est la copie exacte d'une ligne retenue plus haut. Restent donc accusées : une ligne altérée
//! (recalcul), une ligne manquante, déplacée ou insérée (`prev_hash`), et une FOURCHE — même identifiant, autre
//! contenu —, qui n'est pas une copie exacte, ne s'accroche pas à la tête, et que la rupture NOMME.
//!
//! POURQUOI PAS PLUS STRICT. La première forme de cette règle exigeait qu'une répétition soit une tranche CONTIGUË
//! rejoignant la tête avant toute autre ligne. Elle accusait des copies intègres : une tranche rejouée interrompue sur
//! une fin de ligne puis réécrite (`1,2,3 | 1,2 | 1,2,3,4`), des téléchargements recouvrants de bornes différentes
//! (`1..4`, `3`, `5..`). Cette exigence de FORME ne tenait aucune propriété de la chaîne : les lignes qu'elle refusait
//! d'écarter étaient des copies exactes, et toute ligne non écartée passe par les deux ancrages.
//!
//! LES REPRISES sont comptées pour être DITES, jamais pour juger. Une reprise commence à une ligne répétée qui ne
//! continue pas la reprise en cours, se poursuit tant que chaque ligne est, à l'identique, la ligne retenue qui suit, et
//! se clôt en rejoignant la tête. Une copie qui se TERMINE au milieu d'une reprise (écriture interrompue, copie
//! tronquée) n'y perd rien de ce qui a été vérifié ; le verdict le porte (`reprise_inachevee`) — une queue tronquée
//! n'est pas plus visible sans répétition qu'avec.
//!
//! CE QUE LA RÈGLE NE VOIT PAS, COMME AVANT : l'identifiant d'un maillon n'est pas couvert par son hachage, donc une copie
//! RENUMÉROTÉE dont la chaîne reste valide passe ; une queue coupée sur une fin de ligne n'est pas distinguable d'une
//! copie plus courte.
use crate::*;

/// Ce qu'une copie chaînée qui se vérifie porte : ses maillons distincts, et les répétitions écartées.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CopieChaineeVerifiee {
    /// Maillons DISTINCTS vérifiés : la chaîne, sans ses répétitions.
    pub(crate) maillons: usize,
    /// Lignes écartées parce qu'identiques, octet pour octet, à une ligne déjà vérifiée.
    pub(crate) lignes_repetees: usize,
    /// Nombre de reprises (suites de lignes répétées) rencontrées.
    pub(crate) reprises: usize,
    /// La copie se termine au milieu d'une reprise, avant d'avoir rejoint la tête.
    pub(crate) reprise_inachevee: bool,
}

/// Ce qui distingue un journal de l'autre.
pub(crate) struct RecetteDeChaine {
    /// Le texte dont le SHA-256 est le hachage du maillon, à partir du hachage précédent, de l'horodatage et de la
    /// ligne lue — la recette d'écriture du journal, à la lettre.
    pub(crate) texte_hache: fn(&str, i64, &Value) -> String,
    /// Ce que dit la rupture quand le hachage recalculé diffère du hachage porté.
    pub(crate) alteration: &'static str,
}

/// Le champ texte `k` d'une ligne lue ; "" s'il manque, comme les deux journaux l'ont toujours lu.
pub(crate) fn champ_texte<'v>(v: &'v Value, k: &str) -> &'v str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}

/// Les lignes retenues d'une copie, et la reprise en cours.
struct LignesRetenues<'a> {
    /// (id, ligne exacte) de chaque ligne retenue, dans l'ordre de la chaîne. Les lignes retenues sont deux à deux
    /// distinctes : une ligne identique à une ligne retenue est toujours écartée.
    ordre: Vec<(i64, &'a str)>,
    /// Rang, dans `ordre`, de chaque ligne retenue — la clé est le texte EXACT de la ligne.
    rang_par_ligne: HashMap<&'a str, usize>,
    /// Pendant une reprise : le rang de la ligne retenue qui la continuerait.
    reprise: Option<usize>,
    /// La reprise que la ligne courante vient d'interrompre, pour le dire si cette ligne rompt la chaîne.
    interrompue: Option<usize>,
    lignes_repetees: usize,
    reprises: usize,
}

impl<'a> LignesRetenues<'a> {
    fn neuves() -> Self {
        Self { ordre: Vec::new(), rang_par_ligne: HashMap::new(), reprise: None, interrompue: None, lignes_repetees: 0, reprises: 0 }
    }

    /// Vrai si `ligne` est la copie exacte d'une ligne retenue : elle est alors écartée et comptée. Faux sinon, et la
    /// ligne doit passer par les deux ancrages.
    fn ecarter_si_repetee(&mut self, ligne: &'a str) -> bool {
        let rang = match self.reprise {
            Some(attendu) if self.ordre[attendu].1 == ligne => attendu,
            _ => match self.rang_par_ligne.get(ligne) {
                Some(&rang) => {
                    self.reprises += 1;
                    rang
                }
                None => {
                    self.interrompue = self.reprise.take();
                    return false;
                }
            },
        };
        self.lignes_repetees += 1;
        self.reprise = if rang + 1 == self.ordre.len() { None } else { Some(rang + 1) };
        true
    }

    /// Le complément d'une rupture de chaîne. Un identifiant déjà retenu avec un autre contenu est une FOURCHE ; une
    /// ligne qui interrompt une reprise n'est ni la suite exacte de la tranche répétée, ni un maillon accroché à la tête.
    /// Parcours linéaire des lignes retenues : il n'a lieu qu'une fois, sur la ligne qui rompt.
    fn precision_de_rupture(&self, id: i64) -> String {
        if self.ordre.iter().any(|&(vu, _)| vu == id) {
            return format!(" — l'entrée #{id} a déjà été vérifiée avec un contenu DIFFÉRENT (fourche) : ce n'est pas une répétition exacte");
        }
        match (self.interrompue, self.ordre.last()) {
            (Some(attendu), Some(&(id_tete, _))) => format!(
                " — une tranche répétée s'interrompt ici : cette ligne n'est ni l'entrée #{} attendue à l'identique, ni un maillon accroché à la tête (entrée #{id_tete})",
                self.ordre[attendu].0
            ),
            _ => String::new(),
        }
    }

    fn retenir(&mut self, id: i64, ligne: &'a str) {
        self.rang_par_ligne.insert(ligne, self.ordre.len());
        self.ordre.push((id, ligne));
        self.interrompue = None;
    }

    fn verdict(&self) -> CopieChaineeVerifiee {
        CopieChaineeVerifiee {
            maillons: self.ordre.len(),
            lignes_repetees: self.lignes_repetees,
            reprises: self.reprises,
            reprise_inachevee: self.reprise.is_some(),
        }
    }
}

/// Vérifie HORS LIGNE une copie JSONL d'un journal chaîné. `expect_prev` = hachage attendu AVANT la première ligne (le
/// `last_hash` du curseur pour un export incrémental, "" pour un export complet). Renvoie ce que la copie porte, ou
/// `Err` à la première rupture, nommée par son rang dans la copie et l'identifiant de l'entrée.
pub(crate) fn verifier_une_copie_chainee(lines: &[String], expect_prev: &str, recette: &RecetteDeChaine) -> Result<CopieChaineeVerifiee, String> {
    let mut prev = expect_prev.to_string();
    let mut retenues = LignesRetenues::neuves();
    for (i, line) in lines.iter().enumerate() {
        let v: Value = serde_json::from_str(line).map_err(|e| format!("ligne {i}: JSON invalide: {e}"))?;
        let id = v.get("id").and_then(|x| x.as_i64()).ok_or_else(|| format!("ligne {i}: id manquant"))?;
        let ts = v.get("ts").and_then(|x| x.as_i64()).ok_or_else(|| format!("ligne {i}: ts manquant"))?;
        if retenues.ecarter_si_repetee(line) {
            continue;
        }
        let (prev_hash, hash) = (champ_texte(&v, "prev_hash"), champ_texte(&v, "hash"));
        if prev_hash != prev {
            return Err(format!("ligne {i} (entrée #{id}): rupture de chaîne (prev_hash != hash précédent){}", retenues.precision_de_rupture(id)));
        }
        if sha256_hex((recette.texte_hache)(&prev, ts, &v).as_bytes()) != hash {
            return Err(format!("ligne {i} (entrée #{id}): {}", recette.alteration));
        }
        retenues.retenir(id, line);
        prev = hash.to_string();
    }
    Ok(retenues.verdict())
}
