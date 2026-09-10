//! LE FONDEMENT D'UNE ALERTE (`P11.14-h`) — SUR QUOI ELLE EST FONDÉE, écrit à sa LEVÉE, là où le démon
//! sait ce qu'il fait, dans un vocabulaire FERMÉ. La console ne devine plus le fondement d'après le
//! jeton de règle (ce serait refaire, un étage plus haut, la fabrication que `P11.14-b` a retirée) :
//! elle LIT ce champ, et une alerte antérieure à la migration v121 (fondement vide) garde son refus
//! honnête. Quatre fondements, pas un de plus : un cinquième ne compile pas sans être traité ici, et
//! chaque site qui lève une alerte écrit le sien — un témoin dérivé de la source le tient.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fondement {
    /// Une RÈGLE a compté des événements (règle livrée ou de l'exploitant, corrélation, ligne de base,
    /// score de risque agrégé sur des contributions de règles) : le pivot est la recherche.
    Regle,
    /// Un INSTANTANÉ posté par une machine (pare-feu, catalogue de contrôles) : le pivot est le dernier
    /// instantané de ce genre pour cette machine — `basis_ref` porte le genre, `host` la machine.
    Instantane,
    /// Un BATTEMENT DE CŒUR manqué : une source, un capteur ou la flotte se sont tus.
    BattementDeCoeur,
    /// L'ÉTAT D'UN CAPTEUR du démon lui-même (magasin de secrets, règle aveugle) : rien à chercher.
    Capteur,
}

impl Fondement {
    pub(crate) const TOUS: [Fondement; 4] =
        [Fondement::Regle, Fondement::Instantane, Fondement::BattementDeCoeur, Fondement::Capteur];

    /// Le mot écrit dans `alert.basis` et servi tel quel à la console.
    pub(crate) const fn mot(self) -> &'static str {
        match self {
            Fondement::Regle => "regle",
            Fondement::Instantane => "instantane",
            Fondement::BattementDeCoeur => "battement",
            Fondement::Capteur => "capteur",
        }
    }

    pub(crate) fn depuis_le_mot(mot: &str) -> Option<Fondement> {
        Self::TOUS.into_iter().find(|f| f.mot() == mot)
    }
}
