//! `P9.5-a` — LE GESTE QUI BRANCHE UNE SOURCE, DÉRIVÉ DE CE QUE LE DÉPÔT LIVRE.
//!
//! Une technique ATT&CK dont la règle attend sa source, ou dont la règle a été semée éteinte faute de
//! producteur, n'est fermée que par UN geste : poser sur un hôte le fichier qui produit cette source.
//! La console le disait sans le nommer (« brancher le producteur »), alors que le dépôt sait exactement
//! quel fichier et où : les entrées scriptées livrées sous `deploy/` déclarent leur `SOURCE=` et leur
//! première ligne dit où les copier ; les capteurs de `collectors/` sont posés par l'amorçage dans un
//! répertoire unique de l'hôte.
//!
//! LES DEUX TABLES CI-DESSOUS NE SONT PAS TENUES À LA MAIN — elles sont le MIROIR de l'arbre, et deux
//! témoins (`entrees_scriptees_livrees_est_le_miroir_de_deploy`,
//! `le_repertoire_des_capteurs_est_celui_de_l_amorcage`) rougissent dès qu'une entrée scriptée est
//! ajoutée, retirée ou déplacée, ou que l'amorçage change de répertoire.

/// Les entrées scriptées livrées : `(source produite, fichier livré, destination sur l'hôte)`.
/// Une entrée scriptée est lue par `collectors/custom.sh` depuis `/etc/plume/inputs.d/`.
pub(crate) const ENTREES_SCRIPTEES_LIVREES: &[(&str, &str, &str)] =
    &[("vault-audit", "deploy/vault-audit.input.example", "/etc/plume/inputs.d/vault-audit.input")];

/// Le répertoire où l'amorçage (`bootstrap.sh`, `bootstrap-agent.sh`) pose les capteurs de `collectors/`.
pub(crate) const REPERTOIRE_DES_CAPTEURS_SUR_L_HOTE: &str = "/usr/local/lib/plume/collectors";

/// Ce qu'il faut poser, et où, pour qu'une source existe sur un hôte. `destination` est `None` quand le
/// producteur n'est pas un fichier que l'on copie (le démon lui-même, l'agent, un collecteur compilé) :
/// le fichier est nommé pour que l'exploitant sache QUI émet, sans qu'on lui prescrive un geste faux.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GesteDeBranchement {
    pub(crate) source: String,
    pub(crate) fichier: String,
    pub(crate) destination: Option<String>,
}

/// LE GESTE POUR UNE SOURCE, DANS L'ORDRE DE CE QUE LE DÉPÔT SAIT : une entrée scriptée livrée (fichier
/// ET destination), puis un capteur shell livré (fichier ET destination de l'amorçage), puis tout autre
/// fichier livré qui l'émet (fichier seul). `None` = aucun fichier de ce dépôt ne produit cette source :
/// la console doit alors le DIRE, jamais inventer un chemin.
pub(crate) fn geste_de_branchement(source: &str) -> Option<GesteDeBranchement> {
    if let Some((s, fichier, destination)) = ENTREES_SCRIPTEES_LIVREES.iter().find(|(s, _, _)| *s == source) {
        return Some(GesteDeBranchement {
            source: s.to_string(),
            fichier: fichier.to_string(),
            destination: Some(destination.to_string()),
        });
    }
    let (_, fichier) = crate::handlers::sources::SOURCES_LIVREES.iter().find(|(s, _)| *s == source)?;
    let destination = fichier
        .strip_prefix("collectors/")
        .filter(|nom| nom.ends_with(".sh") && !nom.contains('/'))
        .map(|nom| format!("{REPERTOIRE_DES_CAPTEURS_SUR_L_HOTE}/{nom}"));
    Some(GesteDeBranchement { source: source.to_string(), fichier: fichier.to_string(), destination })
}

/// Les gestes d'un ensemble de sources, dans l'ordre des sources, SANS les sources que rien ne produit :
/// une liste plus courte que celle des sources manquantes dit à l'exploitant lesquelles ce dépôt ne sait
/// pas brancher.
pub(crate) fn gestes_de_branchement<'a>(sources: impl IntoIterator<Item = &'a String>) -> Vec<GesteDeBranchement> {
    sources.into_iter().filter_map(|s| geste_de_branchement(s)).collect()
}
