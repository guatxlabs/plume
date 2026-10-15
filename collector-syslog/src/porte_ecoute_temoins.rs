//! P10.32-l — LA REGLE DE RESOLUTION DE LA PORTE, JUGEE SEULE.
//!
//! Le binaire ne peut pas etre mis devant un nom qui rendrait a la fois la boucle locale et le reseau
//! (cela depend du resolveur de la machine de test) ; la regle qui en decide l'est ici : UNE seule
//! resolution hors de la boucle locale suffit a fermer la porte, et une ecoute sans resolution n'est pas
//! prouvee locale.
use super::resolutions_hors_boucle_locale;
use std::net::SocketAddr;

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[test]
fn une_seule_resolution_hors_de_la_boucle_locale_ferme_la_porte() {
    // Un nom qui rend la boucle locale ET le reseau ouvre le reseau, dans les deux ordres.
    assert!(resolutions_hors_boucle_locale(&[a("127.0.0.1:514"), a("192.0.2.1:514")]));
    assert!(resolutions_hors_boucle_locale(&[a("192.0.2.1:514"), a("[::1]:514")]));
    // Aucune resolution : rien n'est prouve local.
    assert!(resolutions_hors_boucle_locale(&[]));
    // Toutes les interfaces ne sont pas la boucle locale.
    assert!(resolutions_hors_boucle_locale(&[a("0.0.0.0:514")]));
    assert!(resolutions_hors_boucle_locale(&[a("[::]:514")]));
    // `localhost` : toutes ses resolutions sont locales.
    assert!(!resolutions_hors_boucle_locale(&[a("127.0.0.1:514"), a("[::1]:514")]));
}
