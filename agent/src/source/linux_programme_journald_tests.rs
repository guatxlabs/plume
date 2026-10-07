//! Témoin `P10.31-e` : le programme lancé par défaut par `JournaldReader::new` (sonde ET lot) est
//! `journalctl`. Un littéral changé lancerait autre chose ; aucun autre témoin ne l'épingle (les
//! sondes de `linux_sonde_output_fields_tests.rs` y substituent un exécutable).

use super::*;
use crate::config::JournaldCfg;

#[test]
fn programme_par_defaut_est_journalctl() {
    let r = JournaldReader::new(
        JournaldCfg { id: "auth".into(), comm: vec!["sudo".into()], units: vec![], since: "15min".into() },
        "h".into(),
    );
    assert_eq!(r.programme, "journalctl", "JournaldReader::new ne lance plus journalctl");
}
