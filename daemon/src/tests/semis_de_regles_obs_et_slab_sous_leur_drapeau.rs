// =====================================================================================
// `P10.28-l` (les deux derniers semis de règles) — LES TROIS RÈGLES D'EXEMPLE D'OBSERVABILITÉ ET LA RÈGLE « FUITE SLAB
// NOYAU » S'ÉCRIVENT ENTIÈRES SOUS LEUR DRAPEAU, POSÉ EN DERNIER.
//
// LE DÉFAUT, RELU SUR 318bf0e : `seed_obs_rules` et `seed_slab_rule` (seeds.rs) posaient leur drapeau `seeded_*` EN
// PREMIER (écriture avalée), puis chaque INSERT avalé (`let _`). Un INSERT refusé laissait le drapeau posé : la règle
// (charge CPU, mémoire, pic d'erreurs, fuite slab) n'était JAMAIS resemée, et un refus à la N-ième règle laissait les
// N-1 premières seules.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une base EN SERVICE dont le drapeau est déjà posé sans la ligne n'est pas
// réparée (le semis voit son drapeau et ne fait rien) ; `seed_malware_rule` (aucun drapeau), `seed_runbooks` et la
// famille « Ok(0) puis `last_insert_rowid` » ne sont pas touchés ; l'aveu au journal (`eprintln!` de
// `semer_sous_son_drapeau`) n'est pas capturé. Aucune variable d'environnement n'est lue par ces deux semis.
// =====================================================================================
mod semis_de_regles_obs_et_slab_sous_leur_drapeau {
    use super::*;

    const SOS_LIGNE: &str = "SELECT name||'|'||query||'|'||is_soql||'|'||op||'|'||printf('%.1f',threshold)||'|'||severity||'|'||interval_s||'|'||window_s||'|'||enabled FROM rule WHERE id>?1 ORDER BY id";

    fn sos_dernier(conn: &Connection) -> i64 {
        conn.query_row("SELECT COALESCE(MAX(id),0) FROM rule", [], |r| r.get(0)).expect("max id")
    }

    fn sos_lignes(conn: &Connection, depuis: i64) -> Vec<String> {
        let mut st = conn.prepare(SOS_LIGNE).expect("select");
        st.query_map(params![depuis], |r| r.get::<_, String>(0)).expect("lignes").collect::<Result<Vec<_>, _>>().expect("lignes lues")
    }

    fn sos_drapeau(conn: &Connection, drapeau: &str) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM meta WHERE key=?1", params![drapeau], |r| r.get(0)).expect("drapeau")
    }

    /// (étiquette, drapeau, semis, lignes attendues octet pour octet — celles d'avant le correctif).
    type SosSemis = (&'static str, &'static str, fn(&Connection), Vec<&'static str>);

    fn sos_semis() -> Vec<SosSemis> {
        vec![
            (
                "obs",
                "seeded_obs_rules",
                seed_obs_rules,
                vec![
                    "hôte: charge CPU élevée (load1)|metric load1 | stats max(value)|1|>|8.0|2|120|300|0",
                    "hôte: mémoire élevée (%)|metric mem_pct | stats max(value)|1|>|90.0|3|120|300|0",
                    "logs: pic d'erreurs (sév>=3)|search severity>=3 | stats count|1|>|20.0|2|120|300|0",
                ],
            ),
            (
                "slab",
                "seeded_slab_rule",
                seed_slab_rule,
                vec!["noyau: fuite slab (SUnreclaim > 2.5 Go)|metric mem_slab_mb | stats max(value)|1|>|2500.0|3|600|1800|0"],
            ),
        ]
    }

    /// INVERSE NOMINAL : sur une base neuve, chaque semis écrit ses règles octet pour octet comme avant (désactivées),
    /// pose son drapeau, et un second appel n'ajoute rien.
    #[test]
    fn sos_un_semis_nominal_ecrit_ses_regles_d_avant_et_son_drapeau_une_seule_fois() {
        for (tag, drapeau, semer, attendues) in sos_semis() {
            let conn = test_db();
            let depuis = sos_dernier(&conn);
            assert_eq!(sos_drapeau(&conn, drapeau), 0, "`{tag}` : instrument — base neuve sans drapeau");
            assert!(sos_lignes(&conn, depuis).is_empty(), "`{tag}` : instrument — aucune règle après l'existant");
            semer(&conn);
            assert_eq!(sos_lignes(&conn, depuis), attendues, "`{tag}` : règles semées octet pour octet");
            assert_eq!(sos_drapeau(&conn, drapeau), 1, "`{tag}` : drapeau posé après le succès");
            semer(&conn);
            assert_eq!(sos_lignes(&conn, depuis), attendues, "`{tag}` : second appel idempotent, aucun doublon");
        }
    }

    /// CE QU'IL TIENT, pour chaque semis, chaque règle refusée à son tour (toutes les règles : trois pour `obs`, une pour
    /// `slab`) et deux refus (`RAISE(ABORT)`, et `RAISE(IGNORE)` qui rend `Ok(0)`) : après le refus, AUCUNE règle
    /// conservée et AUCUN drapeau, transaction fermée ; au démarrage suivant (base revenue), toutes les règles et le
    /// drapeau ; au démarrage d'après, rien de plus.
    /// MUTATIONS QUI LE FONT ROUGIR : l'ancienne forme, drapeau en tête et INSERT avalés (`VERIF_MUT=obs_tete`,
    /// `slab_tete`) ; l'INSERT de boucle avalé dans le semis (`obs_let`) ; `Ok(0)` accepté comme une écriture
    /// (`slab_ok0`).
    #[test]
    fn sos_un_semis_refuse_ne_garde_ni_regle_ni_drapeau_et_se_rejoue_au_demarrage_suivant() {
        for (tag, drapeau, semer, attendues) in sos_semis() {
            for (rang, ligne) in attendues.iter().enumerate() {
                let refusee = ligne.split('|').next().expect("nom");
                for (forme, corps) in [("ABORT", "RAISE(ABORT,'sos refus')"), ("IGNORE", "RAISE(IGNORE)")] {
                    let conn = test_db();
                    let depuis = sos_dernier(&conn);
                    conn.execute_batch(&format!(
                        "CREATE TRIGGER sos_refus BEFORE INSERT ON rule WHEN NEW.name='{}' BEGIN SELECT {corps}; END;",
                        refusee.replace('\'', "''")
                    ))
                    .expect("déclencheur de refus");
                    semer(&conn);
                    assert!(sos_lignes(&conn, depuis).is_empty(), "`{tag}` ({forme}, règle {rang} « {refusee} ») : aucune règle conservée après le refus");
                    assert_eq!(sos_drapeau(&conn, drapeau), 0, "`{tag}` ({forme}, règle {rang}) : drapeau ABSENT après le refus");
                    assert!(conn.is_autocommit(), "`{tag}` ({forme}, règle {rang}) : la transaction du semis est fermée");
                    conn.execute_batch("DROP TRIGGER sos_refus;").expect("base revenue");
                    semer(&conn);
                    assert_eq!(sos_lignes(&conn, depuis), attendues, "`{tag}` ({forme}, règle {rang}) : rejoué entier au démarrage suivant");
                    assert_eq!(sos_drapeau(&conn, drapeau), 1, "`{tag}` ({forme}, règle {rang}) : drapeau posé après le succès");
                    semer(&conn);
                    assert_eq!(sos_lignes(&conn, depuis), attendues, "`{tag}` ({forme}, règle {rang}) : aucun doublon ensuite");
                }
            }
        }
    }

    /// Une base déjà drapeautée (valeur `7`, posée à la main) : le semis n'écrit RIEN et ne touche pas au drapeau.
    /// Aucun déclencheur ici : la table `rule` accepte tout INSERT, donc une règle écrite serait VUE (un déclencheur qui
    /// refuserait tout rendait « aucune règle » impossible à faire échouer). Le drapeau garde sa valeur `7` : un semis
    /// rejoué le réécrirait à `1`.
    /// MUTATIONS QUI LE FONT ROUGIR : le semis ignore son drapeau (`VERIF_MUT=obs_ignore_drapeau`, `slab_ignore_drapeau`).
    #[test]
    fn sos_une_base_deja_drapeautee_n_ecrit_rien() {
        for (tag, drapeau, semer, attendues) in sos_semis() {
            let conn = test_db();
            let depuis = sos_dernier(&conn);
            conn.execute("INSERT INTO meta(key,value) VALUES(?1,'7')", params![drapeau]).expect("drapeau posé à la main");
            assert!(!attendues.is_empty(), "`{tag}` : instrument — le semis a des règles à écrire");
            semer(&conn);
            assert!(sos_lignes(&conn, depuis).is_empty(), "`{tag}` : aucune règle sur une base déjà drapeautée");
            let valeur: String =
                conn.query_row("SELECT value FROM meta WHERE key=?1", params![drapeau], |r| r.get(0)).expect("valeur du drapeau");
            assert_eq!(valeur, "7", "`{tag}` : drapeau intact (non réécrit)");
            assert!(conn.is_autocommit(), "`{tag}` : aucune transaction laissée ouverte");
        }
    }
}
