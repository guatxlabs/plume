// #16 ASSISTANT IA (advisory NL->GXQL) — UI minimale, feature-gated côté serveur. L'assistant n'apparaît QUE
// si GET /api/ai/status renvoie { enabled:true } (feature `ai` compilée + PLUME_AI_ENABLE + provider actif).
// L'IA PROPOSE une requête GXQL : on l'écrit dans #sql pour que l'analyste la RÉVISE puis l'exécute lui-même
// (Exécuter). ZÉRO exécution automatique — le handler serveur ne fait que compiler+valider (compilo fermé).
import { $, api, apiSend, showErr, faceDansLaLangue, causeDeLaTraceManquante, toast } from './core.js';

// `P10.31-u` (volet console) — L'APPEL IA A EU LIEU, SA TRACE MANQUE : L'AVIS LE DIT. `ai_nl2soql` (daemon/src/handlers/ai.rs)
// inscrit `ai.call` au registre tamper-evident APRÈS l'appel au fournisseur : la question rédigée est déjà sortie du
// processus. Quand le maillon n'entre pas, le corps de succès garde tous ses champs et gagne la clé commune, lue par
// `causeDeLaTraceManquante` (core.js) — ce module n'en écrit pas le nom. AVANT CE LOT la réponse était lue sans elle :
// une sortie de données vers un fournisseur d'IA hors de la trace non purgeable, et la console se taisait. La proposition
// reste écrite dans la barre (le geste a eu lieu) ; l'aveu part à l'AVIS, phrase PUIS « cause servie », en une chaîne —
// cette barre n'a pas de puits. Les deux faces côte à côte : aucune langue ne part sans l'autre.
const MOTS_DE_L_APPEL_IA_SANS_TRACE = {
  fr: "Appel IA FAIT, mais SANS TRACE D'AUDIT : la question est partie chez le fournisseur d'IA — la reposer ferait un second appel sans combler le trou. Ce qui manque est la ligne du registre tamper-evident qui atteste cette sortie. Le démon en nomme la cause —",
  en: 'AI call DONE, but WITHOUT AUDIT TRACE: the question went out to the AI provider — asking again would make a second call without filling the gap. What is missing is the tamper-evident ledger line attesting this egress. The daemon names the cause —',
};
function avouerLAppelIaSansTrace(r) {
  const cause = causeDeLaTraceManquante(r);
  if (cause) toast(faceDansLaLangue(MOTS_DE_L_APPEL_IA_SANS_TRACE) + ' « ' + cause + ' »', 'bad', 9000);
}

// Appelé au boot (app.js) : sonde le statut ; révèle et câble l'assistant seulement si activé.
export async function initAiAssist() {
  const box = $('#aiassist');
  if (!box) return;
  let status;
  try {
    status = await api('/ai/status');   // 501/erreur -> catch -> reste caché (feature off)
  } catch (_) {
    box.style.display = 'none';
    return;
  }
  if (!status || !status.enabled) {
    box.style.display = 'none';   // inerte : feature off / pas de provider / PLUME_AI_ENABLE absent
    return;
  }
  box.style.display = '';   // révèle (barre .qbar en flex)
  const input = $('#ainl'), btn = $('#airun'), stat = $('#aistat');

  const ask = async () => {
    const nl = (input.value || '').trim();
    if (!nl) return;
    btn.disabled = true;
    stat.classList.remove('warn');
    stat.textContent = 'IA…';
    try {
      const r = await apiSend('/ai/nl2soql', 'POST', { nl });
      if (r && r.soql) {
        // Proposition écrite dans la barre de requête -> l'analyste RÉVISE puis presse Exécuter.
        $('#sql').value = r.soql;
        if (r.valid) {
          stat.textContent = 'GXQL proposé — révisez puis Exécuter';
        } else {
          stat.classList.add('warn');
          stat.textContent = faceDansLaLangue({ fr: 'GXQL proposé mais REJETÉ par le compilateur : {cause}', en: 'GXQL proposed but REJECTED by the compiler: {cause}' }, { cause: r.error || faceDansLaLangue({ fr: 'invalide', en: 'invalid' }) });   // `P10.29-c`
        }
      } else {
        stat.textContent = 'aucune proposition';
      }
      avouerLAppelIaSansTrace(r);   // `P10.31-u`
    } catch (e) {
      stat.classList.add('warn');
      stat.textContent = 'erreur IA';
      try { showErr(e); } catch (_) { /* best-effort */ }
    } finally {
      btn.disabled = false;
    }
  };

  btn.onclick = ask;
  input.onkeydown = (e) => {
    if (e.key === 'Enter') { e.preventDefault(); ask(); }
  };
}
