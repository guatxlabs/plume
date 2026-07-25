// #16 ASSISTANT IA (advisory NL->SOQL) — UI minimale, feature-gated côté serveur. L'assistant n'apparaît QUE
// si GET /api/ai/status renvoie { enabled:true } (feature `ai` compilée + PLUME_AI_ENABLE + provider actif).
// L'IA PROPOSE une requête SOQL : on l'écrit dans #sql pour que l'analyste la RÉVISE puis l'exécute lui-même
// (Exécuter). ZÉRO exécution automatique — le handler serveur ne fait que compiler+valider (compilo fermé).
import { $, api, apiSend, showErr } from './core.js';

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
          stat.textContent = 'SOQL proposé — révisez puis Exécuter';
        } else {
          stat.classList.add('warn');
          stat.textContent = 'SOQL proposé mais REJETÉ par le compilateur : ' + (r.error || 'invalide');
        }
      } else {
        stat.textContent = 'aucune proposition';
      }
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
