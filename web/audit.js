// audit.js — extracted from app.js (DEEP state-container split). Behaviour-preserving.
// Audit / ledger (lecture seule): journal des mutations hashe (id DESC, admin).
import { $, api, fmtTs, pagedList } from './core.js';
import { S } from './state.js';
import { loadOperatorAudit } from './multitenant.js';

// cellule textContent (anti-XSS B7) + title optionnel — pour les colonnes pagedList (render -> Node).
function ledgerCell(txt, title) { const s = document.createElement('span'); s.textContent = txt; if (title) s.title = title; return s; }

async function loadLedger() {
  const wrap = $('#ledger-body'); if (!wrap) return;
  loadOperatorAudit(); // #2c — sous-panneau accès opérateur (multi-tenant only ; masqué/inerte en mode 0)
  // BATCH 1 : pagination SERVEUR (LIMIT/OFFSET + total). Le sélecteur #ledger-limit fixe la taille de page.
  pagedList(wrap, {
    mode: 'server',
    pageSize: S.LEDGER_LIMIT,
    emptyText: "aucune entrée d'audit",
    columns: [
      { key: 'id', label: '#', render: en => String(en.id) },
      { key: 'ts', label: 'Horodatage', render: en => ledgerCell(fmtTs(en.ts), en.ts ? String(en.ts) : '') },
      { key: 'kind', label: 'Type', render: en => ledgerCell(en.kind || '') },
      { key: 'detail', label: 'Détail', render: en => ledgerCell(en.detail || '', en.detail || '') },
      { key: 'hash', label: 'Empreinte', render: en => { const h = en.hash || ''; return ledgerCell(h ? h.slice(0, 16) + '…' : '', h); } },
    ],
    fetchPage: async ({ limit, offset }) => {
      const j = await api('/ledger?limit=' + limit + '&offset=' + offset);
      return { rows: j.entries || [], total: j.total };
    },
  });
}


export { loadLedger };
