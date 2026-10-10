'use strict';

const TIMEOUT_MS = 20000;

function sincronizacaoAtiva() {
    return String(process.env.CTT_SHEETS_SYNC_ENABLED).toLowerCase() === 'true';
}

async function sincronizarViaturaCtt({ prefixo, responsavel, modelo, placa, km, km_revisao, status, setor }) {
    if (!sincronizacaoAtiva() || setor !== 'CTT') return { ignorado: true };

    const url = process.env.CTT_SHEETS_WEBHOOK_URL;
    const secret = process.env.CTT_SHEETS_WEBHOOK_SECRET;
    if (!url || !secret) throw new Error('Integração da planilha CTT não configurada');

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret, prefixo, responsavel, modelo, placa, km, km_revisao, status }),
            signal: controller.signal
        });
        const texto = await response.text();
        let resultado;
        try { resultado = JSON.parse(texto); } catch (_) { resultado = null; }
        if (!response.ok || !resultado?.success) {
            throw new Error('A planilha CTT recusou a atualização');
        }
        return resultado;
    } finally {
        clearTimeout(timeout);
    }
}

module.exports = { sincronizarViaturaCtt };

