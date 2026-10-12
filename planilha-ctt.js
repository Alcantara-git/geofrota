'use strict';

const TIMEOUT_MS = 20000;
const SETORES_SINCRONIZADOS = new Set(['EM', 'CTT', '1° CIA', '2° CIA', '3° CIA', '4° CIA']);

function sincronizacaoAtiva() {
    return String(process.env.CTT_SHEETS_SYNC_ENABLED).toLowerCase() === 'true';
}

async function enviarParaPlanilha(dados) {
    const { setor } = dados;
    if (!sincronizacaoAtiva() || !SETORES_SINCRONIZADOS.has(setor)) return { ignorado: true };

    const url = process.env.CTT_SHEETS_WEBHOOK_URL;
    const secret = process.env.CTT_SHEETS_WEBHOOK_SECRET;
    if (!url || !secret) throw new Error('Integração da planilha da frota não configurada');

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret, ...dados }),
            signal: controller.signal
        });
        const texto = await response.text();
        let resultado;
        try { resultado = JSON.parse(texto); } catch (_) { resultado = null; }
        if (!response.ok || !resultado?.success) {
            throw new Error('A planilha da frota recusou a atualização');
        }
        return resultado;
    } finally {
        clearTimeout(timeout);
    }
}

function sincronizarViaturaPlanilha({ prefixo, responsavel, modelo, placa, km, km_revisao, status, setor, setor_anterior }) {
    return enviarParaPlanilha({ acao: 'atualizar', prefixo, responsavel, modelo, placa, km, km_revisao, status, setor, setor_anterior });
}

function excluirViaturaPlanilha({ prefixo, responsavel, setor }) {
    return enviarParaPlanilha({ acao: 'excluir', prefixo, responsavel, setor });
}

module.exports = { sincronizarViaturaPlanilha, excluirViaturaPlanilha };
