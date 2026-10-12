const NOME_ABA_RESPOSTAS = 'Respostas ao formulário 1';
const NOMES_ABAS_FROTA = ['EM', 'CTT', '1° CIA', '2° CIA', '3° CIA', '4° CIA'];
const CHAVE_SEGREDO = 'GEOFROTA_WEBHOOK_SECRET';
const VERSAO_CONECTOR = 9;

function respostaJson(dados) {
  return ContentService
    .createTextOutput(JSON.stringify(dados))
    .setMimeType(ContentService.MimeType.JSON);
}

function doGet() {
  return respostaJson({ success: true, servico: 'GEOFROTA Frota', versao: VERSAO_CONECTOR });
}

function normalizarPrefixo(valor) {
  return String(valor || '')
    .normalize('NFKC')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/[‐‑‒–—−]/g, '-')
    .replace(/\s+/g, '')
    .toUpperCase();
}

function statusParaPlanilha(status) {
  if (status === 'Operante' || status === 'Troca de Óleo') return 'OPERANDO';
  if (status === 'Baixada') return 'BAIXADA';
  return null;
}

function normalizarSetor(valor) {
  const setor = String(valor || '').normalize('NFKC').trim().toUpperCase();
  return NOMES_ABAS_FROTA.find(nome => nome.toUpperCase() === setor) || null;
}

function localizarLinhasPorPrefixo(aba, prefixo) {
  const ultimaLinha = Math.max(aba.getLastRow(), 1);
  if (ultimaLinha < 3) return [];
  const prefixoNormalizado = normalizarPrefixo(prefixo);
  const prefixos = aba.getRange(3, 1, ultimaLinha - 2, 1).getDisplayValues();
  const linhas = [];
  prefixos.forEach((linha, indice) => {
    if (normalizarPrefixo(linha[0]) === prefixoNormalizado) linhas.push(indice + 3);
  });
  return linhas;
}

function removerViaturaDaAba(planilha, nomeAba, prefixo) {
  const aba = planilha.getSheetByName(nomeAba);
  if (!aba) return [];
  const linhas = localizarLinhasPorPrefixo(aba, prefixo);
  linhas.slice().sort((a, b) => b - a).forEach(linha => aba.deleteRow(linha));
  return linhas;
}

function atualizarViaturaFrota(planilha, dados) {
  const aba = planilha.getSheetByName(dados.setor);
  if (!aba) throw new Error('Aba da subunidade não encontrada: ' + dados.setor);

  const ultimaLinha = Math.max(aba.getLastRow(), 1);
  const statusPlanilha = statusParaPlanilha(dados.status);
  const linhas = localizarLinhasPorPrefixo(aba, dados.prefixo);
  if (linhas.length) {
    linhas.forEach(linha => {
      aba.getRange(linha, 6).setValue(dados.km);
      if (dados.completa) {
        aba.getRange(linha, 2).setValue(dados.modelo);
        aba.getRange(linha, 5).setValue(dados.placa);
        aba.getRange(linha, 9).setValue(dados.kmRevisao);
        if (statusPlanilha) aba.getRange(linha, 4).setValue(statusPlanilha);
      }
    });
    return { aba: dados.setor, linha: linhas[0], linhas, nova: false, duplicadas: linhas.length > 1 };
  }

  const novaLinha = Math.max(ultimaLinha + 1, 3);
  if (aba.getMaxRows() >= 3) {
    const linhaModelo = ultimaLinha >= 3 ? ultimaLinha : 3;
    const origem = aba.getRange(linhaModelo, 1, 1, 9);
    const destino = aba.getRange(novaLinha, 1, 1, 9);
    origem.copyTo(destino, SpreadsheetApp.CopyPasteType.PASTE_FORMAT, false);
    origem.copyTo(destino, SpreadsheetApp.CopyPasteType.PASTE_DATA_VALIDATION, false);
  }
  aba.getRange(novaLinha, 1).setValue(dados.prefixo);
  aba.getRange(novaLinha, 6).setValue(dados.km);
  if (dados.completa) {
    aba.getRange(novaLinha, 2).setValue(dados.modelo);
    aba.getRange(novaLinha, 4).setValue(statusPlanilha || 'OPERANDO');
    aba.getRange(novaLinha, 5).setValue(dados.placa);
    aba.getRange(novaLinha, 9).setValue(dados.kmRevisao);
  }
  return { aba: dados.setor, linha: novaLinha, linhas: [novaLinha], nova: true, duplicadas: false };
}

function doPost(e) {
  try {
    const dados = JSON.parse(e && e.postData && e.postData.contents || '{}');
    const segredo = PropertiesService.getScriptProperties().getProperty(CHAVE_SEGREDO);
    if (!segredo || dados.secret !== segredo) return respostaJson({ success: false, error: 'Não autorizado' });

    const acao = String(dados.acao || 'atualizar').trim();
    const prefixo = String(dados.prefixo || '').trim();
    const responsavel = String(dados.responsavel || '').trim();
    // Compatibilidade temporária com versões antigas do site, que sincronizavam apenas a CTT.
    const setor = normalizarSetor(dados.setor || 'CTT');
    if (!['atualizar', 'excluir'].includes(acao) || !prefixo || !responsavel || !setor) {
      return respostaJson({ success: false, error: 'Dados inválidos' });
    }

    const planilha = SpreadsheetApp.getActiveSpreadsheet();
    if (acao === 'excluir') {
      const bloqueio = LockService.getScriptLock();
      bloqueio.waitLock(10000);
      try {
        const linhas = removerViaturaDaAba(planilha, setor, prefixo);
        SpreadsheetApp.flush();
        return respostaJson({ success: true, versao: VERSAO_CONECTOR, exclusao: { aba: setor, linhas, removidas: linhas.length } });
      } finally {
        bloqueio.releaseLock();
      }
    }

    const modelo = String(dados.modelo || '').trim();
    const placa = String(dados.placa || '').trim();
    const km = Number(dados.km);
    const kmRevisao = Number(dados.km_revisao);
    const status = String(dados.status || '').trim();
    const setorAnterior = normalizarSetor(dados.setor_anterior);
    const completa = modelo !== '' || placa !== '' || status !== '' || dados.km_revisao !== undefined;
    if (!Number.isInteger(km) || km < 0) {
      return respostaJson({ success: false, error: 'Dados inválidos' });
    }
    if (completa && (!modelo || !placa || !Number.isInteger(kmRevisao) || kmRevisao < 0 || !['Operante', 'Troca de Óleo', 'Baixada'].includes(status))) {
      return respostaJson({ success: false, error: 'Dados completos inválidos' });
    }

    const abaRespostas = planilha.getSheetByName(NOME_ABA_RESPOSTAS);
    if (!abaRespostas) return respostaJson({ success: false, error: 'Aba de respostas não encontrada' });

    const bloqueio = LockService.getScriptLock();
    bloqueio.waitLock(10000);
    let atualizacao;
    try {
      abaRespostas.appendRow([new Date(), prefixo, responsavel, km]);
      if (setorAnterior && setorAnterior !== setor) removerViaturaDaAba(planilha, setorAnterior, prefixo);
      atualizacao = atualizarViaturaFrota(planilha, { prefixo, modelo, placa, km, kmRevisao, status, setor, completa });
      SpreadsheetApp.flush();
    } finally {
      bloqueio.releaseLock();
    }

    return respostaJson({ success: true, versao: VERSAO_CONECTOR, frota: atualizacao });
  } catch (erro) {
    console.error(erro);
    return respostaJson({ success: false, error: 'Falha interna' });
  }
}
