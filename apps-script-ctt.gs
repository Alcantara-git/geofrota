const NOME_ABA_RESPOSTAS = 'Respostas ao formulário 1';
const NOME_ABA_REVISAO = 'REVISÃO';
const CHAVE_SEGREDO = 'GEOFROTA_WEBHOOK_SECRET';
const VERSAO_CONECTOR = 7;

function respostaJson(dados) {
  return ContentService
    .createTextOutput(JSON.stringify(dados))
    .setMimeType(ContentService.MimeType.JSON);
}

function doGet() {
  return respostaJson({ success: true, servico: 'GEOFROTA CTT', versao: VERSAO_CONECTOR });
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

function atualizarViaturaRevisao(planilha, dados) {
  const aba = planilha.getSheetByName(NOME_ABA_REVISAO);
  if (!aba) throw new Error('Aba REVISÃO não encontrada');

  const ultimaLinha = Math.max(aba.getLastRow(), 1);
  const prefixoNormalizado = normalizarPrefixo(dados.prefixo);
  const statusPlanilha = statusParaPlanilha(dados.status);
  if (ultimaLinha >= 2) {
    const prefixos = aba.getRange(2, 1, ultimaLinha - 1, 1).getDisplayValues();
    const linhas = [];
    prefixos.forEach((linha, indice) => {
      if (normalizarPrefixo(linha[0]) === prefixoNormalizado) linhas.push(indice + 2);
    });
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
      return { linha: linhas[0], linhas, nova: false, duplicadas: linhas.length > 1 };
    }
  }

  const novaLinha = ultimaLinha + 1;
  if (ultimaLinha >= 2) {
    const origem = aba.getRange(ultimaLinha, 1, 1, 9);
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
  return { linha: novaLinha, linhas: [novaLinha], nova: true, duplicadas: false };
}

function doPost(e) {
  try {
    const dados = JSON.parse(e && e.postData && e.postData.contents || '{}');
    const segredo = PropertiesService.getScriptProperties().getProperty(CHAVE_SEGREDO);
    if (!segredo || dados.secret !== segredo) return respostaJson({ success: false, error: 'Não autorizado' });

    const prefixo = String(dados.prefixo || '').trim();
    const responsavel = String(dados.responsavel || '').trim();
    const modelo = String(dados.modelo || '').trim();
    const placa = String(dados.placa || '').trim();
    const km = Number(dados.km);
    const kmRevisao = Number(dados.km_revisao);
    const status = String(dados.status || '').trim();
    const completa = modelo !== '' || placa !== '' || status !== '' || dados.km_revisao !== undefined;
    if (!prefixo || !responsavel || !Number.isInteger(km) || km < 0) {
      return respostaJson({ success: false, error: 'Dados inválidos' });
    }
    if (completa && (!modelo || !placa || !Number.isInteger(kmRevisao) || kmRevisao < 0 || !['Operante', 'Troca de Óleo', 'Baixada'].includes(status))) {
      return respostaJson({ success: false, error: 'Dados completos inválidos' });
    }

    const planilha = SpreadsheetApp.getActiveSpreadsheet();
    const abaRespostas = planilha.getSheetByName(NOME_ABA_RESPOSTAS);
    if (!abaRespostas) return respostaJson({ success: false, error: 'Aba de respostas não encontrada' });

    const bloqueio = LockService.getScriptLock();
    bloqueio.waitLock(10000);
    let atualizacao;
    try {
      abaRespostas.appendRow([new Date(), prefixo, responsavel, km]);
      atualizacao = atualizarViaturaRevisao(planilha, { prefixo, modelo, placa, km, kmRevisao, status, completa });
      SpreadsheetApp.flush();
    } finally {
      bloqueio.releaseLock();
    }

    return respostaJson({ success: true, versao: VERSAO_CONECTOR, revisao: atualizacao });
  } catch (erro) {
    console.error(erro);
    return respostaJson({ success: false, error: 'Falha interna' });
  }
}

