const NOME_ABA_RESPOSTAS = 'Respostas ao formulário 1';
const NOME_ABA_REVISAO = 'REVISÃO';
const CHAVE_SEGREDO = 'GEOFROTA_WEBHOOK_SECRET';

function respostaJson(dados) {
  return ContentService
    .createTextOutput(JSON.stringify(dados))
    .setMimeType(ContentService.MimeType.JSON);
}

function doGet() {
  return respostaJson({ success: true, servico: 'GEOFROTA CTT' });
}

function atualizarKmRevisao(planilha, prefixo, km) {
  const aba = planilha.getSheetByName(NOME_ABA_REVISAO);
  if (!aba) throw new Error('Aba REVISÃO não encontrada');

  const ultimaLinha = Math.max(aba.getLastRow(), 1);
  const prefixoNormalizado = prefixo.toUpperCase();
  if (ultimaLinha >= 2) {
    const prefixos = aba.getRange(2, 1, ultimaLinha - 1, 1).getDisplayValues();
    const indice = prefixos.findIndex(linha => String(linha[0] || '').trim().toUpperCase() === prefixoNormalizado);
    if (indice >= 0) {
      const linha = indice + 2;
      aba.getRange(linha, 6).setValue(km);
      return { linha, nova: false };
    }
  }

  const novaLinha = ultimaLinha + 1;
  if (ultimaLinha >= 2) aba.getRange(ultimaLinha, 1, 1, 6).copyTo(aba.getRange(novaLinha, 1, 1, 6), SpreadsheetApp.CopyPasteType.PASTE_FORMAT, false);
  aba.getRange(novaLinha, 1).setValue(prefixo);
  aba.getRange(novaLinha, 6).setValue(km);
  return { linha: novaLinha, nova: true };
}

function doPost(e) {
  try {
    const dados = JSON.parse(e && e.postData && e.postData.contents || '{}');
    const segredo = PropertiesService.getScriptProperties().getProperty(CHAVE_SEGREDO);
    if (!segredo || dados.secret !== segredo) return respostaJson({ success: false, error: 'Não autorizado' });

    const prefixo = String(dados.prefixo || '').trim();
    const responsavel = String(dados.responsavel || '').trim();
    const km = Number(dados.km);
    if (!prefixo || !responsavel || !Number.isInteger(km) || km < 0) {
      return respostaJson({ success: false, error: 'Dados inválidos' });
    }

    const planilha = SpreadsheetApp.getActiveSpreadsheet();
    const abaRespostas = planilha.getSheetByName(NOME_ABA_RESPOSTAS);
    if (!abaRespostas) return respostaJson({ success: false, error: 'Aba de respostas não encontrada' });

    const bloqueio = LockService.getScriptLock();
    bloqueio.waitLock(10000);
    let atualizacao;
    try {
      abaRespostas.appendRow([new Date(), prefixo, responsavel, km]);
      atualizacao = atualizarKmRevisao(planilha, prefixo, km);
      SpreadsheetApp.flush();
    } finally {
      bloqueio.releaseLock();
    }

    return respostaJson({ success: true, revisao: atualizacao });
  } catch (erro) {
    console.error(erro);
    return respostaJson({ success: false, error: 'Falha interna' });
  }
}

