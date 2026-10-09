const NOME_ABA_RESPOSTAS = 'Respostas ao formulário 1';
const CHAVE_SEGREDO = 'GEOFROTA_WEBHOOK_SECRET';

function respostaJson(dados) {
  return ContentService
    .createTextOutput(JSON.stringify(dados))
    .setMimeType(ContentService.MimeType.JSON);
}

function doGet() {
  return respostaJson({ success: true, servico: 'GEOFROTA CTT' });
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
    const aba = planilha.getSheetByName(NOME_ABA_RESPOSTAS);
    if (!aba) return respostaJson({ success: false, error: 'Aba de respostas não encontrada' });

    const bloqueio = LockService.getScriptLock();
    bloqueio.waitLock(10000);
    try {
      aba.appendRow([new Date(), prefixo, responsavel, km]);
      SpreadsheetApp.flush();
    } finally {
      bloqueio.releaseLock();
    }

    return respostaJson({ success: true });
  } catch (erro) {
    console.error(erro);
    return respostaJson({ success: false, error: 'Falha interna' });
  }
}

