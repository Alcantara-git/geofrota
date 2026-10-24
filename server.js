const express = require('express');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const pool = require('./database');
const { hashPassword, verifyPassword } = require('./auth');
const { sincronizarViaturaPlanilha, excluirViaturaPlanilha } = require('./planilha-ctt');
const app = express();

function sincronizarPlanilhaEmSegundoPlano(descricao, tarefa) {
    Promise.resolve()
        .then(tarefa)
        .catch(e => console.error(`Falha ao ${descricao} na planilha da frota:`, e.message));
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '32kb' }));
app.use(cookieParser());
app.use((req, res, next) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Referrer-Policy', 'same-origin');
    res.set('X-Frame-Options', 'DENY');
    res.set('Cache-Control', 'no-store');
    // A interface existente usa Tailwind via CDN e scripts inline.
    res.set('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data: https://raw.githubusercontent.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
    next();
});
const sessions = new Map();
const attempts = new Map();
const COOKIE = 'geofrota_session';
const DURATION = 12 * 60 * 60 * 1000;
setInterval(() => {
    const now = Date.now();
    for (const [token, s] of sessions) if (s.expires <= now) sessions.delete(token);
    for (const [key, a] of attempts) if (a.until <= now) attempts.delete(key);
}, 15 * 60 * 1000).unref();
const cookieOptions = req => ({ httpOnly: true, sameSite: 'strict', secure: req.secure, path: '/', maxAge: DURATION });
function session(req) {
    const token = req.cookies[COOKIE];
    if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)) return null;
    const s = sessions.get(token);
    if (!s) return null;
    if (s.expires <= Date.now()) { sessions.delete(token); return null; }
    return s;
}
function proteger(...roles) {
    return (req, res, next) => {
        const s = session(req);
        if (!s) return res.status(401).json({ error: 'Acesso não autenticado' });
        if (!roles.includes(s.role)) return res.status(403).json({ error: 'Sem permissão' });
        req.role = s.role;
        req.auth = s;
        next();
    };
}
const protegerAdminBase = proteger('admin');
const protegerAdmin = (req, res, next) => protegerAdminBase(req, res, () => {
    if (req.auth.trocarSenha) return res.status(428).json({ error: 'Troque a senha temporária antes de continuar', code: 'PASSWORD_CHANGE_REQUIRED' });
    next();
});
const protegerOperacionalBase = proteger('admin', 'oper');
const protegerOperacional = (req, res, next) => protegerOperacionalBase(req, res, () => {
    if (req.auth.role === 'admin' && req.auth.trocarSenha)
        return res.status(428).json({ error: 'Troque a senha temporária antes de continuar', code: 'PASSWORD_CHANGE_REQUIRED' });
    next();
});
const protegerSuperadmin = (req, res, next) => protegerAdmin(req, res, () => {
    if (!req.auth.superadmin) return res.status(403).json({ error: 'Acesso exclusivo do administrador 1BPTRAN' });
    next();
});
app.use((req, res, next) => {
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
    const origin = req.get('origin');
    let invalid = req.get('sec-fetch-site') === 'cross-site';
    if (origin) { try { invalid ||= new URL(origin).host !== req.get('host'); } catch { invalid = true; } }
    if (invalid) return res.status(403).json({ error: 'Origem não autorizada' });
    next();
});
const reValido = re => typeof re === 'string' && /^[0-9]{6}$/.test(re.trim());
const senhaOperacionalValida = senha => typeof senha === 'string' && /^[^\s\x00-\x1F\x7F]{4,8}$/u.test(senha);
function criarSessao(req, res, dadosSessao, now = Date.now()) {
    if (req.cookies[COOKIE]) sessions.delete(req.cookies[COOKIE]);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { ...dadosSessao, expires: now + DURATION });
    res.cookie(COOKIE, token, cookieOptions(req));
}
app.post('/api/login', async (req, res) => {
    const { senha, tipo } = req.body || {};
    const usuarioInformado = typeof req.body?.usuario === 'string' ? req.body.usuario.trim().toUpperCase() : '';
    const reInformado = typeof req.body?.re === 'string' ? req.body.re.trim() : '';
    const now = Date.now(), key = req.ip;
    const a = attempts.get(key) || { count: 0, until: now + 15 * 60 * 1000 };
    if (now > a.until) { a.count = 0; a.until = now + 15 * 60 * 1000; }
    if (a.count >= 10) return res.status(429).json({ error: 'Muitas tentativas. Aguarde 15 minutos.' });
    try {
        if (typeof senha !== 'string' || senha.length > 256 || !['admin', 'oper'].includes(tipo)) {
            a.count++; attempts.set(key, a); return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        let dadosSessao, redirect;
        if (tipo === 'oper') {
            if (!reValido(reInformado) || !senhaOperacionalValida(senha)) {
                a.count++; attempts.set(key, a); return res.status(401).json({ error: 'RE ou senha incorretos' });
            }
            const conta = (await pool.query('SELECT id, nome, re, setor, senha_hash, servico_dia FROM usuarios WHERE re=$1', [reInformado])).rows[0];
            if (!conta?.senha_hash) {
                a.count++; attempts.set(key, a);
                return res.status(conta ? 403 : 401).json({ error: conta ? 'Faça o primeiro acesso para criar sua senha' : 'RE ou senha incorretos' });
            }
            if (!(await verifyPassword(senha, conta.senha_hash))) {
                a.count++; attempts.set(key, a); return res.status(401).json({ error: 'RE ou senha incorretos' });
            }
            dadosSessao = { role: 'oper', operadorId: String(conta.id), usuario: conta.re, nome: conta.nome, re: conta.re, setor: conta.setor, servicoDia: Boolean(conta.servico_dia), superadmin: false, trocarSenha: false };
            redirect = 'operacional.html';
        } else {
            if (!/^[A-Z0-9_-]{2,30}$/.test(usuarioInformado)) {
                a.count++; attempts.set(key, a); return res.status(401).json({ error: 'Usuário ou senha incorretos' });
            }
            const result = await pool.query(`SELECT id, usuario, nome, setor, papel, senha_hash, ativo, trocar_senha
                FROM administradores WHERE usuario=$1`, [usuarioInformado]);
            const conta = result.rows[0];
            const senhaValida = conta ? await verifyPassword(senha, conta.senha_hash) : false;
            if (!conta || !conta.ativo || !senhaValida) {
                a.count++; attempts.set(key, a); return res.status(401).json({ error: 'Usuário ou senha incorretos' });
            }
            dadosSessao = {
                role: 'admin', adminId: String(conta.id), usuario: conta.usuario, nome: conta.nome,
                setor: conta.setor, superadmin: conta.papel === 'superadmin', trocarSenha: conta.trocar_senha
            };
            redirect = conta.trocar_senha ? 'trocar-senha.html' : 'index.html';
            await pool.query('UPDATE administradores SET ultimo_acesso=CURRENT_TIMESTAMP WHERE id=$1', [conta.id]);
        }
        attempts.delete(key);
        criarSessao(req, res, dadosSessao, now);
        res.json({ success: true, redirect });
    } catch (e) { erro(res, e); }
});
app.post('/api/operadores/primeiro-acesso', async (req, res) => {
    const re = typeof req.body?.re === 'string' ? req.body.re.trim() : '';
    const senha = req.body?.senha;
    const now = Date.now(), key = `${req.ip}:primeiro-acesso`;
    const a = attempts.get(key) || { count: 0, until: now + 15 * 60 * 1000 };
    if (now > a.until) { a.count = 0; a.until = now + 15 * 60 * 1000; }
    if (a.count >= 10) return res.status(429).json({ error: 'Muitas tentativas. Aguarde 15 minutos.' });
    if (!reValido(re) || !senhaOperacionalValida(senha)) {
        a.count++; attempts.set(key, a);
        return res.status(400).json({ error: 'Informe um RE com 6 números e uma senha de 4 a 8 caracteres, sem espaços' });
    }
    try {
        const conta = (await pool.query('SELECT id, nome, re, setor, senha_hash, servico_dia FROM usuarios WHERE re=$1', [re])).rows[0];
        if (!conta) { a.count++; attempts.set(key, a); return res.status(404).json({ error: 'RE não cadastrado. Procure o administrador da sua subunidade.' }); }
        if (conta.senha_hash) return res.status(409).json({ error: 'Este RE já possui senha. Entre normalmente ou peça a redefinição ao administrador.' });
        const senhaHash = await hashPassword(senha, { minLength: 4, maxLength: 8 });
        const atualizada = await pool.query('UPDATE usuarios SET senha_hash=$1 WHERE id=$2 AND senha_hash IS NULL RETURNING id', [senhaHash, conta.id]);
        if (!atualizada.rowCount) return res.status(409).json({ error: 'A senha deste RE já foi cadastrada.' });
        attempts.delete(key);
        criarSessao(req, res, { role: 'oper', operadorId: String(conta.id), usuario: conta.re, nome: conta.nome, re: conta.re, setor: conta.setor, servicoDia: Boolean(conta.servico_dia), superadmin: false, trocarSenha: false }, now);
        res.json({ success: true, redirect: 'operacional.html' });
    } catch (e) { erro(res, e); }
});
app.post('/api/logout', (req, res) => {
    if (req.cookies[COOKIE]) sessions.delete(req.cookies[COOKIE]);
    res.clearCookie(COOKIE, { path: '/', sameSite: 'strict', secure: req.secure });
    res.json({ success: true });
});
app.get('/api/session', (req, res) => {
    const s = session(req);
    if (!s) return res.status(401).json({ error: 'Acesso não autenticado' });
    res.json({ role: s.role, usuario: s.usuario, nome: s.nome || null, re: s.re || null, setor: s.setor, servico_dia: Boolean(s.servicoDia), superadmin: Boolean(s.superadmin), trocar_senha: Boolean(s.trocarSenha) });
});
// Lista explícita: código, banco, documentos e configuração não são arquivos públicos.
app.get(['/', '/login.html'], (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/index.html', protegerOperacional, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/usuarios.html', protegerAdmin, (req, res) => res.sendFile(path.join(__dirname, 'usuarios.html')));
app.get('/operacional.html', protegerOperacional, (req, res) => res.sendFile(path.join(__dirname, 'operacional.html')));
app.get('/trocar-senha.html', protegerAdminBase, (req, res) => res.sendFile(path.join(__dirname, 'trocar-senha.html')));
app.get('/administradores.html', protegerAdmin, (req, res) => {
    if (!req.auth.superadmin) return res.redirect(303, '/index.html?aviso=administradores');
    res.sendFile(path.join(__dirname, 'administradores.html'));
});
app.get(['/BRASAO%201BPTRAN.png', '/BRASAO 1BPTRAN.png'], (req, res) => res.sendFile(path.join(__dirname, 'BRASAO 1BPTRAN.png')));
const inteiro = (v, min = 0) => { if (typeof v !== 'number' && (typeof v !== 'string' || !/^\d+$/.test(v))) return null; const n = Number(v); return Number.isSafeInteger(n) && n >= min ? n : null; };
const texto = (v, max = 150) => typeof v === 'string' && v.trim() && v.length <= max ? v.trim() : null;
const normalizarPrefixo = v => String(v ?? '')
    .normalize('NFKC')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/[‐‑‒–—−]/g, '-')
    .replace(/\s+/g, '')
    .toUpperCase();
const erro = (res, e) => { console.error(e); res.status(500).json({ error: 'Erro interno' }); };
const categoriasBaixa = new Set(["Mecânico", "Pneu", "Bateria", "Freios", "Troca de óleo", "Iluminação e/ou sonoro", "Sindicância", "Avaria", "Elétrica", "Outros"]);
const setoresValidos = new Set(['EM', 'CTT', '1° CIA', '2° CIA', '3° CIA', '4° CIA']);
const podeGerenciarSetor = (req, setor) => Boolean(req.auth?.superadmin || (req.auth?.role === 'admin' && req.auth.setor === setor));
const nomeConta = req => req.auth?.usuario ? `ADM ${req.auth.usuario}` : 'Gestor';

app.post('/api/minha-senha', protegerAdminBase, async (req, res) => {
    const atual = typeof req.body?.senha_atual === 'string' ? req.body.senha_atual : '';
    const nova = typeof req.body?.nova_senha === 'string' ? req.body.nova_senha : '';
    if (nova.length < 10 || nova.length > 256 || !/[A-Za-z]/.test(nova) || !/\d/.test(nova))
        return res.status(400).json({ error: 'A nova senha deve ter ao menos 10 caracteres, com letras e números' });
    if (atual === nova) return res.status(400).json({ error: 'A nova senha deve ser diferente da atual' });
    try {
        const conta = (await pool.query('SELECT senha_hash FROM administradores WHERE id=$1 AND ativo=TRUE', [req.auth.adminId])).rows[0];
        if (!conta || !(await verifyPassword(atual, conta.senha_hash))) return res.status(401).json({ error: 'Senha atual incorreta' });
        const senhaHash = await hashPassword(nova);
        await pool.query('UPDATE administradores SET senha_hash=$1, trocar_senha=FALSE, atualizado_em=CURRENT_TIMESTAMP WHERE id=$2', [senhaHash, req.auth.adminId]);
        req.auth.trocarSenha = false;
        res.json({ success: true, redirect: 'index.html' });
    } catch (e) { erro(res, e); }
});

app.get('/api/administradores', protegerSuperadmin, async (req, res) => {
    try {
        const result = await pool.query(`SELECT id, usuario, nome, setor, papel, ativo, trocar_senha, criado_em, ultimo_acesso
            FROM administradores ORDER BY CASE WHEN papel='superadmin' THEN 0 ELSE 1 END, setor NULLS FIRST, usuario`);
        res.json(result.rows);
    } catch (e) { erro(res, e); }
});

app.post('/api/administradores', protegerSuperadmin, async (req, res) => {
    const usuario = typeof req.body?.usuario === 'string' ? req.body.usuario.trim().toUpperCase() : '';
    const nome = texto(req.body?.nome, 100);
    const setor = texto(req.body?.setor, 20);
    const senha = typeof req.body?.senha_temporaria === 'string' ? req.body.senha_temporaria : '';
    if (!/^[A-Z0-9_-]{2,30}$/.test(usuario) || !nome || !setoresValidos.has(setor) || senha.length < 10 || !/[A-Za-z]/.test(senha) || !/\d/.test(senha))
        return res.status(400).json({ error: 'Preencha usuário, nome, subunidade e uma senha temporária de ao menos 10 caracteres com letras e números' });
    try {
        const senhaHash = await hashPassword(senha);
        await pool.query(`INSERT INTO administradores (usuario, nome, setor, papel, senha_hash, trocar_senha)
            VALUES ($1,$2,$3,'admin',$4,TRUE)`, [usuario, nome, setor, senhaHash]);
        res.json({ success: true });
    } catch (e) {
        if (e.code === '23505') return res.status(409).json({ error: 'Esse usuário já existe' });
        erro(res, e);
    }
});

app.put('/api/administradores/:id/status', protegerSuperadmin, async (req, res) => {
    const id = inteiro(req.params.id, 1);
    if (!id || typeof req.body?.ativo !== 'boolean') return res.status(400).json({ error: 'Dados inválidos' });
    if (String(id) === String(req.auth.adminId) && !req.body.ativo) return res.status(400).json({ error: 'Você não pode bloquear a própria conta' });
    try {
        const result = await pool.query(`UPDATE administradores SET ativo=$1, atualizado_em=CURRENT_TIMESTAMP
            WHERE id=$2 AND papel<>'superadmin' RETURNING id`, [req.body.ativo, id]);
        if (!result.rowCount) return res.status(404).json({ error: 'Conta não encontrada ou protegida' });
        if (!req.body.ativo) for (const [token, s] of sessions) if (String(s.adminId) === String(id)) sessions.delete(token);
        res.json({ success: true });
    } catch (e) { erro(res, e); }
});

app.put('/api/administradores/:id/redefinir-senha', protegerSuperadmin, async (req, res) => {
    const id = inteiro(req.params.id, 1);
    const senha = typeof req.body?.senha_temporaria === 'string' ? req.body.senha_temporaria : '';
    if (!id || senha.length < 10 || !/[A-Za-z]/.test(senha) || !/\d/.test(senha))
        return res.status(400).json({ error: 'A senha temporária deve ter ao menos 10 caracteres, com letras e números' });
    try {
        const senhaHash = await hashPassword(senha);
        const result = await pool.query(`UPDATE administradores SET senha_hash=$1, trocar_senha=TRUE, ativo=TRUE, atualizado_em=CURRENT_TIMESTAMP
            WHERE id=$2 RETURNING id`, [senhaHash, id]);
        if (!result.rowCount) return res.status(404).json({ error: 'Conta não encontrada' });
        for (const [token, s] of sessions) if (String(s.adminId) === String(id) && token !== req.cookies[COOKIE]) sessions.delete(token);
        res.json({ success: true });
    } catch (e) { erro(res, e); }
});
// historico.data_hora é timestamp sem fuso e armazena UTC no banco existente.
// Primeiro interpreta UTC, depois converte para São Paulo, sem mudar os registros.
// Consulta independente: não altera o marcador usado pelos relatórios existentes.
app.get('/api/alteracoes-recentes', protegerOperacional, async (req, res) => {
    const setor = req.query.setor;
    if (setor !== undefined && (typeof setor !== 'string' || !texto(setor, 50)))
        return res.status(400).json({ error: 'Subunidade inválida' });
    try {
        const params = [];
        let where = '';
        if (setor && setor !== 'Todos') { where = 'WHERE setor = $1'; params.push(setor); }
        const result = await pool.query(`SELECT id, prefixo, km_anterior, km_novo, status,
            motivo, categoria_baixa, usuario, autor_conta, setor, data_hora,
            TO_CHAR((data_hora AT TIME ZONE 'UTC') AT TIME ZONE 'America/Sao_Paulo', 'DD/MM/YYYY HH24:MI') AS hora
            FROM historico ${where} ORDER BY data_hora DESC, id DESC LIMIT 10`, params);
        res.json(result.rows);
    } catch (e) { erro(res, e); }
});

// Detalhes expansíveis de uma viatura: anotação atual e seus 5 registros mais recentes.
app.get('/api/viaturas/:id/detalhes', protegerOperacional, async (req, res) => {
    const id = inteiro(req.params.id, 1);
    if (!id) return res.status(400).json({ error: 'Viatura inválida' });
    try {
        const viatura = (await pool.query('SELECT id, prefixo, setor, observacoes FROM viaturas WHERE id=$1', [id])).rows[0];
        if (!viatura) return res.status(404).json({ error: 'Viatura não encontrada' });
        const historico = await pool.query(`SELECT id, km_anterior, km_novo, status, motivo,
            categoria_baixa, usuario, autor_conta,
            TO_CHAR((data_hora AT TIME ZONE 'UTC') AT TIME ZONE 'America/Sao_Paulo', 'DD/MM/YYYY HH24:MI') AS hora
            FROM historico WHERE prefixo=$1 ORDER BY data_hora DESC, id DESC LIMIT 5`, [viatura.prefixo]);
        res.json({
            observacoes: viatura.observacoes || '',
            historico: historico.rows
        });
    } catch (e) { erro(res, e); }
});

// A anotação não participa da sincronização com o Google Sheets; cada alteração fica auditada no histórico.
app.put('/api/viaturas/:id/observacoes', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1);
    const recebida = typeof req.body?.observacoes === 'string' ? req.body.observacoes.replace(/\r\n?/g, '\n').trim() : null;
    if (!id || recebida === null || recebida.length > 2000 || recebida.includes('\u0000'))
        return res.status(400).json({ error: 'A anotação deve ter no máximo 2.000 caracteres' });
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        const viatura = (await client.query('SELECT id, prefixo, setor, km, status, observacoes FROM viaturas WHERE id=$1 FOR UPDATE', [id])).rows[0];
        if (!viatura) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Viatura não encontrada' }); }
        if (!podeGerenciarSetor(req, viatura.setor)) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: 'Você pode alterar somente viaturas da sua subunidade' });
        }
        if ((viatura.observacoes || '') === recebida) {
            await client.query('COMMIT');
            return res.json({ success: true, observacoes: recebida, alterada: false });
        }
        await client.query('UPDATE viaturas SET observacoes=$1 WHERE id=$2', [recebida, id]);
        const resumo = recebida ? `Anotação atualizada: ${recebida.slice(0, 300)}` : 'Anotação removida.';
        await client.query(`INSERT INTO historico
            (prefixo, km_anterior, km_novo, status, motivo, usuario, setor, autor_conta)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
            [viatura.prefixo, viatura.km, viatura.km, viatura.status, resumo, nomeConta(req), viatura.setor, req.auth.usuario]);
        await client.query('COMMIT');
        res.json({ success: true, observacoes: recebida, alterada: true });
    } catch (e) { if (client) await client.query('ROLLBACK').catch(() => {}); erro(res, e); }
    finally { if (client) client.release(); }
});

function cicloRevisao(modelo) {
    const nome = String(modelo ?? '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toUpperCase().replace(/[^A-Z0-9]+/g, ' ').replace(/([A-Z])([0-9])/g, '$1 $2').replace(/([0-9])([A-Z])/g, '$1 $2');
    const bmw850 = /\bBMW\b/.test(nome) && /\b(?:F\s*)?850\b/.test(nome) && /\bGS\b/.test(nome);
    return bmw850 ? 3000 : 5000;
}
function atingiuTrocaOleo(km, revisao, modelo) {
    const ciclo = cicloRevisao(modelo);
    const percentual = Math.max(0, Math.round((Number(km) - (Number(revisao) - ciclo)) / ciclo * 100));
    return percentual > 90;
}

// Confirmação de manutenção: somente administrador, com histórico e bloqueio de concorrência.
app.post('/api/viaturas/:id/troca-oleo', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1);
    const kmEsperado = inteiro(req.body.km_atual);
    const revisaoEsperada = inteiro(req.body.km_revisao);
    if (!id || kmEsperado === null || revisaoEsperada === null)
        return res.status(400).json({ error: 'Dados da troca inválidos' });
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        const old = (await client.query('SELECT id, prefixo, modelo, placa, km, km_revisao, status, setor FROM viaturas WHERE id=$1 FOR UPDATE', [id])).rows[0];
        if (!old) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Viatura não encontrada' }); }
        if (!podeGerenciarSetor(req, old.setor)) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Você pode alterar somente viaturas da sua subunidade' }); }
        if (Number(old.km) !== kmEsperado || Number(old.km_revisao) !== revisaoEsperada) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'Os dados da viatura mudaram. Atualize e confirme a troca novamente.' });
        }
        if (old.status === 'Baixada') {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'A viatura está baixada. Regularize a baixa antes de registrar a troca.' });
        }
        const incremento = cicloRevisao(old.modelo);
        const novaRevisao = kmEsperado + incremento;
        if (novaRevisao === revisaoEsperada) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: `A próxima revisão já está definida para este KM + ${incremento.toLocaleString('pt-BR')}. Nenhuma alteração foi feita.` });
        }
        if (novaRevisao > 2147483647) {
            await client.query('ROLLBACK'); return res.status(400).json({ error: 'Quilometragem fora do limite' });
        }
        await client.query("UPDATE viaturas SET km_revisao=$1, status='Operante', motivo='', categoria_baixa=NULL WHERE id=$2", [novaRevisao, id]);
        const registro = `Troca de óleo realizada. Revisão anterior: ${revisaoEsperada} km. Próxima revisão: ${novaRevisao} km.`;
        await client.query('INSERT INTO historico (prefixo, km_anterior, km_novo, status, motivo, usuario, setor, autor_conta) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
            [old.prefixo, kmEsperado, kmEsperado, 'Operante', registro, nomeConta(req), old.setor, req.auth.usuario]);
        await client.query('COMMIT');
        sincronizarPlanilhaEmSegundoPlano('sincronizar a troca de óleo', () =>
            sincronizarViaturaPlanilha({ prefixo: old.prefixo, responsavel: nomeConta(req), modelo: old.modelo, placa: old.placa, km: kmEsperado, km_revisao: novaRevisao, status: 'Operante', setor: old.setor })
        );
        res.json({ success: true, km_revisao: novaRevisao, status: 'Operante' });
    } catch (e) { if (client) await client.query('ROLLBACK').catch(() => {}); erro(res, e); }
    finally { if (client) client.release(); }
});
// ==========================================
// ROTA DO RELATÓRIO: ÚLTIMO ACESSO (CORREÇÃO FUSO)
// ==========================================
app.get('/api/relatorio-ultimo', protegerAdmin, async (req, res) => {
    try {
        const setor = texto(req.query.setor, 30), prefixo = texto(req.query.prefixo, 50);

        // 1. Pega o carimbo do último clique salvo (UTC)
        const config = await pool.query("SELECT valor FROM configuracoes WHERE chave = 'ultimo_acesso_relatorio'");
        const ultimoAcesso = config.rows[0] ? new Date(config.rows[0].valor) : new Date(0);
        const agora = new Date();

        // 2. Transforma as duas datas em string de "Data Brasileira" para comparar
        const dataHojeBR = agora.toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' });
        const dataUltimoBR = ultimoAcesso.toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' });

        let sql, params;

        if (dataHojeBR === dataUltimoBR) {
            // CENÁRIO A: Mesmo dia.
            // AJUSTE: DD/MM/YY HH24:MI
            sql = `SELECT *,
                   TO_CHAR((data_hora AT TIME ZONE 'UTC') AT TIME ZONE 'America/Sao_Paulo', 'DD/MM/YY HH24:MI') as hora
                   FROM historico
                   WHERE ((data_hora AT TIME ZONE 'UTC') AT TIME ZONE 'America/Sao_Paulo')::date = (CURRENT_TIMESTAMP AT TIME ZONE 'America/Sao_Paulo')::date`;
            params = [];
        } else {
            // CENÁRIO B: Dia diferente.
            // AJUSTE: DD/MM/YY HH24:MI
            sql = `SELECT *,
                   TO_CHAR((data_hora AT TIME ZONE 'UTC') AT TIME ZONE 'America/Sao_Paulo', 'DD/MM/YY HH24:MI') as hora
                   FROM historico
                   WHERE (data_hora AT TIME ZONE 'UTC') > $1::timestamptz`;
            params = [ultimoAcesso];
        }

        // Filtro de Setor Integrado
        if (setor && setor !== 'Todos') {
            sql += ` AND setor = $${params.length + 1}`;
            params.push(setor);
        }
        if (prefixo) {
            sql += ` AND prefixo = $${params.length + 1}`;
            params.push(prefixo);
        }

        const result = await pool.query(sql + ` ORDER BY data_hora DESC`, params);

        // Atualiza a memória de acesso para o próximo clique (Agora)
        await pool.query("UPDATE configuracoes SET valor = CURRENT_TIMESTAMP WHERE chave = 'ultimo_acesso_relatorio'");

        res.json(result.rows);
    } catch (e) { erro(res, e); }
});

app.get('/api/relatorio-periodo', protegerAdmin, async (req, res) => {
    try {
        const { inicio, fim } = req.query;
        const setor = texto(req.query.setor, 30), prefixo = texto(req.query.prefixo, 50);
        if (![inicio, fim].every(d => typeof d === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(d)) || inicio > fim) return res.status(400).json({ error: 'Período inválido' });
        let sql = `SELECT *, TO_CHAR((data_hora AT TIME ZONE 'UTC') AT TIME ZONE 'America/Sao_Paulo', 'DD/MM/YY HH24:MI') as hora FROM historico WHERE ((data_hora AT TIME ZONE 'UTC') AT TIME ZONE 'America/Sao_Paulo')::date >= $1 AND ((data_hora AT TIME ZONE 'UTC') AT TIME ZONE 'America/Sao_Paulo')::date <= $2`;
        let params = [inicio, fim];
        if (setor && setor !== 'Todos') { sql += ` AND setor = $${params.length + 1}`; params.push(setor); }
        if (prefixo) { sql += ` AND prefixo = $${params.length + 1}`; params.push(prefixo); }
        const result = await pool.query(sql + ` ORDER BY data_hora DESC`, params);
        res.json(result.rows);
    } catch (e) { erro(res, e); }
});

app.get('/api/viaturas', protegerOperacional, async (req, res) => {
    try {
        const rows = (await pool.query(`SELECT id, prefixo, placa, modelo, km, km_revisao, status,
            ultimo_usuario, motivo, setor, categoria_baixa
            FROM viaturas ORDER BY setor ASC, prefixo ASC`)).rows;
        res.json(rows.map(v => v.status === 'Baixada' ? v : {
            ...v,
            status: atingiuTrocaOleo(v.km, v.km_revisao, v.modelo) ? 'Troca de Óleo' : 'Operante'
        }));
    }
    catch (e) { erro(res, e); }
});
app.get('/api/operacional/responsaveis', protegerOperacional, async (req, res) => {
    if (req.auth.role !== 'oper' || !req.auth.servicoDia)
        return res.status(403).json({ error: 'Seleção disponível somente para policiais de serviço de dia' });
    try {
        const rows = (await pool.query(`SELECT id, nome, re
            FROM usuarios WHERE re IS NOT NULL ORDER BY nome ASC`)).rows;
        res.json(rows);
    } catch (e) { erro(res, e); }
});
// O operacional registra somente KM, responsável e baixa. A revisão e o setor são imutáveis aqui.
app.put('/api/operacional/viaturas/:id', protegerOperacional, async (req, res) => {
    const id = inteiro(req.params.id, 1), km = inteiro(req.body.km);
    const responsavelInformado = req.body?.responsavel_id;
    const responsavelId = responsavelInformado === undefined || responsavelInformado === null ? null : inteiro(responsavelInformado, 1);
    if (responsavelInformado !== undefined && responsavelInformado !== null && !responsavelId)
        return res.status(400).json({ error: 'Policial responsável inválido' });
    let usuario = req.auth.role === 'oper' ? `${req.auth.nome} (${req.auth.re})` : nomeConta(req);
    let autorConta = null;
    const baixa = req.body.baixa;
    const motivo = baixa ? texto(req.body.motivo, 500) : '';
    const categoria = baixa ? texto(req.body.categoria_baixa, 50) : null;
    // Clientes antigos podem manter o envio sem categoria; valores fornecidos são validados.
    if (baixa && req.body.categoria_baixa !== undefined && !categoriasBaixa.has(categoria))
        return res.status(400).json({ error: 'Selecione um motivo da baixa válido' });
    if (!id || km === null || !usuario || typeof baixa !== 'boolean' || (baixa && !motivo))
        return res.status(400).json({ error: 'Dados operacionais inválidos' });
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        if (req.auth.role === 'oper' && responsavelId && String(responsavelId) !== String(req.auth.operadorId)) {
            if (!req.auth.servicoDia) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Somente policiais de serviço de dia podem selecionar outro responsável' }); }
            const responsavel = (await client.query('SELECT id, nome, re, setor FROM usuarios WHERE id=$1 AND re IS NOT NULL', [responsavelId])).rows[0];
            if (!responsavel) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Policial responsável não encontrado' }); }
            usuario = `${responsavel.nome} (${responsavel.re})`;
            autorConta = `${req.auth.nome} (${req.auth.re})`;
        }
        const old = (await client.query('SELECT prefixo, modelo, placa, km, setor, km_revisao, status, motivo, categoria_baixa FROM viaturas WHERE id=$1 FOR UPDATE', [id])).rows[0];
        if (!old) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Viatura não encontrada' }); }
        if (req.auth.role === 'admin' && !podeGerenciarSetor(req, old.setor)) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Você pode alterar somente viaturas da sua subunidade' }); }
        if (km < old.km) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'KM inferior ao atual' }); }
        const status = baixa || old.status === 'Baixada' ? 'Baixada' : atingiuTrocaOleo(km, old.km_revisao, old.modelo) ? 'Troca de Óleo' : 'Operante';
        const finalMotivo = baixa ? motivo : status === 'Baixada' ? old.motivo : '';
        const finalCategoria = baixa ? (categoria || (old.status === 'Baixada' ? old.categoria_baixa : null)) : status === 'Baixada' ? old.categoria_baixa : null;
        await client.query('UPDATE viaturas SET km=$1, status=$2, ultimo_usuario=$3, motivo=$4, categoria_baixa=$5 WHERE id=$6', [km, status, usuario, finalMotivo, finalCategoria, id]);
        await client.query('INSERT INTO historico (prefixo, km_anterior, km_novo, status, motivo, usuario, setor, categoria_baixa, autor_conta) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [old.prefixo, old.km, km, status, finalMotivo, usuario, old.setor, finalCategoria, autorConta]);
        await client.query('COMMIT');
        sincronizarPlanilhaEmSegundoPlano('sincronizar o KM', () =>
            sincronizarViaturaPlanilha({ prefixo: old.prefixo, responsavel: usuario, modelo: old.modelo, placa: old.placa, km, km_revisao: old.km_revisao, status, setor: old.setor })
        );
        res.json({ success: true });
    } catch (e) { if (client) await client.query('ROLLBACK').catch(() => {}); erro(res, e); }
    finally { if (client) client.release(); }
});
app.put('/api/viaturas/:id', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1), km = inteiro(req.body.km), revisao = inteiro(req.body.km_revisao);
    const setor = texto(req.body.setor, 50), usuario = nomeConta(req);
    const placaSolicitada = req.body.placa === undefined ? undefined : texto(req.body.placa);
    const modeloSolicitado = req.body.modelo === undefined ? undefined : texto(req.body.modelo);
    const baixadaSolicitada = req.body.status === 'Baixada';
    const motivoSolicitado = baixadaSolicitada ? texto(req.body.motivo, 500) : '';
    const categoriaSolicitada = baixadaSolicitada ? texto(req.body.categoria_baixa, 50) : null;
    if (!id || km === null || revisao === null || !setoresValidos.has(setor) || !['Operante', 'Troca de Óleo', 'Baixada'].includes(req.body.status)
        || (req.body.placa !== undefined && !placaSolicitada) || (req.body.modelo !== undefined && !modeloSolicitado)
        || (baixadaSolicitada && (!motivoSolicitado || !categoriasBaixa.has(categoriaSolicitada))))
        return res.status(400).json({ error: 'Dados inválidos' });
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        const old = (await client.query('SELECT prefixo, modelo, placa, km, status, motivo, categoria_baixa, setor FROM viaturas WHERE id=$1 FOR UPDATE', [id])).rows[0];
        if (!old) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Viatura não encontrada' }); }
        if (!podeGerenciarSetor(req, old.setor)) {
            await client.query('ROLLBACK'); return res.status(403).json({ error: 'Você pode alterar somente viaturas da sua subunidade' });
        }
        const placa = placaSolicitada ?? old.placa;
        const modelo = modeloSolicitado ?? old.modelo;
        const status = req.body.status === 'Baixada' ? 'Baixada' : atingiuTrocaOleo(km, revisao, modelo) ? 'Troca de Óleo' : 'Operante';
        const motivo = status === 'Baixada' ? motivoSolicitado : '';
        const categoria = status === 'Baixada' ? categoriaSolicitada : null;
        const alteracoesCadastro = [];
        if (old.placa !== placa) alteracoesCadastro.push(`placa: ${old.placa} → ${placa}`);
        if (old.modelo !== modelo) alteracoesCadastro.push(`modelo: ${old.modelo} → ${modelo}`);
        if (old.setor !== setor) alteracoesCadastro.push(`subunidade: ${old.setor} → ${setor}`);
        const registroHistorico = alteracoesCadastro.length ? `Cadastro atualizado — ${alteracoesCadastro.join('; ')}.` : motivo;
        await client.query('UPDATE viaturas SET placa=$1, modelo=$2, km=$3, km_revisao=$4, status=$5, ultimo_usuario=$6, motivo=$7, setor=$8, categoria_baixa=$9 WHERE id=$10', [placa, modelo, km, revisao, status, usuario, motivo, setor, categoria, id]);
        await client.query('INSERT INTO historico (prefixo, km_anterior, km_novo, status, motivo, usuario, setor, categoria_baixa, autor_conta) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [old.prefixo, old.km, km, status, registroHistorico, usuario, setor, categoria, req.auth.usuario]);
        await client.query('COMMIT');
        sincronizarPlanilhaEmSegundoPlano('sincronizar a edição da viatura', () =>
            sincronizarViaturaPlanilha({ prefixo: old.prefixo, responsavel: usuario, modelo, placa, km, km_revisao: revisao, status, setor, setor_anterior: old.setor })
        );
        res.json({ success: true });
    } catch (e) { if (client) await client.query('ROLLBACK').catch(() => {}); erro(res, e); }
    finally { if (client) client.release(); }
});
app.post('/api/viaturas', protegerAdmin, async (req, res) => {
    const { prefixo, placa, modelo, status } = req.body;
    const prefixoNormalizado = normalizarPrefixo(prefixo);
    const setorSolicitado = texto(req.body.setor, 50);
    const setor = req.auth.superadmin ? setorSolicitado : req.auth.setor;
    const km = inteiro(req.body.km), revisao = inteiro(req.body.km_revisao);
    const baixada = status === 'Baixada';
    const motivo = baixada ? texto(req.body.motivo, 500) : '';
    const categoria = baixada ? texto(req.body.categoria_baixa, 50) : null;
    if (!prefixoNormalizado || prefixoNormalizado.length > 150 || ![placa, modelo].every(v => texto(v)) || !setoresValidos.has(setor) || km === null || revisao === null || !['Operante', 'Troca de Óleo', 'Baixada'].includes(status) || (baixada && (!motivo || !categoriasBaixa.has(categoria))))
        return res.status(400).json({ error: 'Dados inválidos' });
    try {
        const st = status === 'Baixada' ? 'Baixada' : atingiuTrocaOleo(km, revisao, modelo) ? 'Troca de Óleo' : 'Operante';
        await pool.query('INSERT INTO viaturas (prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario, motivo, setor, categoria_baixa) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', [prefixoNormalizado, placa.trim(), modelo.trim(), km, revisao, st, nomeConta(req), motivo, setor, categoria]);
        sincronizarPlanilhaEmSegundoPlano('cadastrar a viatura', () =>
            sincronizarViaturaPlanilha({ prefixo: prefixoNormalizado, responsavel: nomeConta(req), modelo: modelo.trim(), placa: placa.trim(), km, km_revisao: revisao, status: st, setor })
        );
        res.json({ success: true });
    } catch (e) {
        if (e?.code === '23505' && e?.constraint === 'viaturas_prefixo_normalizado_uidx')
            return res.status(409).json({ error: `A viatura ${prefixoNormalizado} já está cadastrada.` });
        erro(res, e);
    }
});
app.delete('/api/viaturas/:id', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1); if (!id) return res.status(400).json({ error: 'ID inválido' });
    try {
        const result = req.auth.superadmin
            ? await pool.query('DELETE FROM viaturas WHERE id=$1 RETURNING id, prefixo, setor', [id])
            : await pool.query('DELETE FROM viaturas WHERE id=$1 AND setor=$2 RETURNING id, prefixo, setor', [id, req.auth.setor]);
        if (!result.rowCount) return res.status(404).json({ error: 'Viatura não encontrada na sua subunidade' });
        const removida = result.rows[0];
        sincronizarPlanilhaEmSegundoPlano('excluir a viatura', () =>
            excluirViaturaPlanilha({ prefixo: removida.prefixo, responsavel: nomeConta(req), setor: removida.setor })
        );
        res.json({ success: true });
    }
    catch (e) { erro(res, e); }
});
app.get('/api/usuarios', protegerAdmin, async (req, res) => {
    try {
        const rows = (await pool.query('SELECT id, nome, re, setor, servico_dia, (senha_hash IS NOT NULL) AS senha_cadastrada FROM usuarios ORDER BY nome ASC')).rows;
        res.json(rows.map(u => ({ ...u, pode_editar: req.auth.superadmin || u.setor === req.auth.setor })));
    }
    catch (e) { erro(res, e); }
});
app.post('/api/usuarios', protegerAdmin, async (req, res) => {
    const nome = texto(req.body.nome), re = typeof req.body.re === 'string' ? req.body.re.trim() : '';
    const setorSolicitado = texto(req.body.setor, 20);
    const setor = req.auth.superadmin ? setorSolicitado : req.auth.setor;
    if (!nome || !reValido(re) || !setoresValidos.has(setor)) return res.status(400).json({ error: 'Informe o QRA, um RE com exatamente 6 números e a subunidade' });
    try { await pool.query('INSERT INTO usuarios (nome, cargo, re, setor) VALUES ($1,$2,$2,$3)', [nome, re, setor]); res.json({ success: true }); }
    catch (e) {
        if (e?.code === '23505') return res.status(409).json({ error: 'Este RE já está cadastrado' });
        erro(res, e);
    }
});
app.put('/api/usuarios/:id', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1);
    const nome = texto(req.body?.nome);
    const setor = texto(req.body?.setor, 20);
    const reInformado = typeof req.body?.re === 'string' ? req.body.re.trim() : '';
    const servicoDiaInformado = req.body?.servico_dia;
    if (!id || !nome || !setoresValidos.has(setor)) return res.status(400).json({ error: 'Informe o QRA e uma subunidade válida' });
    if (reInformado && !reValido(reInformado)) return res.status(400).json({ error: 'O RE deve conter exatamente 6 números' });
    if (servicoDiaInformado !== undefined && typeof servicoDiaInformado !== 'boolean') return res.status(400).json({ error: 'Configuração de serviço de dia inválida' });
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const atual = (await client.query('SELECT id, nome, cargo, re, setor, servico_dia FROM usuarios WHERE id=$1 FOR UPDATE', [id])).rows[0];
        if (!atual) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Militar não encontrado' }); }
        if (!podeGerenciarSetor(req, atual.setor)) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: 'Você pode editar somente militares da sua subunidade' });
        }
        if (atual.re && reInformado && reInformado !== atual.re) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'O RE é o identificador permanente do militar e não pode ser alterado' });
        }
        const reFinal = atual.re || reInformado || null;
        const cargoFinal = atual.re ? atual.cargo : (reFinal || atual.cargo);
        const servicoDiaFinal = typeof servicoDiaInformado === 'boolean' ? servicoDiaInformado : Boolean(atual.servico_dia);
        await client.query('UPDATE usuarios SET nome=$1, setor=$2, re=$3, cargo=$4, servico_dia=$5 WHERE id=$6', [nome, setor, reFinal, cargoFinal, servicoDiaFinal, id]);
        await client.query('COMMIT');
        for (const [token, s] of sessions) if (String(s.operadorId) === String(id)) sessions.delete(token);
        res.json({ success: true, transferido: atual.setor !== setor });
    } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        if (e?.code === '23505') return res.status(409).json({ error: 'Este RE já está cadastrado' });
        erro(res, e);
    } finally { client.release(); }
});
app.put('/api/usuarios/:id/re', protegerAdmin, async (req, res) => {
    res.status(409).json({ error: 'O RE é o identificador permanente do militar e não pode ser alterado' });
});
app.put('/api/usuarios/:id/redefinir-senha', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1);
    if (!id) return res.status(400).json({ error: 'Militar inválido' });
    try {
        const result = req.auth.superadmin
            ? await pool.query('UPDATE usuarios SET senha_hash=NULL WHERE id=$1 RETURNING id', [id])
            : await pool.query('UPDATE usuarios SET senha_hash=NULL WHERE id=$1 AND setor=$2 RETURNING id', [id, req.auth.setor]);
        if (!result.rowCount) return res.status(404).json({ error: 'Militar não encontrado na sua subunidade' });
        for (const [token, s] of sessions) if (String(s.operadorId) === String(id)) sessions.delete(token);
        res.json({ success: true });
    } catch (e) { erro(res, e); }
});
app.put('/api/usuarios/:id/setor', protegerSuperadmin, async (req, res) => {
    const id = inteiro(req.params.id, 1), setor = texto(req.body?.setor, 20);
    if (!id || !setoresValidos.has(setor)) return res.status(400).json({ error: 'Subunidade inválida' });
    try {
        const result = await pool.query('UPDATE usuarios SET setor=$1 WHERE id=$2 RETURNING id', [setor, id]);
        if (!result.rowCount) return res.status(404).json({ error: 'Militar não encontrado' });
        for (const [token, s] of sessions) if (String(s.operadorId) === String(id)) sessions.delete(token);
        res.json({ success: true });
    } catch (e) { erro(res, e); }
});
app.delete('/api/usuarios/:id', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1); if (!id) return res.status(400).json({ error: 'ID inválido' });
    try {
        const result = req.auth.superadmin
            ? await pool.query('DELETE FROM usuarios WHERE id=$1 RETURNING id', [id])
            : await pool.query('DELETE FROM usuarios WHERE id=$1 AND setor=$2 RETURNING id', [id, req.auth.setor]);
        if (!result.rowCount) return res.status(404).json({ error: 'Militar não encontrado na sua subunidade' });
        for (const [token, s] of sessions) if (String(s.operadorId) === String(id)) sessions.delete(token);
        res.json({ success: true });
    }
    catch (e) { erro(res, e); }
});
app.use('/api', (req, res) => res.status(404).json({ error: 'Rota não encontrada' }));
app.use((req, res) => res.status(404).send('Não encontrado'));
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400) return res.status(400).json({ error: 'JSON inválido' });
    erro(res, err);
});

const PORT = process.env.PORT || 3000;
if (require.main === module) app.listen(PORT, () => console.log(`GEOFROTA ON: ${PORT}`));
module.exports = app;
