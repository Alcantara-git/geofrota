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
const protegerMateriais = (req, res, next) => protegerOperacional(req, res, () => {
    if (req.auth.role === 'oper' && !req.auth.servicoDia)
        return res.status(403).json({ error: 'Acesso disponível somente para administradores e policiais de serviço de dia' });
    next();
});
const protegerEncerramentoServico = (req, res, next) => protegerMateriais(req, res, () => {
    if (req.auth.role !== 'oper' || !req.auth.servicoDia)
        return res.status(403).json({ error: 'Encerramento disponível somente para policiais de serviço de dia' });
    next();
});
const protegerPaginaMateriais = (req, res, next) => {
    const s = session(req);
    if (!s) return res.redirect(303, '/login.html');
    if (!['admin', 'oper'].includes(s.role)) return res.redirect(303, '/login.html');
    if (s.role === 'admin' && s.trocarSenha) return res.redirect(303, '/trocar-senha.html');
    if (s.role === 'oper' && !s.servicoDia) return res.redirect(303, '/operacional.html');
    req.auth = s;
    next();
};
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
            const setoresMateriais = await carregarSetoresMateriaisUsuario(conta.id, conta.setor, Boolean(conta.servico_dia));
            dadosSessao = { role: 'oper', operadorId: String(conta.id), usuario: conta.re, nome: conta.nome, re: conta.re, setor: conta.setor, setoresMateriais, servicoDia: Boolean(conta.servico_dia), superadmin: false, trocarSenha: false };
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
        const setoresMateriais = await carregarSetoresMateriaisUsuario(conta.id, conta.setor, Boolean(conta.servico_dia));
        criarSessao(req, res, { role: 'oper', operadorId: String(conta.id), usuario: conta.re, nome: conta.nome, re: conta.re, setor: conta.setor, setoresMateriais, servicoDia: Boolean(conta.servico_dia), superadmin: false, trocarSenha: false }, now);
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
    res.json({ role: s.role, usuario: s.usuario, nome: s.nome || null, re: s.re || null, setor: s.setor, setores_materiais: setoresMateriaisPermitidos({ auth: s }), servico_dia: Boolean(s.servicoDia), superadmin: Boolean(s.superadmin), trocar_senha: Boolean(s.trocarSenha) });
});
// Lista explícita: código, banco, documentos e configuração não são arquivos públicos.
app.get(['/', '/login.html'], (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/index.html', protegerOperacional, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/usuarios.html', protegerAdmin, (req, res) => res.sendFile(path.join(__dirname, 'usuarios.html')));
app.get('/operacional.html', protegerOperacional, (req, res) => res.sendFile(path.join(__dirname, 'operacional.html')));
app.get('/materiais.html', protegerPaginaMateriais, (req, res) => res.sendFile(path.join(__dirname, 'materiais.html')));
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
const normalizarSetoresMateriais = (setores, setorPrincipal) => [...new Set([setorPrincipal, ...(Array.isArray(setores) ? setores : [])].filter(setor => setoresValidos.has(setor)))];
async function carregarSetoresMateriaisUsuario(usuarioId, setorPrincipal, servicoDia, executor = pool) {
    if (!servicoDia) return normalizarSetoresMateriais([], setorPrincipal);
    const rows = (await executor.query('SELECT setor FROM usuarios_materiais_setores WHERE usuario_id=$1 ORDER BY setor', [usuarioId])).rows;
    return normalizarSetoresMateriais(rows.map(row => row.setor), setorPrincipal);
}
const setoresMateriaisPermitidos = req => {
    if (req.auth?.superadmin) return [...setoresValidos];
    if (req.auth?.role === 'oper' && req.auth?.servicoDia)
        return normalizarSetoresMateriais(req.auth.setoresMateriais, req.auth.setor);
    return normalizarSetoresMateriais([], req.auth?.setor);
};
const podeGerenciarSetor = (req, setor) => Boolean(req.auth?.superadmin || (req.auth?.role === 'admin' && req.auth.setor === setor));
const nomeConta = req => req.auth?.usuario ? `ADM ${req.auth.usuario}` : 'Gestor';
const textoOpcional = (v, max = 1000) => {
    if (v === undefined || v === null || v === '') return '';
    return typeof v === 'string' && v.length <= max && !v.includes('\u0000') ? v.trim() : null;
};
const whatsappSuportePadrao = '18996680768';
const normalizarWhatsappSuporte = valor => {
    let numero = String(valor ?? '').replace(/\D/g, '');
    if ((numero.length === 12 || numero.length === 13) && numero.startsWith('55')) numero = numero.slice(2);
    return /^\d{10,11}$/.test(numero) ? numero : null;
};
const dadosWhatsappSuporte = valor => {
    const numero = normalizarWhatsappSuporte(valor) || whatsappSuportePadrao;
    const mensagem = encodeURIComponent('Olá, preciso de suporte no sistema GEOFROTA.');
    return { numero, url: `https://wa.me/55${numero}?text=${mensagem}` };
};
const podeAdministrarMateriaisSetor = (req, setor) => Boolean(req.auth?.role === 'admin' && (req.auth.superadmin || req.auth.setor === setor));
const podeOperarMateriaisSetor = (req, setor) => Boolean(
    req.auth?.superadmin || req.auth?.role === 'admin' && req.auth?.setor === setor || req.auth?.role === 'oper' && req.auth?.servicoDia && setoresMateriaisPermitidos(req).includes(setor)
);
const autorMaterial = req => req.auth.role === 'admin' ? `ADM ${req.auth.usuario}` : `${req.auth.nome} (${req.auth.re})`;
const reAutorMaterial = req => req.auth.role === 'oper' ? req.auth.re : null;

app.get('/api/configuracoes/suporte', protegerOperacional, async (req, res) => {
    try {
        const resultado = await pool.query("SELECT valor FROM configuracoes WHERE chave='whatsapp_suporte'");
        res.json(dadosWhatsappSuporte(resultado.rows[0]?.valor));
    } catch (e) { erro(res, e); }
});

app.put('/api/configuracoes/suporte', protegerSuperadmin, async (req, res) => {
    const numero = normalizarWhatsappSuporte(req.body?.numero);
    if (!numero) return res.status(400).json({ error: 'Informe um WhatsApp válido com DDD e 10 ou 11 números' });
    try {
        await pool.query(`INSERT INTO configuracoes (chave, valor) VALUES ('whatsapp_suporte', $1)
            ON CONFLICT (chave) DO UPDATE SET valor=EXCLUDED.valor`, [numero]);
        res.json({ success: true, ...dadosWhatsappSuporte(numero) });
    } catch (e) { erro(res, e); }
});

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
function prefixoComPrazoSemestral(prefixo) {
    return String(prefixo ?? '').includes('000');
}
function somarMesesUTC(valor, meses) {
    const data = new Date(valor);
    if (Number.isNaN(data.getTime())) return null;
    const diaOriginal = data.getUTCDate();
    data.setUTCDate(1);
    data.setUTCMonth(data.getUTCMonth() + meses);
    const ultimoDiaDestino = new Date(Date.UTC(data.getUTCFullYear(), data.getUTCMonth() + 1, 0)).getUTCDate();
    data.setUTCDate(Math.min(diaOriginal, ultimoDiaDestino));
    return data;
}
function prazoTrocaOleo(prefixo, ultimaTroca, agora = new Date()) {
    const aplica = prefixoComPrazoSemestral(prefixo);
    const proxima = aplica && ultimaTroca ? somarMesesUTC(ultimaTroca, 6) : null;
    const referencia = new Date(agora);
    return { aplica, proxima, vencido: Boolean(proxima && !Number.isNaN(referencia.getTime()) && referencia >= proxima) };
}
function atingiuTrocaOleo(km, revisao, modelo, prefixo, ultimaTroca, agora = new Date()) {
    const ciclo = cicloRevisao(modelo);
    const percentual = Math.max(0, Math.round((Number(km) - (Number(revisao) - ciclo)) / ciclo * 100));
    return percentual > 90 || prazoTrocaOleo(prefixo, ultimaTroca, agora).vencido;
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
        const old = (await client.query('SELECT id, prefixo, modelo, placa, km, km_revisao, status, setor, ultima_troca_oleo_em FROM viaturas WHERE id=$1 FOR UPDATE', [id])).rows[0];
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
        const atualizada = (await client.query("UPDATE viaturas SET km_revisao=$1, status='Operante', motivo='', categoria_baixa=NULL, ultima_troca_oleo_em=CURRENT_TIMESTAMP WHERE id=$2 RETURNING ultima_troca_oleo_em", [novaRevisao, id])).rows[0];
        const controleSemestral = prazoTrocaOleo(old.prefixo, atualizada.ultima_troca_oleo_em);
        const registro = `Troca de óleo realizada. Revisão anterior: ${revisaoEsperada} km. Próxima revisão: ${novaRevisao} km.${controleSemestral.aplica ? ' Prazo especial de 6 meses reiniciado.' : ''}`;
        await client.query('INSERT INTO historico (prefixo, km_anterior, km_novo, status, motivo, usuario, setor, autor_conta) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
            [old.prefixo, kmEsperado, kmEsperado, 'Operante', registro, nomeConta(req), old.setor, req.auth.usuario]);
        await client.query('COMMIT');
        sincronizarPlanilhaEmSegundoPlano('sincronizar a troca de óleo', () =>
            sincronizarViaturaPlanilha({ prefixo: old.prefixo, responsavel: nomeConta(req), modelo: old.modelo, placa: old.placa, km: kmEsperado, km_revisao: novaRevisao, status: 'Operante', setor: old.setor })
        );
        res.json({ success: true, km_revisao: novaRevisao, status: 'Operante', proxima_troca_oleo_em: controleSemestral.proxima?.toISOString() || null });
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
            ultimo_usuario, motivo, setor, categoria_baixa, ultima_troca_oleo_em
            FROM viaturas ORDER BY setor ASC, prefixo ASC`)).rows;
        res.json(rows.map(v => {
            const prazo = prazoTrocaOleo(v.prefixo, v.ultima_troca_oleo_em);
            return {
                ...v,
                controle_tempo_oleo: prazo.aplica,
                proxima_troca_oleo_em: prazo.proxima?.toISOString() || null,
                prazo_troca_oleo_vencido: prazo.vencido,
                status: v.status === 'Baixada' ? v.status : atingiuTrocaOleo(v.km, v.km_revisao, v.modelo, v.prefixo, v.ultima_troca_oleo_em) ? 'Troca de Óleo' : 'Operante'
            };
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
        const old = (await client.query('SELECT prefixo, modelo, placa, km, setor, km_revisao, status, motivo, categoria_baixa, ultima_troca_oleo_em FROM viaturas WHERE id=$1 FOR UPDATE', [id])).rows[0];
        if (!old) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Viatura não encontrada' }); }
        if (req.auth.role === 'admin' && !podeGerenciarSetor(req, old.setor)) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Você pode alterar somente viaturas da sua subunidade' }); }
        if (km < old.km) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'KM inferior ao atual' }); }
        const status = baixa || old.status === 'Baixada' ? 'Baixada' : atingiuTrocaOleo(km, old.km_revisao, old.modelo, old.prefixo, old.ultima_troca_oleo_em) ? 'Troca de Óleo' : 'Operante';
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
        const old = (await client.query('SELECT prefixo, modelo, placa, km, status, motivo, categoria_baixa, setor, ultima_troca_oleo_em FROM viaturas WHERE id=$1 FOR UPDATE', [id])).rows[0];
        if (!old) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Viatura não encontrada' }); }
        if (!podeGerenciarSetor(req, old.setor)) {
            await client.query('ROLLBACK'); return res.status(403).json({ error: 'Você pode alterar somente viaturas da sua subunidade' });
        }
        const placa = placaSolicitada ?? old.placa;
        const modelo = modeloSolicitado ?? old.modelo;
        const status = req.body.status === 'Baixada' ? 'Baixada' : atingiuTrocaOleo(km, revisao, modelo, old.prefixo, old.ultima_troca_oleo_em) ? 'Troca de Óleo' : 'Operante';
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
        const st = status === 'Baixada' ? 'Baixada' : atingiuTrocaOleo(km, revisao, modelo, prefixoNormalizado, null) ? 'Troca de Óleo' : 'Operante';
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
        const rows = (await pool.query(`SELECT u.id,u.nome,u.re,u.setor,u.servico_dia,
            (u.senha_hash IS NOT NULL) AS senha_cadastrada,
            COALESCE((SELECT ARRAY_AGG(ums.setor ORDER BY ums.setor) FROM usuarios_materiais_setores ums WHERE ums.usuario_id=u.id),ARRAY[]::text[]) AS setores_materiais
            FROM usuarios u ORDER BY u.nome ASC`)).rows;
        res.json(rows.map(u => ({
            ...u,
            setores_materiais: u.servico_dia ? normalizarSetoresMateriais(u.setores_materiais, u.setor) : [],
            pode_editar: req.auth.superadmin || u.setor === req.auth.setor
        })));
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
    const setoresMateriaisInformados = req.body?.setores_materiais;
    if (!id || !nome || !setoresValidos.has(setor)) return res.status(400).json({ error: 'Informe o QRA e uma subunidade válida' });
    if (reInformado && !reValido(reInformado)) return res.status(400).json({ error: 'O RE deve conter exatamente 6 números' });
    if (servicoDiaInformado !== undefined && typeof servicoDiaInformado !== 'boolean') return res.status(400).json({ error: 'Configuração de serviço de dia inválida' });
    if (setoresMateriaisInformados !== undefined && (!Array.isArray(setoresMateriaisInformados) || setoresMateriaisInformados.length > setoresValidos.size || setoresMateriaisInformados.some(s => typeof s !== 'string' || !setoresValidos.has(s))))
        return res.status(400).json({ error: 'Abrangência de materiais inválida' });
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
        const setoresAtuais = (await client.query('SELECT setor FROM usuarios_materiais_setores WHERE usuario_id=$1', [id])).rows.map(row => row.setor);
        let setoresMateriaisFinais = [];
        if (servicoDiaFinal) {
            if (req.auth.superadmin && setoresMateriaisInformados !== undefined)
                setoresMateriaisFinais = normalizarSetoresMateriais(setoresMateriaisInformados, setor);
            else if (!req.auth.superadmin && atual.setor !== setor)
                setoresMateriaisFinais = normalizarSetoresMateriais([], setor);
            else
                setoresMateriaisFinais = normalizarSetoresMateriais(setoresAtuais, setor);
        }
        await client.query('UPDATE usuarios SET nome=$1, setor=$2, re=$3, cargo=$4, servico_dia=$5 WHERE id=$6', [nome, setor, reFinal, cargoFinal, servicoDiaFinal, id]);
        await client.query('DELETE FROM usuarios_materiais_setores WHERE usuario_id=$1', [id]);
        if (setoresMateriaisFinais.length) await client.query(`INSERT INTO usuarios_materiais_setores (usuario_id,setor,concedido_por)
            SELECT $1,setor,$3 FROM UNNEST($2::text[]) AS setor`, [id, setoresMateriaisFinais, nomeConta(req)]);
        await client.query('COMMIT');
        for (const [token, s] of sessions) if (String(s.operadorId) === String(id)) sessions.delete(token);
        res.json({ success: true, transferido: atual.setor !== setor, setores_materiais: setoresMateriaisFinais });
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

// ==========================================
// MÓDULO DE CAUTELA DE MATERIAIS
// ==========================================
async function montarEncerramentoMateriais(req, executor = pool) {
    const setores = setoresMateriaisPermitidos(req);
    const marcador = (await executor.query(`SELECT
        COALESCE((SELECT MAX(encerrado_em) FROM materiais_encerramentos WHERE operador_id=$1),
            date_trunc('day',CURRENT_TIMESTAMP AT TIME ZONE 'America/Sao_Paulo') AT TIME ZONE 'America/Sao_Paulo') AS inicio_periodo,
        CURRENT_TIMESTAMP AS encerrado_em`, [req.auth.operadorId])).rows[0];
    const resumos = (await executor.query(`SELECT
        CASE WHEN GROUPING(c.setor)=1 THEN '__TOTAL__' ELSE c.setor END AS chave,
        COUNT(*) FILTER (WHERE c.entregue_em >= $2 AND c.entregue_em <= $3)::int AS materiais_entregues,
        COUNT(*) FILTER (WHERE c.devolvido_em >= $2 AND c.devolvido_em <= $3)::int AS materiais_devolvidos,
        COUNT(*) FILTER (WHERE c.devolvido_em IS NULL)::int AS materiais_pendentes,
        COUNT(DISTINCT c.viatura_id) FILTER (WHERE c.viatura_id IS NOT NULL AND (c.entregue_em >= $2 OR c.devolvido_em IS NULL))::int AS viaturas_vinculadas
        FROM materiais_cautelas c
        WHERE c.setor=ANY($1::text[]) AND c.entregue_em <= $3
        GROUP BY GROUPING SETS ((c.setor),())`, [setores, marcador.inicio_periodo, marcador.encerrado_em])).rows;
    const zero = { materiais_entregues: 0, materiais_devolvidos: 0, materiais_pendentes: 0, viaturas_vinculadas: 0 };
    const resumo = resumos.find(item => item.chave === '__TOTAL__') || zero;
    const porSetor = setores.map(setor => ({ setor, ...(resumos.find(item => item.chave === setor) || zero) }));
    const abertas = (await executor.query(`SELECT c.id AS cautela_id,c.responsavel_id,c.responsavel_nome,c.responsavel_re,
        c.setor,c.lista_nome,c.material_nome,c.material_numero,c.viatura_id,c.viatura_prefixo,c.viatura_placa,c.observacao_entrega,
        TO_CHAR(c.entregue_em AT TIME ZONE 'America/Sao_Paulo','DD/MM/YYYY HH24:MI') AS entrega
        FROM materiais_cautelas c
        WHERE c.setor=ANY($1::text[]) AND c.devolvido_em IS NULL
        ORDER BY c.responsavel_nome,c.responsavel_re,c.setor,c.lista_nome,c.material_nome,c.material_numero,c.id`, [setores])).rows;
    const agrupadas = new Map();
    for (const item of abertas) {
        const chave = `${item.responsavel_id || 'excluido'}:${item.responsavel_re}`;
        if (!agrupadas.has(chave)) agrupadas.set(chave, {
            responsavel_id: item.responsavel_id, responsavel_nome: item.responsavel_nome, responsavel_re: item.responsavel_re,
            setores: [], viaturas: [], materiais: []
        });
        const grupo = agrupadas.get(chave);
        if (!grupo.setores.includes(item.setor)) grupo.setores.push(item.setor);
        const viatura = item.viatura_prefixo ? `${item.viatura_prefixo}${item.viatura_placa ? ` (${item.viatura_placa})` : ''}` : null;
        if (viatura && !grupo.viaturas.includes(viatura)) grupo.viaturas.push(viatura);
        grupo.materiais.push({
            cautela_id: item.cautela_id, setor: item.setor, lista_nome: item.lista_nome, material_nome: item.material_nome,
            material_numero: item.material_numero, entrega: item.entrega, viatura_prefixo: item.viatura_prefixo,
            viatura_placa: item.viatura_placa, observacao_entrega: item.observacao_entrega
        });
    }
    return {
        setores, inicio_periodo: marcador.inicio_periodo, encerrado_em: marcador.encerrado_em,
        resumo: {
            materiais_entregues: Number(resumo.materiais_entregues) || 0,
            materiais_devolvidos: Number(resumo.materiais_devolvidos) || 0,
            materiais_pendentes: Number(resumo.materiais_pendentes) || 0,
            viaturas_vinculadas: Number(resumo.viaturas_vinculadas) || 0
        },
        resumos_setores: porSetor.map(item => ({
            ...item,
            materiais_entregues: Number(item.materiais_entregues) || 0,
            materiais_devolvidos: Number(item.materiais_devolvidos) || 0,
            materiais_pendentes: Number(item.materiais_pendentes) || 0,
            viaturas_vinculadas: Number(item.viaturas_vinculadas) || 0
        })),
        pendencias: [...agrupadas.values()]
    };
}

app.get('/api/materiais/encerramento', protegerEncerramentoServico, async (req, res) => {
    try { res.json(await montarEncerramentoMateriais(req)); }
    catch (e) { erro(res, e); }
});

app.post('/api/materiais/encerramento', protegerEncerramentoServico, async (req, res) => {
    if (req.body?.confirmado !== true) return res.status(400).json({ error: 'Confirme a conferência antes de encerrar o serviço' });
    const observacao = typeof req.body?.observacao === 'string' ? req.body.observacao.trim() : '';
    if (observacao.length > 2000) return res.status(400).json({ error: 'A observação deve ter no máximo 2.000 caracteres' });
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        await client.query('SELECT id FROM usuarios WHERE id=$1 FOR UPDATE', [req.auth.operadorId]);
        const fotografia = await montarEncerramentoMateriais(req, client);
        const salvo = (await client.query(`INSERT INTO materiais_encerramentos
            (operador_id,operador_nome,operador_re,setores,inicio_periodo,encerrado_em,materiais_entregues,materiais_devolvidos,materiais_pendentes,viaturas_vinculadas,pendencias,observacao)
            VALUES ($1,$2,$3,$4::text[],$5,$6,$7,$8,$9,$10,$11::jsonb,$12) RETURNING id,encerrado_em,observacao`,
            [req.auth.operadorId,req.auth.nome,req.auth.re,fotografia.setores,fotografia.inicio_periodo,fotografia.encerrado_em,
                fotografia.resumo.materiais_entregues,fotografia.resumo.materiais_devolvidos,fotografia.resumo.materiais_pendentes,
                fotografia.resumo.viaturas_vinculadas,JSON.stringify(fotografia.pendencias),observacao || null])).rows[0];
        await client.query('COMMIT');
        res.json({ ...fotografia, id: salvo.id, encerrado_por: req.auth.nome, encerrado_por_re: req.auth.re, encerrado_em: salvo.encerrado_em, observacao: salvo.observacao || '' });
    } catch (e) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        erro(res, e);
    } finally { if (client) client.release(); }
});

app.get('/api/materiais/listas', protegerMateriais, async (req, res) => {
    try {
        const params = [];
        let where = '';
        if (req.auth.role === 'oper') { where = 'WHERE l.setor=ANY($1::text[])'; params.push(setoresMateriaisPermitidos(req)); }
        const rows = (await pool.query(`SELECT l.id, l.nome, l.setor, l.ativo, l.criado_em,
            COUNT(m.id)::int AS total,
            COUNT(m.id) FILTER (WHERE m.ativo AND m.status='disponivel')::int AS disponiveis,
            COUNT(m.id) FILTER (WHERE m.ativo AND m.status='em_uso')::int AS em_uso,
            COUNT(m.id) FILTER (WHERE m.ativo AND m.status='manutencao')::int AS manutencao
            FROM materiais_listas l
            LEFT JOIN materiais m ON m.lista_id=l.id
            ${where}
            GROUP BY l.id
            ORDER BY l.setor, l.nome`, params)).rows;
        res.json(rows.map(l => ({
            ...l,
            pode_administrar: podeAdministrarMateriaisSetor(req, l.setor),
            pode_operar: podeOperarMateriaisSetor(req, l.setor)
        })));
    } catch (e) { erro(res, e); }
});

app.post('/api/materiais/listas', protegerAdmin, async (req, res) => {
    const nome = texto(req.body?.nome, 80);
    const solicitado = texto(req.body?.setor, 20);
    const setor = req.auth.superadmin ? solicitado : req.auth.setor;
    if (!nome || !setoresValidos.has(setor)) return res.status(400).json({ error: 'Informe o nome e uma subunidade válida' });
    try {
        const row = (await pool.query(`INSERT INTO materiais_listas (nome,setor,criado_por)
            VALUES ($1,$2,$3) RETURNING id,nome,setor,ativo`, [nome, setor, autorMaterial(req)])).rows[0];
        res.status(201).json(row);
    } catch (e) {
        if (e?.code === '23505') return res.status(409).json({ error: 'Já existe uma lista com esse nome nesta subunidade' });
        erro(res, e);
    }
});

app.put('/api/materiais/listas/:id', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1), nome = texto(req.body?.nome, 80);
    const ativo = req.body?.ativo;
    if (!id || !nome || typeof ativo !== 'boolean') return res.status(400).json({ error: 'Dados da lista inválidos' });
    try {
        const atual = (await pool.query('SELECT id,setor FROM materiais_listas WHERE id=$1', [id])).rows[0];
        if (!atual) return res.status(404).json({ error: 'Lista não encontrada' });
        if (!podeAdministrarMateriaisSetor(req, atual.setor)) return res.status(403).json({ error: 'Você pode administrar somente materiais da sua subunidade' });
        const row = (await pool.query(`UPDATE materiais_listas SET nome=$1,ativo=$2,atualizado_em=CURRENT_TIMESTAMP
            WHERE id=$3 RETURNING id,nome,setor,ativo`, [nome, ativo, id])).rows[0];
        res.json(row);
    } catch (e) {
        if (e?.code === '23505') return res.status(409).json({ error: 'Já existe uma lista com esse nome nesta subunidade' });
        erro(res, e);
    }
});

app.delete('/api/materiais/listas/:id', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1);
    if (!id) return res.status(400).json({ error: 'Lista inválida' });
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        const lista = (await client.query('SELECT id,nome,setor FROM materiais_listas WHERE id=$1 FOR UPDATE', [id])).rows[0];
        if (!lista) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Lista não encontrada' }); }
        if (!podeAdministrarMateriaisSetor(req, lista.setor)) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: 'Você pode excluir somente listas da sua subunidade' });
        }
        if (req.auth.superadmin && req.body?.confirmacao_nome !== lista.nome) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Digite exatamente o nome da lista para confirmar a exclusão definitiva.' });
        }
        const materiais = (await client.query(`SELECT m.id,m.status,
            EXISTS (SELECT 1 FROM materiais_cautelas c WHERE c.material_id=m.id) AS possui_historico
            FROM materiais m WHERE m.lista_id=$1 FOR UPDATE OF m`, [id])).rows;
        if (materiais.some(m => m.status === 'em_uso')) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'Há material entregue nesta lista. Registre a devolução antes de continuar.' });
        }
        const possuiHistorico = materiais.some(m => m.possui_historico);
        if (possuiHistorico && !req.auth.superadmin) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'Esta lista possui histórico de movimentações e não pode ser excluída. Use Editar para desativá-la e preservar os relatórios.' });
        }
        if (req.auth.superadmin && possuiHistorico) {
            await client.query(`DELETE FROM materiais_cautelas
                WHERE material_id IN (SELECT id FROM materiais WHERE lista_id=$1)`, [id]);
        }
        await client.query('DELETE FROM materiais WHERE lista_id=$1', [id]);
        await client.query('DELETE FROM materiais_listas WHERE id=$1', [id]);
        await client.query('COMMIT');
        res.json({ success: true, historico_excluido: Boolean(req.auth.superadmin && possuiHistorico) });
    } catch (e) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        erro(res, e);
    } finally { if (client) client.release(); }
});

app.get('/api/materiais/itens', protegerMateriais, async (req, res) => {
    const listaId = inteiro(req.query.lista_id, 1);
    if (!listaId) return res.status(400).json({ error: 'Selecione uma lista válida' });
    try {
        const params = [listaId];
        let escopo = '';
        if (req.auth.role === 'oper') { params.push(setoresMateriaisPermitidos(req)); escopo = 'AND l.setor=ANY($2::text[])'; }
        const rows = (await pool.query(`SELECT m.id,m.lista_id,m.nome,m.numero,m.status,m.ativo,m.observacoes,
            l.nome AS lista_nome,l.setor,l.ativo AS lista_ativa,
            c.id AS cautela_id,c.responsavel_nome,c.responsavel_re,c.observacao_entrega,c.entregue_em,
            TO_CHAR(c.entregue_em AT TIME ZONE 'America/Sao_Paulo','DD/MM/YYYY HH24:MI') AS entregue_em_texto
            FROM materiais m
            JOIN materiais_listas l ON l.id=m.lista_id
            LEFT JOIN LATERAL (
                SELECT id,responsavel_nome,responsavel_re,observacao_entrega,entregue_em
                FROM materiais_cautelas WHERE material_id=m.id AND devolvido_em IS NULL
                ORDER BY entregue_em DESC,id DESC LIMIT 1
            ) c ON TRUE
            WHERE m.lista_id=$1 ${escopo}
            ORDER BY m.ativo DESC,m.nome,COALESCE(m.numero,''),m.id`, params)).rows;
        res.json(rows.map(m => ({
            ...m,
            pode_administrar: podeAdministrarMateriaisSetor(req, m.setor),
            pode_operar: podeOperarMateriaisSetor(req, m.setor)
        })));
    } catch (e) { erro(res, e); }
});

app.post('/api/materiais/itens', protegerAdmin, async (req, res) => {
    const listaId = inteiro(req.body?.lista_id, 1), nome = texto(req.body?.nome, 120);
    const numero = textoOpcional(req.body?.numero, 80), observacoes = textoOpcional(req.body?.observacoes, 1000);
    const status = req.body?.status === 'manutencao' ? 'manutencao' : 'disponivel';
    if (!listaId || !nome || numero === null || observacoes === null) return res.status(400).json({ error: 'Dados do material inválidos' });
    try {
        const lista = (await pool.query('SELECT id,setor,ativo FROM materiais_listas WHERE id=$1', [listaId])).rows[0];
        if (!lista) return res.status(404).json({ error: 'Lista não encontrada' });
        if (!podeAdministrarMateriaisSetor(req, lista.setor)) return res.status(403).json({ error: 'Você pode cadastrar materiais somente na sua subunidade' });
        if (!lista.ativo) return res.status(409).json({ error: 'Ative a lista antes de cadastrar materiais' });
        const row = (await pool.query(`INSERT INTO materiais (lista_id,nome,numero,status,observacoes,criado_por)
            VALUES ($1,$2,NULLIF($3,''),$4,$5,$6) RETURNING id`,
            [listaId, nome, numero, status, observacoes, autorMaterial(req)])).rows[0];
        res.status(201).json(row);
    } catch (e) {
        if (e?.code === '23505') return res.status(409).json({ error: 'Este número já está cadastrado nesta lista' });
        erro(res, e);
    }
});

app.put('/api/materiais/itens/:id', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1), nome = texto(req.body?.nome, 120);
    const listaId = inteiro(req.body?.lista_id, 1);
    const numero = textoOpcional(req.body?.numero, 80), observacoes = textoOpcional(req.body?.observacoes, 1000);
    const status = req.body?.status, ativo = req.body?.ativo;
    if (!id || !listaId || !nome || numero === null || observacoes === null || !['disponivel','manutencao','em_uso'].includes(status) || typeof ativo !== 'boolean')
        return res.status(400).json({ error: 'Dados do material inválidos' });
    let client;
    try {
        client = await pool.connect(); await client.query('BEGIN');
        const referencia = (await client.query('SELECT lista_id FROM materiais WHERE id=$1', [id])).rows[0];
        if (!referencia) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Material não encontrado' }); }
        const listasBloqueadas = (await client.query(`SELECT id,setor,ativo FROM materiais_listas
            WHERE id=ANY($1::bigint[]) ORDER BY id FOR UPDATE`, [[Number(referencia.lista_id), listaId]])).rows;
        const atual = (await client.query(`SELECT m.id,m.lista_id,m.status,m.ativo,l.setor
            FROM materiais m JOIN materiais_listas l ON l.id=m.lista_id WHERE m.id=$1 FOR UPDATE OF m`, [id])).rows[0];
        if (!atual) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Material não encontrado' }); }
        if (Number(atual.lista_id) !== Number(referencia.lista_id)) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'O material foi movido por outro usuário. Atualize a tela e tente novamente.' }); }
        if (!podeAdministrarMateriaisSetor(req, atual.setor)) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Você pode administrar somente materiais da sua subunidade' }); }
        if (atual.status === 'em_uso' && (status !== 'em_uso' || !ativo)) {
            await client.query('ROLLBACK'); return res.status(409).json({ error: 'Registre a devolução antes de alterar a situação ou desativar o material' });
        }
        if (atual.status === 'em_uso' && Number(atual.lista_id) !== listaId) {
            await client.query('ROLLBACK'); return res.status(409).json({ error: 'Registre a devolução antes de mover o material para outra lista' });
        }
        const destino = listasBloqueadas.find(l => Number(l.id) === listaId);
        if (!destino) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Lista de destino não encontrada' }); }
        if (!podeAdministrarMateriaisSetor(req, destino.setor)) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Você não pode mover materiais para esta lista' }); }
        if (!destino.ativo) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Ative a lista de destino antes de mover o material' }); }
        await client.query(`UPDATE materiais SET lista_id=$1,nome=$2,numero=NULLIF($3,''),status=$4,ativo=$5,
            observacoes=$6,atualizado_em=CURRENT_TIMESTAMP WHERE id=$7`, [listaId, nome, numero, status, ativo, observacoes, id]);
        await client.query('COMMIT'); res.json({ success: true });
    } catch (e) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        if (e?.code === '23505') return res.status(409).json({ error: 'Este número já está cadastrado nesta lista' });
        erro(res, e);
    } finally { if (client) client.release(); }
});

app.delete('/api/materiais/itens/:id', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1);
    if (!id) return res.status(400).json({ error: 'Material inválido' });
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        const material = (await client.query(`SELECT m.id,m.nome,m.numero,m.status,l.setor
            FROM materiais m JOIN materiais_listas l ON l.id=m.lista_id
            WHERE m.id=$1 FOR UPDATE OF m`, [id])).rows[0];
        if (!material) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Material não encontrado' }); }
        if (!podeAdministrarMateriaisSetor(req, material.setor)) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: 'Você pode excluir somente materiais da sua subunidade' });
        }
        if (material.status === 'em_uso') {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'Este material está entregue. Registre a devolução antes de excluí-lo.' });
        }
        const identificacao = `${material.nome}${material.numero ? ` Nº ${material.numero}` : ''}`;
        const possuiHistorico = Boolean((await client.query('SELECT 1 FROM materiais_cautelas WHERE material_id=$1 LIMIT 1', [id])).rowCount);
        if (possuiHistorico && !req.auth.superadmin) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'Este material possui histórico e não pode ser excluído. Desative-o para preservar os relatórios.' });
        }
        if (req.auth.superadmin && req.body?.confirmacao_material !== identificacao) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Digite exatamente a identificação do material para confirmar a exclusão definitiva.' });
        }
        if (req.auth.superadmin && possuiHistorico) await client.query('DELETE FROM materiais_cautelas WHERE material_id=$1', [id]);
        await client.query('DELETE FROM materiais WHERE id=$1', [id]);
        await client.query('COMMIT');
        res.json({ success: true, historico_excluido: Boolean(req.auth.superadmin && possuiHistorico) });
    } catch (e) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        erro(res, e);
    } finally { if (client) client.release(); }
});

app.get('/api/materiais/responsaveis', protegerMateriais, async (req, res) => {
    try {
        const rows = (await pool.query(`SELECT id,nome,re,setor FROM usuarios
            WHERE re IS NOT NULL ORDER BY nome,re`)).rows;
        res.json(rows);
    } catch (e) { erro(res, e); }
});

app.get('/api/materiais/viaturas', protegerMateriais, async (req, res) => {
    try {
        const rows = (await pool.query(`SELECT id,prefixo,placa,modelo,setor,km,km_revisao,status,ultima_troca_oleo_em
            FROM viaturas ORDER BY setor,prefixo,placa`)).rows;
        res.json(rows.map(v => ({
            id: v.id,
            prefixo: v.prefixo,
            placa: v.placa,
            modelo: v.modelo,
            setor: v.setor,
            status: v.status === 'Baixada'
                ? 'Baixada'
                : atingiuTrocaOleo(v.km, v.km_revisao, v.modelo, v.prefixo, v.ultima_troca_oleo_em)
                    ? 'Troca de Óleo'
                    : 'Operante'
        })));
    } catch (e) { erro(res, e); }
});

app.get('/api/materiais/cautelas-abertas', protegerMateriais, async (req, res) => {
    const responsavelId = inteiro(req.query.responsavel_id, 1);
    if (!responsavelId) return res.status(400).json({ error: 'Selecione um policial válido' });
    try {
        const params = [responsavelId];
        let escopo = '';
        if (!req.auth.superadmin) { params.push(setoresMateriaisPermitidos(req)); escopo = 'AND c.setor=ANY($2::text[])'; }
        const rows = (await pool.query(`SELECT c.id AS cautela_id,c.material_id,c.setor,c.lista_nome,
            c.material_nome,c.material_numero,c.responsavel_nome,c.responsavel_re,c.observacao_entrega,
            c.viatura_prefixo,c.viatura_placa,c.viatura_modelo,
            TO_CHAR(c.entregue_em AT TIME ZONE 'America/Sao_Paulo','DD/MM/YYYY HH24:MI') AS entrega
            FROM materiais_cautelas c JOIN materiais m ON m.id=c.material_id
            WHERE c.responsavel_id=$1 AND c.devolvido_em IS NULL ${escopo}
            ORDER BY c.setor,c.lista_nome,c.material_nome,c.material_numero,c.id`, params)).rows;
        res.json(rows);
    } catch (e) { erro(res, e); }
});

app.post('/api/materiais/devolver-lote', protegerMateriais, async (req, res) => {
    const recebidos = Array.isArray(req.body?.cautela_ids) ? req.body.cautela_ids : [];
    const ids = [...new Set(recebidos.map(id => inteiro(id, 1)))];
    const observacao = textoOpcional(req.body?.observacao, 1000);
    if (!ids.length || ids.some(id => !id) || ids.length > 100 || ids.length !== recebidos.length || observacao === null)
        return res.status(400).json({ error: 'Selecione de 1 a 100 materiais válidos para devolução' });
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        const cautelas = (await client.query(`SELECT c.id,c.material_id,c.setor,c.material_nome,c.material_numero,m.status
            FROM materiais_cautelas c JOIN materiais m ON m.id=c.material_id
            WHERE c.id=ANY($1::bigint[]) AND c.devolvido_em IS NULL
            ORDER BY c.id FOR UPDATE OF c,m`, [ids])).rows;
        if (cautelas.length !== ids.length) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'Um ou mais materiais já foram devolvidos. Nenhuma devolução foi registrada.' });
        }
        const semPermissao = cautelas.find(c => !podeOperarMateriaisSetor(req, c.setor));
        if (semPermissao) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: `Sem permissão para receber o material ${semPermissao.material_nome}.` });
        }
        const inconsistente = cautelas.find(c => c.status !== 'em_uso');
        if (inconsistente) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'Um dos materiais não está marcado como em uso. Nenhuma devolução foi registrada.' });
        }
        await client.query(`UPDATE materiais_cautelas SET devolvido_em=CURRENT_TIMESTAMP,devolvido_por=$1,
            devolvido_por_re=$2,observacao_devolucao=$3 WHERE id=ANY($4::bigint[]) AND devolvido_em IS NULL`,
            [autorMaterial(req),reAutorMaterial(req),observacao,ids]);
        const materialIds = cautelas.map(c => c.material_id);
        await client.query("UPDATE materiais SET status='disponivel',atualizado_em=CURRENT_TIMESTAMP WHERE id=ANY($1::bigint[])", [materialIds]);
        await client.query('COMMIT');
        res.json({ success: true, quantidade: cautelas.length });
    } catch (e) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        erro(res, e);
    } finally { if (client) client.release(); }
});

app.post('/api/materiais/entregar-lote', protegerMateriais, async (req, res) => {
    const recebidos = Array.isArray(req.body?.material_ids) ? req.body.material_ids : [];
    const ids = [...new Set(recebidos.map(id => inteiro(id, 1)))];
    const responsavelId = inteiro(req.body?.responsavel_id, 1);
    const viaturaInformada = req.body?.viatura_id;
    const viaturaId = viaturaInformada === undefined || viaturaInformada === null || viaturaInformada === '' ? null : inteiro(viaturaInformada, 1);
    const observacao = textoOpcional(req.body?.observacao, 1000);
    if (!ids.length || ids.some(id => !id) || ids.length > 100 || ids.length !== recebidos.length || !responsavelId || (viaturaInformada !== undefined && viaturaInformada !== null && viaturaInformada !== '' && !viaturaId) || observacao === null)
        return res.status(400).json({ error: 'Selecione de 1 a 100 materiais válidos e o policial responsável' });
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        const grupoEntrega = crypto.randomUUID();
        const materiais = (await client.query(`SELECT m.id,m.nome,m.numero,m.status,m.ativo,
            l.nome AS lista_nome,l.setor,l.ativo AS lista_ativa
            FROM materiais m JOIN materiais_listas l ON l.id=m.lista_id
            WHERE m.id=ANY($1::bigint[]) ORDER BY m.id FOR UPDATE OF m`, [ids])).rows;
        if (materiais.length !== ids.length) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Um ou mais materiais selecionados não foram encontrados. Atualize a tela e tente novamente.' });
        }
        const semPermissao = materiais.find(m => !podeOperarMateriaisSetor(req, m.setor));
        if (semPermissao) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: `Sem permissão para pagar o material ${semPermissao.nome}.` });
        }
        const indisponivel = materiais.find(m => !m.ativo || !m.lista_ativa || m.status !== 'disponivel');
        if (indisponivel) {
            await client.query('ROLLBACK');
            const identificacao = `${indisponivel.nome}${indisponivel.numero ? ` Nº ${indisponivel.numero}` : ''}`;
            return res.status(409).json({ error: `${identificacao} não está mais disponível. Nenhum material foi entregue.` });
        }
        const responsavel = (await client.query('SELECT id,nome,re,setor FROM usuarios WHERE id=$1 AND re IS NOT NULL', [responsavelId])).rows[0];
        if (!responsavel) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Policial responsável não encontrado' });
        }
        const viatura = viaturaId ? (await client.query(`SELECT id,prefixo,placa,modelo
            FROM viaturas WHERE id=$1 FOR KEY SHARE`, [viaturaId])).rows[0] : null;
        if (viaturaId && !viatura) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Viatura selecionada não foi encontrada' });
        }
        for (const material of materiais) {
            await client.query(`INSERT INTO materiais_cautelas
                (material_id,responsavel_id,responsavel_nome,responsavel_re,responsavel_setor,viatura_id,viatura_prefixo,viatura_placa,viatura_modelo,lista_nome,material_nome,material_numero,setor,entregue_por,entregue_por_re,observacao_entrega,grupo_entrega)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
                [material.id,responsavel.id,responsavel.nome,responsavel.re,responsavel.setor,viatura?.id||null,viatura?.prefixo||null,viatura?.placa||null,viatura?.modelo||null,material.lista_nome,material.nome,material.numero,material.setor,autorMaterial(req),reAutorMaterial(req),observacao,grupoEntrega]);
        }
        await client.query("UPDATE materiais SET status='em_uso',atualizado_em=CURRENT_TIMESTAMP WHERE id=ANY($1::bigint[])", [ids]);
        await client.query('COMMIT');
        res.json({ success: true, quantidade: materiais.length });
    } catch (e) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        if (e?.code === '23505') return res.status(409).json({ error: 'Um dos materiais já possui uma cautela aberta. Nenhum material foi entregue.' });
        erro(res, e);
    } finally { if (client) client.release(); }
});

app.post('/api/materiais/itens/:id/entregar', protegerMateriais, async (req, res) => {
    const id = inteiro(req.params.id, 1), responsavelId = inteiro(req.body?.responsavel_id, 1);
    const viaturaInformada = req.body?.viatura_id;
    const viaturaId = viaturaInformada === undefined || viaturaInformada === null || viaturaInformada === '' ? null : inteiro(viaturaInformada, 1);
    const observacao = textoOpcional(req.body?.observacao, 1000);
    if (!id || !responsavelId || (viaturaInformada !== undefined && viaturaInformada !== null && viaturaInformada !== '' && !viaturaId) || observacao === null) return res.status(400).json({ error: 'Informe o material e o policial responsável' });
    let client;
    try {
        client = await pool.connect(); await client.query('BEGIN');
        const material = (await client.query(`SELECT m.id,m.nome,m.numero,m.status,m.ativo,l.nome AS lista_nome,l.setor,l.ativo AS lista_ativa
            FROM materiais m JOIN materiais_listas l ON l.id=m.lista_id WHERE m.id=$1 FOR UPDATE OF m`, [id])).rows[0];
        if (!material) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Material não encontrado' }); }
        if (!podeOperarMateriaisSetor(req, material.setor)) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Você pode pagar somente materiais da sua subunidade' }); }
        if (!material.ativo || !material.lista_ativa) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Este material ou sua lista está desativado' }); }
        if (material.status !== 'disponivel') { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Este material não está disponível para entrega' }); }
        const responsavel = (await client.query('SELECT id,nome,re,setor FROM usuarios WHERE id=$1 AND re IS NOT NULL', [responsavelId])).rows[0];
        if (!responsavel) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Policial responsável não encontrado' }); }
        const viatura = viaturaId ? (await client.query(`SELECT id,prefixo,placa,modelo
            FROM viaturas WHERE id=$1 FOR KEY SHARE`, [viaturaId])).rows[0] : null;
        if (viaturaId && !viatura) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Viatura selecionada não foi encontrada' }); }
        const grupoEntrega = crypto.randomUUID();
        await client.query(`INSERT INTO materiais_cautelas
            (material_id,responsavel_id,responsavel_nome,responsavel_re,responsavel_setor,viatura_id,viatura_prefixo,viatura_placa,viatura_modelo,lista_nome,material_nome,material_numero,setor,entregue_por,entregue_por_re,observacao_entrega,grupo_entrega)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
            [id,responsavel.id,responsavel.nome,responsavel.re,responsavel.setor,viatura?.id||null,viatura?.prefixo||null,viatura?.placa||null,viatura?.modelo||null,material.lista_nome,material.nome,material.numero,material.setor,autorMaterial(req),reAutorMaterial(req),observacao,grupoEntrega]);
        await client.query("UPDATE materiais SET status='em_uso',atualizado_em=CURRENT_TIMESTAMP WHERE id=$1", [id]);
        await client.query('COMMIT'); res.json({ success: true });
    } catch (e) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        if (e?.code === '23505') return res.status(409).json({ error: 'Este material já possui uma cautela aberta' });
        erro(res, e);
    } finally { if (client) client.release(); }
});

app.post('/api/materiais/itens/:id/devolver', protegerMateriais, async (req, res) => {
    const id = inteiro(req.params.id, 1), observacao = textoOpcional(req.body?.observacao, 1000);
    if (!id || observacao === null) return res.status(400).json({ error: 'Dados da devolução inválidos' });
    let client;
    try {
        client = await pool.connect(); await client.query('BEGIN');
        const material = (await client.query(`SELECT m.id,m.status,l.setor
            FROM materiais m JOIN materiais_listas l ON l.id=m.lista_id WHERE m.id=$1 FOR UPDATE OF m`, [id])).rows[0];
        if (!material) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Material não encontrado' }); }
        if (!podeOperarMateriaisSetor(req, material.setor)) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Você pode receber somente materiais da sua subunidade' }); }
        const cautela = (await client.query(`SELECT id FROM materiais_cautelas
            WHERE material_id=$1 AND devolvido_em IS NULL ORDER BY entregue_em DESC,id DESC LIMIT 1 FOR UPDATE`, [id])).rows[0];
        if (!cautela || material.status !== 'em_uso') { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Este material não possui uma cautela aberta' }); }
        await client.query(`UPDATE materiais_cautelas SET devolvido_em=CURRENT_TIMESTAMP,devolvido_por=$1,
            devolvido_por_re=$2,observacao_devolucao=$3 WHERE id=$4`, [autorMaterial(req),reAutorMaterial(req),observacao,cautela.id]);
        await client.query("UPDATE materiais SET status='disponivel',atualizado_em=CURRENT_TIMESTAMP WHERE id=$1", [id]);
        await client.query('COMMIT'); res.json({ success: true });
    } catch (e) { if (client) await client.query('ROLLBACK').catch(() => {}); erro(res, e); }
    finally { if (client) client.release(); }
});

app.get('/api/materiais/movimentacoes', protegerMateriais, async (req, res) => {
    const limite = Math.min(inteiro(req.query.limite, 1) || 20, 100);
    try {
        const params = [];
        let where = '';
        if (req.auth.role === 'oper') { where = 'WHERE c.setor=ANY($1::text[])'; params.push(setoresMateriaisPermitidos(req)); }
        params.push(limite);
        const rows = (await pool.query(`WITH escopo AS (
                SELECT c.*,COALESCE(c.grupo_entrega::text,'individual:'||c.id::text) AS grupo_visual
                FROM materiais_cautelas c ${where}
            ), ultimos_grupos AS (
                SELECT grupo_visual,MAX(entregue_em) AS data_grupo,MAX(id) AS ultimo_id
                FROM escopo GROUP BY grupo_visual
                ORDER BY data_grupo DESC,ultimo_id DESC LIMIT $${params.length}
            )
            SELECT e.*,
                TO_CHAR(e.entregue_em AT TIME ZONE 'America/Sao_Paulo','DD/MM/YYYY HH24:MI') AS entrega,
                TO_CHAR(e.devolvido_em AT TIME ZONE 'America/Sao_Paulo','DD/MM/YYYY HH24:MI') AS devolucao
            FROM escopo e JOIN ultimos_grupos g USING(grupo_visual)
            ORDER BY g.data_grupo DESC,g.ultimo_id DESC,e.id`, params)).rows;
        res.json(rows);
    } catch (e) { erro(res, e); }
});

function filtrosRelatorioMateriais(req, params, alias = 'c') {
    const filtros = [];
    const setor = texto(req.query.setor, 20), listaId = req.query.lista_id ? inteiro(req.query.lista_id, 1) : null;
    const materialId = req.query.material_id ? inteiro(req.query.material_id, 1) : null;
    const situacao = typeof req.query.situacao === 'string' ? req.query.situacao : '';
    if (req.auth.role === 'oper') {
        const permitidos = setoresMateriaisPermitidos(req);
        const escopo = setor && setor !== 'Todos' && permitidos.includes(setor) ? [setor] : permitidos;
        filtros.push(`${alias}.setor=ANY($${params.length + 1}::text[])`); params.push(escopo);
    }
    else if (setor && setor !== 'Todos') { filtros.push(`${alias}.setor=$${params.length + 1}`); params.push(setor); }
    if (listaId) { filtros.push(`m.lista_id=$${params.length + 1}`); params.push(listaId); }
    if (materialId) { filtros.push(`${alias}.material_id=$${params.length + 1}`); params.push(materialId); }
    if (situacao === 'aberta') filtros.push(`${alias}.devolvido_em IS NULL`);
    if (situacao === 'devolvida') filtros.push(`${alias}.devolvido_em IS NOT NULL`);
    return filtros;
}

const selecaoRelatorioMateriais = `SELECT c.id,c.setor,c.lista_nome,c.material_nome,c.material_numero,
    c.responsavel_nome,c.responsavel_re,c.responsavel_setor,c.entregue_por,c.observacao_entrega,
    c.viatura_prefixo,c.viatura_placa,c.viatura_modelo,c.devolvido_por,c.observacao_devolucao,c.devolvido_em,
    TO_CHAR(c.entregue_em AT TIME ZONE 'America/Sao_Paulo','DD/MM/YY HH24:MI') AS entrega,
    TO_CHAR(c.devolvido_em AT TIME ZONE 'America/Sao_Paulo','DD/MM/YY HH24:MI') AS devolucao
    FROM materiais_cautelas c JOIN materiais m ON m.id=c.material_id`;

app.get('/api/materiais/relatorio-ultimo', protegerMateriais, async (req, res) => {
    try {
        const identificador = req.auth.role === 'admin' ? req.auth.adminId : `oper:${req.auth.operadorId}`;
        const chave = `ultimo_relatorio_materiais:${identificador}`;
        const salvo = (await pool.query('SELECT valor FROM configuracoes WHERE chave=$1', [chave])).rows[0]?.valor;
        const ultimo = salvo ? new Date(salvo) : new Date(0), agora = new Date();
        const hojeBR = agora.toLocaleDateString('pt-BR', { timeZone:'America/Sao_Paulo' });
        const ultimoBR = ultimo.toLocaleDateString('pt-BR', { timeZone:'America/Sao_Paulo' });
        const params = [];
        const filtros = hojeBR === ultimoBR
            ? [`(c.entregue_em AT TIME ZONE 'America/Sao_Paulo')::date=(CURRENT_TIMESTAMP AT TIME ZONE 'America/Sao_Paulo')::date`]
            : [`c.entregue_em>$1`];
        if (hojeBR !== ultimoBR) params.push(ultimo);
        filtros.push(...filtrosRelatorioMateriais(req, params));
        const rows = (await pool.query(`${selecaoRelatorioMateriais} WHERE ${filtros.join(' AND ')} ORDER BY c.entregue_em DESC,c.id DESC`, params)).rows;
        await pool.query(`INSERT INTO configuracoes(chave,valor) VALUES($1,CURRENT_TIMESTAMP::text)
            ON CONFLICT(chave) DO UPDATE SET valor=EXCLUDED.valor`, [chave]);
        res.json(rows);
    } catch (e) { erro(res, e); }
});

app.get('/api/materiais/relatorio-periodo', protegerMateriais, async (req, res) => {
    const inicio = req.query.inicio, fim = req.query.fim;
    if (![inicio,fim].every(d => typeof d === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(d)) || inicio > fim)
        return res.status(400).json({ error: 'Período inválido' });
    try {
        const params = [inicio,fim];
        const filtros = [`(c.entregue_em AT TIME ZONE 'America/Sao_Paulo')::date BETWEEN $1::date AND $2::date`];
        filtros.push(...filtrosRelatorioMateriais(req, params));
        const rows = (await pool.query(`${selecaoRelatorioMateriais} WHERE ${filtros.join(' AND ')} ORDER BY c.entregue_em DESC,c.id DESC`, params)).rows;
        res.json(rows);
    } catch (e) { erro(res, e); }
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
