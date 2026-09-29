const express = require('express');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const pool = require('./database');
const app = express();

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
const PWD_ADMIN = process.env.PWD_ADMIN;
const PWD_OPER = process.env.PWD_OPER;
if (!PWD_ADMIN || !PWD_OPER) throw new Error('Configure PWD_ADMIN e PWD_OPER.');
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
        next();
    };
}
const protegerAdmin = proteger('admin');
const protegerOperacional = proteger('admin', 'oper');
app.use((req, res, next) => {
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
    const origin = req.get('origin');
    let invalid = req.get('sec-fetch-site') === 'cross-site';
    if (origin) { try { invalid ||= new URL(origin).host !== req.get('host'); } catch { invalid = true; } }
    if (invalid) return res.status(403).json({ error: 'Origem não autorizada' });
    next();
});
function samePassword(given, expected) {
    const a = crypto.createHash('sha256').update(given).digest();
    const b = crypto.createHash('sha256').update(expected).digest();
    return crypto.timingSafeEqual(a, b);
}
app.post('/api/login', (req, res) => {
    const { senha, tipo } = req.body || {};
    const now = Date.now(), key = req.ip;
    const a = attempts.get(key) || { count: 0, until: now + 15 * 60 * 1000 };
    if (now > a.until) { a.count = 0; a.until = now + 15 * 60 * 1000; }
    if (a.count >= 10) return res.status(429).json({ error: 'Muitas tentativas. Aguarde 15 minutos.' });
    const valid = typeof senha === 'string' && senha.length <= 256 &&
        ((tipo === 'admin' && samePassword(senha, PWD_ADMIN)) ||
         (tipo === 'oper' && samePassword(senha, PWD_OPER)));
    if (!valid) { a.count++; attempts.set(key, a); return res.status(401).json({ error: 'Senha incorreta' }); }
    attempts.delete(key);
    if (req.cookies[COOKIE]) sessions.delete(req.cookies[COOKIE]);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { role: tipo, expires: now + DURATION });
    res.cookie(COOKIE, token, cookieOptions(req));
    res.json({ success: true, redirect: tipo === 'admin' ? 'index.html' : 'operacional.html' });
});
app.post('/api/logout', (req, res) => {
    if (req.cookies[COOKIE]) sessions.delete(req.cookies[COOKIE]);
    res.clearCookie(COOKIE, { path: '/', sameSite: 'strict', secure: req.secure });
    res.json({ success: true });
});
app.get('/api/session', (req, res) => {
    const s = session(req);
    if (!s) return res.status(401).json({ error: 'Acesso não autenticado' });
    res.json({ role: s.role });
});
// Lista explícita: código, banco, documentos e configuração não são arquivos públicos.
app.get(['/', '/login.html'], (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/index.html', protegerAdmin, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/usuarios.html', protegerAdmin, (req, res) => res.sendFile(path.join(__dirname, 'usuarios.html')));
app.get('/operacional.html', protegerOperacional, (req, res) => res.sendFile(path.join(__dirname, 'operacional.html')));
app.get(['/BRASAO%201BPTRAN.png', '/BRASAO 1BPTRAN.png'], (req, res) => res.sendFile(path.join(__dirname, 'BRASAO 1BPTRAN.png')));
const inteiro = (v, min = 0) => { if (typeof v !== 'number' && (typeof v !== 'string' || !/^\d+$/.test(v))) return null; const n = Number(v); return Number.isSafeInteger(n) && n >= min ? n : null; };
const texto = (v, max = 150) => typeof v === 'string' && v.trim() && v.length <= max ? v.trim() : null;
const erro = (res, e) => { console.error(e); res.status(500).json({ error: 'Erro interno' }); };
// ==========================================
// ROTA DO RELATÓRIO: ÚLTIMO ACESSO (CORREÇÃO FUSO)
// ==========================================
app.get('/api/relatorio-ultimo', protegerAdmin, async (req, res) => {
    try {
        const { setor } = req.query;

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
                   TO_CHAR(data_hora AT TIME ZONE 'America/Sao_Paulo', 'DD/MM/YY HH24:MI') as hora
                   FROM historico
                   WHERE (data_hora AT TIME ZONE 'America/Sao_Paulo')::date = (CURRENT_TIMESTAMP AT TIME ZONE 'America/Sao_Paulo')::date`;
            params = [];
        } else {
            // CENÁRIO B: Dia diferente.
            // AJUSTE: DD/MM/YY HH24:MI
            sql = `SELECT *,
                   TO_CHAR(data_hora AT TIME ZONE 'America/Sao_Paulo', 'DD/MM/YY HH24:MI') as hora
                   FROM historico
                   WHERE data_hora > $1`;
            params = [ultimoAcesso];
        }

        // Filtro de Setor Integrado
        if (setor && setor !== 'Todos') {
            sql += ` AND setor = $${params.length + 1}`;
            params.push(setor);
        }

        const result = await pool.query(sql + ` ORDER BY data_hora DESC`, params);

        // Atualiza a memória de acesso para o próximo clique (Agora)
        await pool.query("UPDATE configuracoes SET valor = CURRENT_TIMESTAMP WHERE chave = 'ultimo_acesso_relatorio'");

        res.json(result.rows);
    } catch (e) { erro(res, e); }
});

app.get('/api/relatorio-periodo', protegerAdmin, async (req, res) => {
    try {
        const { inicio, fim, setor } = req.query;
        if (![inicio, fim].every(d => typeof d === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(d)) || inicio > fim) return res.status(400).json({ error: 'Período inválido' });
        let sql = `SELECT *, TO_CHAR(data_hora AT TIME ZONE 'America/Sao_Paulo', 'DD/MM/YY HH24:MI') as hora FROM historico WHERE (data_hora AT TIME ZONE 'America/Sao_Paulo')::date >= $1 AND (data_hora AT TIME ZONE 'America/Sao_Paulo')::date <= $2`;
        let params = [inicio, fim];
        if (setor && setor !== 'Todos') { sql += ` AND setor = $3`; params.push(setor); }
        const result = await pool.query(sql + ` ORDER BY data_hora DESC`, params);
        res.json(result.rows);
    } catch (e) { erro(res, e); }
});

app.get('/api/viaturas', protegerOperacional, async (req, res) => {
    try { res.json((await pool.query('SELECT * FROM viaturas ORDER BY setor ASC, prefixo ASC')).rows); }
    catch (e) { erro(res, e); }
});
// O operacional registra somente KM, responsável e baixa. A revisão e o setor são imutáveis aqui.
app.put('/api/operacional/viaturas/:id', protegerOperacional, async (req, res) => {
    const id = inteiro(req.params.id, 1), km = inteiro(req.body.km);
    const usuario = texto(req.body.ultimo_usuario), baixa = req.body.baixa;
    const motivo = baixa ? texto(req.body.motivo, 500) : '';
    if (!id || km === null || !usuario || typeof baixa !== 'boolean' || (baixa && !motivo))
        return res.status(400).json({ error: 'Dados operacionais inválidos' });
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        const old = (await client.query('SELECT prefixo, km, setor, km_revisao, status, motivo FROM viaturas WHERE id=$1 FOR UPDATE', [id])).rows[0];
        if (!old) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Viatura não encontrada' }); }
        if (km < old.km) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'KM inferior ao atual' }); }
        const status = baixa || old.status === 'Baixada' ? 'Baixada' : km >= old.km_revisao ? 'Troca de Óleo' : 'Operante';
        const finalMotivo = baixa ? motivo : status === 'Baixada' ? old.motivo : '';
        await client.query('UPDATE viaturas SET km=$1, status=$2, ultimo_usuario=$3, motivo=$4 WHERE id=$5', [km, status, usuario, finalMotivo, id]);
        await client.query('INSERT INTO historico (prefixo, km_anterior, km_novo, status, motivo, usuario, setor) VALUES ($1,$2,$3,$4,$5,$6,$7)', [old.prefixo, old.km, km, status, finalMotivo, usuario, old.setor]);
        await client.query('COMMIT');
        res.json({ success: true });
    } catch (e) { if (client) await client.query('ROLLBACK').catch(() => {}); erro(res, e); }
    finally { if (client) client.release(); }
});
app.put('/api/viaturas/:id', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1), km = inteiro(req.body.km), revisao = inteiro(req.body.km_revisao);
    const setor = texto(req.body.setor, 50), usuario = texto(req.body.ultimo_usuario) || 'Gestor';
    if (!id || km === null || revisao === null || !setor || !['Operante', 'Troca de Óleo', 'Baixada'].includes(req.body.status))
        return res.status(400).json({ error: 'Dados inválidos' });
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        const old = (await client.query('SELECT prefixo, km FROM viaturas WHERE id=$1 FOR UPDATE', [id])).rows[0];
        if (!old) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Viatura não encontrada' }); }
        const status = req.body.status === 'Baixada' ? 'Baixada' : km >= revisao ? 'Troca de Óleo' : 'Operante';
        const motivo = status === 'Baixada' && typeof req.body.motivo === 'string' ? req.body.motivo.slice(0, 500) : '';
        await client.query('UPDATE viaturas SET km=$1, km_revisao=$2, status=$3, ultimo_usuario=$4, motivo=$5, setor=$6 WHERE id=$7', [km, revisao, status, usuario, motivo, setor, id]);
        await client.query('INSERT INTO historico (prefixo, km_anterior, km_novo, status, motivo, usuario, setor) VALUES ($1,$2,$3,$4,$5,$6,$7)', [old.prefixo, old.km, km, status, motivo, usuario, setor]);
        await client.query('COMMIT');
        res.json({ success: true });
    } catch (e) { if (client) await client.query('ROLLBACK').catch(() => {}); erro(res, e); }
    finally { if (client) client.release(); }
});
app.post('/api/viaturas', protegerAdmin, async (req, res) => {
    const { prefixo, placa, modelo, setor, status } = req.body;
    const km = inteiro(req.body.km), revisao = inteiro(req.body.km_revisao);
    if (![prefixo, placa, modelo, setor].every(v => texto(v)) || km === null || revisao === null || !['Operante', 'Troca de Óleo', 'Baixada'].includes(status))
        return res.status(400).json({ error: 'Dados inválidos' });
    try {
        const st = status === 'Baixada' ? 'Baixada' : km >= revisao ? 'Troca de Óleo' : 'Operante';
        await pool.query('INSERT INTO viaturas (prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario, motivo, setor) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [prefixo.trim(), placa.trim(), modelo.trim(), km, revisao, st, 'Sistema', '', setor.trim()]);
        res.json({ success: true });
    } catch (e) { erro(res, e); }
});
app.delete('/api/viaturas/:id', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1); if (!id) return res.status(400).json({ error: 'ID inválido' });
    try { await pool.query('DELETE FROM viaturas WHERE id=$1', [id]); res.json({ success: true }); }
    catch (e) { erro(res, e); }
});
app.get('/api/usuarios', protegerOperacional, async (req, res) => {
    try { res.json((await pool.query('SELECT * FROM usuarios ORDER BY nome ASC')).rows); }
    catch (e) { erro(res, e); }
});
app.post('/api/usuarios', protegerAdmin, async (req, res) => {
    const nome = texto(req.body.nome), cargo = typeof req.body.cargo === 'string' && req.body.cargo.length <= 150 ? req.body.cargo.trim() : null;
    if (!nome || cargo === null) return res.status(400).json({ error: 'Dados inválidos' });
    try { await pool.query('INSERT INTO usuarios (nome, cargo) VALUES ($1,$2)', [nome, cargo]); res.json({ success: true }); }
    catch (e) { erro(res, e); }
});
app.delete('/api/usuarios/:id', protegerAdmin, async (req, res) => {
    const id = inteiro(req.params.id, 1); if (!id) return res.status(400).json({ error: 'ID inválido' });
    try { await pool.query('DELETE FROM usuarios WHERE id=$1', [id]); res.json({ success: true }); }
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
