const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const pool = require('./database');
const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

const ADMIN_PASSWORD = "admin123";

const proteger = (req, res, next) => {
    if (req.cookies.auth === 'true') next();
    else if (req.path.startsWith('/api/')) res.status(401).json({ error: "Não autorizado" });
    else res.redirect('/login.html');
};

app.post('/api/login', (req, res) => {
    if (req.body.senha === ADMIN_PASSWORD) {
        res.cookie('auth', 'true', { httpOnly: true, maxAge: 24 * 60 * 60 * 1000, sameSite: 'lax' });
        res.json({ success: true });
    } else res.status(401).json({ error: "Senha incorreta" });
});

app.post('/api/logout', (req, res) => { res.clearCookie('auth'); res.json({ success: true }); });

function definirStatus(km, revisao, statusEnviado) {
    if (statusEnviado === 'Baixada') return 'Baixada';
    return (parseInt(km) >= parseInt(revisao)) ? 'Troca de Óleo' : 'Operante';
}

// --- RELATÓRIOS ---
app.get('/api/relatorio-ultimo', proteger, async (req, res) => {
    try {
        const { setor } = req.query;
        const config = await pool.query("SELECT valor FROM configuracoes WHERE chave = 'ultimo_acesso_relatorio'");
        const ultimoAcesso = new Date(config.rows[0].valor);
        const agora = new Date();
        const hojeBr = new Date(agora.toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));
        hojeBr.setHours(0,0,0,0);
        const ultimoBr = new Date(ultimoAcesso.toLocaleString("en-US", {timeZone: "America/Sao_Paulo"}));

        let sql = `SELECT *, TO_CHAR(data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'DD/MM HH24:MI') as hora FROM historico WHERE `;
        let params = [];

        if (ultimoBr < hojeBr) { sql += `data_hora > $1 `; params.push(ultimoAcesso); }
        else { sql += `data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo' >= DATE_TRUNC('day', NOW() AT TIME ZONE 'America/Sao_Paulo') `; }

        if (setor && setor !== 'Todos') {
            sql += `AND setor = $${params.length + 1} `;
            params.push(setor);
        }

        const result = await pool.query(sql + ` ORDER BY data_hora DESC`, params);
        await pool.query("UPDATE configuracoes SET valor = CURRENT_TIMESTAMP WHERE chave = 'ultimo_acesso_relatorio'");
        res.json(result.rows);
    } catch (e) { res.status(500).json(e); }
});

app.get('/api/relatorio-periodo', proteger, async (req, res) => {
    try {
        const { inicio, fim, setor } = req.query;
        let sql = `SELECT *, TO_CHAR(data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'DD/MM HH24:MI') as hora FROM historico WHERE data_hora::date >= $1 AND data_hora::date <= $2 `;
        let params = [inicio, fim];
        if (setor && setor !== 'Todos') {
            sql += `AND setor = $3 `;
            params.push(setor);
        }
        const result = await pool.query(sql + ` ORDER BY data_hora DESC`, params);
        res.json(result.rows);
    } catch (e) { res.status(500).json(e); }
});

// --- VIATURAS ---
app.get('/api/viaturas', async (req, res) => {
    const result = await pool.query("SELECT * FROM viaturas ORDER BY setor ASC, prefixo ASC");
    res.json(result.rows);
});

app.put('/api/viaturas/:id', async (req, res) => {
    try {
        let { km, km_revisao, status, ultimo_usuario, motivo, setor } = req.body;
        const vtrOld = await pool.query("SELECT prefixo, km, km_revisao, setor FROM viaturas WHERE id = $1", [req.params.id]);
        const d = vtrOld.rows[0];
        
        const kmAnt = d.km;
        const prefixo = d.prefixo;
        const kmRev = km_revisao || d.km_revisao;
        const setorVtr = setor || d.setor; // Garante que o setor não seja perdido

        const st = definirStatus(km, kmRev, status);
        const mot = (st === 'Baixada') ? (motivo || '') : '';
        
        // Atualiza a VTR
        await pool.query('UPDATE viaturas SET km=$1, km_revisao=$2, status=$3, ultimo_usuario=$4, motivo=$5, setor=$6 WHERE id=$7', [km, kmRev, st, ultimo_usuario, mot, setorVtr, req.params.id]);
        
        // GRAVA NO HISTÓRICO INCLUINDO O SETOR (Correção aqui)
        await pool.query('INSERT INTO historico (prefixo, km_anterior, km_novo, status, motivo, usuario, setor) VALUES ($1,$2,$3,$4,$5,$6,$7)', [prefixo, kmAnt, km, st, mot, ultimo_usuario, setorVtr]);
        
        res.json({ success: true });
    } catch (e) { res.status(500).json(e); }
});

app.post('/api/viaturas', proteger, async (req, res) => {
    try {
        let { prefixo, placa, modelo, km, km_revisao, status, setor } = req.body;
        const st = definirStatus(km, km_revisao, status);
        await pool.query('INSERT INTO viaturas (prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario, motivo, setor) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [prefixo, placa, modelo, km, km_revisao, st, 'Sistema', '', setor]);
        res.json({ success: true });
    } catch (e) { res.status(500).json(e); }
});

app.delete('/api/viaturas/:id', proteger, async (req, res) => { await pool.query('DELETE FROM viaturas WHERE id = $1', [req.params.id]); res.json({ success: true }); });

// --- USUÁRIOS ---
app.get('/api/usuarios', async (req, res) => {
    const result = await pool.query("SELECT * FROM usuarios ORDER BY nome ASC");
    res.json(result.rows);
});
app.post('/api/usuarios', proteger, async (req, res) => {
    await pool.query("INSERT INTO usuarios (nome, cargo) VALUES ($1, $2)", [req.body.nome, req.body.cargo]);
    res.json({ success: true });
});
app.delete('/api/usuarios/:id', proteger, async (req, res) => {
    await pool.query("DELETE FROM usuarios WHERE id = $1", [req.params.id]);
    res.json({ success: true });
});

app.get('/index.html', proteger, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/usuarios.html', proteger, (req, res) => res.sendFile(path.join(__dirname, 'usuarios.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/operacional.html', (req, res) => res.sendFile(path.join(__dirname, 'operacional.html')));
app.get('/', (req, res) => res.redirect('/operacional.html'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`GEOFROTA ON: Porta ${PORT}`));