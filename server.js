const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const pool = require('./database');
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

const PWD_ADMIN = "administrador1bptran";
const PWD_OPER = "1bptran";

// TRAVA RÍGIDA: Operador NÃO entra no Admin
const protegerAdmin = (req, res, next) => {
    if (req.cookies.auth_admin === 'true') {
        next();
    } else {
        res.status(401).json({ error: "Acesso restrito ao Gestor" });
    }
};

const protegerOperacional = (req, res, next) => {
    if (req.cookies.auth_oper === 'true' || req.cookies.auth_admin === 'true') {
        next();
    } else {
        res.status(401).json({ error: "Acesso negado" });
    }
};

app.post('/api/login', (req, res) => {
    const { senha, tipo } = req.body;
    if (tipo === 'admin' && senha === PWD_ADMIN) {
        res.cookie('auth_admin', 'true', { httpOnly: true, sameSite: 'lax' });
        return res.json({ success: true, redirect: 'index.html' });
    } 
    if (tipo === 'oper' && senha === PWD_OPER) {
        res.cookie('auth_oper', 'true', { httpOnly: true, sameSite: 'lax' });
        return res.json({ success: true, redirect: 'operacional.html' });
    }
    res.status(401).json({ error: "Senha incorreta" });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('auth_admin'); res.clearCookie('auth_oper');
    res.json({ success: true });
});

// APIs PROTEGIDAS
app.get('/api/relatorio-ultimo', protegerAdmin, async (req, res) => {
    try {
        const { setor } = req.query;
        const config = await pool.query("SELECT valor FROM configuracoes WHERE chave = 'ultimo_acesso_relatorio'");
        const ultimoAcesso = config.rows[0].valor;
        let sql = `SELECT *, TO_CHAR(data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'DD/MM HH24:MI') as hora FROM historico WHERE ((data_hora AT TIME ZONE 'America/Sao_Paulo')::date = (NOW() AT TIME ZONE 'America/Sao_Paulo')::date OR data_hora > $1::timestamp)`;
        let params = [ultimoAcesso];
        if (setor && setor !== 'Todos') { sql += ` AND setor = $2`; params.push(setor); }
        const result = await pool.query(sql + ` ORDER BY data_hora DESC`, params);
        await pool.query("UPDATE configuracoes SET valor = CURRENT_TIMESTAMP WHERE chave = 'ultimo_acesso_relatorio'");
        res.json(result.rows);
    } catch (e) { res.status(500).json(e); }
});

app.get('/api/relatorio-periodo', protegerAdmin, async (req, res) => {
    try {
        const { inicio, fim, setor } = req.query;
        // Correção de filtro de data para Postgres
        let sql = `SELECT *, TO_CHAR(data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'DD/MM HH24:MI') as hora FROM historico WHERE (data_hora AT TIME ZONE 'America/Sao_Paulo')::date >= $1 AND (data_hora AT TIME ZONE 'America/Sao_Paulo')::date <= $2`;
        let params = [inicio, fim];
        if (setor && setor !== 'Todos') { sql += ` AND setor = $3`; params.push(setor); }
        const result = await pool.query(sql + ` ORDER BY data_hora DESC`, params);
        res.json(result.rows);
    } catch (e) { res.status(500).json(e); }
});

app.get('/api/viaturas', protegerOperacional, async (req, res) => {
    const result = await pool.query("SELECT * FROM viaturas ORDER BY setor ASC, prefixo ASC");
    res.json(result.rows);
});

app.put('/api/viaturas/:id', protegerOperacional, async (req, res) => {
    try {
        let { km, status, ultimo_usuario, motivo } = req.body;
        const vtrCheck = await pool.query("SELECT prefixo, km, setor, km_revisao FROM viaturas WHERE id = $1", [req.params.id]);
        const v = vtrCheck.rows[0];
        const statusFinal = (status === 'Baixada') ? 'Baixada' : (parseInt(km) >= parseInt(v.km_revisao) ? 'Troca de Óleo' : 'Operante');
        await pool.query('UPDATE viaturas SET km=$1, status=$2, ultimo_usuario=$3, motivo=$4 WHERE id=$5', [km, statusFinal, ultimo_usuario, (statusFinal === 'Baixada' ? motivo : ''), req.params.id]);
        await pool.query('INSERT INTO historico (prefixo, km_anterior, km_novo, status, motivo, usuario, setor) VALUES ($1,$2,$3,$4,$5,$6,$7)', [v.prefixo, v.km, km, statusFinal, (statusFinal === 'Baixada' ? motivo : ''), ultimo_usuario, v.setor]);
        res.json({ success: true });
    } catch (e) { res.status(500).json(e); }
});

app.post('/api/viaturas', protegerAdmin, async (req, res) => {
    let { prefixo, placa, modelo, km, km_revisao, status, setor } = req.body;
    await pool.query('INSERT INTO viaturas (prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario, motivo, setor) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [prefixo, placa, modelo, km, km_revisao, status, 'Sistema', '', setor]);
    res.json({ success: true });
});

app.delete('/api/viaturas/:id', protegerAdmin, async (req, res) => { await pool.query('DELETE FROM viaturas WHERE id = $1', [req.params.id]); res.json({ success: true }); });
app.get('/api/usuarios', protegerOperacional, async (req, res) => { const result = await pool.query("SELECT * FROM usuarios ORDER BY nome ASC"); res.json(result.rows); });
app.post('/api/usuarios', protegerAdmin, async (req, res) => { await pool.query("INSERT INTO usuarios (nome, cargo) VALUES ($1, $2)", [req.body.nome, req.body.cargo]); res.json({ success: true }); });
app.delete('/api/usuarios/:id', protegerAdmin, async (req, res) => { await pool.query("DELETE FROM usuarios WHERE id = $1", [req.params.id]); res.json({ success: true }); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`GEOFROTA ON: ${PORT}`));