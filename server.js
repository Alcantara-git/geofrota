const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const pool = require('./database');
const app = express();

app.use(express.json());
app.use(cookieParser());

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
    const k = parseInt(km) || 0;
    const r = parseInt(revisao) || 0;
    return (k >= r) ? 'Troca de Óleo' : 'Operante';
}

app.get('/api/viaturas', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM viaturas ORDER BY id DESC");
        res.json(result.rows);
    } catch (e) { res.status(500).json(e); }
});

app.get('/api/usuarios', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM usuarios ORDER BY nome ASC");
        res.json(result.rows);
    } catch (e) { res.status(500).json(e); }
});

app.put('/api/viaturas/:id', async (req, res) => {
    try {
        let { prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario, motivo } = req.body;
        const st = definirStatus(km, km_revisao, status);
        // Se voltar para Operante, limpa o motivo. Se for baixa, salva o motivo.
        const motivoFinal = (st === 'Baixada') ? (motivo || '') : '';
        
        const sql = 'UPDATE viaturas SET prefixo=$1, placa=$2, modelo=$3, km=$4, km_revisao=$5, status=$6, ultimo_usuario=$7, motivo=$8 WHERE id=$9';
        await pool.query(sql, [prefixo, placa, modelo, km, km_revisao, st, ultimo_usuario || 'Operador', motivoFinal, req.params.id]);
        res.json({ success: true, status: st });
    } catch (e) { res.status(500).json(e); }
});

app.post('/api/viaturas', proteger, async (req, res) => {
    try {
        let { prefixo, placa, modelo, km, km_revisao, status } = req.body;
        const st = definirStatus(km, km_revisao, status);
        const sql = 'INSERT INTO viaturas (prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario, motivo) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id';
        const result = await pool.query(sql, [prefixo, placa, modelo, km, km_revisao, st, 'Sistema', '']);
        res.json({ id: result.rows[0].id });
    } catch (e) { res.status(500).json(e); }
});

app.delete('/api/viaturas/:id', proteger, async (req, res) => {
    try {
        await pool.query('DELETE FROM viaturas WHERE id = $1', [req.params.id]);
        res.json({ deleted: 1 });
    } catch (e) { res.status(500).json(e); }
});

app.post('/api/usuarios', proteger, async (req, res) => {
    try {
        const { nome, cargo } = req.body;
        await pool.query("INSERT INTO usuarios (nome, cargo) VALUES ($1, $2)", [nome, cargo]);
        res.json({ success: true });
    } catch (e) { res.status(500).json(e); }
});

app.delete('/api/usuarios/:id', proteger, async (req, res) => {
    try {
        await pool.query("DELETE FROM usuarios WHERE id = $1", [req.params.id]);
        res.json({ deleted: 1 });
    } catch (e) { res.status(500).json(e); }
});

app.get('/index.html', proteger, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/usuarios.html', proteger, (req, res) => res.sendFile(path.join(__dirname, 'usuarios.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/operacional.html', (req, res) => res.sendFile(path.join(__dirname, 'operacional.html')));
app.get('/', (req, res) => res.redirect('/operacional.html'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`GEOFROTA NO AR: Porta ${PORT}`));