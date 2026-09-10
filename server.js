const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const pool = require('./database');
const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

const ADMIN_PASSWORD = "admin123"; // SENHA PARA O DASHBOARD

// Proteção para o Dashboard e Usuários
const proteger = (req, res, next) => {
    if (req.cookies.auth === 'true') next();
    else if (req.path.startsWith('/api/')) res.status(401).json({ error: "Não autorizado" });
    else res.redirect('/login.html');
};

// LOGIN
app.post('/api/login', (req, res) => {
    if (req.body.senha === ADMIN_PASSWORD) {
        res.cookie('auth', 'true', { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
        res.json({ success: true });
    } else res.status(401).json({ error: "Senha incorreta" });
});

app.post('/api/logout', (req, res) => { res.clearCookie('auth'); res.json({ success: true }); });

// Inteligência de Status
function definirStatus(km, revisao, statusEnviado) {
    if (statusEnviado === 'Baixada') return 'Baixada';
    return (parseInt(km) >= parseInt(revisao)) ? 'Troca de Óleo' : 'Operante';
}

// --- ROTAS DE VIATURAS (Operacional e Admin) ---
app.get('/api/viaturas', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM viaturas ORDER BY id DESC");
        res.json(result.rows);
    } catch (e) { res.status(500).send(e); }
});

app.post('/api/viaturas', proteger, async (req, res) => {
    let { prefixo, placa, modelo, km, km_revisao, status } = req.body;
    const st = definirStatus(km, km_revisao, status);
    const sql = 'INSERT INTO viaturas (prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id';
    try {
        const result = await pool.query(sql, [prefixo, placa, modelo, km, km_revisao, st, 'Sistema']);
        res.json({ id: result.rows[0].id });
    } catch (e) { res.status(500).send(e); }
});

app.put('/api/viaturas/:id', async (req, res) => {
    let { prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario } = req.body;
    const st = definirStatus(km, km_revisao, status);
    const sql = 'UPDATE viaturas SET prefixo=$1, placa=$2, modelo=$3, km=$4, km_revisao=$5, status=$6, ultimo_usuario=$7 WHERE id=$8';
    try {
        await pool.query(sql, [prefixo, placa, modelo, km, km_revisao, st, ultimo_usuario || 'Gestor', req.params.id]);
        res.json({ success: true, status: st });
    } catch (e) { res.status(500).send(e); }
});

app.delete('/api/viaturas/:id', proteger, async (req, res) => {
    await pool.query('DELETE FROM viaturas WHERE id = $1', [req.params.id]);
    res.json({ deleted: 1 });
});

// --- ROTAS DE USUÁRIOS (Admin) ---
app.get('/api/usuarios', async (req, res) => {
    const result = await pool.query("SELECT * FROM usuarios ORDER BY nome ASC");
    res.json(result.rows);
});

app.post('/api/usuarios', proteger, async (req, res) => {
    const { nome, cargo } = req.body;
    await pool.query("INSERT INTO usuarios (nome, cargo) VALUES ($1, $2)", [nome, cargo]);
    res.json({ success: true });
});

app.delete('/api/usuarios/:id', proteger, async (req, res) => {
    await pool.query("DELETE FROM usuarios WHERE id = $1", [req.params.id]);
    res.json({ deleted: 1 });
});

// Proteção de Páginas
app.get('/index.html', proteger, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/usuarios.html', proteger, (req, res) => res.sendFile(path.join(__dirname, 'usuarios.html')));
app.get('/', (req, res) => res.redirect('/operacional.html'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`GEOFROTA ONLINE: Porta ${PORT}`));