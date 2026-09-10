const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const db = require('./database');
const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

const ADMIN_PASSWORD = "admin123"; // ALTERE SUA SENHA AQUI

// Middleware para proteger páginas e APIs administrativas
const proteger = (req, res, next) => {
    if (req.cookies.auth === 'true') {
        next();
    } else {
        if (req.path.startsWith('/api/')) {
            res.status(401).json({ error: "Não autorizado" });
        } else {
            res.redirect('/login.html');
        }
    }
};

// ROTA DE LOGIN
app.post('/api/login', (req, res) => {
    const { senha } = req.body;
    if (senha === ADMIN_PASSWORD) {
        res.cookie('auth', 'true', { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }); // 24 horas
        res.json({ success: true });
    } else {
        res.status(401).json({ error: "Senha incorreta" });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('auth');
    res.json({ success: true });
});

// Inteligência de Status
function definirStatus(km, revisao, statusEnviado) {
    const k = parseInt(km) || 0;
    const r = parseInt(revisao) || 0;
    if (statusEnviado === 'Baixada') return 'Baixada';
    return (k >= r) ? 'Troca de Óleo' : 'Operante';
}

// --- ROTAS PÚBLICAS (Operacional usa estas) ---
app.get('/api/viaturas', (req, res) => {
    db.all("SELECT * FROM viaturas ORDER BY id DESC", [], (err, rows) => res.json(rows));
});

app.get('/api/usuarios', (req, res) => {
    db.all("SELECT * FROM usuarios ORDER BY nome ASC", [], (err, rows) => res.json(rows));
});

app.put('/api/viaturas/:id', (req, res) => {
    let { prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario } = req.body;
    const st = definirStatus(km, km_revisao, status);
    db.run('UPDATE viaturas SET prefixo=?, placa=?, modelo=?, km=?, km_revisao=?, status=?, ultimo_usuario=? WHERE id=?', 
    [prefixo, placa, modelo, km, km_revisao, st, ultimo_usuario || 'Gestor', req.params.id], () => res.json({ success: true }));
});

// --- ROTAS PROTEGIDAS (Dashboard e Gestão de Usuários) ---
app.post('/api/viaturas', proteger, (req, res) => {
    let { prefixo, placa, modelo, km, km_revisao, status } = req.body;
    const st = definirStatus(km, km_revisao, status);
    db.run('INSERT INTO viaturas (prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario) VALUES (?,?,?,?,?,?,?)', 
    [prefixo, placa, modelo, km, km_revisao, st, 'Sistema'], function() { res.json({ id: this.lastID }); });
});

app.delete('/api/viaturas/:id', proteger, (req, res) => {
    db.run('DELETE FROM viaturas WHERE id = ?', req.params.id, () => res.json({ deleted: 1 }));
});

app.post('/api/usuarios', proteger, (req, res) => {
    const { nome, cargo } = req.body;
    db.run("INSERT INTO usuarios (nome, cargo) VALUES (?, ?)", [nome, cargo], function() { res.json({ id: this.lastID }); });
});

app.delete('/api/usuarios/:id', proteger, (req, res) => {
    db.run("DELETE FROM usuarios WHERE id = ?", req.params.id, () => res.json({ deleted: 1 }));
});

// Proteção das páginas estáticas
app.get('/index.html', proteger, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/usuarios.html', proteger, (req, res) => res.sendFile(path.join(__dirname, 'usuarios.html')));
app.get('/', (req, res) => res.redirect('/operacional.html'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`GEOFROTA ONLINE: Porta ${PORT}`));