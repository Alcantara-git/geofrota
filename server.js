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

// --- RELATÓRIOS COM CORREÇÃO DE FUSO ---
app.get('/api/relatorio-ultimo', proteger, async (req, res) => {
    try {
        const { setor } = req.query;
        // 1. Define a sessão do banco para o horário de Brasília
        await pool.query("SET TIME ZONE 'America/Sao_Paulo'");

        const config = await pool.query("SELECT valor FROM configuracoes WHERE chave = 'ultimo_acesso_relatorio'");
        const ultimoAcesso = new Date(config.rows[0].valor);
        
        const agora = new Date();
        const hojeMeiaNoite = new Date();
        hojeMeiaNoite.setHours(0,0,0,0);

        let sql = `SELECT *, TO_CHAR(data_hora, 'DD/MM HH24:MI') as hora FROM historico WHERE `;
        let params = [];

        // Se o último acesso foi em outro dia, mostra desde aquele horário
        if (ultimoAcesso < hojeMeiaNoite) {
            sql += `data_hora > $1 `;
            params.push(ultimoAcesso);
        } else {
            // Se já acessou hoje, mostra tudo de hoje (00:00 em diante)
            sql += `data_hora >= CURRENT_DATE `;
        }

        if (setor && setor !== 'Todos') {
            sql += ` AND setor = $${params.length + 1}`;
            params.push(setor);
        }

        const result = await pool.query(sql + ` ORDER BY data_hora DESC`, params);
        
        // Atualiza marcador de acesso
        await pool.query("UPDATE configuracoes SET valor = CURRENT_TIMESTAMP WHERE chave = 'ultimo_acesso_relatorio'");
        
        res.json(result.rows);
    } catch (e) { res.status(500).json(e); }
});

app.get('/api/relatorio-periodo', proteger, async (req, res) => {
    try {
        const { inicio, fim, setor } = req.query;
        await pool.query("SET TIME ZONE 'America/Sao_Paulo'");
        let sql = `SELECT *, TO_CHAR(data_hora, 'DD/MM HH24:MI') as hora FROM historico WHERE data_hora::date >= $1 AND data_hora::date <= $2 `;
        let params = [inicio, fim];
        if (setor && setor !== 'Todos') {
            sql += ` AND setor = $3`;
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
        await pool.query("SET TIME ZONE 'America/Sao_Paulo'");
        let { km, km_revisao, status, ultimo_usuario, motivo, setor } = req.body;
        const vCheck = await pool.query("SELECT prefixo, setor, km, km_revisao FROM viaturas WHERE id = $1", [req.params.id]);
        const v = vCheck.rows[0];

        const st = definirStatus(km, km_revisao || v.km_revisao, status);
        const mot = (st === 'Baixada') ? (motivo || '') : '';
        const set = setor || v.setor;

        await pool.query('UPDATE viaturas SET km=$1, km_revisao=$2, status=$3, ultimo_usuario=$4, motivo=$5, setor=$6 WHERE id=$7', [km, km_revisao || v.km_revisao, st, ultimo_usuario, mot, set, req.params.id]);
        await pool.query('INSERT INTO historico (prefixo, km_anterior, km_novo, status, motivo, usuario, setor) VALUES ($1,$2,$3,$4,$5,$6,$7)', [v.prefixo, v.km, km, st, mot, ultimo_usuario, set]);
        
        res.json({ success: true });
    } catch (e) { res.status(500).json(e); }
});

app.post('/api/viaturas', proteger, async (req, res) => {
    try {
        await pool.query("SET TIME ZONE 'America/Sao_Paulo'");
        let { prefixo, placa, modelo, km, km_revisao, status, setor } = req.body;
        const st = definirStatus(km, km_revisao, status);
        await pool.query('INSERT INTO viaturas (prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario, motivo, setor) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [prefixo, placa, modelo, km, km_revisao, st, 'Sistema', '', setor]);
        res.json({ success: true });
    } catch (e) { res.status(500).json(e); }
});

app.delete('/api/viaturas/:id', proteger, async (req, res) => { await pool.query('DELETE FROM viaturas WHERE id = $1', [req.params.id]); res.json({ success: true }); });
app.get('/api/usuarios', async (req, res) => { const result = await pool.query("SELECT * FROM usuarios ORDER BY nome ASC"); res.json(result.rows); });
app.post('/api/usuarios', proteger, async (req, res) => { await pool.query("INSERT INTO usuarios (nome, cargo) VALUES ($1, $2)", [req.body.nome, req.body.cargo]); res.json({ success: true }); });
app.delete('/api/usuarios/:id', proteger, async (req, res) => { await pool.query("DELETE FROM usuarios WHERE id = $1", [req.params.id]); res.json({ success: true }); });

app.get('/index.html', proteger, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/usuarios.html', proteger, (req, res) => res.sendFile(path.join(__dirname, 'usuarios.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/operacional.html', (req, res) => res.sendFile(path.join(__dirname, 'operacional.html')));
app.get('/', (req, res) => res.redirect('/operacional.html'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`GEOFROTA ONLINE: Porta ${PORT}`));