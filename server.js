const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const pool = require('./database');
const app = express();

app.use(express.json());
app.use(cookieParser());

const ADMIN_PASSWORD = "admin123"; // Sua senha de acesso

// --- PORTEIRO DE SEGURANÇA ---
const proteger = (req, res, next) => {
    if (req.cookies.auth === 'true') next();
    else if (req.path.startsWith('/api/')) res.status(401).json({ error: "Não autorizado" });
    else res.redirect('/login.html');
};

// --- LOGIN / LOGOUT ---
app.post('/api/login', (req, res) => {
    if (req.body.senha === ADMIN_PASSWORD) {
        res.cookie('auth', 'true', { httpOnly: true, maxAge: 24 * 60 * 60 * 1000, sameSite: 'lax' });
        res.json({ success: true });
    } else res.status(401).json({ error: "Senha incorreta" });
});
app.post('/api/logout', (req, res) => { res.clearCookie('auth'); res.json({ success: true }); });

// --- LÓGICA DE STATUS AUTOMÁTICO ---
function definirStatus(km, revisao, statusEnviado) {
    if (statusEnviado === 'Baixada') return 'Baixada';
    return (parseInt(km) >= parseInt(revisao)) ? 'Troca de Óleo' : 'Operante';
}

// ==========================================
// ROTA DO RELATÓRIO: ÚLTIMO ACESSO (CORRIGIDA)
// ==========================================
app.get('/api/relatorio-ultimo', proteger, async (req, res) => {
    try {
        // 1. Busca quando foi o último clique gravado no banco
        const config = await pool.query("SELECT valor FROM configuracoes WHERE chave = 'ultimo_acesso_relatorio'");
        const ultimoAcesso = new Date(config.rows[0].valor);
        const agora = new Date();

        // Compara as datas (Dia/Mês/Ano) no fuso de Brasília
        const dataUltimoStr = ultimoAcesso.toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' });
        const dataHojeStr = agora.toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' });

        let sql, params;

        if (dataUltimoStr === dataHojeStr) {
            // CENÁRIO A: Mesmo dia. Mostra tudo das 00:00 de hoje até agora.
            sql = `SELECT *, TO_CHAR(data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'HH24:MI') as hora 
                   FROM historico 
                   WHERE data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo' >= CURRENT_DATE 
                   ORDER BY data_hora DESC`;
            params = [];
        } else {
            // CENÁRIO B: Dias diferentes. Mostra o acumulado desde o último acesso real.
            sql = `SELECT *, TO_CHAR(data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'DD/MM HH24:MI') as hora 
                   FROM historico 
                   WHERE data_hora > $1 
                   ORDER BY data_hora DESC`;
            params = [ultimoAcesso];
        }

        const result = await pool.query(sql, params);
        
        // 2. Atualiza o marcador de "Último Acesso" para AGORA
        await pool.query("UPDATE configuracoes SET valor = CURRENT_TIMESTAMP WHERE chave = 'ultimo_acesso_relatorio'");
        
        res.json(result.rows);
    } catch (e) { 
        console.error(e);
        res.status(500).json(e); 
    }
});

// --- ROTA RELATÓRIO: POR PERÍODO ---
app.get('/api/relatorio-periodo', proteger, async (req, res) => {
    try {
        const { inicio, fim } = req.query;
        const sql = `
            SELECT *, TO_CHAR(data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'DD/MM HH24:MI') as hora 
            FROM historico 
            WHERE data_hora::date >= $1 AND data_hora::date <= $2 
            ORDER BY data_hora DESC
        `;
        const result = await pool.query(sql, [inicio, fim]);
        res.json(result.rows);
    } catch (e) { res.status(500).json(e); }
});

// --- ROTAS DE VIATURAS ---
app.get('/api/viaturas', async (req, res) => {
    const result = await pool.query("SELECT * FROM viaturas ORDER BY id DESC");
    res.json(result.rows);
});

app.put('/api/viaturas/:id', async (req, res) => {
    try {
        let { prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario, motivo } = req.body;
        const vtrAntiga = await pool.query("SELECT km FROM viaturas WHERE id = $1", [req.params.id]);
        const kmAnterior = vtrAntiga.rows[0].km;
        const st = definirStatus(km, km_revisao, status);
        const motivoFinal = (st === 'Baixada') ? (motivo || '') : '';
        
        await pool.query('UPDATE viaturas SET prefixo=$1, placa=$2, modelo=$3, km=$4, km_revisao=$5, status=$6, ultimo_usuario=$7, motivo=$8 WHERE id=$9', [prefixo, placa, modelo, km, km_revisao, st, ultimo_usuario, motivoFinal, req.params.id]);
        await pool.query('INSERT INTO historico (prefixo, km_anterior, km_novo, status, motivo, usuario) VALUES ($1,$2,$3,$4,$5,$6)', [prefixo, kmAnterior, km, st, motivoFinal, ultimo_usuario]);
        res.json({ success: true });
    } catch (e) { res.status(500).json(e); }
});

app.post('/api/viaturas', proteger, async (req, res) => {
    let { prefixo, placa, modelo, km, km_revisao, status } = req.body;
    const st = definirStatus(km, km_revisao, status);
    await pool.query('INSERT INTO viaturas (prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario, motivo) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [prefixo, placa, modelo, km, km_revisao, st, 'Sistema', '']);
    res.json({ success: true });
});

app.delete('/api/viaturas/:id', proteger, async (req, res) => {
    await pool.query('DELETE FROM viaturas WHERE id = $1', [req.params.id]);
    res.json({ success: true });
});

// --- ROTAS DE USUÁRIOS ---
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

// --- SERVIR PÁGINAS ---
app.get('/index.html', proteger, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/usuarios.html', proteger, (req, res) => res.sendFile(path.join(__dirname, 'usuarios.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/operacional.html', (req, res) => res.sendFile(path.join(__dirname, 'operacional.html')));
app.get('/', (req, res) => res.redirect('/operacional.html'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`GEOFROTA NO AR: Porta ${PORT}`));