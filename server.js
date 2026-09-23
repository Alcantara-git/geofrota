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

// Proteção para quem pode apenas VER ou LANÇAR (Ambos)
const permitirAmbos = (req, res, next) => {
    if (req.cookies.auth_admin === 'true' || req.cookies.auth_oper === 'true') next();
    else res.status(401).redirect('/login.html');
};

// Proteção exclusiva para ações de COMANDO (Cadastrar/Deletar)
const permitirApenasAdmin = (req, res, next) => {
    if (req.cookies.auth_admin === 'true') next();
    else res.status(403).json({ error: "Apenas Administradores" });
};

app.post('/api/login', (req, res) => {
    const { senha, tipo } = req.body;
    if (tipo === 'admin' && senha === PWD_ADMIN) {
        res.cookie('auth_admin', 'true', { httpOnly: true, sameSite: 'lax' });
        return res.json({ success: true, redirect: 'index.html', role: 'admin' });
    } 
    if (tipo === 'oper' && senha === PWD_OPER) {
        res.cookie('auth_oper', 'true', { httpOnly: true, sameSite: 'lax' });
        return res.json({ success: true, redirect: 'operacional.html', role: 'oper' });
    }
    res.status(401).json({ error: "Senha incorreta" });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('auth_admin'); res.clearCookie('auth_oper');
    res.json({ success: true });
});

// PÁGINAS (Navegação permitida para ambos)
app.get('/index.html', permitirAmbos, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/usuarios.html', permitirAmbos, (req, res) => res.sendFile(path.join(__dirname, 'usuarios.html')));
app.get('/operacional.html', permitirAmbos, (req, res) => res.sendFile(path.join(__dirname, 'operacional.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/', (req, res) => res.redirect('/login.html'));

// RELATÓRIOS
app.get('/api/relatorio-ultimo', permitirAmbos, async (req, res) => {
    try {
        const { setor } = req.query;
        const config = await pool.query("SELECT valor FROM configuracoes WHERE chave = 'ultimo_acesso_relatorio'");
        const ultimoAcesso = new Date(config.rows[0].valor);
        const agora = new Date();
        const formatter = new Intl.DateTimeFormat('pt-BR', { timeZone: 'America/Sao_Paulo', year: 'numeric', month: '2-digit', day: '2-digit' });
        const dataHojeBR = formatter.format(agora).split('/').reverse().join('-');
        const dataUltimoBR = formatter.format(ultimoAcesso).split('/').reverse().join('-');

        let sql, params;
        if (dataHojeBR === dataUltimoBR) {
            sql = `SELECT *, TO_CHAR(data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'HH24:MI') as hora FROM historico WHERE data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo' >= $1::timestamp`;
            params = [dataHojeBR + ' 00:00:00'];
        } else {
            sql = `SELECT *, TO_CHAR(data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'DD/MM HH24:MI') as hora FROM historico WHERE data_hora > $1`;
            params = [ultimoAcesso];
        }
        if (setor && setor !== 'Todos') { sql += ` AND setor = $${params.length + 1}`; params.push(setor); }
        const result = await pool.query(sql + ` ORDER BY data_hora DESC`, params);
        await pool.query("UPDATE configuracoes SET valor = CURRENT_TIMESTAMP WHERE chave = 'ultimo_acesso_relatorio'");
        res.json(result.rows);
    } catch (e) { res.status(500).json(e); }
});

app.get('/api/relatorio-periodo', permitirAmbos, async (req, res) => {
    try {
        const { inicio, fim, setor } = req.query;
        let sql = `SELECT *, TO_CHAR(data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo', 'DD/MM HH24:MI') as hora FROM historico WHERE (data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo')::date >= $1 AND (data_hora AT TIME ZONE 'UTC' AT TIME ZONE 'America/Sao_Paulo')::date <= $2`;
        let params = [inicio, fim];
        if (setor && setor !== 'Todos') { sql += ` AND setor = $3`; params.push(setor); }
        const result = await pool.query(sql + ` ORDER BY data_hora DESC`, params);
        res.json(result.rows);
    } catch (e) { res.status(500).json(e); }
});

app.get('/api/viaturas', permitirAmbos, async (req, res) => {
    const result = await pool.query("SELECT * FROM viaturas ORDER BY setor ASC, prefixo ASC");
    res.json(result.rows);
});

app.put('/api/viaturas/:id', permitirAmbos, async (req, res) => {
    try {
        let { km, km_revisao, status, ultimo_usuario, motivo, setor } = req.body;
        const vtrOld = await pool.query("SELECT prefixo, km, setor, km_revisao FROM viaturas WHERE id = $1", [req.params.id]);
        const d = vtrOld.rows[0];
        
        const kmNovo = (km !== undefined) ? km : d.km;
        const revFinal = (km_revisao !== undefined) ? parseInt(km_revisao) : d.km_revisao;
        const statusFinal = (status === 'Baixada') ? 'Baixada' : (parseInt(kmNovo) >= revFinal ? 'Troca de Óleo' : 'Operante');
        
        await pool.query('UPDATE viaturas SET km=$1, km_revisao=$2, status=$3, ultimo_usuario=$4, motivo=$5, setor=$6 WHERE id=$7', [kmNovo, revFinal, statusFinal, ultimo_usuario, (statusFinal === 'Baixada' ? motivo : ''), setor || d.setor, req.params.id]);
        await pool.query('INSERT INTO historico (prefixo, km_anterior, km_novo, status, motivo, usuario, setor) VALUES ($1,$2,$3,$4,$5,$6,$7)', [d.prefixo, d.km, kmNovo, statusFinal, (statusFinal === 'Baixada' ? motivo : ''), ultimo_usuario, setor || d.setor]);
        res.json({ success: true });
    } catch (e) { res.status(500).json(e); }
});

app.post('/api/viaturas', permitirApenasAdmin, async (req, res) => {
    let { prefixo, placa, modelo, km, km_revisao, status, setor } = req.body;
    const st = (status === 'Baixada') ? 'Baixada' : (parseInt(km) >= parseInt(km_revisao) ? 'Troca de Óleo' : 'Operante');
    await pool.query('INSERT INTO viaturas (prefixo, placa, modelo, km, km_revisao, status, ultimo_usuario, motivo, setor) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [prefixo, placa, modelo, km, km_revisao, st, 'Sistema', '', setor]);
    res.json({ success: true });
});

app.delete('/api/viaturas/:id', permitirApenasAdmin, async (req, res) => { await pool.query('DELETE FROM viaturas WHERE id = $1', [req.params.id]); res.json({ success: true }); });
app.get('/api/usuarios', permitirAmbos, async (req, res) => { const result = await pool.query("SELECT * FROM usuarios ORDER BY nome ASC"); res.json(result.rows); });
app.post('/api/usuarios', permitirApenasAdmin, async (req, res) => { await pool.query("INSERT INTO usuarios (nome, cargo) VALUES ($1, $2)", [req.body.nome, req.body.cargo]); res.json({ success: true }); });
app.delete('/api/usuarios/:id', permitirApenasAdmin, async (req, res) => { await pool.query("DELETE FROM usuarios WHERE id = $1", [req.params.id]); res.json({ success: true }); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`GEOFROTA ON: ${PORT}`));