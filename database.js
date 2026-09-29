const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const linkBanco = process.env.DATABASE_URL;
if (!linkBanco) throw new Error('Configure DATABASE_URL.');
const pool = new Pool({
    connectionString: linkBanco,
    ssl: process.env.DATABASE_SSL === 'false' ? false : {
        rejectUnauthorized: true,
        ...(process.env.DATABASE_CA_FILE ? { ca: fs.readFileSync(path.resolve(__dirname, process.env.DATABASE_CA_FILE), 'utf8') } : {})
    }
});
async function inicializarBanco() {
    try {
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS motivo TEXT DEFAULT '';`);
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS setor TEXT DEFAULT 'CTT';`);
        await pool.query(`CREATE TABLE IF NOT EXISTS historico (id SERIAL PRIMARY KEY, prefixo TEXT, km_anterior INTEGER, km_novo INTEGER, status TEXT, motivo TEXT, usuario TEXT, setor TEXT, data_hora TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP);`);
        await pool.query(`CREATE TABLE IF NOT EXISTS configuracoes (chave TEXT PRIMARY KEY, valor TEXT);`);
        await pool.query(`INSERT INTO configuracoes (chave, valor) VALUES ('ultimo_acesso_relatorio', CURRENT_TIMESTAMP::text) ON CONFLICT DO NOTHING;`);
        console.log("✅ Banco de Dados Sincronizado.");
    } catch (err) { console.error("Falha ao inicializar banco:", err); }
}
if (process.env.INIT_DB === 'true') inicializarBanco();
module.exports = pool;