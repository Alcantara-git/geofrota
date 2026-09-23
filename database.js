const { Pool } = require('pg');
const linkBanco = process.env.DATABASE_URL || 'postgresql://postgres:1BPTRANPOLCIAMILITAR@db.cggyjbdpztsnhtrroiru.supabase.co:5432/postgres';
const pool = new Pool({
    connectionString: linkBanco.trim().replace(/['"]/g, ''),
    ssl: { rejectUnauthorized: false }
});
async function inicializarBanco() {
    try {
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS motivo TEXT DEFAULT '';`);
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS setor TEXT DEFAULT 'CTT';`);
        await pool.query(`CREATE TABLE IF NOT EXISTS historico (id SERIAL PRIMARY KEY, prefixo TEXT, km_anterior INTEGER, km_novo INTEGER, status TEXT, motivo TEXT, usuario TEXT, setor TEXT, data_hora TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP);`);
        await pool.query(`CREATE TABLE IF NOT EXISTS configuracoes (chave TEXT PRIMARY KEY, valor TEXT);`);
        await pool.query(`INSERT INTO configuracoes (chave, valor) VALUES ('ultimo_acesso_relatorio', CURRENT_TIMESTAMP::text) ON CONFLICT DO NOTHING;`);
    } catch (err) { console.log("DB Pronto."); }
}
inicializarBanco();
module.exports = pool;