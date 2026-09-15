const { Pool } = require('pg');

const linkBanco = process.env.DATABASE_URL || 'postgresql://postgres:1BPTRANPOLCIAMILITAR@db.cggyjbdpztsnhtrroiru.supabase.co:5432/postgres';

const pool = new Pool({
    connectionString: linkBanco.trim().replace(/['"]/g, ''),
    ssl: { rejectUnauthorized: false }
});

async function inicializarBanco() {
    try {
        // 1. Tabelas Base
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS motivo TEXT DEFAULT '';`);
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS setor TEXT DEFAULT 'CTT';`);
        
        // 2. Tabela de Histórico (Garante a existência da coluna setor)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS historico (
                id SERIAL PRIMARY KEY,
                prefixo TEXT,
                km_anterior INTEGER,
                km_novo INTEGER,
                status TEXT,
                motivo TEXT,
                usuario TEXT,
                setor TEXT,
                data_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 3. Memória de Acesso
        await pool.query(`CREATE TABLE IF NOT EXISTS configuracoes (chave TEXT PRIMARY KEY, valor TEXT);`);
        await pool.query(`INSERT INTO configuracoes (chave, valor) VALUES ('ultimo_acesso_relatorio', CURRENT_TIMESTAMP::text) ON CONFLICT DO NOTHING;`);

        console.log("✅ Sistema de Dados GEOFROTA pronto.");
    } catch (err) {
        console.error("Erro na base de dados:", err);
    }
}

inicializarBanco();
module.exports = pool;