const { Pool } = require('pg');
const linkBanco = process.env.DATABASE_URL || 'postgresql://postgres:1BPTRANPOLCIAMILITAR@db.cggyjbdpztsnhtrroiru.supabase.co:5432/postgres';

const pool = new Pool({
    connectionString: linkBanco.trim().replace(/['"]/g, ''),
    ssl: { rejectUnauthorized: false }
});

async function inicializarBanco() {
    try {
        // Atualiza estrutura das viaturas
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS motivo TEXT DEFAULT '';`);
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS setor TEXT DEFAULT 'CTT';`);
        
        // Atualiza estrutura do histórico
        await pool.query(`
            CREATE TABLE IF NOT EXISTS historico (
                id SERIAL PRIMARY KEY,
                prefixo TEXT,
                km_anterior INTEGER,
                km_novo INTEGER,
                status TEXT,
                motivo TEXT,
                usuario TEXT,
                setor TEXT DEFAULT 'CTT',
                data_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Garante que históricos antigos não fiquem nulos (evita erro no filtro)
        await pool.query(`UPDATE historico SET setor = 'CTT' WHERE setor IS NULL;`);

        await pool.query(`CREATE TABLE IF NOT EXISTS configuracoes (chave TEXT PRIMARY KEY, valor TEXT);`);
        await pool.query(`INSERT INTO configuracoes (chave, valor) VALUES ('ultimo_acesso_relatorio', CURRENT_TIMESTAMP::text) ON CONFLICT DO NOTHING;`);

        console.log("✅ Banco de Dados e Histórico por Setor sincronizados.");
    } catch (err) {
        console.log("Nota: Estrutura já atualizada.");
    }
}
inicializarBanco();
module.exports = pool;