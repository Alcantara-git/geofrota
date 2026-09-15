const { Pool } = require('pg');

const linkBanco = process.env.DATABASE_URL || 'postgresql://postgres:1BPTRANPOLCIAMILITAR@db.cggyjbdpztsnhtrroiru.supabase.co:5432/postgres';

const pool = new Pool({
    connectionString: linkBanco.trim().replace(/['"]/g, ''),
    ssl: { rejectUnauthorized: false }
});

async function inicializarBanco() {
    try {
        // Garante a coluna motivo
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS motivo TEXT DEFAULT '';`);
        
        // ADICIONA A COLUNA SETOR (Define CTT como padrão para o que já existe)
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS setor TEXT DEFAULT 'CTT';`);
        
        // Tabela de Histórico
        await pool.query(`
            CREATE TABLE IF NOT EXISTS historico (
                id SERIAL PRIMARY KEY,
                prefixo TEXT,
                km_anterior INTEGER,
                km_novo INTEGER,
                status TEXT,
                motivo TEXT,
                usuario TEXT,
                data_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Tabela de Configurações
        await pool.query(`
            CREATE TABLE IF NOT EXISTS configuracoes (
                chave TEXT PRIMARY KEY,
                valor TEXT
            );
        `);

        await pool.query(`
            INSERT INTO configuracoes (chave, valor) 
            VALUES ('ultimo_acesso_relatorio', CURRENT_TIMESTAMP::text)
            ON CONFLICT DO NOTHING;
        `);

        console.log("✅ Banco de Dados sincronizado com Setores.");
    } catch (err) {
        console.log("Nota na inicialização:", err.message);
    }
}

inicializarBanco();
module.exports = pool;