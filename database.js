const { Pool } = require('pg');

const linkBanco = process.env.DATABASE_URL || 'postgresql://postgres:1BPTRANPOLCIAMILITAR@db.cggyjbdpztsnhtrroiru.supabase.co:5432/postgres';

const pool = new Pool({
    connectionString: linkBanco.trim().replace(/['"]/g, ''),
    ssl: { rejectUnauthorized: false }
});

// Criar tabelas e colunas necessárias
async function inicializarBanco() {
    try {
        // Garante coluna motivo
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS motivo TEXT DEFAULT '';`);
        
        // Cria tabela de histórico
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
        console.log("✅ Banco de Dados e Histórico prontos.");
    } catch (err) {
        console.log("Nota: Tabelas já existem ou erro na migração.");
    }
}

inicializarBanco();

module.exports = pool;