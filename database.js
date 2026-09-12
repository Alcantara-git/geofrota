const { Pool } = require('pg');

const linkBanco = process.env.DATABASE_URL || 'postgresql://postgres:1BPTRANPOLCIAMILITAR@db.cggyjbdpztsnhtrroiru.supabase.co:5432/postgres';

const pool = new Pool({
    connectionString: linkBanco.trim().replace(/['"]/g, ''),
    ssl: { rejectUnauthorized: false }
});

// Criar coluna de motivo se ela não existir (Migração automática)
pool.query(`
    ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS motivo TEXT DEFAULT '';
`, (err) => {
    if (err) console.log("Nota: Coluna motivo já existe ou erro na criação.");
});

module.exports = pool;