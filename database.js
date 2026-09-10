const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL || 'postgresql://postgres:W/NbpV_c45B*izk@db.cggyjbdpztsnhtrroiru.supabase.co:5432/postgres';

const pool = new Pool({
    connectionString: connectionString,
    ssl: { rejectUnauthorized: false }
});

// Teste de conexão imediato
pool.query('SELECT NOW()', (err, res) => {
    if (err) console.error("ERRO DE CONEXÃO COM BANCO:", err.message);
    else console.log("BANCO CONECTADO COM SUCESSO.");
});

module.exports = pool;