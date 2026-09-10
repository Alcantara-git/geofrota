const { Pool } = require('pg');

// Substitua a string abaixo pelo URI que você copiou do Supabase
const connectionString = process.env.DATABASE_URL || 'postgresql://postgres:W/NbpV_c45B*izk@db.cggyjbdpztsnhtrroiru.supabase.co:5432/postgres';

const pool = new Pool({
    connectionString: connectionString,
    ssl: { rejectUnauthorized: false } // Necessário para conexões externas
});

module.exports = pool;