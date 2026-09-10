const { Pool } = require('pg');

// Aqui é onde a mágica acontece. 
// O link abaixo conecta o seu site ao banco de dados do Supabase.
const connectionString = process.env.DATABASE_URL || 'postgresql://postgres:W/NbpV_c45B*izk@db.cggyjbdpztsnhtrroiru.supabase.co:5432/postgres';

const pool = new Pool({
    connectionString: connectionString,
    ssl: { rejectUnauthorized: false } 
});

module.exports = pool;