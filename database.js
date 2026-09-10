const { Pool } = require('pg');

/**
 * GEOFROTA - Conexão Blindada com PostgreSQL
 */

// Puxa o link do Render ou do seu código
let linkBanco = process.env.DATABASE_URL || 'postgresql://postgres:1BPTRANPOLCIAMILITAR@db.cggyjbdpztsnhtrroiru.supabase.co:5432/postgres';

// Limpeza automática: remove espaços, aspas e quebras de linha
linkBanco = linkBanco.trim().replace(/['"]/g, '');

const pool = new Pool({
    connectionString: linkBanco,
    ssl: {
        rejectUnauthorized: false // Necessário para o Supabase
    }
});

// Testa a conexão e avisa no log do Render
pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ ERRO AO CONECTAR NO SUPABASE:', err.message);
    } else {
        console.log('✅ CONEXÃO ESTABELECIDA COM SUCESSO AO POSTGRESQL!');
        release();
    }
});

module.exports = pool;