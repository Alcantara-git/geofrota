const { Pool } = require('pg');

// Pega o link do Render (Environment) ou usa o que você colar abaixo
let connectionString = process.env.DATABASE_URL || 'postgresql://postgres:W/NbpV_c45B*izk@db.cggyjbdpztsnhtrroiru.supabase.co:5432/postgres';

// Limpeza de segurança: remove espaços ou quebras de linha acidentais
connectionString = connectionString.trim();

const pool = new Pool({
    connectionString: connectionString,
    ssl: {
        rejectUnauthorized: false // Obrigatório para Supabase
    }
});

// Testa a conexão de forma silenciosa para não travar o servidor no início
pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ ERRO CRÍTICO NO BANCO:', err.message);
    } else {
        console.log('✅ BANCO DE DADOS CONECTADO COM SUCESSO!');
        release();
    }
});

module.exports = pool;