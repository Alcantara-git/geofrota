const { Pool } = require('pg');

const linkBanco = process.env.DATABASE_URL || 'postgresql://postgres:1BPTRANPOLCIAMILITAR@db.cggyjbdpztsnhtrroiru.supabase.co:5432/postgres';

const pool = new Pool({
    connectionString: linkBanco.trim().replace(/['"]/g, ''),
    ssl: { rejectUnauthorized: false }
});

async function inicializarBanco() {
    try {
        // 1. Garante colunas na tabela de viaturas
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS motivo TEXT DEFAULT '';`);
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS setor TEXT DEFAULT 'CTT';`);
        
        // 2. Garante a tabela de histórico com a coluna SETOR obrigatória
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
                data_hora TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 3. Garante que nenhum rastro novo fique com setor vazio
        await pool.query(`ALTER TABLE historico ALTER COLUMN setor SET DEFAULT 'CTT';`);

        // 4. Memória de acesso ao relatório
        await pool.query(`CREATE TABLE IF NOT EXISTS configuracoes (chave TEXT PRIMARY KEY, valor TEXT);`);
        await pool.query(`INSERT INTO configuracoes (chave, valor) VALUES ('ultimo_acesso_relatorio', CURRENT_TIMESTAMP::text) ON CONFLICT DO NOTHING;`);

        console.log("✅ Banco de Dados GEOFROTA: Sincronização de histórico concluída.");
    } catch (err) {
        console.error("Erro inicialização DB:", err);
    }
}

inicializarBanco();
module.exports = pool;