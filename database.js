const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const linkBanco = process.env.DATABASE_URL;
if (!linkBanco) throw new Error('Configure DATABASE_URL.');
const pool = new Pool({
    connectionString: linkBanco,
    ssl: process.env.DATABASE_SSL === 'false' ? false : {
        rejectUnauthorized: true,
        ...(process.env.DATABASE_CA_FILE ? { ca: fs.readFileSync(path.resolve(__dirname, process.env.DATABASE_CA_FILE), 'utf8') } : {})
    }
});
async function inicializarBanco() {
    try {
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS motivo TEXT DEFAULT '';`);
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS setor TEXT DEFAULT 'CTT';`);
        await pool.query(`ALTER TABLE viaturas ADD COLUMN IF NOT EXISTS observacoes TEXT NOT NULL DEFAULT '';`);
        await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS viaturas_prefixo_normalizado_uidx ON viaturas ((UPPER(REGEXP_REPLACE(TRIM(prefixo), '[[:space:]]+', '', 'g'))));`);
        await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS setor TEXT;`);
        await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS re TEXT;`);
        await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS senha_hash TEXT;`);
        await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS servico_dia BOOLEAN NOT NULL DEFAULT FALSE;`);
        await pool.query(`DO $$ BEGIN ALTER TABLE usuarios ADD CONSTRAINT usuarios_re_formato_chk CHECK (re IS NULL OR re ~ '^[0-9]{6}$'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;`);
        await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS usuarios_re_uidx ON usuarios (re) WHERE re IS NOT NULL;`);
        await pool.query(`CREATE TABLE IF NOT EXISTS historico (id SERIAL PRIMARY KEY, prefixo TEXT, km_anterior INTEGER, km_novo INTEGER, status TEXT, motivo TEXT, usuario TEXT, setor TEXT, data_hora TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP);`);
        await pool.query(`ALTER TABLE historico ADD COLUMN IF NOT EXISTS autor_conta TEXT;`);
        await pool.query(`CREATE TABLE IF NOT EXISTS configuracoes (chave TEXT PRIMARY KEY, valor TEXT);`);
        await pool.query(`INSERT INTO configuracoes (chave, valor) VALUES ('ultimo_acesso_relatorio', CURRENT_TIMESTAMP::text) ON CONFLICT DO NOTHING;`);
        console.log("✅ Banco de Dados Sincronizado.");
    } catch (err) { console.error("Falha ao inicializar banco:", err); }
}
if (process.env.INIT_DB === 'true') inicializarBanco();
module.exports = pool;
