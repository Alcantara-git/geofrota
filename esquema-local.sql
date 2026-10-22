-- Somente para um banco PostgreSQL local e vazio de testes.
CREATE TABLE IF NOT EXISTS viaturas (
    id SERIAL PRIMARY KEY,
    prefixo TEXT NOT NULL,
    placa TEXT,
    modelo TEXT,
    km INTEGER NOT NULL DEFAULT 0,
    km_revisao INTEGER NOT NULL DEFAULT 10000,
    status TEXT NOT NULL DEFAULT 'Operante',
    ultimo_usuario TEXT DEFAULT 'Sistema',
    motivo TEXT DEFAULT '',
    setor TEXT DEFAULT 'CTT'
);
CREATE UNIQUE INDEX IF NOT EXISTS viaturas_prefixo_normalizado_uidx
    ON viaturas ((UPPER(REGEXP_REPLACE(TRIM(prefixo), '[[:space:]]+', '', 'g'))));
CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    nome TEXT NOT NULL,
    cargo TEXT,
    setor TEXT,
    re TEXT CHECK (re IS NULL OR re ~ '^[0-9]{6}$'),
    senha_hash TEXT,
    servico_dia BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE UNIQUE INDEX IF NOT EXISTS usuarios_re_uidx ON usuarios (re) WHERE re IS NOT NULL;
-- historico e configuracoes são criados automaticamente pelo servidor.
