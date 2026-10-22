-- Permissão especial para policiais que lançam dados em nome de outro militar.
-- Todos os registros existentes permanecem desmarcados por padrão.
ALTER TABLE public.usuarios
    ADD COLUMN IF NOT EXISTS servico_dia BOOLEAN NOT NULL DEFAULT FALSE;
