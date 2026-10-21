-- Autenticação individual dos operadores do GEOFROTA.
-- Preserva cargo para compatibilidade e usa uma coluna própria para o RE de acesso.
ALTER TABLE public.usuarios ADD COLUMN IF NOT EXISTS re TEXT;
ALTER TABLE public.usuarios ADD COLUMN IF NOT EXISTS senha_hash TEXT;

-- Migra automaticamente apenas REs válidos e não repetidos.
WITH res_unicos AS (
    SELECT BTRIM(cargo) AS re
    FROM public.usuarios
    WHERE BTRIM(cargo) ~ '^[0-9]{6}$'
    GROUP BY BTRIM(cargo)
    HAVING COUNT(*) = 1
)
UPDATE public.usuarios AS u
SET re = BTRIM(u.cargo)
FROM res_unicos
WHERE u.re IS NULL AND BTRIM(u.cargo) = res_unicos.re;

DO $$
BEGIN
    ALTER TABLE public.usuarios
        ADD CONSTRAINT usuarios_re_formato_chk
        CHECK (re IS NULL OR re ~ '^[0-9]{6}$');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS usuarios_re_uidx
    ON public.usuarios (re)
    WHERE re IS NOT NULL;

COMMENT ON COLUMN public.usuarios.re IS 'RE operacional: exatamente seis algarismos e exclusivo quando preenchido.';
COMMENT ON COLUMN public.usuarios.senha_hash IS 'Hash scrypt da senha operacional; NULL indica primeiro acesso pendente.';
