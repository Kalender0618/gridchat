-- Session expiry required by the hardened server authentication.
ALTER TABLE public.sessions
  ADD COLUMN IF NOT EXISTS expires_at timestamptz;

UPDATE public.sessions
SET expires_at = now()
WHERE expires_at IS NULL;

ALTER TABLE public.sessions
  ALTER COLUMN expires_at SET DEFAULT (now() + interval '30 days'),
  ALTER COLUMN expires_at SET NOT NULL;

CREATE INDEX IF NOT EXISTS sessions_expires_at_idx
  ON public.sessions (expires_at);
