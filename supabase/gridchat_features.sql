-- GridChat feature setup: profile fields, group roles, read receipts and reactions.
-- Run once in the Supabase SQL Editor before deploying the matching server code.

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS profile_photo text,
  ADD COLUMN IF NOT EXISTS status_message text,
  ADD COLUMN IF NOT EXISTS last_seen_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE public.conversation_members
  ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'member';

UPDATE public.conversation_members AS cm
SET role = 'owner'
FROM public.conversations AS c
WHERE c.id = cm.conversation_id
  AND c.type = 'group'
  AND c.created_by = cm.user_id
  AND cm.role = 'member';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'conversation_members_role_check'
      AND conrelid = 'public.conversation_members'::regclass
  ) THEN
    ALTER TABLE public.conversation_members
      ADD CONSTRAINT conversation_members_role_check
      CHECK (role IN ('owner', 'admin', 'member'));
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.message_reads (
  message_id uuid NOT NULL REFERENCES public.messages(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  read_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id)
);

CREATE INDEX IF NOT EXISTS message_reads_user_id_idx
  ON public.message_reads (user_id, message_id);

CREATE TABLE IF NOT EXISTS public.message_reactions (
  message_id uuid NOT NULL REFERENCES public.messages(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  emoji text NOT NULL CHECK (char_length(emoji) <= 12),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id, emoji)
);

CREATE INDEX IF NOT EXISTS message_reactions_message_id_idx
  ON public.message_reactions (message_id);

ALTER TABLE public.message_reads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.message_reactions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.message_reads, public.message_reactions FROM anon, authenticated;
GRANT ALL ON public.message_reads, public.message_reactions TO service_role;

CREATE OR REPLACE FUNCTION public.transfer_group_owner(
  p_conversation_id uuid,
  p_from_user_id uuid,
  p_to_user_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
BEGIN
  IF p_from_user_id = p_to_user_id THEN
    RAISE EXCEPTION 'The new owner must be a different member';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.conversations
    WHERE id = p_conversation_id
      AND type = 'group'
      AND created_by = p_from_user_id
  ) OR NOT EXISTS (
    SELECT 1 FROM public.conversation_members
    WHERE conversation_id = p_conversation_id
      AND user_id = p_from_user_id
      AND role = 'owner'
  ) OR NOT EXISTS (
    SELECT 1 FROM public.conversation_members
    WHERE conversation_id = p_conversation_id
      AND user_id = p_to_user_id
  ) THEN
    RAISE EXCEPTION 'Group owner or target membership is invalid';
  END IF;

  UPDATE public.conversation_members
  SET role = CASE
    WHEN user_id = p_from_user_id THEN 'admin'
    WHEN user_id = p_to_user_id THEN 'owner'
  END
  WHERE conversation_id = p_conversation_id
    AND user_id IN (p_from_user_id, p_to_user_id);

  UPDATE public.conversations
  SET created_by = p_to_user_id
  WHERE id = p_conversation_id;
END;
$$;

REVOKE ALL ON FUNCTION public.transfer_group_owner(uuid, uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.transfer_group_owner(uuid, uuid, uuid) TO service_role;
