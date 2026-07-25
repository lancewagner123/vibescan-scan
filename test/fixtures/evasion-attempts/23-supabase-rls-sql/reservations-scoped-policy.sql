-- Companion "does NOT fire" fixture for 23-supabase-rls-sql: the properly-scoped
-- equivalent of reservations-permissive-policy.sql's vulnerable policy in this same
-- folder. Both policies below grant SELECT and both mention the `anon`/`authenticated`
-- roles, but each restricts visibility to rows the requester actually owns via a real
-- USING() condition -- the correct RLS pattern, which supabase-rls-disabled's new .sql
-- migration coverage must stay silent on.

CREATE TABLE reservations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  guest_name text NOT NULL,
  guest_email text NOT NULL,
  guest_phone text,
  party_size integer NOT NULL,
  reservation_time timestamptz NOT NULL,
  user_id uuid REFERENCES auth.users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE reservations ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own reservations"
  ON reservations
  FOR SELECT
  TO authenticated
  USING (auth.uid() = user_id);

-- Even when the anon role is granted access at all, a real ownership check in USING()
-- must stay silent -- this isn't the "TO anon" grant alone that's dangerous, it's an
-- absent/trivially-true USING clause combined with it.
CREATE POLICY "Anon can view only a session-linked reservation"
  ON reservations
  FOR SELECT
  TO anon
  USING (auth.uid() = user_id);
