-- Migration: reservations table + RLS policy for the public-facing confirmation page.
--
-- Reconstructs (anonymized, not tied to the original repo) the real false-negative found
-- during VibeScan's real-world validation exercise: while manually triaging a Bolt.new-
-- built reservation app's dependency findings, the person doing triage found this exact
-- shape of bug in the app's Supabase migration -- check 8 never flagged it, because it
-- never looked inside .sql files at all. See docs/REAL_WORLD_VALIDATION.md §6.

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

-- Intent (per the migration's own name): let the public confirmation page look up a
-- reservation without requiring the guest to sign in. Actual effect: grants the public
-- `anon` role unrestricted SELECT access to every row in the table -- every other guest's
-- name, email, and phone number, not just the requester's own reservation.
CREATE POLICY "Public can view reservations"
  ON reservations
  FOR SELECT
  TO anon
  USING (true);
