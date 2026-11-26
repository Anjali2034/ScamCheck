-- ScamCheck's storage on Supabase Postgres. Safe to run again: the server runs it on startup, and it can also be
-- pasted into the Supabase SQL Editor.

-- One row per person per indicator (link, UPI ID, number) they checked: the "flagged by N other people" memory.
create table if not exists indicators (
  id bigint generated always as identity primary key,
  kind text, value text, verdict text, scam_type text, seen_at text, reporter text
);
create index if not exists ix_val on indicators (kind, value);

-- reporter_key: the secret that turns a person into an unguessable hash.
create table if not exists meta (name text primary key, value text);

-- Free-tier budgets, one counter per bucket (e.g. today's AI tokens, this month's WhatsApp messages).
create table if not exists usage (bucket text primary key, n integer not null);

-- Supabase serves tables in the public schema through its REST API. With RLS on and no policies, the public keys
-- can read nothing; the server connects as the postgres role, which bypasses RLS.
alter table indicators enable row level security;
alter table meta enable row level security;
alter table usage enable row level security;
