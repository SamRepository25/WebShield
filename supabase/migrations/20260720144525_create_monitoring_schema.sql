/*
# Create monitoring schema for WebShield v2.0

## Purpose
Transforms WebShield from a manual-only scanner into an automated monitoring platform.
This migration creates two tables that let users register websites for recurring
security scans and store the full result of every scan ever performed against them.

## 1. New Tables

### `monitored_sites`
The registry of websites under continuous monitoring. One row per website.
- `id` (uuid, primary key)
- `name` (text, not null) — human-friendly label, e.g. "Marketing Site"
- `url` (text, not null) — the website URL to scan
- `frequency` (text, not null, default 'daily') — scan cadence; one of
  '6h', '12h', 'daily', 'weekly'
- `monitoring_enabled` (boolean, not null, default true) — pause/resume monitoring
  without deleting the site
- `last_scan_at` (timestamptz, nullable) — timestamp of the most recent scan
- `next_scan_at` (timestamptz, nullable) — when the scheduler should next scan it
- `last_score` (integer, nullable) — most recent security score (0-100)
- `last_grade` (text, nullable) — most recent letter grade (A-F)
- `created_at` (timestamptz, default now())
- `updated_at` (timestamptz, default now()) — auto-maintained by trigger

### `scans`
The immutable audit log of every scan ever run against a monitored site.
One row per scan execution. Rows are never updated — only inserted.
- `id` (uuid, primary key)
- `site_id` (uuid, foreign key -> monitored_sites.id ON DELETE CASCADE)
- `url` (text, not null) — the URL scanned (denormalized for history queries
  that survive even if the site is later deleted)
- `score` (integer, not null) — 0-100
- `grade` (text, not null) — A-F
- `https_enabled` (boolean, not null)
- `https_valid` (boolean, not null) — certificate validity
- `https_redirect` (boolean, not null) — HTTP->HTTPS redirect active
- `headers_present` (integer, not null) — count of present headers
- `headers_weak` (integer, not null) — count of weak headers
- `headers_missing` (integer, not null) — count of missing headers
- `vulnerability_count` (integer, not null) — total vulnerabilities detected
- `critical_count` (integer, not null)
- `high_count` (integer, not null)
- `medium_count` (integer, not null)
- `low_count` (integer, not null)
- `info_count` (integer, not null)
- `result_json` (jsonb, not null) — the full ScanResult object, so the
  detailed view (headers, recommendations, raw headers) can be reconstructed
  without a separate fetch
- `trigger` (text, not null, default 'manual') — 'manual' | 'scheduled'
- `scanned_at` (timestamptz, default now())

## 2. Indexes
- `monitored_sites_monitoring_enabled_idx` on `monitored_sites(monitoring_enabled)`
  for the scheduler to find active sites quickly.
- `monitored_sites_next_scan_at_idx` on `monitored_sites(next_scan_at)` for the
  scheduler to find due sites.
- `scans_site_id_scanned_at_idx` on `scans(site_id, scanned_at DESC)` for
  efficient history queries per site.
- `scans_scanned_at_idx` on `scans(scanned_at DESC)` for the global history page.

## 3. Security (Row Level Security)
This is a single-tenant, no-auth application (no sign-in screen). The frontend
talks to Supabase with the anon key for its entire lifetime, so EVERY policy
on EVERY table MUST list `anon` alongside `authenticated`, and the policies
use `USING (true)` / `WITH CHECK (true)` because the data is intentionally
shared/public across the single tenant. This is the documented, correct
pattern for a no-auth app — it is NOT a shortcut around ownership checks.

- RLS enabled on both tables.
- 4 policies per table (select/insert/update/delete), all `TO anon, authenticated`.

## 4. Triggers
- `update_monitored_sites_updated_at` — auto-maintains `updated_at` on every
  UPDATE of `monitored_sites`.

## 5. Important Notes
1. The `scans` table is append-only by convention. The API never UPDATEs or
   DELETEs scan rows; it only INSERTs them. The DELETE policy exists only so
   a future admin tool could prune old history.
2. `result_json` stores the complete `ScanResult` payload so the scan detail
   view can be rendered without re-scanning the target site.
3. `monitored_sites.last_score` / `last_grade` / `last_scan_at` are denormalized
   snapshots updated by the service layer after each scan, so the dashboard
   can render without joining to `scans`.
4. `next_scan_at` is computed from `frequency` by the service layer and stored
   here so the scheduler only needs a single indexed range query to find due
   sites.
*/

CREATE TABLE IF NOT EXISTS monitored_sites (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  url text NOT NULL,
  frequency text NOT NULL DEFAULT 'daily'
    CHECK (frequency IN ('6h', '12h', 'daily', 'weekly')),
  monitoring_enabled boolean NOT NULL DEFAULT true,
  last_scan_at timestamptz,
  next_scan_at timestamptz,
  last_score integer,
  last_grade text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS monitored_sites_monitoring_enabled_idx
  ON monitored_sites(monitoring_enabled);
CREATE INDEX IF NOT EXISTS monitored_sites_next_scan_at_idx
  ON monitored_sites(next_scan_at);

CREATE TABLE IF NOT EXISTS scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  site_id uuid REFERENCES monitored_sites(id) ON DELETE CASCADE,
  url text NOT NULL,
  score integer NOT NULL,
  grade text NOT NULL,
  https_enabled boolean NOT NULL,
  https_valid boolean NOT NULL,
  https_redirect boolean NOT NULL,
  headers_present integer NOT NULL,
  headers_weak integer NOT NULL,
  headers_missing integer NOT NULL,
  vulnerability_count integer NOT NULL,
  critical_count integer NOT NULL,
  high_count integer NOT NULL,
  medium_count integer NOT NULL,
  low_count integer NOT NULL,
  info_count integer NOT NULL,
  result_json jsonb NOT NULL,
  trigger text NOT NULL DEFAULT 'manual'
    CHECK (trigger IN ('manual', 'scheduled')),
  scanned_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scans_site_id_scanned_at_idx
  ON scans(site_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS scans_scanned_at_idx
  ON scans(scanned_at DESC);

ALTER TABLE monitored_sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_monitored_sites" ON monitored_sites;
CREATE POLICY "anon_select_monitored_sites" ON monitored_sites FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_monitored_sites" ON monitored_sites;
CREATE POLICY "anon_insert_monitored_sites" ON monitored_sites FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_monitored_sites" ON monitored_sites;
CREATE POLICY "anon_update_monitored_sites" ON monitored_sites FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_monitored_sites" ON monitored_sites;
CREATE POLICY "anon_delete_monitored_sites" ON monitored_sites FOR DELETE
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_select_scans" ON scans;
CREATE POLICY "anon_select_scans" ON scans FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_scans" ON scans;
CREATE POLICY "anon_insert_scans" ON scans FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_scans" ON scans;
CREATE POLICY "anon_update_scans" ON scans FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_scans" ON scans;
CREATE POLICY "anon_delete_scans" ON scans FOR DELETE
  TO anon, authenticated USING (true);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS update_monitored_sites_updated_at ON monitored_sites;
CREATE TRIGGER update_monitored_sites_updated_at
  BEFORE UPDATE ON monitored_sites
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();
