import { promises as fs } from 'fs';
import path from 'path';
import type { MonitoredSite, ScanRecord, ScanFrequency } from '@/lib/monitoring-types';

interface StoreShape {
  sites: MonitoredSite[];
  scans: ScanRecord[];
}

const DATA_DIR = path.join(process.cwd(), '.data');
const STORE_PATH = path.join(DATA_DIR, 'monitoring.json');

const EMPTY_STORE: StoreShape = { sites: [], scans: [] };

let writeLock: Promise<void> = Promise.resolve();

function uuid(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

async function ensureDataDir(): Promise<void> {
  await fs.mkdir(DATA_DIR, { recursive: true });
}

async function readStore(): Promise<StoreShape> {
  try {
    const raw = await fs.readFile(STORE_PATH, 'utf8');
    const parsed = JSON.parse(raw) as StoreShape;
    return {
      sites: Array.isArray(parsed.sites) ? parsed.sites : [],
      scans: Array.isArray(parsed.scans) ? parsed.scans : [],
    };
  } catch {
    return { ...EMPTY_STORE };
  }
}

async function writeStore(store: StoreShape): Promise<void> {
  await ensureDataDir();
  await fs.writeFile(STORE_PATH, JSON.stringify(store, null, 2), 'utf8');
}

async function withWriteLock<T>(fn: () => Promise<T>): Promise<T> {
  const previous = writeLock;
  let release: () => void;
  writeLock = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous;
  try {
    return await fn();
  } finally {
    release!();
  }
}

export async function getSites(): Promise<MonitoredSite[]> {
  const store = await readStore();
  return store.sites.slice().sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  );
}

export async function getSite(id: string): Promise<MonitoredSite | null> {
  const store = await readStore();
  return store.sites.find((s) => s.id === id) ?? null;
}

export async function insertSite(input: {
  name: string;
  url: string;
  frequency: ScanFrequency;
  monitoring_enabled: boolean;
  next_scan_at: string | null;
}): Promise<MonitoredSite> {
  return withWriteLock(async () => {
    const store = await readStore();
    const now = new Date().toISOString();
    const site: MonitoredSite = {
      id: uuid(),
      name: input.name,
      url: input.url,
      frequency: input.frequency,
      monitoring_enabled: input.monitoring_enabled,
      last_scan_at: null,
      next_scan_at: input.next_scan_at,
      last_score: null,
      last_grade: null,
      created_at: now,
      updated_at: now,
    };
    store.sites.push(site);
    await writeStore(store);
    return site;
  });
}

export async function updateSiteFields(
  id: string,
  fields: Partial<Omit<MonitoredSite, 'id' | 'created_at' | 'updated_at'>>
): Promise<MonitoredSite | null> {
  return withWriteLock(async () => {
    const store = await readStore();
    const idx = store.sites.findIndex((s) => s.id === id);
    if (idx === -1) return null;
    const updated: MonitoredSite = {
      ...store.sites[idx],
      ...fields,
      updated_at: new Date().toISOString(),
    };
    store.sites[idx] = updated;
    await writeStore(store);
    return updated;
  });
}

export async function deleteSite(id: string): Promise<void> {
  return withWriteLock(async () => {
    const store = await readStore();
    store.sites = store.sites.filter((s) => s.id !== id);
    store.scans = store.scans.filter((s) => s.site_id !== id);
    await writeStore(store);
  });
}

export async function insertScan(scan: Omit<ScanRecord, 'id' | 'scanned_at'>): Promise<ScanRecord> {
  return withWriteLock(async () => {
    const store = await readStore();
    const record: ScanRecord = {
      ...scan,
      id: uuid(),
      scanned_at: new Date().toISOString(),
    };
    store.scans.push(record);
    await writeStore(store);
    return record;
  });
}

export async function getScansForSite(siteId: string, limit?: number): Promise<ScanRecord[]> {
  const store = await readStore();
  let scans = store.scans.filter((s) => s.site_id === siteId);
  scans = scans.sort(
    (a, b) => new Date(b.scanned_at).getTime() - new Date(a.scanned_at).getTime()
  );
  if (limit) scans = scans.slice(0, limit);
  return scans;
}

export async function getAllScans(limit?: number, offset?: number): Promise<ScanRecord[]> {
  const store = await readStore();
  let scans = store.scans.slice().sort(
    (a, b) => new Date(b.scanned_at).getTime() - new Date(a.scanned_at).getTime()
  );
  const start = offset ?? 0;
  const end = limit ? start + limit : undefined;
  return scans.slice(start, end);
}

export async function getScanCount(): Promise<number> {
  const store = await readStore();
  return store.scans.length;
}

export async function getRecentScans(limit: number): Promise<ScanRecord[]> {
  return getAllScans(limit);
}

export async function getDueSites(): Promise<MonitoredSite[]> {
  const store = await readStore();
  const now = Date.now();
  return store.sites
    .filter((s) => s.monitoring_enabled)
    .filter((s) => s.next_scan_at === null || new Date(s.next_scan_at).getTime() <= now)
    .sort((a, b) => {
      const aTime = a.next_scan_at ? new Date(a.next_scan_at).getTime() : 0;
      const bTime = b.next_scan_at ? new Date(b.next_scan_at).getTime() : 0;
      return aTime - bTime;
    });
}
